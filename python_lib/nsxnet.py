# Hesiod NSX Edge, Tier-0 and VPC networking for a workload domain (Module 15)
# Description: Part EDGE (US-017): edge cluster, Tier-0 (Active/Standby), eBGP + BFD to the lab router, inbound
#              prefix list (default route only), route redistribution, global gateway MTU.
#              Part VPC (US-018): external and private transit gateway IP blocks, transit gateway attached to the
#              Tier-0, VPC connectivity profile with Auto-SNAT, the Hello World VPC with a private and a public subnet,
#              two Ubuntu test VMs, and the Hello World tests (egress via Auto-SNAT, public reachability, jumbo TEPs).
#              Everything goes through the NSX Policy API of the workload domain's NSX (nsx-w01) and the domain's vCenter.
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.5 (--diagnose shows route types, BGP session state and the raw advertised-routes answer)
#         1.4 (-m15 VPC --diagnose: where the VPC routes stop between VPC, transit gateway, Tier-0 and BGP)
#         1.3 (Hello World: diagnostics when egress fails, TEP test details, no crash after the vCenter logout)
#         1.2 (idempotent reruns: existing objects are updated with PUT + _revision, not PATCHed)
#         1.1 (edge state read from the realized transport node; the policy path has no usable /state)
#
# lab_spec: workload_domains[n]["edge"] and workload_domains[n]["vpc"] (see json_lib/lab_spec.json). The lab router
# (the design's tor-a/tor-b) is configured by hand: -m15 EDGE --router-config prints what it needs.
#
# Public functions
#   edge_settings(lab_spec, name=None) / vpc_settings(lab_spec, name=None)   resolve lab_spec (no network calls)
#   edge_plan(lab_spec, name=None)          -m15 EDGE: plan + preflight (NSX reachable, objects found, IPs free)
#   router_config(lab_spec, name=None)      -m15 EDGE --router-config: what the lab router needs (table + FRR example)
#   edge_deploy(lab_spec, name=None)        -m15 EDGE --deploy: profiles, TEP pool, trunks, edges, edge cluster, Tier-0, BGP
#   edge_report(lab_spec, name=None)        -m15 EDGE --report: US-017 evidence (BGP/BFD, routes, MTU, edge CLI output)
#   vpc_plan / vpc_deploy / hello_world / vpc_report / hello_world_cleanup   the same for -m15 VPC (US-018)
#
# Every failure raises NetError.

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import vmware as libvmw
from python_lib import wld as libwld
from python_lib import ubuntu as libubuntu

# Import Standard Python Libraries
import base64
import datetime
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import time

import requests
import urllib3
import yaml

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

EP = "/infra/sites/default/enforcement-points/default"
PROJECT = "/orgs/default/projects/default"
EDGE_TIMEOUT = 45 * 60
EVIDENCE_DIR = "conf/evidence"


class NetError(Exception):
    pass


# ---------------------------------------------------------------- NSX Policy API client

class Nsx:
    def __init__(self, fqdn, password, user="admin"):
        self.fqdn, self.base = fqdn, f"https://{fqdn}"
        self.s = requests.Session()
        self.s.trust_env, self.s.verify = False, False
        self.s.auth = (user, password)

    def _call(self, method, path, body=None, ok404=False, timeout=60):
        url = path if path.startswith("http") else f"{self.base}{path if path.startswith('/api') else '/policy/api/v1' + path}"
        for attempt in range(3):
            try:
                r = self.s.request(method, url, json=body, timeout=timeout)
            except requests.RequestException as e:
                if attempt == 2:
                    raise NetError(f"NSX {self.fqdn}: {method} {path}: {e}")
                time.sleep(5)
                continue
            if r.status_code == 404 and ok404:
                return None
            if r.status_code in (502, 503) and attempt < 2:
                time.sleep(10)
                continue
            if r.status_code >= 300:
                try:
                    j = r.json()
                    msg = j.get("error_message") or r.text
                    msg += "".join(f" | {x.get('error_message')}" for x in j.get("related_errors") or [])
                except ValueError:
                    msg = r.text
                raise NetError(f"NSX {self.fqdn}: {method} {path}: HTTP {r.status_code} {msg[:700]}")
            return r.json() if r.text.strip() else {}
        return None

    def get(self, path, ok404=False):
        return self._call("GET", path, ok404=ok404)

    def patch(self, path, body):
        return self._call("PATCH", path, body)

    def post(self, path, body=None):
        return self._call("POST", path, body)

    def put(self, path, body):
        return self._call("PUT", path, body)

    def ensure(self, path, body):
        """Create with PATCH; when the object exists, PUT it back only if a field we set differs (some NSX objects,
        e.g. host switch profiles, refuse a PATCH on an existing path)."""
        cur = self.get(path, ok404=True)
        if not cur:
            return self.patch(path, body)
        if all(cur.get(k) == v for k, v in body.items()):
            return cur
        return self.put(path, {**cur, **body})

    def delete(self, path):
        return self._call("DELETE", path, ok404=True)

    def results(self, path):
        out, cursor = [], None
        while True:
            r = self.get(path + (("&" if "?" in path else "?") + f"cursor={cursor}" if cursor else "")) or {}
            out += r.get("results") or []
            cursor = r.get("cursor")
            if not cursor:
                return out

    def realized_id(self, intent_path, timeout_s=300):
        """The management-plane id NSX realized for a policy object (what edge and vCenter references need)."""
        deadline = time.time() + timeout_s
        while True:
            r = self.get(f"/infra/realized-state/realized-entities?intent_path={intent_path}") or {}
            for e in r.get("results") or []:
                if e.get("realization_specific_identifier") and e.get("state") == "REALIZED":
                    return e["realization_specific_identifier"]
            if time.time() > deadline:
                raise NetError(f"NSX {self.fqdn}: {intent_path} not realized after {timeout_s}s")
            time.sleep(5)


# ---------------------------------------------------------------- settings

def _net(lab_spec, idx):
    n = lab_spec["network"][int(idx)]
    gw = n["default_gateway"]
    prefix = int(n["cidr"])
    return {"name": n["name"], "gateway": gw, "prefix": prefix, "vlan": int(n["vlan"]),
            "cidr": str(ipaddress.ip_network(f"{gw}/{prefix}", strict=False))}


def _host_ip(net, octet):
    return libvmw.get_ip_range(net["gateway"], str(octet), str(octet))[0]


def _placeholder(v):
    return v is None or str(v).startswith("<")


def edge_settings(lab_spec, name=None):
    w = libwld.wld_settings(lab_spec, name)
    if not w["recorded"]:
        raise NetError(f"workload domain {w['name']} has no recorded address plan ({libwld._plan_file(w['name'])}): "
                       "create it with -m14 first")
    e = w["entry"].get("edge") or {}
    if not e:
        raise NetError(f'workload_domains[{w["name"]}] has no "edge" section (see json_lib/lab_spec.json)')
    count = int(e.get("count", 2))
    ec = e.get("edge_cluster_name", f"ec-{w['name']}")
    # management IPs: next free in the DNS range, after everything (recorded like the domain's vCenter/NSX)
    plan_name = f"{w['name']}-edge"
    pf = libwld._plan_file(plan_name)
    if os.path.exists(pf):
        addresses = json.load(open(pf))["addresses"]
        recorded = True
    else:
        addresses = libwld._allocate(lab_spec, {"name": plan_name}, [f"en{i + 1:02d}" for i in range(count)])
        recorded = False
    if len(addresses) != count:
        raise NetError(f"{pf} was recorded for {len(addresses)} edges, lab_spec asks for {count}")
    tep_cfg = e.get("tep") or {}
    if _placeholder(tep_cfg.get("assign_ip_from_this_network")):
        raise NetError("edge.tep.assign_ip_from_this_network is required (the edge TEP VLAN; may be the host TEP VLAN)")
    tep = _net(lab_spec, tep_cfg["assign_ip_from_this_network"])
    tep_range = libvmw.get_ip_range(tep["gateway"], str(tep_cfg["range_start"]), str(tep_cfg["range_end"]))
    if len(tep_range) < count * 2:
        raise NetError(f"edge.tep range has {len(tep_range)} address(es); {count} edges x 2 uplinks need {count * 2}")
    host_tep = w["tep"]
    if host_tep["subnet"] == tep["cidr"] and set(host_tep["range"]) & set(tep_range):
        raise NetError(f"edge.tep range overlaps the workload domain host TEP range {host_tep['range'][0]}-{host_tep['range'][-1]}")
    uplinks = []
    for j, u in enumerate(e.get("uplinks") or []):
        if _placeholder(u.get("assign_ip_from_this_network")):
            raise NetError(f"edge.uplinks[{j}].assign_ip_from_this_network is required")
        n = _net(lab_spec, u["assign_ip_from_this_network"])
        ips = [_host_ip(n, o) for o in (u.get("edge_ips") or [])]
        if len(ips) != count:
            raise NetError(f"edge.uplinks[{j}].edge_ips needs {count} host octets, one per edge")
        uplinks.append({"label": "ab"[j] if j < 2 else str(j), "net": n, "edge_ips": ips,
                        "peer": _host_ip(n, u.get("peer_ip", "1"))})
    if len(uplinks) != 2:
        raise NetError("edge.uplinks needs exactly 2 entries (the design's two ToR uplink VLANs)")
    t0 = e.get("tier0") or {}
    bgp = e.get("bgp") or {}
    mtu = e.get("mtu") or {}
    root, wname = w["root"], w["name"]
    return {
        "wld": w, "name": wname, "edge_cluster": ec, "count": count,
        "form_factor": str(e.get("form_factor", "MEDIUM")).upper(),
        "addresses": addresses, "recorded": recorded, "plan_name": plan_name,
        "tep": tep, "tep_range": tep_range, "uplinks": uplinks,
        "t0": t0.get("name", f"t0-{wname}"), "ha_mode": t0.get("ha_mode", "ACTIVE_STANDBY"),
        "local_asn": str(t0.get("asn", "65100")), "remote_asn": str(bgp.get("remote_asn", "65001")),
        "keepalive": int(bgp.get("keepalive", 60)), "hold": int(bgp.get("hold", 180)),
        "bfd": bool(bgp.get("bfd", True)), "bfd_interval": int(bgp.get("bfd_interval_ms", 1000)),
        "bfd_multiple": int(bgp.get("bfd_multiple", 3)),
        "interface_mtu": int(mtu.get("interface", 9000)), "gateway_mtu": int(mtu.get("global_gateway", 8800)),
        "prefix_list": e.get("inbound_prefix_list", "pl-default-only"),
        # NSX objects (ids)
        "uplink_profile": f"{ec}-uplink-profile", "tep_pool": f"{ec}-tep-pool",
        "uplink_tz": f"{ec}-uplink-tz", "trunks": [f"{ec}-trunk-a", f"{ec}-trunk-b"],
        "uplink_segments": [f"{ec}-uplink-{u['label']}" for u in uplinks],
        "host_overlay_tz": f"{root}-{wname}-overlay-tz", "host_vlan_tz": f"{root}-{wname}-vlan-tz",
        "password": w["password"],
    }


def vpc_settings(lab_spec, name=None):
    edge = edge_settings(lab_spec, name)
    v = edge["wld"]["entry"].get("vpc") or {}
    if not v:
        raise NetError(f'workload_domains[{edge["name"]}] has no "vpc" section (see json_lib/lab_spec.json)')
    ext = v.get("external_block") or {}
    ptgw = v.get("private_tgw_block") or {}
    hw = v.get("hello_world") or {}
    if _placeholder(ext.get("cidr")):
        raise NetError("vpc.external_block.cidr is required (routable; advertised to the lab router)")
    if _placeholder(hw.get("private_cidr")):
        raise NetError("vpc.hello_world.private_cidr is required")
    subnets = hw.get("subnets") or {}
    ubuntu = next((g for g in lab_spec.get("ubuntu_servers") or [] if g.get("OVA_path")), {})
    return {
        "edge": edge, "name": edge["name"],
        "ext_block": {"id": ext.get("name", "ext-block"), "cidr": ext["cidr"]},
        "ptgw_block": {"id": ptgw.get("name", "ptgw-block"), "cidr": ptgw.get("cidr")},
        "profile_name": v.get("profile_name", "mpc-vpc-profile"),
        "gateway_connection": f"gc-{edge['t0']}",
        "vpc": hw.get("vpc", "hello-world-vpc"), "private_cidr": hw["private_cidr"],
        "subnets": {"private": {"id": (subnets.get("private") or {}).get("name", "sn-private"),
                                "size": int((subnets.get("private") or {}).get("size", 16))},
                    "public": {"id": (subnets.get("public") or {}).get("name", "sn-public"),
                               "size": int((subnets.get("public") or {}).get("size", 16))}},
        "vm_prefix": hw.get("vm_prefix", "hw"), "vm_cpu": int(hw.get("vm_cpu", 1)),
        "vm_memory_gb": int(hw.get("vm_memory_gb", 2)), "test_url": hw.get("test_url", "https://dl.broadcom.com"),
        "ova_path": (None if _placeholder(hw.get("OVA_path")) else hw["OVA_path"]) or ubuntu.get("OVA_path"),
        "ova_url": (None if _placeholder(hw.get("OVA_url")) else hw["OVA_url"]) or ubuntu.get("OVA_url"),
        "os_auth": _ubuntu_auth(lab_spec),
    }


def _ubuntu_auth(lab_spec):
    auths = lab_spec["authentication"]
    a = next((x for x in auths if str(x.get("system", "")).lower() == "ubuntu"), None)
    return a or auths[0]


# ---------------------------------------------------------------- discovery

def _nsx(edge):
    return Nsx(edge["wld"]["addresses"]["nsx_vip"]["fqdn"], edge["password"])


def _tz(nsx, display_name, tz_type=None):
    for t in nsx.results(f"{EP}/transport-zones"):
        if t.get("display_name") == display_name or t.get("id") == display_name:
            if tz_type is None or t.get("tz_type", "").startswith(tz_type):
                return t
    return None


def _compute_manager(nsx, vc_fqdn):
    for cm in (nsx.get("/api/v1/fabric/compute-managers") or {}).get("results") or []:
        if cm.get("server", "").lower() == vc_fqdn.lower() or cm.get("display_name", "").lower() == vc_fqdn.lower():
            return cm["id"]
    raise NetError(f"{vc_fqdn} is not a compute manager in NSX {nsx.fqdn}")


def _vc_objects(edge):
    from pyVmomi import vim
    from pyVim.connect import Disconnect
    w = edge["wld"]
    si = libwld._vc_connect(w)
    try:
        c = si.content

        def find(t, n):
            v = c.viewManager.CreateContainerView(c.rootFolder, [t], True)
            try:
                return next((o for o in v.view if o.name == n), None)
            finally:
                v.Destroy()
        cl = find(vim.ClusterComputeResource, w["cluster"])
        ds = find(vim.Datastore, w["datastore"])
        pg = find(vim.dvs.DistributedVirtualPortgroup, f"{w['vds']}-pg-management")
        missing = [n for n, o in ((w["cluster"], cl), (w["datastore"], ds), (f"{w['vds']}-pg-management", pg)) if not o]
        if missing:
            raise NetError(f"not found in {w['addresses']['vcenter']['fqdn']}: {missing}")
        return {"cluster": cl._moId, "datastore": ds._moId, "mgmt_pg": pg._moId,
                "hosts": sorted(h.name for h in cl.host)}
    finally:
        Disconnect(si)


def _pings(ip):
    try:
        return subprocess.run(["ping", "-c", "2", "-W", "1", ip], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    except FileNotFoundError:
        return False


# ---------------------------------------------------------------- EDGE: plan, router config

def _print_edge_plan(edge):
    liblog.print_logs(f"Edge plan for workload domain {edge['name']} (NSX {edge['wld']['addresses']['nsx_vip']['fqdn']})"
                      f"{' (recorded)' if edge['recorded'] else ''}:")
    for i, (k, a) in enumerate(edge["addresses"].items()):
        ups = ", ".join(f"{u['net']['vlan']}:{u['edge_ips'][i]}" for u in edge["uplinks"])
        liblog.print_logs(f"    edge {k}  {a['fqdn']:30} mgmt {a['ip']:15} uplinks {ups}  ({edge['form_factor']})")
    liblog.print_logs(f"    Edge cluster {edge['edge_cluster']}; edge TEP VLAN {edge['tep']['vlan']} "
                      f"{edge['tep_range'][0]}-{edge['tep_range'][-1]}")
    liblog.print_logs(f"    Tier-0 {edge['t0']} {edge['ha_mode']}, AS {edge['local_asn']}; BGP to "
                      + ", ".join(f"{u['peer']} (VLAN {u['net']['vlan']})" for u in edge["uplinks"])
                      + f" AS {edge['remote_asn']}, timers {edge['keepalive']}/{edge['hold']}, BFD {'on' if edge['bfd'] else 'off'}")
    liblog.print_logs(f"    Inbound prefix list {edge['prefix_list']} (0.0.0.0/0 only); interface MTU {edge['interface_mtu']}, "
                      f"global gateway MTU {edge['gateway_mtu']}")


def edge_plan(lab_spec, name=None):
    edge = edge_settings(lab_spec, name)
    _print_edge_plan(edge)
    checks = []
    servers = lab_spec["vcf"].get("nameservers") or lab_spec["domain"].get("server_ips", [])
    for a in edge["addresses"].values():
        p = next((f"{s}: {x}" for s in servers for x in [libwld.libvcf._dns_check(s, a["fqdn"], a["ip"])] if x), None)
        checks.append((f"DNS {a['fqdn']} <-> {a['ip']}", p))
        if not edge["recorded"]:
            checks.append((f"{a['ip']} free", "answers ping" if _pings(a["ip"]) else None))
    for u in edge["uplinks"]:
        checks.append((f"lab router {u['peer']} answers on VLAN {u['net']['vlan']}",
                       None if _pings(u["peer"]) else "no ping reply (configure the router first: --router-config)"))
    try:
        nsx = _nsx(edge)
        nsx.get("/infra")
        checks.append((f"NSX {nsx.fqdn} reachable", None))
        for tz, kind in ((edge["host_overlay_tz"], "OVERLAY"), (edge["host_vlan_tz"], "VLAN")):
            checks.append((f"transport zone {tz}", None if _tz(nsx, tz, kind) else "not found"))
        _compute_manager(nsx, edge["wld"]["addresses"]["vcenter"]["fqdn"])
        checks.append(("vCenter is NSX's compute manager", None))
    except NetError as e:
        checks.append(("NSX objects", str(e)[:200]))
    try:
        _vc_objects(edge)
        checks.append(("cluster, vSAN datastore, management port group in vCenter", None))
    except Exception as e:
        checks.append(("vCenter objects", str(getattr(e, "msg", e))[:200]))
    failed = [c for c in checks if c[1]]
    for n, p in checks:
        liblog.print_logs(f"  {'FAIL' if p else 'ok  '}  {n}{': ' + p if p else ''}")
    liblog.print_logs(f"Preflight: {len(checks) - len(failed)} passed, {len(failed)} failed.")
    return failed


def router_config(lab_spec, name=None):
    edge = edge_settings(lab_spec, name)
    v = (edge["wld"]["entry"].get("vpc") or {}).get("external_block") or {}
    ext = v.get("cidr") if not _placeholder(v.get("cidr")) else "<vpc.external_block.cidr>"
    L = ["", f"Lab router configuration for {edge['t0']} (AS {edge['local_asn']}) - the design's tor-a/tor-b roles:", ""]
    L.append(f"  {'VLAN':6} {'router IP':16} {'neighbors (edges)':34} remote-AS  timers   BFD")
    for u in edge["uplinks"]:
        L.append(f"  {u['net']['vlan']:<6} {u['peer'] + '/' + str(u['net']['prefix']):16} {', '.join(u['edge_ips']):34} "
                 f"{edge['local_asn']:9}  {edge['keepalive']}/{edge['hold']}   {'yes' if edge['bfd'] else 'no'}")
    L += ["", f"  Router AS {edge['remote_asn']}. Send only a default route to the edges (default-originate); accept",
          f"  {ext} (VPC external block: public subnets, Auto-SNAT IPs) from them. MTU {edge['interface_mtu']} on both VLANs.",
          "", "  FRR example (adapt to your router's syntax):", "", f"    router bgp {edge['remote_asn']}"]
    for u in edge["uplinks"]:
        for ip in u["edge_ips"]:
            L.append(f"     neighbor {ip} remote-as {edge['local_asn']}")
            L.append(f"     neighbor {ip} timers {edge['keepalive']} {edge['hold']}")
            if edge["bfd"]:
                L.append(f"     neighbor {ip} bfd")
    L.append("     address-family ipv4 unicast")
    for u in edge["uplinks"]:
        for ip in u["edge_ips"]:
            L += [f"      neighbor {ip} default-originate", f"      neighbor {ip} prefix-list FROM-NSX in"]
    L += ["     exit-address-family", f"    ip prefix-list FROM-NSX seq 10 permit {ext} le 32", ""]
    for line in L:
        print(line)
    return L


# ---------------------------------------------------------------- EDGE: deploy

def _record_edge_plan(edge):
    pf = libwld._plan_file(edge["plan_name"])
    if not os.path.exists(pf):
        os.makedirs(os.path.dirname(pf), exist_ok=True)
        with open(pf, "w") as f:
            json.dump({"name": edge["plan_name"], "recorded": time.strftime("%Y-%m-%d %H:%M"),
                       "addresses": edge["addresses"]}, f, indent=2)
        liblog.print_logs(f"    Recorded the edge addresses in {pf} (Module 7 and 14 IPAM now skip them).")


def _uplinks_profile(edge):
    up = [{"uplink_name": "uplink-1", "uplink_type": "PNIC"}, {"uplink_name": "uplink-2", "uplink_type": "PNIC"}]
    return {"resource_type": "PolicyUplinkHostSwitchProfile", "display_name": edge["uplink_profile"],
            "transport_vlan": edge["tep"]["vlan"],
            "teaming": {"policy": "LOADBALANCE_SRCID", "active_list": up},
            "named_teamings": [{"name": "uplink-1-only", "policy": "FAILOVER_ORDER", "active_list": [up[0]]},
                               {"name": "uplink-2-only", "policy": "FAILOVER_ORDER", "active_list": [up[1]]}]}


_MP_IDS = {}


def _edge_state(nsx, eid):
    """Deployment state of an edge: the policy /state when it answers with one, else the management-plane transport
    node state (/api/v1/transport-nodes/<uuid>/state), the uuid found by the edge's display name."""
    try:
        st = nsx.get(f"{EP}/edge-transport-nodes/{eid}/state", ok404=True) or {}
    except NetError:
        st = {}
    if st.get("state"):
        return st
    if eid not in _MP_IDS:
        try:
            for tn in (nsx.get("/api/v1/transport-nodes?node_types=EdgeNode") or {}).get("results") or []:
                if tn.get("display_name") == eid or (tn.get("node_deployment_info") or {}).get("display_name") == eid:
                    _MP_IDS[eid] = tn.get("node_id") or tn.get("id")
        except NetError:
            pass
        if eid not in _MP_IDS:
            if st:
                liblog.print_logs(f"    edge {eid}: unrecognised state answer {sorted(st)[:12]}")
            return {}
    try:
        return nsx.get(f"/api/v1/transport-nodes/{_MP_IDS[eid]}/state", ok404=True) or {}
    except NetError:
        return {}


def _wait_edges(nsx, ids):
    deadline = time.time() + EDGE_TIMEOUT
    last = {}
    while True:
        done = 0
        for i in ids:
            st = _edge_state(nsx, i)
            dep = (st.get("node_deployment_state") or {}).get("state", "")
            s = f"{st.get('state', '?')}/{dep or '?'}"
            if last.get(i) != s:
                liblog.print_logs(f"    edge {i}: {s}")
                last[i] = s
            if st.get("state") == "failed" or "FAILED" in dep:
                details = "; ".join(str(x.get("failure_message") or x.get("sub_system_type") or x)
                                    for x in st.get("details") or [])[:600]
                raise NetError(f"edge {i} deployment failed: {dep} {details}")
            if st.get("state") == "success" and dep in ("NODE_READY", ""):
                done += 1
        if done == len(ids):
            return
        if time.time() > deadline:
            raise NetError(f"edges not ready after {EDGE_TIMEOUT // 60} min (NSX > System > Fabric > Nodes > Edge Transport Nodes)")
        time.sleep(30)


def _anti_affinity(edge, names):
    from pyVmomi import vim
    from pyVim.connect import Disconnect
    w = edge["wld"]
    si = libwld._vc_connect(w)
    try:
        c = si.content
        v = c.viewManager.CreateContainerView(c.rootFolder, [vim.ClusterComputeResource, vim.VirtualMachine], True)
        try:
            objs = list(v.view)
        finally:
            v.Destroy()
        cl = next(o for o in objs if isinstance(o, vim.ClusterComputeResource) and o.name == w["cluster"])
        vms = [o for o in objs if isinstance(o, vim.VirtualMachine) and o.name in names]
        rule = f"{edge['edge_cluster']}-anti-affinity"
        if any(r.name == rule for r in cl.configurationEx.rule or []) or len(vms) < 2:
            return
        spec = vim.cluster.ConfigSpecEx(rulesSpec=[vim.cluster.RuleSpec(operation="add", info=vim.cluster.AntiAffinityRuleSpec(
            name=rule, enabled=True, mandatory=False, vm=vms))])
        task = cl.ReconfigureComputeResource_Task(spec, modify=True)
        while task.info.state in ("queued", "running"):
            time.sleep(2)
        liblog.print_logs(f"    DRS rule {rule}: {', '.join(names)} kept on different hosts.")
    except Exception as e:
        liblog.print_logs(f"    WARNING: DRS anti-affinity rule not created: {getattr(e, 'msg', e)}")
    finally:
        Disconnect(si)


def edge_deploy(lab_spec, name=None):
    edge = edge_settings(lab_spec, name)
    _print_edge_plan(edge)
    nsx = _nsx(edge)
    w = edge["wld"]
    _record_edge_plan(edge)
    overlay = _tz(nsx, edge["host_overlay_tz"], "OVERLAY")
    host_vlan = _tz(nsx, edge["host_vlan_tz"], "VLAN")
    if not overlay or not host_vlan:
        raise NetError(f"transport zones {edge['host_overlay_tz']} / {edge['host_vlan_tz']} not found in NSX {nsx.fqdn}")
    cm = _compute_manager(nsx, w["addresses"]["vcenter"]["fqdn"])
    vc = _vc_objects(edge)

    liblog.print_logs("(Edge 1) Uplink profile, edge TEP pool, edge uplink transport zone, trunk and uplink segments.")
    nsx.ensure(f"/infra/host-switch-profiles/{edge['uplink_profile']}", _uplinks_profile(edge))
    nsx.ensure(f"/infra/ip-pools/{edge['tep_pool']}", {"display_name": edge["tep_pool"]})
    nsx.ensure(f"/infra/ip-pools/{edge['tep_pool']}/ip-subnets/s1", {
        "resource_type": "IpAddressPoolStaticSubnet", "cidr": edge["tep"]["cidr"], "gateway_ip": edge["tep"]["gateway"],
        "allocation_ranges": [{"start": edge["tep_range"][0], "end": edge["tep_range"][-1]}]})
    nsx.ensure(f"{EP}/transport-zones/{edge['uplink_tz']}", {
        "display_name": edge["uplink_tz"], "tz_type": "VLAN_BACKED",
        "uplink_teaming_policy_names": ["uplink-1-only", "uplink-2-only"]})
    # Edge data NICs sit on NSX VLAN trunk segments in the hosts' VLAN zone, so the edge TEP may share the host TEP VLAN
    for t in edge["trunks"]:
        nsx.ensure(f"/infra/segments/{t}", {"display_name": t, "transport_zone_path": host_vlan["path"],
                                           "vlan_ids": ["0-4094"]})
    for seg, u, team in zip(edge["uplink_segments"], edge["uplinks"], ("uplink-1-only", "uplink-2-only")):
        nsx.ensure(f"/infra/segments/{seg}", {"display_name": seg, "transport_zone_path": f"{EP}/transport-zones/{edge['uplink_tz']}",
                                             "vlan_ids": [str(u["net"]["vlan"])],
                                             "advanced_config": {"uplink_teaming_policy_name": team}})
    for t in edge["trunks"]:
        nsx.realized_id(f"/infra/segments/{t}")

    liblog.print_logs(f"(Edge 2) {edge['count']} edge node(s), {edge['form_factor']}, on {w['cluster']} (reservations off for the nested lab).")
    ids = []
    mgmt = edge["wld"]["mgmt"]
    for i, (k, a) in enumerate(edge["addresses"].items()):
        eid = a["short"]
        ids.append(eid)
        if nsx.get(f"{EP}/edge-transport-nodes/{eid}", ok404=True):
            liblog.print_logs(f"    {eid}: already defined in NSX.")
            continue
        body = {
            "resource_type": "PolicyEdgeTransportNode", "display_name": eid, "hostname": a["fqdn"],
            "form_factor": edge["form_factor"],
            "credentials": {"cli_username": "admin", "cli_password": edge["password"], "root_password": edge["password"],
                            "audit_username": "audit", "audit_password": edge["password"]},
            "appliance_config": {"enable_ssh": True, "allow_ssh_root_login": True,
                                 "dns_servers": lab_spec["vcf"].get("nameservers") or lab_spec["domain"].get("server_ips", [])},
            "management_interface": {"network_id": vc["mgmt_pg"], "ip_assignment_specs": [{
                "ip_assignment_type": "StaticIpv4", "default_gateway": [mgmt["gateway"]],
                "management_port_subnets": [{"ip_addresses": [a["ip"]], "prefix_length": int(mgmt["cidr"])}]}]},
            "switch_spec": {"switches": [{
                "switch_name": "nsxDefaultHostSwitch",
                "overlay_transport_zone_paths": [overlay["path"]],
                "vlan_transport_zone_paths": [f"{EP}/transport-zones/{edge['uplink_tz']}"],
                "pnics": [{"device_name": "fp-eth0", "uplink_name": "uplink-1", "datapath_network_id": f"/infra/segments/{edge['trunks'][0]}"},
                          {"device_name": "fp-eth1", "uplink_name": "uplink-2", "datapath_network_id": f"/infra/segments/{edge['trunks'][1]}"}],
                "profile_paths": [{"key": "UplinkHostSwitchProfile", "value": f"/infra/host-switch-profiles/{edge['uplink_profile']}"}],
                "tunnel_endpoints": [{"ip_assignment_specs": [{"ip_assignment_type": "StaticIpv4Pool",
                                                                "ip_pool": f"/infra/ip-pools/{edge['tep_pool']}"}]}]}]},
            "vm_deployment_config": {"placement_type": "PolicyVsphereDeploymentConfig", "vc_id": cm,
                                     "compute_id": vc["cluster"], "storage_id": vc["datastore"],
                                     "reservation_info": {"cpu_reservation": {"reservation_in_mhz": 0,
                                                                              "reservation_in_shares": "LOW_PRIORITY"},
                                                          "memory_reservation": {"reservation_percentage": 0}}},
        }
        nsx.patch(f"{EP}/edge-transport-nodes/{eid}", body)
        liblog.print_logs(f"    {eid}: deployment started ({a['fqdn']}, {a['ip']}).")
    _wait_edges(nsx, ids)
    _anti_affinity(edge, ids)

    liblog.print_logs(f"(Edge 3) Edge cluster {edge['edge_cluster']}.")
    ec_path = f"{EP}/edge-clusters/{edge['edge_cluster']}"
    if not nsx.get(ec_path, ok404=True):
        nsx.patch(ec_path, {"display_name": edge["edge_cluster"],
                            "policy_edge_nodes": [{"id": str(i), "edge_transport_node_path": f"{EP}/edge-transport-nodes/{eid}"}
                                                  for i, eid in enumerate(ids)]})
    nsx.realized_id(ec_path)
    nodes = nsx.results(f"{ec_path}/edge-nodes")
    node_path = {}
    for n in nodes:
        tn = n.get("nsx_id") or n.get("id")
        match = next((eid for eid in ids if eid in (n.get("display_name"), tn) or n.get("display_name", "").startswith(eid)), None)
        node_path[match or n.get("id")] = n["path"]
    if not all(eid in node_path for eid in ids):   # fall back to member order
        node_path = {eid: n["path"] for eid, n in zip(ids, sorted(nodes, key=lambda x: str(x.get("member_index", x.get("id")))))}

    liblog.print_logs(f"(Edge 4) Tier-0 {edge['t0']}: {edge['ha_mode']}, interfaces, prefix list, BGP + BFD, redistribution.")
    t0 = f"/infra/tier-0s/{edge['t0']}"
    nsx.patch(t0, {"display_name": edge["t0"], "ha_mode": edge["ha_mode"], "failover_mode": "NON_PREEMPTIVE"})
    nsx.patch(f"{t0}/locale-services/default", {
        "edge_cluster_path": ec_path,
        "route_redistribution_config": {"bgp_enabled": True, "redistribution_rules": [{
            "name": "mpc-redistribution", "route_redistribution_types": ["TGW_STATIC", "TIER0_NAT", "TIER0_STATIC"]}]}})
    for i, eid in enumerate(ids):
        for u, seg in zip(edge["uplinks"], edge["uplink_segments"]):
            nsx.patch(f"{t0}/locale-services/default/interfaces/{eid}-uplink-{u['label']}", {
                "type": "EXTERNAL", "segment_path": f"/infra/segments/{seg}", "edge_path": node_path[eid],
                "subnets": [{"ip_addresses": [u["edge_ips"][i]], "prefix_len": u["net"]["prefix"]}],
                "mtu": edge["interface_mtu"]})
    nsx.patch(f"{t0}/prefix-lists/{edge['prefix_list']}", {
        "display_name": edge["prefix_list"],
        "prefixes": [{"network": "0.0.0.0/0", "action": "PERMIT"}, {"network": "ANY", "action": "DENY"}]})
    nsx.patch(f"{t0}/locale-services/default/bgp", {
        "enabled": True, "local_as_num": edge["local_asn"], "inter_sr_ibgp": edge["ha_mode"] == "ACTIVE_ACTIVE",
        "graceful_restart_config": {"mode": "HELPER_ONLY"}})
    for u in edge["uplinks"]:
        nsx.patch(f"{t0}/locale-services/default/bgp/neighbors/{_nbr_id(u)}", {
            "neighbor_address": u["peer"], "remote_as_num": edge["remote_asn"],
            "keep_alive_time": edge["keepalive"], "hold_down_time": edge["hold"],
            "source_addresses": u["edge_ips"],
            "bfd": {"enabled": edge["bfd"], "interval": edge["bfd_interval"], "multiple": edge["bfd_multiple"]},
            "route_filtering": [{"address_family": "IPV4", "enabled": True,
                                 "in_route_filters": [f"{t0}/prefix-lists/{edge['prefix_list']}"]}]})

    liblog.print_logs(f"(Edge 5) Global gateway MTU {edge['gateway_mtu']}.")
    g = nsx.get("/infra/global-config") or {}
    if g.get("mtu") != edge["gateway_mtu"]:
        nsx.patch("/infra/global-config", {"resource_type": "GlobalConfig", "mtu": edge["gateway_mtu"]})
    liblog.print_logs("Edge deployment complete. Waiting up to 5 minutes for BGP to come up.")
    deadline = time.time() + 300
    while time.time() < deadline:
        st = _bgp_status(nsx, edge)
        if st and all(x["state"] == "ESTABLISHED" for x in st):
            break
        time.sleep(20)
    for x in _bgp_status(nsx, edge):
        liblog.print_logs(f"    BGP {x['source']} -> {x['neighbor']}: {x['state']}")
    liblog.print_logs("Next: -m15 EDGE --report (US-017 evidence).")
    return ids


def _nbr_id(u):
    return f"peer-{u['peer'].replace('.', '-')}"


# ---------------------------------------------------------------- EDGE: status + evidence

def _bgp_status(nsx, edge):
    out = []
    t0 = f"/infra/tier-0s/{edge['t0']}/locale-services/default/bgp/neighbors/status"
    try:
        for r in (nsx.get(t0) or {}).get("results") or []:
            out.append({"neighbor": r.get("neighbor_address"), "source": r.get("source_address"),
                        "state": str(r.get("connection_state", "?")).upper(),
                        "edge": r.get("edge_path") or r.get("transport_node", {}).get("display_name"),
                        "received": r.get("total_in_prefix_count"), "sent": r.get("total_out_prefix_count")})
    except NetError:
        pass
    return out


def _bgp_routes(nsx, edge):
    learned = set()
    try:
        r = nsx.get(f"/infra/tier-0s/{edge['t0']}/routing-table?route_source=BGP") or {}
        for per_edge in r.get("results") or []:
            for e in per_edge.get("route_entries") or []:
                if str(e.get("route_type", "")).lower().startswith("b"):
                    learned.add(e.get("network"))
    except NetError:
        return None
    return learned


def _edge_cli(ip, password, t0):
    """Best-effort `get bgp neighbor summary` / `get bfd-sessions` on an edge (the US-017 'edge CLI output')."""
    import paramiko
    out = []
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username="admin", password=password, timeout=15, look_for_keys=False, allow_agent=False)
        ch = ssh.invoke_shell(width=200)

        def run(cmd, wait=4):
            ch.send(cmd + "\n")
            time.sleep(wait)
            buf = b""
            while ch.recv_ready():
                buf += ch.recv(65535)
            return buf.decode(errors="replace")
        run("", 2)
        lr = run("get logical-routers", 5)
        vrf = None
        for line in lr.splitlines():
            if "SERVICE_ROUTER_TIER0" in line and (t0 in line or vrf is None):
                parts = line.split()
                vrf = next((p for p in parts if p.isdigit()), vrf)
        out.append(lr)
        if vrf:
            run(f"vrf {vrf}", 2)
            for cmd in ("get bgp neighbor summary", "get bfd-sessions", "get route bgp"):
                out.append(f"### {cmd}\n" + run(cmd, 5))
        ssh.close()
    except Exception as e:
        out.append(f"(edge CLI not collected: {e})")
    return "\n".join(out)


def _write_evidence(prefix, title, rep, extra_md=None):
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.join(EVIDENCE_DIR, f"{prefix}_{stamp}")
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2, default=str)
    L = [f"# {title}", "", f"Generated {rep['generated']}. Result: **{rep['result']}**.", "",
         "| Check | Result | Detail |", "|---|---|---|"]
    L += [f"| {c['check']} | {c['result']} | {str(c['detail']).replace('|', '/')} |" for c in rep["checks"]]
    L += extra_md or []
    with open(base + ".md", "w") as f:
        f.write("\n".join(L) + "\n")
    for c in rep["checks"]:
        liblog.print_logs(f"    {c['result']:4}  {c['check']}{': ' + str(c['detail']) if c['result'] != 'PASS' and c['detail'] else ''}")
    liblog.print_logs(f"Evidence report: {rep['result']}  ->  {base}.md  (+ .json)")
    return base


def _report(title):
    rep = {"generated": datetime.datetime.now().isoformat(timespec="seconds"), "title": title, "checks": []}

    def add(check, ok, detail=""):
        rep["checks"].append({"check": check, "result": "PASS" if ok else "FAIL", "detail": detail})
    return rep, add


def edge_report(lab_spec, name=None):
    edge = edge_settings(lab_spec, name)
    nsx = _nsx(edge)
    rep, add = _report(f"US-017 evidence: edges, Tier-0 and BGP for {edge['name']}")
    rep["plan"] = {"edges": edge["addresses"], "t0": edge["t0"], "uplinks": [
        {"vlan": u["net"]["vlan"], "edge_ips": u["edge_ips"], "peer": u["peer"]} for u in edge["uplinks"]]}
    ids = [a["short"] for a in edge["addresses"].values()]
    for eid in ids:
        st = _edge_state(nsx, eid)
        add(f"Edge {eid} deployed and ready", st.get("state") == "success",
            f"{st.get('state')}/{(st.get('node_deployment_state') or {}).get('state')}")
    bgp = _bgp_status(nsx, edge)
    rep["bgp"] = bgp
    for u in edge["uplinks"]:
        sessions = [b for b in bgp if b["neighbor"] == u["peer"]]
        est = [b for b in sessions if b["state"] == "ESTABLISHED"]
        add(f"BGP to {u['peer']} (VLAN {u['net']['vlan']}) Established", bool(est),
            ", ".join(f"{b['source']}:{b['state']}" for b in sessions) or "no session")
    routes = _bgp_routes(nsx, edge)
    rep["bgp_learned"] = sorted(routes) if routes is not None else None
    add("Only 0.0.0.0/0 accepted inbound", routes == {"0.0.0.0/0"},
        "routing table not readable" if routes is None else ", ".join(sorted(routes)) or "nothing learned")
    g = nsx.get("/infra/global-config") or {}
    add(f"Global gateway MTU {edge['gateway_mtu']}", g.get("mtu") == edge["gateway_mtu"], g.get("mtu"))
    cli = []
    for eid, a in zip(ids, edge["addresses"].values()):
        text = _edge_cli(a["ip"], edge["password"], edge["t0"])
        cli.append(f"## {eid} ({a['ip']})\n\n```\n{text.strip()}\n```")
    bfd_text = "\n".join(cli)
    if edge["bfd"]:
        up = bfd_text.lower().count(" up")
        add("BFD sessions up (edge CLI)", up >= 1 and "bfd" in bfd_text.lower(),
            "see the edge CLI output below" if up else "no BFD session reported up in the edge CLI output")
    add("Edge CLI output stored", "get bgp neighbor summary" in bfd_text, "")
    rep["result"] = "PASS" if all(c["result"] == "PASS" for c in rep["checks"]) else "FAIL"
    _write_evidence(f"edge_{edge['name']}_evidence", rep["title"], rep, ["", "## Edge CLI output", ""] + cli)
    return rep


# ---------------------------------------------------------------- VPC: plan + deploy

def _print_vpc_plan(v):
    liblog.print_logs(f"VPC plan for workload domain {v['name']}:")
    liblog.print_logs(f"    External IP block {v['ext_block']['id']} {v['ext_block']['cidr']} (advertised by {v['edge']['t0']})")
    liblog.print_logs(f"    Private transit gateway block {v['ptgw_block']['id']} {v['ptgw_block']['cidr'] or '(reuse the existing one)'}")
    liblog.print_logs(f"    Transit gateway default attached to {v['edge']['t0']} via {v['gateway_connection']}; "
                      f"connectivity profile {v['profile_name']} (N/S services, Auto-SNAT, edge cluster {v['edge']['edge_cluster']})")
    liblog.print_logs(f"    VPC {v['vpc']} {v['private_cidr']}: {v['subnets']['private']['id']} (private, {v['subnets']['private']['size']} IPs), "
                      f"{v['subnets']['public']['id']} (public, {v['subnets']['public']['size']} IPs)")
    liblog.print_logs(f"    Test VMs {v['vm_prefix']}-private and {v['vm_prefix']}-public ({v['vm_cpu']} vCPU / {v['vm_memory_gb']} GB, "
                      f"{os.path.basename(v['ova_path'] or '?')})")


def vpc_plan(lab_spec, name=None):
    v = vpc_settings(lab_spec, name)
    _print_vpc_plan(v)
    checks = []
    nsx = _nsx(v["edge"])
    try:
        t0 = nsx.get(f"/infra/tier-0s/{v['edge']['t0']}", ok404=True)
        checks.append((f"Tier-0 {v['edge']['t0']} exists (-m15 EDGE first)", None if t0 else "not found"))
        tgw = nsx.get(f"{PROJECT}/transit-gateways/default", ok404=True)
        checks.append(("transit gateway default exists", None if tgw else "not found"))
        prof = nsx.get(f"{PROJECT}/vpc-connectivity-profiles/default", ok404=True)
        checks.append(("default VPC connectivity profile exists", None if prof else "not found"))
        bgp = _bgp_status(nsx, v["edge"])
        checks.append(("BGP Established", None if bgp and all(b["state"] == "ESTABLISHED" for b in bgp) else "not all sessions up"))
    except NetError as e:
        checks.append(("NSX", str(e)[:200]))
    checks.append((f"Ubuntu OVA {v['ova_path']}", None if v["ova_path"] and (os.path.exists(v["ova_path"]) or v["ova_url"])
                   else "missing (set vpc.hello_world.OVA_path or ubuntu_servers[].OVA_path)"))
    failed = [c for c in checks if c[1]]
    for n, p in checks:
        liblog.print_logs(f"  {'FAIL' if p else 'ok  '}  {n}{': ' + p if p else ''}")
    liblog.print_logs(f"Preflight: {len(checks) - len(failed)} passed, {len(failed)} failed.")
    return failed


def _overlaps(a, b):
    return ipaddress.ip_network(a, strict=False).overlaps(ipaddress.ip_network(b, strict=False))


def vpc_deploy(lab_spec, name=None):
    v = vpc_settings(lab_spec, name)
    _print_vpc_plan(v)
    nsx = _nsx(v["edge"])
    t0 = f"/infra/tier-0s/{v['edge']['t0']}"
    if not nsx.get(t0, ok404=True):
        raise NetError(f"Tier-0 {v['edge']['t0']} not found: run -m15 EDGE --deploy first")
    ec_path = f"{EP}/edge-clusters/{v['edge']['edge_cluster']}"

    liblog.print_logs("(VPC 1) IP blocks.")
    ext_path = f"/infra/ip-blocks/{v['ext_block']['id']}"
    nsx.ensure(ext_path, {"display_name": v["ext_block"]["id"], "cidr": v["ext_block"]["cidr"], "visibility": "EXTERNAL"})
    prof_path = f"{PROJECT}/vpc-connectivity-profiles/default"
    prof = nsx.get(prof_path) or {}
    ptgw_paths = list(prof.get("private_tgw_ip_blocks") or [])
    if v["ptgw_block"]["cidr"]:
        existing = [b for b in nsx.results("/infra/ip-blocks") if b.get("visibility") == "PRIVATE"]
        mine = next((b for b in existing if b.get("id") == v["ptgw_block"]["id"]), None)
        clash = [b for b in existing if b is not mine and b.get("cidr") and _overlaps(b["cidr"], v["ptgw_block"]["cidr"])]
        if mine or not clash:
            nsx.ensure(f"/infra/ip-blocks/{v['ptgw_block']['id']}", {"display_name": v["ptgw_block"]["id"],
                                                                    "cidr": v["ptgw_block"]["cidr"], "visibility": "PRIVATE"})
            ptgw_paths = [f"/infra/ip-blocks/{v['ptgw_block']['id']}"]
        else:
            liblog.print_logs(f"    {v['ptgw_block']['cidr']} overlaps {clash[0].get('display_name')} ({clash[0]['cidr']}); "
                              "keeping the existing private transit gateway block.")
    if not ptgw_paths:
        raise NetError("no private transit gateway IP block: set vpc.private_tgw_block.cidr (a /16 in 9.1)")

    liblog.print_logs(f"(VPC 2) Transit gateway default attached to {v['edge']['t0']}.")
    gc = f"/infra/gateway-connections/{v['gateway_connection']}"
    nsx.ensure(gc, {"display_name": v["gateway_connection"], "tier0_path": t0,
                   "advertise_outbound_networks": {"allow_external_blocks": [ext_path]}})
    tgw = f"{PROJECT}/transit-gateways/default"
    atts = nsx.results(f"{tgw}/attachments")
    if not any(a.get("connection_path") == gc for a in atts):
        nsx.patch(f"{tgw}/attachments/{v['gateway_connection']}", {"connection_path": gc})

    liblog.print_logs(f"(VPC 3) VPC connectivity profile {v['profile_name']}.")
    nsx.patch(prof_path, {"display_name": v["profile_name"], "transit_gateway_path": tgw,
                          "external_ip_blocks": [ext_path], "private_tgw_ip_blocks": ptgw_paths,
                          "service_gateway": {"enable": True, "nat_config": {"enable_default_snat": True},
                                              "edge_cluster_paths": [ec_path]}})

    liblog.print_logs(f"(VPC 4) VPC {v['vpc']} and its subnets.")
    vpc = f"{PROJECT}/vpcs/{v['vpc']}"
    nsx.patch(vpc, {"display_name": v["vpc"], "private_ips": [v["private_cidr"]]})
    nsx.patch(f"{vpc}/attachments/default", {"vpc_connectivity_profile": prof_path})
    for kind, mode in (("private", "Private"), ("public", "Public")):
        sn = v["subnets"][kind]
        if not nsx.get(f"{vpc}/subnets/{sn['id']}", ok404=True):
            nsx.patch(f"{vpc}/subnets/{sn['id']}", {"display_name": sn["id"], "access_mode": mode,
                                                    "ipv4_subnet_size": sn["size"],
                                                    "subnet_dhcp_config": {"mode": "DHCP_SERVER"}})
        s = nsx.get(f"{vpc}/subnets/{sn['id']}") or {}
        liblog.print_logs(f"    {sn['id']}: {mode}, {', '.join(s.get('ip_addresses') or ['(allocating)'])}")
    liblog.print_logs("VPC networking configured. Next: -m15 VPC --hello-world (test VMs + tests).")


# ---------------------------------------------------------------- VPC: Hello World VMs + tests

def _vc_find(si, vimtype, pred):
    c = si.content
    v = c.viewManager.CreateContainerView(c.rootFolder, [vimtype], True)
    try:
        return [o for o in v.view if pred(o)]
    finally:
        v.Destroy()


def _subnet_network(si, v, sn_id):
    from pyVmomi import vim
    nets = _vc_find(si, vim.Network, lambda n: sn_id in n.name)
    exact = [n for n in nets if n.name == sn_id] or [n for n in nets if v["vpc"] in n.name] or nets
    if not exact:
        raise NetError(f"no vCenter network for VPC subnet {sn_id} yet (VPC subnets appear as NSX port groups)")
    return exact[0]


def _hw_vm_spec(v, kind):
    a = v["os_auth"]
    return {"name": f"{v['vm_prefix']}-{kind}", "hostname": f"{v['vm_prefix']}-{kind}", "esxi_host": None,
            "ova_path": v["ova_path"], "ova_url": v["ova_url"], "cpu": v["vm_cpu"], "memory_gb": v["vm_memory_gb"],
            "disks_gb": [10], "nested_hv": False, "username": a["username"], "password": a["password"]}


def _hw_cloud_init(spec, dns, mac):
    eth = {"match": {"macaddress": mac} if mac else {"name": "en*"}, "dhcp4": True}
    if dns:
        eth["dhcp4-overrides"] = {"use-dns": False}
        eth["nameservers"] = {"addresses": dns}
    meta = {"instance-id": f"{spec['name']}-{int(time.time())}", "local-hostname": spec["hostname"],
            "network": {"version": 2, "ethernets": {"primary": eth}}}
    user = {"hostname": spec["hostname"], "users": [{"name": spec["username"], "groups": ["sudo"], "shell": "/bin/bash",
                                                     "lock_passwd": False, "passwd": libubuntu._hash_password(spec["password"])}],
            "ssh_pwauth": True}
    return yaml.safe_dump(meta, sort_keys=False), "#cloud-config\n" + yaml.safe_dump(user, sort_keys=False)


def _guest_ip(vm, cidr, timeout_s=900):
    net = ipaddress.ip_network(cidr, strict=False)
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        for n in vm.guest.net or []:
            for ip in n.ipAddress or []:
                try:
                    if ipaddress.ip_address(ip) in net:
                        return ip
                except ValueError:
                    pass
        time.sleep(10)
    raise NetError(f"{vm.name}: no address from {cidr} reported by VMware Tools after {timeout_s}s")


def _deploy_hw_vm(si, v, kind, subnet_cidr, dns):
    from pyVmomi import vim
    w = v["edge"]["wld"]
    spec = _hw_vm_spec(v, kind)
    spec["esxi_host"] = w["addresses"]["vcenter"]["fqdn"]
    existing = _vc_find(si, vim.VirtualMachine, lambda o: o.name == spec["name"])
    if existing:
        liblog.print_logs(f"    {spec['name']}: exists.")
        return existing[0], _guest_ip(existing[0], subnet_cidr, 300)
    libubuntu._ensure_ova(spec)
    dc = _vc_find(si, vim.Datacenter, lambda o: o.name == w["datacenter"])
    cl = _vc_find(si, vim.ClusterComputeResource, lambda o: o.name == w["cluster"])
    ds = _vc_find(si, vim.Datastore, lambda o: o.name == w["datastore"])
    if not (dc and cl and ds):
        raise NetError(f"{w['datacenter']} / {w['cluster']} / {w['datastore']} not found in {spec['esxi_host']}")
    net = _subnet_network(si, v, v["subnets"][kind]["id"])
    loc = {"content": si.content, "dc": dc[0], "pool": cl[0].resourcePool, "host": cl[0].host[0], "ds": ds[0], "net": net}
    liblog.print_logs(f"    {spec['name']}: importing {os.path.basename(spec['ova_path'])} onto {net.name}.")
    vm = libubuntu._import_ova(si, loc, spec)
    meta, user = _hw_cloud_init(spec, dns, libubuntu._vm_mac(vm))
    libubuntu._reconfigure(vm, spec, meta, user)
    libubuntu._wait_task(vm.PowerOnVM_Task(), "power_on")
    ip = _guest_ip(vm, subnet_cidr)
    liblog.print_logs(f"    {spec['name']}: up at {ip}.")
    return vm, ip


def _guest_run(si, vm, auth, script, timeout_s=180):
    """Run a shell script inside the VM through VMware Tools; returns (exit code, output)."""
    from pyVmomi import vim
    gom = si.content.guestOperationsManager
    out_file = f"/tmp/hesiod-{int(time.time())}.out"
    creds = vim.vm.guest.NamePasswordAuthentication(username=auth["username"], password=auth["password"])
    deadline = time.time() + 300
    while vm.guest.toolsRunningStatus != "guestToolsRunning":
        if time.time() > deadline:
            raise NetError(f"{vm.name}: VMware Tools not running")
        time.sleep(5)
    pid = gom.processManager.StartProgramInGuest(vm, creds, vim.vm.guest.ProcessManager.ProgramSpec(
        programPath="/bin/sh", arguments=f"-c '{script} > {out_file} 2>&1'"))
    deadline = time.time() + timeout_s
    rc = None
    while time.time() < deadline:
        p = gom.processManager.ListProcessesInGuest(vm, creds, [pid])
        if p and p[0].exitCode is not None and p[0].endTime:
            rc = p[0].exitCode
            break
        time.sleep(3)
    output = ""
    try:
        info = gom.fileManager.InitiateFileTransferFromGuest(vm, creds, out_file)
        url = info.url.replace("*", vm.runtime.host.name)
        output = requests.get(url, verify=False, timeout=30).text
    except Exception as e:
        output = f"(output not retrieved: {getattr(e, 'msg', e)})"
    return rc, output.strip()


def hello_world(lab_spec, name=None):
    from pyVim.connect import Disconnect
    v = vpc_settings(lab_spec, name)
    if not v["ova_path"]:
        raise NetError("no Ubuntu OVA: set vpc.hello_world.OVA_path (or ubuntu_servers[].OVA_path)")
    nsx = _nsx(v["edge"])
    vpc = f"{PROJECT}/vpcs/{v['vpc']}"
    cidrs = {}
    for kind in ("private", "public"):
        s = nsx.get(f"{vpc}/subnets/{v['subnets'][kind]['id']}", ok404=True)
        if not s or not s.get("ip_addresses"):
            raise NetError(f"subnet {v['subnets'][kind]['id']} not ready: run -m15 VPC --deploy first")
        cidrs[kind] = s["ip_addresses"][0]
    dns = lab_spec["vcf"].get("nameservers") or [s for s in lab_spec["domain"].get("server_ips", []) if s[0].isdigit()]
    liblog.print_logs(f"(Hello World 1) Test VMs on {v['subnets']['private']['id']} ({cidrs['private']}) and "
                      f"{v['subnets']['public']['id']} ({cidrs['public']}).")
    si = libwld._vc_connect(v["edge"]["wld"])
    try:
        vm_priv, ip_priv = _deploy_hw_vm(si, v, "private", cidrs["private"], dns)
        vm_pub, ip_pub = _deploy_hw_vm(si, v, "public", cidrs["public"], dns)
        liblog.print_logs("(Hello World 2) Tests.")
        rc, out = _guest_run(si, vm_priv, v["os_auth"],
                             f"curl -sS -o /dev/null -w \"%{{http_code}} %{{remote_ip}}\" --max-time 30 {v['test_url']}")
        priv = {"vm": vm_priv.name, "ip": ip_priv, "url": v["test_url"], "exit": rc, "output": out}
        liblog.print_logs(f"    private VM {ip_priv}: curl {v['test_url']} -> exit {rc}, {out[:120]}")
        if rc != 0:
            # Which part failed: DNS server reachable? Internet reachable by IP? (separates DNS from routing/NAT)
            probes = " ; ".join([f"echo DNS {d}: $(ping -c 2 -W 2 {d} >/dev/null 2>&1 && echo reachable || echo unreachable)" for d in dns]
                                + ["echo GW $(ip -4 route show default | head -1)",
                                   "echo 1.1.1.1: $(ping -c 2 -W 2 1.1.1.1 >/dev/null 2>&1 && echo reachable || echo unreachable)",
                                   "echo resolv: $(grep ^nameserver /etc/resolv.conf | tr \"\\n\" \" \")",
                                   "echo resolved: $(resolvectl dns 2>/dev/null | tr \"\\n\" \" \")"])
            _, diag = _guest_run(si, vm_priv, v["os_auth"], probes, timeout_s=90)
            priv["diagnostics"] = diag
            for line in diag.splitlines():
                liblog.print_logs(f"        {line}")
        pub_name = vm_pub.name
    finally:
        Disconnect(si)
    pub_ok = _pings(ip_pub)
    liblog.print_logs(f"    public VM {ip_pub}: ping from {socket.gethostname()} (jump01) -> {'reply' if pub_ok else 'no reply'}")
    teps = tep_jumbo_test(v)
    res = {"time": time.strftime("%Y-%m-%d %H:%M:%S"), "private": priv,
           "public": {"vm": pub_name, "ip": ip_pub, "ping_from": socket.gethostname(), "ok": pub_ok},
           "teps": teps}
    os.makedirs(libwld.WLD_DIR, exist_ok=True)
    with open(os.path.join(libwld.WLD_DIR, f"{v['name']}_hello_world.json"), "w") as f:
        json.dump(res, f, indent=2)
    liblog.print_logs("Hello World done. -m15 VPC --report writes the US-018 evidence.")
    return res


def tep_jumbo_test(v):
    """vmkping ++netstack=vxlan -d -s 8972 from every host TEP to every other host TEP and to the edge TEPs."""
    import paramiko
    w = v["edge"]["wld"]
    nsx = _nsx(v["edge"])
    edge_teps = []
    for a in v["edge"]["addresses"].values():
        st = _edge_state(nsx, a["short"])
        for hs in st.get("host_switch_states") or []:
            edge_teps += [e.get("ip") for e in hs.get("endpoints") or [] if e.get("ip")]
    hosts = {}
    for h in w["hosts"]:
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(h["ip"], username="root", password=h["password"], timeout=15, look_for_keys=False, allow_agent=False)
            _, o, _ = ssh.exec_command("esxcli network ip interface ipv4 get -N vxlan", timeout=30)
            sub = ipaddress.ip_network(w["tep"]["subnet"])
            teps = []
            for line in o.read().decode().splitlines():   # Name  IPv4 Address  Netmask  Broadcast  Type  Gateway ...
                parts = line.split()
                if len(parts) > 1 and parts[0].startswith("vmk") and parts[1].count(".") == 3:
                    if ipaddress.ip_address(parts[1]) in sub:
                        teps.append(parts[1])
            hosts[h["fqdn"]] = {"ssh": ssh, "teps": teps}
        except Exception as e:
            hosts[h["fqdn"]] = {"ssh": None, "teps": [], "error": str(e)}
    results = []
    all_teps = {ip: f for f, x in hosts.items() for ip in x["teps"]}
    for ip in edge_teps:
        all_teps.setdefault(ip, "edge")
    for f, x in hosts.items():
        if not x["ssh"]:
            results.append({"from": f, "to": None, "ok": False, "detail": x.get("error")})
            continue
        for ip, owner in all_teps.items():
            if owner == f:
                continue
            _, o, _ = x["ssh"].exec_command(f"vmkping ++netstack=vxlan -d -s 8972 -c 2 {ip}", timeout=30)
            text = o.read().decode()
            ok = " 0% packet loss" in text or "0.0% packet loss" in text
            results.append({"from": f, "to": ip, "owner": owner, "ok": ok, "detail": text.strip().splitlines()[-1:] or ""})
        x["ssh"].close()
    good = sum(r["ok"] for r in results)
    liblog.print_logs(f"    jumbo vmkping (8972 bytes, DF) between TEPs: {good}/{len(results)} passed.")
    for f, x in hosts.items():
        liblog.print_logs(f"        {f}: TEPs {', '.join(x['teps']) or 'none found'}{'  (' + x['error'][:120] + ')' if x.get('error') else ''}")
    for r in [r for r in results if not r["ok"]][:8]:
        liblog.print_logs(f"        FAIL {r['from']} -> {r['to']} ({r.get('owner')}): {r.get('detail')}")
    if edge_teps:
        liblog.print_logs(f"        edge TEPs: {', '.join(edge_teps)}")
    return results


def hello_world_cleanup(lab_spec, name=None):
    from pyVmomi import vim
    from pyVim.connect import Disconnect
    v = vpc_settings(lab_spec, name)
    si = libwld._vc_connect(v["edge"]["wld"])
    try:
        for kind in ("private", "public"):
            for vm in _vc_find(si, vim.VirtualMachine, lambda o: o.name == f"{v['vm_prefix']}-{kind}"):
                libubuntu._destroy_vm(vm)
                liblog.print_logs(f"    {vm.name}: deleted.")
    finally:
        Disconnect(si)


def vpc_report(lab_spec, name=None):
    v = vpc_settings(lab_spec, name)
    nsx = _nsx(v["edge"])
    rep, add = _report(f"US-018 evidence: transit gateway, IP blocks, VPC profile and Hello World for {v['name']}")
    tgw = f"{PROJECT}/transit-gateways/default"
    atts = nsx.results(f"{tgw}/attachments")
    gc = f"/infra/gateway-connections/{v['gateway_connection']}"
    add(f"Transit gateway attached to {v['edge']['t0']}", any(a.get("connection_path") == gc for a in atts),
        ", ".join(a.get("connection_path", "?") for a in atts))
    ext = nsx.get(f"/infra/ip-blocks/{v['ext_block']['id']}", ok404=True) or {}
    add(f"External IP block {v['ext_block']['cidr']}", ext.get("visibility") == "EXTERNAL", ext.get("cidr"))
    prof = nsx.get(f"{PROJECT}/vpc-connectivity-profiles/default", ok404=True) or {}
    sg = prof.get("service_gateway") or {}
    add(f"Profile {v['profile_name']}: N/S services + Auto-SNAT + edge cluster",
        bool(sg.get("enable")) and bool((sg.get("nat_config") or {}).get("enable_default_snat")) and bool(sg.get("edge_cluster_paths")),
        f"{prof.get('display_name')}: enable={sg.get('enable')}, snat={(sg.get('nat_config') or {}).get('enable_default_snat')}")
    hw_file = os.path.join(libwld.WLD_DIR, f"{v['name']}_hello_world.json")
    hw = json.load(open(hw_file)) if os.path.exists(hw_file) else None
    if not hw:
        add("Hello World run", False, "no results yet: -m15 VPC --hello-world")
    else:
        p = hw["private"]
        code = (p.get("output") or "").split()[:1]
        add(f"Private VM {p['ip']} egresses via Auto-SNAT ({p['url']})", p.get("exit") == 0 and code and code[0][:1] in "23",
            p.get("output"))
        add(f"Public VM {hw['public']['ip']} reachable from {hw['public']['ping_from']} (jump01)", hw["public"]["ok"], "")
        t = hw.get("teps") or []
        add("Jumbo vmkping (8972, DF) passes between all TEPs", bool(t) and all(r["ok"] for r in t),
            f"{sum(r['ok'] for r in t)}/{len(t)} " + "; ".join(f"{r['from']}->{r['to']}" for r in t if not r["ok"])[:300])
        rep["hello_world"] = hw
    learned = _bgp_routes(nsx, v["edge"])
    rep["edge_bgp_learned"] = sorted(learned) if learned is not None else None
    rep["result"] = "PASS" if all(c["result"] == "PASS" for c in rep["checks"]) else "FAIL"
    _write_evidence(f"vpc_{v['name']}_evidence", rep["title"], rep)
    return rep


def _routes_in(obj, prefix):
    """Every network string inside an NSX routing/forwarding-table answer that falls inside prefix."""
    net = ipaddress.ip_network(prefix, strict=False)
    found = set()

    def walk(o):
        if isinstance(o, dict):
            for k, val in o.items():
                if k in ("network", "prefix", "destination") and isinstance(val, str):
                    try:
                        if ipaddress.ip_network(val, strict=False).subnet_of(net):
                            rt = o.get("route_type") or o.get("type") or o.get("route_source")
                            found.add(f"{val} ({rt})" if rt else val)
                    except (ValueError, TypeError):
                        pass
                walk(val)
        elif isinstance(o, list):
            for x in o:
                walk(x)
    walk(obj)
    return sorted(found, key=lambda x: ipaddress.ip_network(x.split()[0], strict=False))


def vpc_diagnose(lab_spec, name=None):
    """Read-only: follow the VPC external block from the VPC to the transit gateway, the Tier-0 and BGP."""
    v = vpc_settings(lab_spec, name)
    e = v["edge"]
    nsx = _nsx(e)
    ext = v["ext_block"]["cidr"]
    t0 = f"/infra/tier-0s/{e['t0']}"
    ls = f"{t0}/locale-services/default"
    out = {}

    def step(label, fn):
        try:
            r = fn()
        except NetError as x:
            r = f"ERROR {str(x)[:300]}"
        out[label] = r
        text = r if isinstance(r, str) else json.dumps(r, default=str)
        liblog.print_logs(f"  {label}: {text[:400]}")
        return r

    liblog.print_logs(f"(Diagnose) Where do the {ext} routes stop? VPC -> transit gateway -> {e['t0']} -> BGP -> lab router")
    step("VPC subnets", lambda: {s_.get("id"): {"mode": s_.get("access_mode"), "ips": s_.get("ip_addresses")}
                                for s_ in nsx.results(f"{PROJECT}/vpcs/{v['vpc']}/subnets")})
    step("VPC attachment", lambda: {k: (nsx.get(f"{PROJECT}/vpcs/{v['vpc']}/attachments/default") or {}).get(k)
                                    for k in ("vpc_connectivity_profile",)})
    step("VPC realized", lambda: [(x.get("entity_type"), x.get("state"), x.get("runtime_status"))
                                  for x in (nsx.get(f"/infra/realized-state/realized-entities?intent_path={PROJECT}/vpcs/{v['vpc']}") or {}).get("results") or []])
    step("Gateway connection", lambda: {k: (nsx.get(f"/infra/gateway-connections/{v['gateway_connection']}") or {}).get(k)
                                        for k in ("tier0_path", "advertise_outbound_networks", "aggregate_routes",
                                                  "inbound_remote_networks")})
    step("Gateway connection realized", lambda: [(x.get("entity_type"), x.get("state"), x.get("runtime_status"))
                                                 for x in (nsx.get(f"/infra/realized-state/realized-entities?intent_path=/infra/gateway-connections/{v['gateway_connection']}") or {}).get("results") or []])
    step("Transit gateway attachments", lambda: [a.get("connection_path") for a in nsx.results(f"{PROJECT}/transit-gateways/default/attachments")])
    for label, path in (("Transit gateway routes", f"{PROJECT}/transit-gateways/default/routing-table"),
                        ("Transit gateway forwarding", f"{PROJECT}/transit-gateways/default/forwarding-table")):
        step(label + f" in {ext}", lambda path=path: _routes_in(nsx.get(path) or {}, ext))
    step("Tier-0 redistribution", lambda: (nsx.get(ls) or {}).get("route_redistribution_config"))
    for label, path in (("Tier-0 routing table", f"{t0}/routing-table"),
                        ("Tier-0 forwarding table", f"{t0}/forwarding-table")):
        step(label + f" in {ext}", lambda path=path: _routes_in(nsx.get(path) or {}, ext))
    step("BGP sessions", lambda: [f"{b['source']}->{b['neighbor']} {b['state']} in={b['received']} out={b['sent']}"
                                  for b in _bgp_status(nsx, e)])
    for u in e["uplinks"]:
        def adv(u=u):
            raw = nsx.get(f"{ls}/bgp/neighbors/{_nbr_id(u)}/advertised-routes") or {}
            routes = _routes_in(raw, "0.0.0.0/0")
            return routes or f"none; raw answer: {json.dumps(raw, default=str)[:300]}"
        step(f"Advertised to {u['peer']}", adv)
    os.makedirs(libwld.WLD_DIR, exist_ok=True)
    path = os.path.join(libwld.WLD_DIR, f"{v['name']}_vpc_diagnose.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2, default=str)
    liblog.print_logs(f"Saved: {path}")
    return out


# Dry run (settings only, no network calls):  python3 -m python_lib.nsxnet conf/lab_spec.json [domain]
if __name__ == "__main__":
    import sys
    with open(sys.argv[1] if len(sys.argv) > 1 else "conf/lab_spec.json") as f:
        spec_py = json.load(f)
    n = sys.argv[2] if len(sys.argv) > 2 else None
    _print_edge_plan(edge_settings(spec_py, n))
    try:
        _print_vpc_plan(vpc_settings(spec_py, n))
    except NetError as e:
        print(f"VPC: {e}")
