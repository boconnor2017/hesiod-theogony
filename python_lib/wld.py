# Hesiod VCF VI Workload Domain (Module 14)
# Description: Creates a VI workload domain through the SDDC Manager API from lab_spec["workload_domains"]:
#              network pool -> host commissioning (the VI hosts from Module 7) -> domain spec -> SDDC Manager
#              validation -> domain creation (vCenter + NSX + vSAN cluster) -> default vSAN storage policy.
#              Certificates, backups and encryption for the new vCenter/NSX come from Modules 10, 11 and 12.
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.5 (day-1 extensions for US-016: --certs, --backups, --roles; evidence checks for all three)
#         1.4 (TEP pool sized for hosts x uplinks)
#         1.3 (own SSO domain per workload domain: VCF 9 has no ELM join; NSX network profile for the uplink profile)
#         1.2 (VI hosts get lab-CA certificates before commissioning, KB 415767)
#         1.1 (vMotion, vSAN and host TEP ranges on their own lab_spec networks: assign_ip_from_this_network)
#
# IP plan: the workload domain vCenter, NSX VIP and NSX node(s) take the addresses right after the highest one already
# allocated in the Module 4 DNS range of the management network (VCF management components, every nested ESXi host,
# earlier workload domains), never below it. The first --validate/--deploy records the plan in conf/wld/<name>_plan.json;
# from then on the recorded addresses are used, and Module 7's IPAM treats them as taken.
#
# Public functions
#   wld_settings(lab_spec, name=None)     Names, addresses, pools for one workload domain (no network calls).
#   show_plan(lab_spec, name=None)        -m14: plan + local preflight (DNS, free IPs, hosts answering).
#   commission(lab_spec, name=None)       -m14 --commission: network pool + validate + commission the VI hosts.
#   validate(lab_spec, name=None)         -m14 --validate: commission if needed, render the domain spec, SDDC Manager validation.
#   deploy(lab_spec, name=None)           -m14 --deploy: validate, create the domain, monitor it, then the storage policy.
#   status(lab_spec, name=None)           -m14 --status: attach to the recorded domain creation task.
#   retry(lab_spec, name=None)            -m14 --retry: retry the recorded failed task (PATCH /v1/tasks/{id}).
#   storage_policy(lab_spec, name=None)   -m14 --policy: create the vSAN policy and make it the datastore default.
#   extend_certificates(lab_spec, ...)    -m14 --certs: lab CA certificates for the domain's vCenter, NSX, hosts (Module 10 code).
#   extend_backups(lab_spec, ...)         -m14 --backups: NSX (via SDDC Manager) + vCenter schedule to the SFTP target (Module 11 code).
#   extend_roles(lab_spec, ...)           -m14 --roles: directory groups -> vCenter permissions and NSX role bindings.
#   evidence_report(lab_spec, name=None)  -m14 --report: US-016 evidence (conf/evidence/wld_<name>_evidence_*.md/json).
#
# Every failure raises WldError.

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import vmware as libvmw
from python_lib import esxi as libesxi
from python_lib import vcf as libvcf
from python_lib import conjur as libconjur
from python_lib import ca as libca
from python_lib import backup as libbackup

# Import Standard Python Libraries
import datetime
import ipaddress
import json
import os
import ssl
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

WLD_DIR = "conf/wld"
TERMINAL = {"SUCCESSFUL", "FAILED", "CANCELLED", "COMPLETED_WITH_WARNING", "SKIPPED", "TIMED_OUT"}
DOMAIN_TIMEOUT = 10 * 3600
POLL_S = 60
RAID5 = "RAID-5/6 (Erasure Coding) - Capacity"


class WldError(Exception):
    pass


# ---------------------------------------------------------------- settings and IP plan

def _entry(lab_spec, name=None):
    wlds = lab_spec.get("workload_domains") or []
    if not wlds:
        raise WldError('lab_spec has no "workload_domains" section (see json_lib/lab_spec.json for the template).')
    if name:
        w = next((w for w in wlds if w.get("name") == name), None)
        if not w:
            raise WldError(f"no workload domain named {name} in lab_spec (have: {[w.get('name') for w in wlds]})")
        return w
    return wlds[0]


def _plan_file(name):
    return os.path.join(WLD_DIR, f"{name}_plan.json")


def recorded_ips():
    """IP -> owner for every recorded workload domain plan (used by Module 7's IPAM)."""
    out = {}
    if not os.path.isdir(WLD_DIR):
        return out
    for f in sorted(os.listdir(WLD_DIR)):
        if f.endswith("_plan.json"):
            try:
                plan = json.load(open(os.path.join(WLD_DIR, f)))
            except (OSError, ValueError):
                continue
            for label, a in plan.get("addresses", {}).items():
                out[a["ip"]] = f"workload domain {plan.get('name')} {label} ({a['fqdn']})"
    return out


def _range(gw, start, end):
    return libvmw.get_ip_range(gw, str(start), str(end))


def _allocate(lab_spec, w, labels):
    """Next free addresses in the Module 4 DNS range of the management network."""
    domain = lab_spec["domain"]
    mgmt_idx = libvcf._role(lab_spec, "management")["index"]
    fq = next((f for f in domain["fqdns"] if f["assign_ip_from_this_network"] == mgmt_idx), None)
    if not fq:
        raise WldError("domain.fqdns has no range on the management network")
    taken = dict(libesxi._reserved_ips(lab_spec))
    for h in libesxi.get_nested_esxi_specs(lab_spec):          # every nested host, every group
        taken.setdefault(h["ip"], f"nested host {h['name']}")
    for ip, owner in recorded_ips().items():
        if f"workload domain {w['name']} " not in owner:
            taken.setdefault(ip, owner)
    candidates = _range(lab_spec["network"][mgmt_idx]["default_gateway"], fq["assign_ip_from_this_range_start"],
                        fq["assign_ip_from_this_range_end"])[1:]  # index 0 is the DNS server
    # Only after the highest address already handed out in that range: the low end of the range also holds things
    # Theogony does not plan here (HKS nodes and load balancer IPs, the installer, Ubuntu servers).
    last = max((i for i, ip in enumerate(candidates) if ip in taken), default=-1)
    free = [ip for ip in candidates[last + 1:] if ip not in taken]
    if len(free) < len(labels):
        raise WldError(f"only {len(free)} free address(es) left in the DNS range for {len(labels)} needed; widen domain.fqdns")
    out = {}
    for label, ip in zip(labels, free):
        short = libesxi._dns_name_for_ip(lab_spec, ip)
        out[label] = {"ip": ip, "short": short, "fqdn": f"{short}.{domain['name']}"}
    return out


def _network(lab_spec, role, rng, what):
    """A workload domain range on its own VLAN: rng["assign_ip_from_this_network"] (an index into lab_spec["network"]),
    else the network the management domain uses for that role (vcf.networks)."""
    if not rng or "range_start" not in rng or "range_end" not in rng:
        raise WldError(f"workload_domains[].{what} needs range_start and range_end")
    idx = rng.get("assign_ip_from_this_network")
    if idx is not None and not str(idx).startswith("<"):
        try:
            net = libvcf._net(lab_spec, int(idx))
        except (IndexError, KeyError, ValueError) as e:
            raise WldError(f"workload_domains[].{what}.assign_ip_from_this_network={idx!r}: no such lab_spec network ({e!r})")
    else:
        net = libvcf._role(lab_spec, role)
        if not net:
            raise WldError(f"workload_domains[].{what} has no assign_ip_from_this_network and vcf.networks.{role} is missing")
        net = {k: v for k, v in net.items() if k != "range"}
    ips = _range(net["gateway"], rng["range_start"], rng["range_end"])
    subnet = ipaddress.ip_network(net["subnet"])
    outside = [ip for ip in (ips[0], ips[-1]) if ipaddress.ip_address(ip) not in subnet]
    if outside:
        raise WldError(f"workload_domains[].{what}: {outside[0]} is outside {net['subnet']} ({net['name']})")
    if net["gateway"] in ips:
        raise WldError(f"workload_domains[].{what} includes the gateway {net['gateway']}")
    return {**net, "range": ips, "what": what}


def _check_overlaps(lab_spec, nets):
    """No overlap with any management domain range on the same subnet, nor between the workload domain's own ranges."""
    claims = []
    for role in ("vmotion", "vsan", "host_tep"):
        r = libvcf._role(lab_spec, role)
        if r and r.get("range"):
            claims.append((f"the management domain's vcf.networks.{role}", r["subnet"], set(r["range"])))
    for n in nets:
        mine = set(n["range"])
        for owner, subnet, ips in claims:
            both = sorted(mine & ips, key=ipaddress.ip_address) if subnet == n["subnet"] else []
            if both:
                raise WldError(f"workload_domains[].{n['what']} ({n['range'][0]}-{n['range'][-1]} on {n['subnet']}) "
                               f"overlaps {owner} at {both[0]}" + (f" ... {both[-1]}" if len(both) > 1 else ""))
        claims.append((f"workload_domains[].{n['what']}", n["subnet"], mine))


def wld_settings(lab_spec, name=None):
    w = _entry(lab_spec, name)
    if not w.get("name"):
        raise WldError("workload_domains[].name is required")
    vcf = lab_spec["vcf"]
    names = libvcf._naming(lab_spec)
    objs = {o["name"]: o["value"] for o in vcf["naming_convention"].get("object", [])}
    hosts = libesxi.get_nested_esxi_specs(lab_spec, types=[w.get("nested_esxi_type", "VI")])
    if len(hosts) < 3:
        raise WldError(f"a vSAN workload domain needs at least 3 hosts; nested_esxi_type "
                       f"{w.get('nested_esxi_type', 'VI')} gives {len(hosts)}")
    nsx = w.get("nsx", {})
    count = int(nsx.get("count", 1))
    labels = ["vcenter", "nsx_vip"] + [f"nsx_node{i + 1}" for i in range(count)]
    recorded = None
    if os.path.exists(_plan_file(w["name"])):
        recorded = json.load(open(_plan_file(w["name"])))
        if sorted(recorded.get("addresses", {})) != sorted(labels):
            raise WldError(f"{_plan_file(w['name'])} was recorded for a different NSX node count; delete it only if "
                           f"the domain was never created")
    addresses = recorded["addresses"] if recorded else _allocate(lab_spec, w, labels)
    mgmt = libvcf._role(lab_spec, "management")
    cluster = w.get("cluster_name") or f"{names['root']}-{objs.get('vi-cluster', 'vcl')}"
    pw = lab_spec["authentication"][vcf["use_these_credentials"]]["password"]
    pool = w.get("network_pool", {})
    sp = w.get("storage_policy", {})
    # VCF 9 workload domains get their own vCenter SSO domain (joining the management domain's ELM ring is not
    # supported); VCF SSO / the Identity Broker is what spans domains.
    sso = str(w.get("sso_domain") or "").strip()
    sso = f"{w['name']}.local" if not sso or sso.startswith("<") else sso
    nets = [_network(lab_spec, "vmotion", pool.get("vmotion"), "network_pool.vmotion"),
            _network(lab_spec, "vsan", pool.get("vsan"), "network_pool.vsan"),
            _network(lab_spec, "host_tep", w.get("host_tep"), "host_tep")]
    _check_overlaps(lab_spec, nets)
    if nets[0]["subnet"] == nets[1]["subnet"]:
        raise WldError(f"network_pool.vmotion and network_pool.vsan are both on {nets[0]['subnet']}; a network pool "
                       f"needs a separate subnet (VLAN) for each")
    # NSX gives every host one TEP per active uplink (LOADBALANCE_SRCID teaming), so the TEP pool needs
    # hosts x uplinks addresses; vMotion and vSAN need one per host. Too small a TEP pool only shows up late, as
    # "transport node realization failed" in Create NSX Transport Node Collection.
    vmnics = w.get("vmnics") or vcf.get("cluster", {}).get("vmnics", ["vmnic0", "vmnic1"])
    need = {"host_tep": len(hosts) * len(vmnics), "network_pool.vmotion": len(hosts), "network_pool.vsan": len(hosts)}
    for n in nets:
        if len(n["range"]) < need[n["what"]]:
            raise WldError(f"workload_domains[].{n['what']} has {len(n['range'])} address(es) but {len(hosts)} hosts need "
                           f"{need[n['what']]}" + (f" ({len(vmnics)} TEPs per host, one per uplink)" if n["what"] == "host_tep" else ""))
    return {
        "name": w["name"], "entry": w, "recorded": bool(recorded),
        "hosts": hosts, "addresses": addresses, "mgmt": mgmt,
        "datacenter": w.get("datacenter_name") or f"{names['root']}-{w['name']}-dc",
        "cluster": cluster, "vds": f"{cluster}-vds01", "datastore": f"{cluster}-vsan01",
        "vcenter_size": w.get("vcenter_size", "small"),
        "nsx_size": nsx.get("size", "medium"), "nsx_count": count,
        "esa": str(w.get("vsan_type", vcf.get("cluster", {}).get("vsan_type", "ESA"))).upper() == "ESA",
        "vmnics": w.get("vmnics") or vcf.get("cluster", {}).get("vmnics", ["vmnic0", "vmnic1"]),
        "pool_name": pool.get("name", f"np-{w['name']}"),
        "vmotion": nets[0], "vsan": nets[1], "tep": nets[2],
        "image": None if str(w.get("cluster_image") or "<").startswith("<") else w["cluster_image"],
        "policy": {"name": sp.get("name", f"{w['name']}-r5"), "ftt": int(sp.get("failures_to_tolerate", 1)),
                   "raid5": str(sp.get("raid", "RAID-5")).upper().startswith("RAID-5")},
        "password": pw, "root": names["root"],
        "sso_domain": sso, "sso_user": f"administrator@{sso}",
    }


def _record_plan(cfg):
    os.makedirs(WLD_DIR, exist_ok=True)
    if not os.path.exists(_plan_file(cfg["name"])):
        with open(_plan_file(cfg["name"]), "w") as f:
            json.dump({"name": cfg["name"], "recorded": time.strftime("%Y-%m-%d %H:%M"),
                       "addresses": cfg["addresses"]}, f, indent=2)
        liblog.print_logs(f"    Recorded the address plan in {_plan_file(cfg['name'])} (Module 7 IPAM now skips these).")


def _print_plan(cfg):
    a = cfg["addresses"]
    liblog.print_logs(f"Workload domain {cfg['name']}{' (recorded plan)' if cfg['recorded'] else ''}:")
    liblog.print_logs(f"    vCenter        {a['vcenter']['fqdn']:32} {a['vcenter']['ip']:15} ({cfg['vcenter_size']})")
    liblog.print_logs(f"    NSX VIP        {a['nsx_vip']['fqdn']:32} {a['nsx_vip']['ip']:15}")
    for i in range(cfg["nsx_count"]):
        n = a[f"nsx_node{i + 1}"]
        liblog.print_logs(f"    NSX node {i + 1}     {n['fqdn']:32} {n['ip']:15} ({cfg['nsx_size']})")
    liblog.print_logs(f"    Datacenter {cfg['datacenter']}, cluster {cfg['cluster']}, VDS {cfg['vds']}, "
                      f"datastore {cfg['datastore']} (vSAN {'ESA' if cfg['esa'] else 'OSA'})")
    for h in cfg["hosts"]:
        liblog.print_logs(f"    host           {h['fqdn']:32} {h['ip']:15}")
    for k, label in (("vmotion", "vMotion"), ("vsan", "vSAN"), ("tep", "host TEP")):
        n = cfg[k]
        liblog.print_logs(f"    {label:14} VLAN {n['vlan']:<5} {n['subnet']:18} {n['range'][0]} - {n['range'][-1]}")
    liblog.print_logs(f"    vCenter SSO domain {cfg['sso_domain']} (log in as {cfg['sso_user']})")
    liblog.print_logs(f"    Network pool {cfg['pool_name']}; default storage policy {cfg['policy']['name']} "
                      f"({'RAID-5' if cfg['policy']['raid5'] else 'RAID-1'}, FTT={cfg['policy']['ftt']})")


# ---------------------------------------------------------------- preflight (local)

def preflight(lab_spec, cfg):
    results = []
    servers = [s for s in (lab_spec["vcf"].get("nameservers") or lab_spec["domain"].get("server_ips", []))]
    for label, a in cfg["addresses"].items():
        problem = None
        for s in servers:
            p = libvcf._dns_check(s, a["fqdn"], a["ip"])
            if p:
                problem = f"{s}: {p}"
                break
        results.append((f"DNS {a['fqdn']} <-> {a['ip']}", problem))
        if not cfg["recorded"]:
            results.append((f"{a['ip']} free", "answers ping" if libvcf._pings(a["ip"]) else None))
    for h in cfg["hosts"]:
        try:
            libesxi._served_cert(h["ip"])
            results.append((f"host {h['fqdn']} answers on 443", None))
        except Exception as e:
            results.append((f"host {h['fqdn']} answers on 443", str(e)[:120]))
    failed = [r for r in results if r[1]]
    for name, problem in results:
        liblog.print_logs(f"  {'FAIL' if problem else 'ok  '}  {name}{': ' + problem if problem else ''}")
    liblog.print_logs(f"Preflight: {len(results) - len(failed)} passed, {len(failed)} failed.")
    return failed


def show_plan(lab_spec, name=None):
    cfg = wld_settings(lab_spec, name)
    _print_plan(cfg)
    return preflight(lab_spec, cfg)


# ---------------------------------------------------------------- SDDC Manager helpers

def _sddc(lab_spec):
    return libconjur.sddc_manager_client(lab_spec)


def _wait_task(sddc, task, what, timeout_s=3600, every_s=20, subtasks=False):
    tid = (task or {}).get("id")
    if not tid:
        return task
    deadline, last, seen = time.time() + timeout_s, None, {}
    while time.time() < deadline:
        t = sddc.get_patiently(f"/v1/tasks/{tid}")
        status = str(t.get("status", "")).upper()
        if status != last:
            liblog.print_logs(f"    {what}: {status}")
            last = status
        if subtasks:
            for st in t.get("subTasks") or []:
                k = st.get("name") or st.get("description")
                s = str(st.get("status", "")).upper()
                if seen.get(k) != s and s not in ("PENDING", "NOT_STARTED", ""):
                    seen[k] = s
                    liblog.print_logs(f"        {s:12} {st.get('description') or k}")
        if status in TERMINAL:
            if status not in ("SUCCESSFUL", "COMPLETED_WITH_WARNING"):
                errs = [e.get("message") for e in t.get("errors") or []]
                for st in t.get("subTasks") or []:
                    if str(st.get("status", "")).upper() == "FAILED":
                        errs += [f"{st.get('description') or st.get('name')}: "
                                 + "; ".join(e.get("message", "") for e in st.get("errors") or [])]
                raise WldError(f"{what} {status}: " + " | ".join(e for e in errs if e)[:1200])
            return t
        time.sleep(every_s)
    raise WldError(f"{what}: task {tid} still running after {timeout_s // 60} min (it carries on in SDDC Manager)")


def _wait_validation(sddc, path, v, what, timeout_s=3600):
    vid = v.get("id")
    deadline = time.time() + timeout_s
    while v.get("executionStatus") in ("IN_PROGRESS", None) and time.time() < deadline:
        time.sleep(15)
        v = sddc.get_patiently(f"{path}/{vid}")
    os.makedirs(WLD_DIR, exist_ok=True)
    issues = libvcf._print_checks(v.get("validationChecks"))
    liblog.print_logs(f"    {what} validation: {v.get('executionStatus')} / {v.get('resultStatus')} "
                      f"({sum(1 for i in issues if i[0] == 'FAILED')} failed, "
                      f"{sum(1 for i in issues if i[0] == 'WARNING')} warnings)")
    return v


def _elements(body):
    return (body or {}).get("elements") or []


def _domain(sddc, name):
    return next((d for d in _elements(sddc.get("/v1/domains")) if d.get("name") == name), None)


# ---------------------------------------------------------------- network pool + commissioning

def ensure_network_pool(sddc, cfg):
    pools = _elements(sddc.get("/v1/network-pools"))
    p = next((p for p in pools if p.get("name") == cfg["pool_name"]), None)
    if p:
        liblog.print_logs(f"    Network pool {cfg['pool_name']} exists.")
        return p["id"]

    def net(kind, n):
        return {"type": kind, "vlanId": n["vlan"], "mtu": 9000, "subnet": n["subnet"].split("/")[0], "mask": n["mask"],
                "gateway": n["gateway"], "ipPools": [{"start": n["range"][0], "end": n["range"][-1]}]}
    spec = {"name": cfg["pool_name"], "networks": [net("VMOTION", cfg["vmotion"]), net("VSAN", cfg["vsan"])]}
    p = sddc.post("/v1/network-pools", spec)
    liblog.print_logs(f"    Network pool {cfg['pool_name']} created.")
    return p.get("id") or next(x["id"] for x in _elements(sddc.get("/v1/network-pools")) if x.get("name") == cfg["pool_name"])


def _lab_ca_verified(h):
    try:
        return libca.served_chain_check(h["fqdn"]).get("verified", False)
    except Exception:
        return False


def lab_ca_host_certificates(lab_spec, hosts, timeout_s=300):
    """SDDC Manager only commissions hosts whose certificate it trusts once the management domain hosts carry external
    certificates (Module 10), KB 415767. So each new host gets the lab CA chain in its trust store and a step-ca
    certificate for its own CSR, the same way Module 10 rotated the management hosts. Hosts already on the lab CA are
    left alone."""
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
    try:
        root, inter = (c.public_bytes(libca.serialization.Encoding.PEM).decode().strip() for c in libca._ca_chain())
    except libca.CaError as e:
        raise WldError(str(e))
    for h in hosts:
        if _lab_ca_verified(h):
            liblog.print_logs(f"    {h['fqdn']}: certificate already from the lab CA.")
            continue
        liblog.print_logs(f"    {h['fqdn']}: replacing the self-signed certificate with a lab CA certificate (KB 415767).")
        try:
            si = SmartConnect(host=h["ip"], user="root", pwd=h["password"], sslContext=ssl._create_unverified_context())
        except Exception as e:
            raise WldError(f"{h['fqdn']}: cannot log in as root: {getattr(e, 'msg', None) or e}")
        try:
            view = si.content.viewManager.CreateContainerView(si.content.rootFolder, [vim.HostSystem], True)
            host = view.view[0]
            view.Destroy()
            cm = host.configManager.certificateManager
            try:
                current = list(cm.ListCACertificates() or [])
            except Exception:
                current = []
            norm = lambda p: "".join(p.split())
            cas = current + [p for p in (root, inter) if norm(p) not in {norm(c) for c in current}]
            cm.ReplaceCACertificatesAndCRLs(caCert=cas, caCrl=[])
            csr = cm.GenerateCertificateSigningRequest(useIpAddressAsCommonName=False)
            leaf, _, _ = libca.sign_csr(lab_spec, csr)
            cm.InstallServerCertificate(cert=leaf)
            try:
                cm.NotifyAffectedServices()
            except Exception:
                pass  # deprecated on newer ESX; the services pick the certificate up on their own
        except libca.CaError as e:
            raise WldError(f"{h['fqdn']}: step-ca signing failed: {e}")
        except Exception as e:
            raise WldError(f"{h['fqdn']}: certificate replacement failed: {getattr(e, 'msg', None) or e}")
        finally:
            try:
                Disconnect(si)
            except Exception:
                pass
        deadline = time.time() + timeout_s
        while not _lab_ca_verified(h):
            if time.time() > deadline:
                raise WldError(f"{h['fqdn']}: still not serving a lab CA certificate after {timeout_s}s")
            time.sleep(10)
        liblog.print_logs(f"    {h['fqdn']}: now serves a lab CA certificate (verifies to the lab root).")


def ensure_ssh(hosts):
    """Commissioning reads each host's SSH thumbprint, so SSH (TSM-SSH) must be running. Started, never re-enabled
    at boot here (the SCG esx-9.ssh exception covers the lab)."""
    from pyVim.connect import SmartConnect, Disconnect
    from pyVmomi import vim
    for h in hosts:
        try:
            si = SmartConnect(host=h["ip"], user="root", pwd=h["password"], sslContext=ssl._create_unverified_context())
        except Exception as e:
            raise WldError(f"{h['fqdn']}: cannot log in as root: {getattr(e, 'msg', None) or e}")
        try:
            view = si.content.viewManager.CreateContainerView(si.content.rootFolder, [vim.HostSystem], True)
            ss = view.view[0].configManager.serviceSystem
            view.Destroy()
            svc = next((x for x in ss.serviceInfo.service if x.key == "TSM-SSH"), None)
            if svc and not svc.running:
                ss.StartService(id="TSM-SSH")
                liblog.print_logs(f"    {h['fqdn']}: started SSH (needed for its SSH thumbprint).")
        finally:
            Disconnect(si)


def _hosts_by_fqdn(sddc):
    return {h.get("fqdn", "").lower(): h for h in _elements(sddc.get("/v1/hosts"))}


def commission(lab_spec, name=None, sddc=None, cfg=None):
    cfg = cfg or wld_settings(lab_spec, name)
    sddc = sddc or _sddc(lab_spec)
    liblog.print_logs(f"(Commission) {len(cfg['hosts'])} {cfg['entry'].get('nested_esxi_type', 'VI')} host(s) "
                      f"into network pool {cfg['pool_name']}.")
    pool_id = ensure_network_pool(sddc, cfg)
    known = _hosts_by_fqdn(sddc)
    todo = [h for h in cfg["hosts"] if h["fqdn"].lower() not in known]
    for h in cfg["hosts"]:
        if h["fqdn"].lower() in known:
            k = known[h["fqdn"].lower()]
            liblog.print_logs(f"    {h['fqdn']}: already commissioned ({k.get('status')}).")
    if todo:
        ensure_ssh(todo)
        lab_ca_host_certificates(lab_spec, todo)
        specs = []
        for h in todo:
            ssl_tp, ssh_tp = libvcf._host_thumbprints(h)
            specs.append({"fqdn": h["fqdn"], "username": "root", "password": h["password"],
                          "storageType": "VSAN_ESA" if cfg["esa"] else "VSAN",
                          "skipHclCompatibilityPrecheck": bool(cfg["esa"]),   # nested NVMe disks are not on the ESA HCL
                          "networkPoolId": pool_id, "networkPoolName": cfg["pool_name"],
                          "sslThumbprint": ssl_tp, "sshThumbprint": ssh_tp})
        v = _wait_validation(sddc, "/v1/hosts/validations", sddc.post("/v1/hosts/validations", specs), "Host commission")
        if v.get("resultStatus") == "FAILED":
            raise WldError("host commission validation FAILED (see the checks above)")
        _wait_task(sddc, sddc.post("/v1/hosts", specs), f"Commission {len(todo)} host(s)", timeout_s=3600)
        known = _hosts_by_fqdn(sddc)
    ids = []
    for h in cfg["hosts"]:
        k = known.get(h["fqdn"].lower())
        if not k:
            raise WldError(f"{h['fqdn']} is not in SDDC Manager after commissioning")
        ids.append(k)
    return ids


# ---------------------------------------------------------------- domain spec

def _personality(sddc, cfg):
    items = _elements(sddc.get("/v1/personalities"))
    if cfg["image"]:
        p = next((p for p in items if cfg["image"] in (p.get("personalityName"), p.get("personalityId"))), None)
        if not p:
            raise WldError(f"cluster image {cfg['image']} not in SDDC Manager (have: "
                           f"{[p.get('personalityName') for p in items]})")
        return p
    if len(items) == 1:
        return items[0]
    if not items:
        raise WldError("SDDC Manager has no cluster images. In SDDC Manager: Lifecycle Management > Image Management > "
                       "Import Image, from the management cluster, then rerun.")
    raise WldError(f"several cluster images in SDDC Manager: {[p.get('personalityName') for p in items]}; set "
                   'workload_domains[].cluster_image to one of them.')


def render_domain_spec(lab_spec, cfg, host_ids, sddc=None):
    a, mgmt = cfg["addresses"], cfg["mgmt"]

    def nd(x):
        return {"ipAddress": x["ip"], "dnsName": x["fqdn"], "gateway": mgmt["gateway"], "subnetMask": mgmt["mask"]}
    uplinks = [f"uplink{i + 1}" for i in range(len(cfg["vmnics"]))]       # VDS uplinks
    nsx_uplinks = [f"uplink-{i + 1}" for i in range(len(cfg["vmnics"]))]  # NSX uplink profile uplinks
    profile = f"{cfg['cluster']}-network-profile"
    host_specs = [{"id": h["id"], "hostNetworkSpec": {"networkProfileName": profile,
                                                      "vmNics": [{"id": v, "vdsName": cfg["vds"], "uplink": u}
                                                                 for v, u in zip(cfg["vmnics"], uplinks)]}}
                  for h in host_ids]
    pg = lambda role, t: {"name": f"{cfg['vds']}-pg-{role}", "transportType": t, "activeUplinks": uplinks,
                          "standByUplinks": [], "teamingPolicy": "loadbalance_loadbased"}
    vsan = {"datastoreName": cfg["datastore"]}
    if cfg["esa"]:
        vsan["esaConfig"] = {"enabled": True}
    else:
        vsan["failuresToTolerate"] = cfg["policy"]["ftt"]
    tep = cfg["tep"]
    cluster = {
        "name": cfg["cluster"], "hostSpecs": host_specs,
        "datastoreSpec": {"vsanDatastoreSpec": vsan},
        "networkSpec": {
            "vdsSpecs": [{
                "name": cfg["vds"], "mtu": 9000,
                "portGroupSpecs": [pg("management", "MANAGEMENT"), pg("vmotion", "VMOTION"), pg("vsan", "VSAN")],
                "nsxtSwitchConfig": {"transportZones": [
                    {"name": f"{cfg['root']}-{cfg['name']}-overlay-tz", "transportType": "OVERLAY"},
                    {"name": f"{cfg['root']}-{cfg['name']}-vlan-tz", "transportType": "VLAN"}],
                    "hostSwitchOperationalMode": "STANDARD"}}],
            # The uplink profile is only used through a network profile that ties it to the VDS and the TEP pool
            "networkProfiles": [{"name": profile, "description": f"{cfg['cluster']} NSX host switch",
                                 "isDefault": True,
                                 "nsxtHostSwitchConfigs": [{
                                     "vdsName": cfg["vds"], "uplinkProfileName": f"{cfg['cluster']}-uplink-profile",
                                     "ipAddressPoolName": f"{cfg['cluster']}-tep01",
                                     "vdsUplinkToNsxUplink": [{"vdsUplinkName": u, "nsxUplinkName": n}
                                                              for u, n in zip(uplinks, nsx_uplinks)]}]}],
            "nsxClusterSpec": {"nsxTClusterSpec": {
                "uplinkProfiles": [{"name": f"{cfg['cluster']}-uplink-profile", "transportVlan": tep["vlan"],
                                    "teamings": [{"policy": "LOADBALANCE_SRCID", "activeUplinks": nsx_uplinks,
                                                  "standByUplinks": []}]}],
                "ipAddressPoolsSpec": [{"name": f"{cfg['cluster']}-tep01",
                                        "description": f"{cfg['cluster']} host TEP pool",
                                        "subnets": [{"cidr": tep["subnet"], "gateway": tep["gateway"],
                                                     "ipAddressPoolRanges": [{"start": tep["range"][0],
                                                                              "end": tep["range"][-1]}]}]}]}}},
    }
    if sddc is not None:
        p = _personality(sddc, cfg)
        cluster["clusterImageId"] = p.get("personalityId")
        liblog.print_logs(f"    Cluster image: {p.get('personalityName')} ({p.get('personalityId')}).")
    return {
        "domainName": cfg["name"],
        "vcenterSpec": {"name": a["vcenter"]["short"], "networkDetailsSpec": nd(a["vcenter"]),
                        "rootPassword": cfg["password"], "datacenterName": cfg["datacenter"],
                        "vmSize": cfg["vcenter_size"]},
        "computeSpec": {"clusterSpecs": [cluster]},
        "nsxTSpec": {"nsxManagerSpecs": [{"name": a[f"nsx_node{i + 1}"]["short"],
                                          "networkDetailsSpec": nd(a[f"nsx_node{i + 1}"])}
                                         for i in range(cfg["nsx_count"])],
                     "vip": a["nsx_vip"]["ip"], "vipFqdn": a["nsx_vip"]["fqdn"], "formFactor": cfg["nsx_size"],
                     "nsxManagerAdminPassword": cfg["password"], "nsxManagerRootPassword": cfg["password"],
                     "nsxManagerAuditPassword": cfg["password"]},
        "ssoDomainSpec": {"ssoDomainName": cfg["sso_domain"], "ssoDomainPassword": cfg["password"]},
        "deployWithoutLicenseKeys": True,
    }


def _save_spec(cfg, spec):
    os.makedirs(WLD_DIR, exist_ok=True)
    path = os.path.join(WLD_DIR, f"{cfg['name']}_domain_spec.redacted.json")
    with open(path, "w") as f:
        json.dump(libvcf.redact(spec), f, indent=2)
    return path


def validate(lab_spec, name=None, force=False, sddc=None):
    cfg = wld_settings(lab_spec, name)
    _print_plan(cfg)
    failed = preflight(lab_spec, cfg)
    if failed and not force:
        raise WldError(f"{len(failed)} preflight check(s) failed (fix them, or --force to continue)")
    sddc = sddc or _sddc(lab_spec)
    existing = _domain(sddc, cfg["name"])
    if existing:
        liblog.print_logs(f"Domain {cfg['name']} already exists ({existing.get('status')}); nothing to validate.")
        return cfg, None, sddc
    _record_plan(cfg)
    hosts = commission(lab_spec, sddc=sddc, cfg=cfg)
    busy = [h["fqdn"] for h in hosts if str(h.get("status", "")).upper() not in ("UNASSIGNED_USEABLE", "")]
    if busy:
        raise WldError(f"host(s) not free for a new domain: {busy}")
    spec = render_domain_spec(lab_spec, cfg, hosts, sddc)
    liblog.print_logs(f"(Validate) Domain spec (redacted): {_save_spec(cfg, spec)}")
    v = _wait_validation(sddc, "/v1/domains/validations", sddc.post("/v1/domains/validations", spec), "Domain")
    with open(os.path.join(WLD_DIR, f"{cfg['name']}_domain_validation.json"), "w") as f:
        json.dump(v, f, indent=2)
    if v.get("resultStatus") == "FAILED":
        raise WldError(f"domain validation FAILED (full report: {WLD_DIR}/{cfg['name']}_domain_validation.json)")
    return cfg, spec, sddc


# ---------------------------------------------------------------- create + monitor

def _task_file(name):
    return os.path.join(WLD_DIR, f"{name}_task.json")


def _monitor(sddc, cfg, task_id):
    liblog.print_logs(f"Monitoring domain creation task {task_id} (poll every {POLL_S}s; Ctrl+C is safe: "
                      f"-m14 --status reattaches). Nested hosts: expect 2-4 hours.")
    try:
        _wait_task(sddc, {"id": task_id}, f"Create domain {cfg['name']}", timeout_s=DOMAIN_TIMEOUT,
                   every_s=POLL_S, subtasks=True)
    except WldError as e:
        raise WldError(f"{e}. Fix the cause, then -m14 --retry")
    d = _domain(sddc, cfg["name"])
    liblog.print_logs(f"Domain {cfg['name']}: {d.get('status') if d else 'not listed yet'}.")
    return d


def deploy(lab_spec, name=None, force=False):
    cfg = wld_settings(lab_spec, name)
    sddc = _sddc(lab_spec)
    d = _domain(sddc, cfg["name"])
    if d and str(d.get("status", "")).upper() == "ACTIVE":
        liblog.print_logs(f"Domain {cfg['name']} is already ACTIVE.")
        storage_policy(lab_spec, name)
        return d
    if os.path.exists(_task_file(cfg["name"])):
        tid = json.load(open(_task_file(cfg["name"])))["id"]
        t = sddc.get_patiently(f"/v1/tasks/{tid}")
        st = str(t.get("status", "")).upper()
        if st not in TERMINAL:
            liblog.print_logs(f"Domain creation task {tid} is running; attaching.")
            d = _monitor(sddc, cfg, tid)
            storage_policy(lab_spec, name)
            return d
        if st == "FAILED":
            raise WldError(f"the last domain creation task {tid} FAILED; use -m14 --retry (or -m14 --status for details)")
    cfg, spec, sddc = validate(lab_spec, name, force=force, sddc=sddc)
    if spec is None:
        storage_policy(lab_spec, name)
        return _domain(sddc, cfg["name"])
    task = sddc.post("/v1/domains", spec)
    with open(_task_file(cfg["name"]), "w") as f:
        json.dump({"id": task.get("id"), "started": time.strftime("%Y-%m-%d %H:%M")}, f, indent=2)
    liblog.print_logs(f"Domain creation started: task {task.get('id')}.")
    d = _monitor(sddc, cfg, task.get("id"))
    storage_policy(lab_spec, name)
    return d


def status(lab_spec, name=None):
    cfg = wld_settings(lab_spec, name)
    sddc = _sddc(lab_spec)
    d = _domain(sddc, cfg["name"])
    liblog.print_logs(f"Domain {cfg['name']}: {d.get('status') if d else 'not in SDDC Manager'}.")
    if not os.path.exists(_task_file(cfg["name"])):
        return d
    tid = json.load(open(_task_file(cfg["name"])))["id"]
    t = sddc.get_patiently(f"/v1/tasks/{tid}")
    liblog.print_logs(f"Creation task {tid}: {t.get('status')}.")
    if str(t.get("status", "")).upper() not in TERMINAL:
        return _monitor(sddc, cfg, tid)
    for st in t.get("subTasks") or []:
        if str(st.get("status", "")).upper() == "FAILED":
            liblog.print_logs(f"    FAILED: {st.get('description') or st.get('name')}")
            for e in st.get("errors") or []:
                liblog.print_logs(f"        {e.get('message', '')}"
                                  f"{' | fix: ' + e['remediationMessage'] if e.get('remediationMessage') else ''}")
    return d


def retry(lab_spec, name=None):
    cfg = wld_settings(lab_spec, name)
    if not os.path.exists(_task_file(cfg["name"])):
        raise WldError("no recorded domain creation task to retry")
    sddc = _sddc(lab_spec)
    tid = json.load(open(_task_file(cfg["name"])))["id"]
    t = sddc.get_patiently(f"/v1/tasks/{tid}")
    if str(t.get("status", "")).upper() != "FAILED":
        raise WldError(f"task {tid} is {t.get('status')}, not FAILED")
    sddc.patch(f"/v1/tasks/{tid}", {})
    liblog.print_logs(f"Retrying task {tid}.")
    d = _monitor(sddc, cfg, tid)
    storage_policy(lab_spec, name)
    return d


# ---------------------------------------------------------------- vCenter: default vSAN storage policy

def _vc_connect(cfg):
    from pyVim.connect import SmartConnect
    try:
        return SmartConnect(host=cfg["addresses"]["vcenter"]["fqdn"], user=cfg["sso_user"],
                            pwd=cfg["password"], sslContext=ssl._create_unverified_context())
    except Exception as e:
        raise WldError(f"cannot log in to {cfg['addresses']['vcenter']['fqdn']}: {getattr(e, 'msg', None) or e}")


def _pbm(si, host, port=443, path="/pbm/sdk"):
    from pyVmomi import pbm, VmomiSupport, SoapStubAdapter
    try:
        version = VmomiSupport.newestVersions.Get("pbm")
    except Exception:
        version = "pbm.version.version11"
    # SPBM authenticates with the vCenter session id in a vcSessionCookie SOAP header (pyVmomi's SPBM samples)
    session = si._stub.cookie.split('"')[1] if '"' in si._stub.cookie else si._stub.cookie.split("=", 1)[-1].split(";")[0]
    stub = SoapStubAdapter(host=host, port=port, path=path, version=version, sslContext=ssl._create_unverified_context(),
                           requestContext={"vcSessionCookie": session})
    stub.cookie = si._stub.cookie
    return pbm.ServiceInstance("ServiceInstance", stub).RetrieveContent().profileManager


def _vsan_datastore(si, cfg):
    from pyVmomi import vim
    view = si.content.viewManager.CreateContainerView(si.content.rootFolder, [vim.Datastore], True)
    try:
        ds = [d for d in view.view if d.summary.type == "vsan"]
    finally:
        view.Destroy()
    d = next((d for d in ds if d.name == cfg["datastore"]), None) or (ds[0] if len(ds) == 1 else None)
    if not d:
        raise WldError(f"vSAN datastore {cfg['datastore']} not found in {cfg['addresses']['vcenter']['fqdn']}")
    return d


def _policy_rules(cfg):
    rules = {"hostFailuresToTolerate": cfg["policy"]["ftt"]}
    if cfg["policy"]["raid5"]:
        rules["replicaPreference"] = RAID5
    return rules


def _find_profile(pm, name):
    from pyVmomi import pbm
    ids = pm.PbmQueryProfile(resourceType=pbm.profile.ResourceType(resourceType="STORAGE"), profileCategory="REQUIREMENT")
    for p in pm.PbmRetrieveContent(profileIds=ids) if ids else []:
        if p.name == name:
            return p
    return None


def _profile_rules(p):
    out = {}
    for sub in getattr(p.constraints, "subProfiles", None) or []:
        for cap in sub.capability or []:
            for c in cap.constraint or []:
                for prop in c.propertyInstance or []:
                    out[prop.id] = prop.value
    return out


def storage_policy(lab_spec, name=None):
    from pyVmomi import pbm
    from pyVim.connect import Disconnect
    cfg = wld_settings(lab_spec, name)
    want = cfg["policy"]["name"]
    liblog.print_logs(f"(Policy) {want} on {cfg['datastore']} in {cfg['addresses']['vcenter']['fqdn']}.")
    si = _vc_connect(cfg)
    try:
        pm = _pbm(si, cfg["addresses"]["vcenter"]["fqdn"])
        rules = _policy_rules(cfg)

        def cap(key, value):
            return pbm.capability.CapabilityInstance(
                id=pbm.capability.CapabilityMetadata.UniqueId(namespace="VSAN", id=key),
                constraint=[pbm.capability.ConstraintInstance(propertyInstance=[
                    pbm.capability.PropertyInstance(id=key, value=value)])])
        constraints = pbm.profile.SubProfileCapabilityConstraints(subProfiles=[
            pbm.profile.SubProfileCapabilityConstraints.SubProfile(
                name="VSAN sub-profile", capability=[cap(k, v) for k, v in rules.items()])])
        prof = _find_profile(pm, want)
        if not prof:
            pid = pm.PbmCreate(createSpec=pbm.profile.CapabilityBasedProfileCreateSpec(
                name=want, description=f"Theogony: default for {cfg['name']} ({', '.join(f'{k}={v}' for k, v in rules.items())})",
                resourceType=pbm.profile.ResourceType(resourceType="STORAGE"), category="REQUIREMENT",
                constraints=constraints))
            liblog.print_logs(f"    Created {want}: {rules}.")
        else:
            pid = prof.profileId
            if _profile_rules(prof) != rules:
                pm.PbmUpdate(profileId=pid, updateSpec=pbm.profile.CapabilityBasedProfileUpdateSpec(constraints=constraints))
                liblog.print_logs(f"    Updated {want} to {rules}.")
            else:
                liblog.print_logs(f"    {want} exists with {rules}.")
        ds = _vsan_datastore(si, cfg)
        hub = pbm.placement.PlacementHub(hubType="Datastore", hubId=ds._moId)
        current = pm.PbmQueryDefaultRequirementProfile(hub=hub)
        if current and current.uniqueId == pid.uniqueId:
            liblog.print_logs(f"    {want} is already the default policy of {ds.name}.")
        else:
            pm.PbmAssignDefaultRequirementProfile(profile=pid, datastores=[hub])
            liblog.print_logs(f"    {want} is now the default policy of {ds.name}.")
    finally:
        Disconnect(si)


# ---------------------------------------------------------------- day-1 extensions (US-016)
# Certificates, backups and role mappings "extended to vc-w01 and nsx-w01". Certificates and backups reuse the
# Module 10 and Module 11 code with the workload domain as the target; role mappings follow Design Table 7.

CERT_TYPES = ["VCENTER", "NSXT_MANAGER", "ESXI"]   # SDDC Manager's own certificate lives in the management domain

# Design Table 7 (AD group -> role). Override per domain with workload_domains[].role_mappings.
DEFAULT_ROLE_MAPPINGS = [
    {"group": "mpc-platform-admins", "vcenter": "Admin", "nsx": "enterprise_admin"},
    {"group": "mpc-platform-operators", "vcenter": "MPC Operator", "nsx": "network_op"},
    {"group": "mpc-security-admins", "vcenter": "MPC Security Admin", "nsx": "security_engineer"},
    {"group": "mpc-auditors", "vcenter": "ReadOnly", "nsx": "auditor"},
]
CUSTOM_VC_ROLES = {   # Design Table 7 custom vCenter roles (System.Anonymous/View/Read are always included)
    "MPC Operator": ["System.Anonymous", "System.View", "System.Read",
                     "VirtualMachine.Interact.PowerOn", "VirtualMachine.Interact.PowerOff",
                     "VirtualMachine.Interact.Reset", "VirtualMachine.Interact.Suspend",
                     "VirtualMachine.Interact.ConsoleInteract", "VirtualMachine.State.CreateSnapshot",
                     "VirtualMachine.State.RemoveSnapshot", "VirtualMachine.State.RevertToSnapshot"],
    "MPC Security Admin": ["System.Anonymous", "System.View", "System.Read", "Cryptographer.*"],
}


def _domain_endpoints(cfg):
    a = cfg["addresses"]
    return a["vcenter"]["fqdn"], a["nsx_vip"]["fqdn"]


def extend_certificates(lab_spec, name=None, dry_run=False, force=False):
    cfg = wld_settings(lab_spec, name)
    liblog.print_logs(f"(Certificates) Domain {cfg['name']}: {', '.join(CERT_TYPES)} from the lab CA (Module 10 rotation).")
    try:
        result = libca.rotate(lab_spec, types=CERT_TYPES, force=force, dry_run=dry_run, domain=cfg["name"])
        libca.inventory(lab_spec, domain=cfg["name"])
    except libca.CaError as e:
        raise WldError(f"certificates: {e}")
    return result


def extend_backups(lab_spec, name=None, dry_run=False, backup_now=False):
    cfg = wld_settings(lab_spec, name)
    vc, nsx = _domain_endpoints(cfg)
    b = libbackup.backup_settings(lab_spec)
    minute = (b["vcenter_minute"] + 20) % 60   # the management vCenter runs at vcenter_minute; stagger this one
    liblog.print_logs(f"(Backups) Domain {cfg['name']}: NSX {nsx} and vCenter {vc} to the SFTP target.")
    try:
        libbackup.configure_domain(lab_spec, vc, cfg["sso_user"], nsx, minute, dry_run=dry_run)
        if backup_now and not dry_run:
            libbackup.backup_domain_now(lab_spec, vc, cfg["sso_user"], nsx)
    except libbackup.BackupError as e:
        raise WldError(f"backups: {e}")
    liblog.print_logs(f"Backups {'validated (dry run)' if dry_run else 'configured'} for {cfg['name']}.")


def _role_mappings(cfg):
    m = cfg["entry"].get("role_mappings")
    if not m or (isinstance(m, list) and m and str(m[0].get("group", "")).startswith("<")):
        return DEFAULT_ROLE_MAPPINGS
    return m


def _vc_find_group(si, group, local_domain):
    ud = si.content.userDirectory
    hits = []
    for exact in (True, False):
        try:
            hits = [r for r in ud.RetrieveUserGroups(domain=None, searchStr=group, belongsToGroup=None,
                                                     belongsToUser=None, exactMatch=exact, findUsers=False,
                                                     findGroups=True) or []
                    if r.group and r.principal.split("\\")[-1].split("@")[0].lower() == group.lower()]
        except Exception:
            hits = []
        if hits:
            break
    outside = [h for h in hits if not h.principal.lower().startswith(local_domain.split(".")[0].lower() + "\\")]
    return (outside or hits or [None])[0]


def _vc_role(am, name, dry_run):
    builtin = {"admin": -1, "administrator": -1, "readonly": -2, "read-only": -2, "noaccess": -5}
    if name.lower().replace(" ", "") in builtin:
        return builtin[name.lower().replace(" ", "")], "built-in"
    r = next((r for r in am.roleList if r.name == name), None)
    if r:
        return r.roleId, "exists"
    want = CUSTOM_VC_ROLES.get(name)
    if not want:
        raise WldError(f"vCenter role {name!r} does not exist and is not one Theogony knows how to create")
    all_ids = [p.privId for p in am.privilegeList]
    privs = sorted({p for w in want for p in ([x for x in all_ids if x.startswith(w[:-1])] if w.endswith("*") else [w])
                    if p in all_ids})
    if dry_run:
        return None, f"would create ({len(privs)} privileges)"
    return am.AddAuthorizationRole(name=name, privIds=privs), f"created ({len(privs)} privileges)"


def _nsx_session(cfg, fqdn):
    s = requests.Session()
    s.trust_env, s.verify = False, False
    s.auth = ("admin", cfg["password"])
    s.base = f"https://{fqdn}"
    return s


def _nsx_identity_source(lab_spec, cfg, s):
    """How the new NSX can see directory groups: copy what the management NSX's remote-group bindings use, else
    the VCF SSO (Identity Broker) source NSX exposes as VIDM."""
    try:
        mgmt_nsx = libbackup._plan(lab_spec)["nsx"]
        m = _nsx_session(cfg, mgmt_nsx)
        r = m.get(f"{m.base}/policy/api/v1/aaa/role-bindings", params={"type": "remote_group"}, timeout=30)
        for b in (r.json().get("results") or []) if r.status_code == 200 else []:
            if b.get("identity_source_type"):
                return {"identity_source_type": b["identity_source_type"],
                        **({"identity_source_id": b["identity_source_id"]} if b.get("identity_source_id") else {})}
    except Exception:
        pass
    return {"identity_source_type": "VIDM"}


def _nsx_find_group(s, group, source):
    if source["identity_source_type"] == "VIDM":
        r = s.get(f"{s.base}/policy/api/v1/aaa/vidm/search", params={"search_string": group}, timeout=30)
        if r.status_code == 200:
            for g in r.json().get("results") or []:
                n = g.get("name") or ""
                if g.get("type", "remote_group") == "remote_group" and n.split("@")[0].lower() == group.lower():
                    return n
        return None
    path = f"{s.base}/policy/api/v1/aaa/ldap-identity-sources/{source.get('identity_source_id')}/search"
    r = s.get(path, params={"filter_value": group}, timeout=30)
    if r.status_code == 200:
        for g in r.json().get("results") or []:
            if g.get("kind", "group").lower() == "group" and (g.get("name") or "").split("@")[0].lower() == group.lower():
                return g.get("name")
    return None


def extend_roles(lab_spec, name=None, dry_run=False):
    """Directory groups (through VCF SSO / the Identity Broker) -> vCenter permissions on the root folder (propagating)
    and NSX role bindings. Groups the domain cannot see yet are reported, not created: the domain's vCenter and NSX
    must first be connected to VCF SSO in VCF Operations (the manual step, as for the management domain)."""
    from pyVim.connect import Disconnect
    from pyVmomi import vim
    cfg = wld_settings(lab_spec, name)
    vc, nsx = _domain_endpoints(cfg)
    mappings = _role_mappings(cfg)
    result = {"vcenter": [], "nsx": [], "missing": [], "pending": []}
    liblog.print_logs(f"(Roles) Domain {cfg['name']}: {len(mappings)} group mapping(s) on {vc} and {nsx}"
                      f"{' (dry run)' if dry_run else ''}.")
    si = _vc_connect(cfg)
    try:
        am, root = si.content.authorizationManager, si.content.rootFolder
        current = {(p.principal.lower(), p.roleId) for p in am.RetrieveEntityPermissions(entity=root, inherited=False)}
        for m in mappings:
            if not m.get("vcenter"):
                continue
            hit = _vc_find_group(si, m["group"], cfg["sso_domain"])
            if not hit:
                result["missing"].append(f"vCenter: {m['group']}")
                liblog.print_logs(f"    vCenter: group {m['group']} not visible in {vc} (connect it to VCF SSO first).")
                continue
            role_id, how = _vc_role(am, m["vcenter"], dry_run)
            if role_id is not None and (hit.principal.lower(), role_id) in current:
                liblog.print_logs(f"    vCenter: {hit.principal} already {m['vcenter']} on the root folder.")
            elif dry_run:
                liblog.print_logs(f"    vCenter: would grant {hit.principal} {m['vcenter']} (role {how}) on the root folder.")
                result["pending"].append(f"vCenter: {m['group']} -> {m['vcenter']}")
            else:
                am.SetEntityPermissions(entity=root, permission=[vim.AuthorizationManager.Permission(
                    principal=hit.principal, group=True, roleId=role_id, propagate=True)])
                liblog.print_logs(f"    vCenter: granted {hit.principal} {m['vcenter']} (role {how}) on the root folder.")
            result["vcenter"].append({"group": hit.principal, "role": m["vcenter"]})
    finally:
        Disconnect(si)

    s = _nsx_session(cfg, nsx)
    source = _nsx_identity_source(lab_spec, cfg, s)
    r = s.get(f"{s.base}/policy/api/v1/aaa/role-bindings", params={"type": "remote_group"}, timeout=30)
    if r.status_code >= 300:
        raise WldError(f"NSX {nsx}: role bindings: HTTP {r.status_code} {r.text[:200]}")
    existing = {b.get("name", "").lower(): b for b in r.json().get("results") or []}
    for m in mappings:
        if not m.get("nsx"):
            continue
        gname = _nsx_find_group(s, m["group"], source)
        if not gname:
            result["missing"].append(f"NSX: {m['group']}")
            liblog.print_logs(f"    NSX: group {m['group']} not visible in {nsx} via {source['identity_source_type']} "
                              f"(connect it to VCF SSO first).")
            continue
        b = existing.get(gname.lower())
        roles = {x.get("role") for p in (b or {}).get("roles_for_paths") or [] for x in p.get("roles") or []}
        if m["nsx"] in roles:
            liblog.print_logs(f"    NSX: {gname} already {m['nsx']}.")
        elif dry_run:
            liblog.print_logs(f"    NSX: would bind {gname} to {m['nsx']}.")
            result["pending"].append(f"NSX: {m['group']} -> {m['nsx']}")
        else:
            body = {"name": gname, "type": "remote_group", **source,
                    "roles_for_paths": [{"path": "/", "roles": [{"role": x} for x in sorted(roles | {m["nsx"]})]}]}
            if b:
                body["_revision"] = b.get("_revision")
                w = s.put(f"{s.base}/policy/api/v1/aaa/role-bindings/{b['id']}", json={**b, **body}, timeout=30)
            else:
                w = s.post(f"{s.base}/policy/api/v1/aaa/role-bindings", json=body, timeout=30)
            if w.status_code >= 300:
                raise WldError(f"NSX {nsx}: binding {gname} to {m['nsx']}: HTTP {w.status_code} {w.text[:300]}")
            liblog.print_logs(f"    NSX: bound {gname} to {m['nsx']}.")
        result["nsx"].append({"group": gname, "role": m["nsx"]})
    if result["missing"]:
        liblog.print_logs(f"Roles: {len(result['missing'])} mapping(s) waiting on groups the domain cannot see yet. "
                          f"In VCF Operations, connect {vc} and {nsx} to VCF SSO, then rerun -m14 --roles.")
    else:
        liblog.print_logs(f"Roles: all {len(mappings)} mapping(s) in place.")
    return result


def _extension_checks(lab_spec, cfg, add):
    vc, nsx = _domain_endpoints(cfg)
    # certificates
    try:
        inv = libca.inventory(lab_spec, domain=cfg["name"])
        rows = [r for r in inv["certificates"] if r["type"] in CERT_TYPES]
        bad = [f"{r['fqdn']} ({r['type']})" for r in rows if not (r["from_lab_ca"] and r.get("served_verified"))]
        add(f"Certificates: {len(rows)} vCenter/NSX/ESX certificate(s) from the lab CA and served as such", not bad and rows,
            ", ".join(bad) if bad else "")
    except Exception as e:
        add("Certificates from the lab CA", False, e)
    # backups
    try:
        b = libbackup.backup_settings(lab_spec)
        st = libbackup.nsx_backup_state(lab_spec, nsx)
        add(f"NSX {nsx} backs up to the SFTP target", bool(st.get("enabled")) and st.get("server") == libbackup._target_host(b),
            f"{st.get('server')}:{st.get('directory')}")
        last = (st.get("history") or [None])[-1]
        add(f"NSX {nsx} last backup succeeded", bool(last and last.get("success")),
            f"{last['end']}" if last else "no backup yet (-m14 --backups --backup-now)")
        v = libbackup._Vcenter(vc, cfg["password"], cfg["sso_user"])
        sched = v.call("GET", "/api/appliance/recovery/backup/schedules") or {}
        ok = any(str((x or {}).get("location", "")).startswith("sftp://") and (x or {}).get("enable") for x in sched.values())
        add(f"vCenter {vc} has an enabled SFTP backup schedule", ok, ", ".join(sched) or "none")
    except Exception as e:
        add("Backups configured", False, e)
    # role mappings
    try:
        r = extend_roles(lab_spec, cfg["name"], dry_run=True)
        gaps = r["missing"] + [f"not applied: {x}" for x in r["pending"]]
        add("Role mappings (vCenter + NSX) in place", not gaps, ", ".join(gaps))
    except Exception as e:
        add("Role mappings", False, e)


# ---------------------------------------------------------------- evidence (US-016)

def _vsan_health(si, cfg):
    from pyVmomi import vim, VmomiSupport, SoapStubAdapter
    try:
        version = VmomiSupport.newestVersions.Get("vsan")
    except Exception:
        version = "vsan.version.version3"
    host = cfg["addresses"]["vcenter"]["fqdn"]
    stub = SoapStubAdapter(host=host, port=443, path="/vsanHealth", version=version, sslContext=ssl._create_unverified_context())
    stub.cookie = si._stub.cookie
    view = si.content.viewManager.CreateContainerView(si.content.rootFolder, [vim.ClusterComputeResource], True)
    try:
        cl = next((c for c in view.view if c.name == cfg["cluster"]), None)
    finally:
        view.Destroy()
    if not cl:
        return {"error": f"cluster {cfg['cluster']} not found"}
    hs = vim.cluster.VsanVcClusterHealthSystem("vsan-cluster-health-system", stub)
    s = hs.VsanQueryVcClusterHealthSummary(cluster=cl, fetchFromCache=False, perspective="defaultView")
    red = [f"{g.groupName}: {t.testName}" for g in (s.groups or []) for t in (g.groupTests or [])
           if str(t.testHealth) in ("red", "yellow")]
    cfg_sys = vim.cluster.VsanVcClusterConfigSystem("vsan-cluster-config-system", stub)
    info = cfg_sys.GetConfigInfoEx(cl)
    return {"overall": str(s.overallHealth), "not_green": red, "esa": bool(getattr(info, "vsanEsaEnabled", False))}


def evidence_report(lab_spec, name=None, out_dir="conf/evidence"):
    from pyVim.connect import Disconnect
    from pyVmomi import pbm
    cfg = wld_settings(lab_spec, name)
    rep = {"generated": datetime.datetime.now().isoformat(timespec="seconds"), "domain": cfg["name"],
           "user_story": "US-016", "plan": cfg["addresses"], "checks": []}
    add = lambda check, ok, detail="": rep["checks"].append({"check": check, "result": "PASS" if ok else "FAIL",
                                                             "detail": str(detail)})
    try:
        sddc = _sddc(lab_spec)
        d = _domain(sddc, cfg["name"])
        add(f"Domain {cfg['name']} is ACTIVE in SDDC Manager", bool(d) and str(d.get("status")).upper() == "ACTIVE",
            d.get("status") if d else "not found")
        if d:
            rep["sddc_domain"] = {k: d.get(k) for k in ("id", "name", "status", "type")}
            for c in d.get("clusters") or []:
                cl = sddc.get(f"/v1/clusters/{c['id']}")
                rep.setdefault("clusters", []).append({k: cl.get(k) for k in ("name", "primaryDatastoreType",
                                                                              "primaryDatastoreName", "isImageBased")})
                add(f"Cluster {cl.get('name')} on vSAN {'ESA' if cfg['esa'] else 'OSA'}",
                    str(cl.get("primaryDatastoreType", "")).upper() == ("VSAN_ESA" if cfg["esa"] else "VSAN"),
                    cl.get("primaryDatastoreType"))
    except Exception as e:
        add("SDDC Manager reachable", False, e)
    try:
        si = _vc_connect(cfg)
        try:
            h = _vsan_health(si, cfg)
            rep["vsan_health"] = h
            add("vSAN health is green", h.get("overall") == "green",
                h.get("overall") if not h.get("not_green") else f"{h.get('overall')}: {', '.join(h['not_green'][:8])}")
            pm = _pbm(si, cfg["addresses"]["vcenter"]["fqdn"])
            ds = _vsan_datastore(si, cfg)
            cur = pm.PbmQueryDefaultRequirementProfile(hub=pbm.placement.PlacementHub(hubType="Datastore", hubId=ds._moId))
            prof = _find_profile(pm, cfg["policy"]["name"])
            is_default = bool(prof and cur and cur.uniqueId == prof.profileId.uniqueId)
            add(f"{cfg['policy']['name']} is the default policy of {ds.name}", is_default,
                _profile_rules(prof) if prof else "policy not found")
        finally:
            Disconnect(si)
    except Exception as e:
        add(f"vCenter {cfg['addresses']['vcenter']['fqdn']} checks", False, getattr(e, "msg", None) or e)
    _extension_checks(lab_spec, cfg, add)
    rep["result"] = "PASS" if all(c["result"] == "PASS" for c in rep["checks"]) else "FAIL"
    rep["pending"] = ["key provider + vSAN data-at-rest encryption (Module 12 covers the management domain only)"]
    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    base = os.path.join(out_dir, f"wld_{cfg['name']}_evidence_{stamp}")
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2, default=str)
    L = [f"# US-016 evidence: workload domain {cfg['name']}", "", f"Generated {rep['generated']}. Result: **{rep['result']}**.",
         "", "| Check | Result | Detail |", "|---|---|---|"]
    L += [f"| {c['check']} | {c['result']} | {c['detail'].replace('|', '/')} |" for c in rep["checks"]]
    L += ["", "## Addresses", "", "| Role | FQDN | IP |", "|---|---|---|"]
    L += [f"| {k} | {v['fqdn']} | {v['ip']} |" for k, v in cfg["addresses"].items()]
    L += ["", "## Not covered by -m14", ""] + [f"- {p}" for p in rep["pending"]]
    with open(base + ".md", "w") as f:
        f.write("\n".join(L) + "\n")
    for c in rep["checks"]:
        liblog.print_logs(f"    {c['result']:4}  {c['check']}{': ' + c['detail'] if c['result'] != 'PASS' else ''}")
    liblog.print_logs(f"Evidence report: {rep['result']}  ->  {base}.md  (+ .json)")
    return rep


# Dry run (plan only; no SDDC Manager calls):  python3 -m python_lib.wld conf/lab_spec.json
if __name__ == "__main__":
    import sys
    with open(sys.argv[1] if len(sys.argv) > 1 else "conf/lab_spec.json") as f:
        spec_py = json.load(f)
    c = wld_settings(spec_py, sys.argv[2] if len(sys.argv) > 2 else None)
    _print_plan(c)
    print(json.dumps(libvcf.redact(render_domain_spec(spec_py, c, [{"id": f"<host-id {h['fqdn']}>"} for h in c["hosts"]])),
                     indent=2))
