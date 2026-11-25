# Hesiod vSphere Supervisor with VPC networking (Module 18)
# Description: US-021. Enables the Supervisor on a workload domain cluster with NSX VPC networking (the transit gateway,
#              external block and connectivity profile from -m15), gives its API a DNS name and a lab-CA certificate,
#              and proves kubectl access as an admin-group user. Part 2 creates a vSphere Namespace with its own VPC
#              and proves pod networking and a LoadBalancer VIP from the external block.
#                SPV  Supervisor   (control plane Small x1 in the lab: a logged exception against the design's x3)
#                VPC  Namespace    (its own NSX VPC, auto-created by the Supervisor)
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.3 (--certs adds the API name + VIP as SANs when the CSR has none (UI CSRs); --report samples the
#              status for ~3 min when a service warning makes it flap)
#         1.2 (--certs: CSR via the 9.1 certificate-management API or a CSR saved from the UI; install with the
#              clusters update call (tls_endpoint_certificate), KB 450791)
#         1.1 (RUNNING / WARNING counts as up: a Supervisor Service warning (e.g. cci-ns) no longer blocks the
#              DNS step; --report shows the warning in the Running row)
#         1.0
#
# vCenter REST (9.1):
#   GET  /api/vcenter/namespace-management/cluster-compatibility?network_provider=NSX_VPC
#   POST /api/vcenter/namespace-management/supervisors/<cluster>?action=enable_on_compute_cluster
#   GET  /api/vcenter/namespace-management/supervisors/summaries          config_status RUNNING, kubernetes_status READY
#   GET  /api/vcenter/namespace-management/clusters/<cluster>             api_server_cluster_endpoint (the API VIP)
#   POST /api/vcenter/namespace-management/clusters/<cluster>/csr/tls-endpoint            CSR for the API certificate
#   PUT  /api/vcenter/namespace-management/clusters/<cluster>/certificate-manager/tls-endpoint-certificate
#   POST /api/vcenter/namespaces/instances/v2                                              vSphere Namespace
#
# lab_spec workload_domains[n].supervisor (see json_lib/lab_spec.json); control plane IPs are the next 5 consecutive
# free addresses in the Module 4 DNS range, recorded in conf/wld/<wld>-supervisor_plan.json like -m14/-m15.
#
# Public functions
#   settings(lab_spec, part, name)    resolve lab_spec (no network calls)
#   plan / deploy / status / certs / report      SPV and VPC as dispatched by -m18
#
# Every failure raises SpvError.

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import vcf as libvcf
from python_lib import wld as libwld
from python_lib import nsxnet as libnsxnet

# Import Standard Python Libraries
import datetime
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import time
import zipfile

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPV_DIR = "conf/spv"
EVIDENCE_DIR = "conf/evidence"
ENABLE_TIMEOUT = 4 * 3600
CA_CHAIN = "conf/ca/ca_chain.pem"


class SpvError(Exception):
    pass


def _placeholder(v):
    return v is None or not str(v).strip() or str(v).strip().startswith("<")


# ---------------------------------------------------------------- vCenter REST

class Vc:
    def __init__(self, fqdn, user, password):
        self.fqdn, self.base = fqdn, f"https://{fqdn}/api"
        self.user, self.password = user, password
        self.http, self.sid = requests.Session(), None
        self.http.verify = False

    def login(self):
        try:
            r = self.http.post(f"{self.base}/session", auth=(self.user, self.password), timeout=30)
        except requests.RequestException as e:
            raise SpvError(f"vCenter {self.fqdn} not reachable: {e.__class__.__name__}")
        if r.status_code not in (200, 201):
            raise SpvError(f"vCenter {self.fqdn}: login as {self.user} failed (HTTP {r.status_code})")
        self.sid = r.json()
        return self

    def call(self, method, path, body=None, ok404=False, params=None):
        for attempt in range(4):
            if not self.sid:
                self.login()
            try:
                r = self.http.request(method, self.base + path, json=body, params=params, timeout=120,
                                      headers={"vmware-api-session-id": self.sid})
            except requests.RequestException as e:
                if attempt == 3:
                    raise SpvError(f"{method} {path}: {e.__class__.__name__}")
                time.sleep(10)
                continue
            if r.status_code == 401 and attempt < 3:
                self.sid = None
                continue
            if r.status_code == 404 and ok404:
                return None
            if r.status_code >= 500 and attempt < 3 and method == "GET":
                time.sleep(10)
                continue
            if r.status_code >= 400:
                raise SpvError(f"{method} /api{path}: HTTP {r.status_code}: {_vapi_error(r)}")
            return r.json() if r.text.strip() else {}
        raise SpvError(f"{method} {path}: gave up")


def _vapi_error(r):
    try:
        j = r.json()
    except ValueError:
        return r.text[:400]
    msgs = [m.get("default_message") for m in j.get("messages") or [] if isinstance(m, dict)]
    return ("; ".join(m for m in msgs if m) or j.get("error_type") or json.dumps(j))[:600]


def _vc(s):
    return Vc(s["wld"]["addresses"]["vcenter"]["fqdn"], s["wld"]["sso_user"], s["wld"]["password"]).login()


# ---------------------------------------------------------------- settings

def settings(lab_spec, part="SPV", name=None):
    w = libwld.wld_settings(lab_spec, name)
    if not w["recorded"]:
        raise SpvError(f"workload domain {w['name']} has no recorded plan: create it with -m14 first")
    sv = w["entry"].get("supervisor") or {}
    if not sv:
        raise SpvError(f'workload_domains[{w["name"]}] has no "supervisor" section (see json_lib/lab_spec.json)')
    dom = lab_spec["domain"]["name"]
    mgmt = libvcf._role(lab_spec, "management")
    pf = libwld._plan_file(f"{w['name']}-supervisor")
    labels = [f"cp{i}" for i in range(1, 6)]
    if os.path.exists(pf):
        cps, recorded = json.load(open(pf))["addresses"], True
    else:
        cps, recorded = libwld._allocate(lab_spec, {"name": f"{w['name']}-supervisor"}, labels), False
    ips = [cps[l]["ip"] for l in labels]
    if [int(ipaddress.ip_address(i)) for i in ips] != list(range(int(ipaddress.ip_address(ips[0])), int(ipaddress.ip_address(ips[0])) + 5)):
        raise SpvError(f"the 5 control plane addresses are not consecutive ({ips}): widen domain.fqdns or free the gap")
    sname = sv.get("name", f"sv-{w['name']}")
    api = sv.get("api_dns_name") if not _placeholder(sv.get("api_dns_name")) else sname
    api_fqdn = api if "." in api else f"{api}.{dom}"
    svc = ipaddress.ip_network(sv.get("service_cidr", "10.96.0.0/23"))
    prv = [ipaddress.ip_network(c) for c in sv.get("default_private_cidrs") or ["172.26.0.0/16"]]
    ns = sv.get("namespace") or {}
    tu = sv.get("test_user") or {}
    ldap_users = (lab_spec.get("ldap") or {}).get("users") or []
    uidx = int(tu.get("use_ldap_user", 0)) if ldap_users else None
    user = ldap_users[uidx] if uidx is not None and uidx < len(ldap_users) else None
    groups = (lab_spec.get("ldap") or {}).get("groups") or []
    gidx = tu.get("admin_group")
    return {
        "part": part, "wld": w, "name": sname, "zone": sv.get("zone", f"zone-{w['name']}"),
        "size": str(sv.get("control_plane_size", "SMALL")).upper(), "count": int(sv.get("control_plane_count", 1)),
        "cp": cps, "cp_ips": ips, "recorded": recorded, "plan_file": pf,
        "mgmt_pg": sv.get("management_portgroup") if not _placeholder(sv.get("management_portgroup")) else f"{w['vds']}-pg-management",
        "gateway": f"{mgmt['gateway']}/{ipaddress.ip_network(mgmt['subnet']).prefixlen}" if mgmt.get("subnet") else mgmt["gateway"],
        "storage_policy": sv.get("storage_policy") if not _placeholder(sv.get("storage_policy")) else w["policy"]["name"],
        "api_fqdn": api_fqdn, "service_cidr": svc, "private_cidrs": prv,
        "project": sv.get("nsx_project", libnsxnet.PROJECT),
        "profile": sv.get("vpc_connectivity_profile", f"{libnsxnet.PROJECT}/vpc-connectivity-profiles/default"),
        "dns": lab_spec["vcf"].get("nameservers") or lab_spec["domain"].get("server_ips", []),
        "ntp": [lab_spec["domain"].get("ntp", "pool.ntp.org")], "domain": dom,
        "content_library": None if _placeholder(sv.get("content_library")) else sv["content_library"],
        "namespace": {"name": ns.get("name", "hw-k8s"), "private_cidrs": [ipaddress.ip_network(c) for c in ns.get("private_cidrs") or []],
                      "image": ns.get("test_image", "nginx:stable")},
        "test_user": ({"username": user["username"], "password": user["password"],
                       "login": f"{user['username']}@{tu.get('login_domain', dom)}"} if user else None),
        "admin_group": (groups[int(gidx)]["name"] if gidx is not None and str(gidx).isdigit() and int(gidx) < len(groups)
                        else tu.get("admin_group") if not _placeholder(tu.get("admin_group")) else None),
        "group_domain": tu.get("login_domain", dom),
        "exceptions": [e for e in sv.get("exceptions") or [] if not _placeholder(e.get("criterion"))],
    }


def _record(s):
    if s["recorded"]:
        return
    os.makedirs(os.path.dirname(s["plan_file"]), exist_ok=True)
    with open(s["plan_file"], "w") as f:
        json.dump({"name": f"{s['wld']['name']}-supervisor", "recorded": time.strftime("%Y-%m-%d %H:%M"),
                   "addresses": s["cp"]}, f, indent=2)
    s["recorded"] = True
    liblog.print_logs(f"    Recorded the control plane addresses in {s['plan_file']} (Module 7/14/15/16 IPAM skip them).")


def _print(s):
    w = s["wld"]
    liblog.print_logs(f"Supervisor {s['name']} on {w['cluster']} ({w['addresses']['vcenter']['fqdn']}), zone {s['zone']}:")
    liblog.print_logs(f"    control plane {s['size']} x{s['count']} on {s['mgmt_pg']}, gateway {s['gateway']}, "
                      f"IPs {s['cp_ips'][0]}-{s['cp_ips'][-1]} (5 consecutive){' (recorded)' if s['recorded'] else ''}")
    liblog.print_logs(f"    storage policy {s['storage_policy']}; service CIDR {s['service_cidr']}; "
                      f"default private CIDRs {', '.join(map(str, s['private_cidrs']))}")
    liblog.print_logs(f"    NSX project {s['project']}, connectivity profile {s['profile']}")
    liblog.print_logs(f"    API {s['api_fqdn']} -> the VIP NSX gives it from the external block (DNS record added after enable)")
    for e in s["exceptions"]:
        liblog.print_logs(f"    EXCEPTION: {e['criterion']}: {e.get('reason', '')}")


# ---------------------------------------------------------------- lookups

def _cluster_id(vc, s):
    r = vc.call("GET", "/vcenter/cluster", params={"names": s["wld"]["cluster"]}) or []
    if not r:
        raise SpvError(f"cluster {s['wld']['cluster']} not found in {vc.fqdn}")
    return r[0]["cluster"]


def _network_id(vc, s):
    r = vc.call("GET", "/vcenter/network", params={"names": s["mgmt_pg"]}) or []
    if not r:
        raise SpvError(f"portgroup {s['mgmt_pg']} not found in {vc.fqdn}")
    return r[0]["network"]


def _policy_id(vc, s):
    for p in vc.call("GET", "/vcenter/storage/policies") or []:
        if p.get("name") == s["storage_policy"]:
            return p["policy"]
    raise SpvError(f"storage policy {s['storage_policy']} not found in {vc.fqdn}")


def _library_id(vc, name):
    for lid in vc.call("GET", "/content/library") or []:
        lib = vc.call("GET", f"/content/library/{lid}", ok404=True) or {}
        if lib.get("name") == name:
            return lid
    raise SpvError(f"content library {name} not found")


def _summary(vc, s):
    for it in (vc.call("GET", "/vcenter/namespace-management/supervisors/summaries") or {}).get("items") or []:
        if it.get("info", {}).get("name") == s["name"]:
            return it["supervisor"], it["info"]
    return None, None


def _cluster_info(vc, cid):
    return vc.call("GET", f"/vcenter/namespace-management/clusters/{cid}", ok404=True) or {}


def _api_vip(info):
    return info.get("api_server_cluster_endpoint") or next(iter(info.get("api_servers") or []), None)


def _cidr(n):
    return {"address": str(n.network_address), "prefix": n.prefixlen}


def _enable_spec(vc, s):
    services = {"dns": {"servers": s["dns"], "search_domains": [s["domain"]]}, "ntp": {"servers": s["ntp"]}}
    pol = _policy_id(vc, s)
    spec = {
        "name": s["name"], "zone": s["zone"],
        "control_plane": {
            "count": s["count"], "size": s["size"], "storage_policy": pol,
            "network": {"backing": {"backing": "NETWORK", "network": _network_id(vc, s)},
                        "ip_management": {"dhcp_enabled": False, "gateway_address": s["gateway"],
                                          "ip_assignments": [{"assignee": "NODE",
                                                              "ranges": [{"address": s["cp_ips"][0], "count": 5}]}]},
                        "services": services},
        },
        "workloads": {
            "edge": {"provider": "NSX_VPC"},
            "network": {"network_type": "NSX_VPC",
                        "nsx_vpc": {"nsx_project": s["project"], "vpc_connectivity_profile": s["profile"],
                                    "default_private_cidrs": [_cidr(n) for n in s["private_cidrs"]]},
                        "ip_management": {"dhcp_enabled": False,
                                          "ip_assignments": [{"assignee": "SERVICE",
                                                              "ranges": [{"address": str(s["service_cidr"].network_address),
                                                                          "count": s["service_cidr"].num_addresses}]}]},
                        "services": services},
            "kube_api_server_options": {"security": {"certificate_dns_names": [s["api_fqdn"]]}},
            "storage": {"ephemeral_storage_policy": pol, "image_storage_policy": pol},
        },
    }
    if s["content_library"]:
        spec["workloads"]["images"] = {"kubernetes_content_library": _library_id(vc, s["content_library"])}
    return spec


# ---------------------------------------------------------------- SPV: plan / deploy / status

def plan(lab_spec, part, name=None):
    s = settings(lab_spec, part, name)
    _print(s)
    if part == "VPC":
        return _vpc_plan(s)
    checks = []
    for ip in s["cp_ips"]:
        if not s["recorded"]:
            checks.append((f"{ip} free", "answers ping" if libvcf._pings(ip) else None))
    try:
        vc = _vc(s)
        cid = _cluster_id(vc, s)
        checks.append((f"vCenter login, cluster {s['wld']['cluster']} ({cid})", None))
        sid, info = _summary(vc, s)
        checks.append((f"Supervisor {s['name']} not enabled yet",
                       f"already {info.get('config_status')}/{info.get('kubernetes_status')}" if sid else None))
        for what, fn in (("portgroup", _network_id), ("storage policy", _policy_id)):
            try:
                fn(vc, s)
                checks.append((f"{what} exists", None))
            except SpvError as e:
                checks.append((f"{what} exists", str(e)))
        comp = vc.call("GET", "/vcenter/namespace-management/cluster-compatibility",
                       params={"network_provider": "NSX_VPC"}) or []
        mine = next((c for c in comp if c.get("cluster") == cid), None)
        reasons = "; ".join(m.get("default_message", "") for m in (mine or {}).get("incompatibility_reasons") or [])
        checks.append(("cluster compatible with NSX VPC Supervisor", None if mine and mine.get("compatible") else
                       (reasons or "not listed as compatible")))
    except SpvError as e:
        checks.append(("vCenter API", str(e)[:300]))
    try:
        nsx = libnsxnet._nsx(libnsxnet.edge_settings(lab_spec, s["wld"]["name"]))
        for what, path in (("NSX project", s["project"]), ("VPC connectivity profile", s["profile"])):
            checks.append((f"{what} {path}", None if nsx.get(path, ok404=True) else "not found"))
    except Exception as e:
        checks.append(("NSX", str(e)[:200]))
    failed = [c for c in checks if c[1]]
    for n, p in checks:
        liblog.print_logs(f"  {'FAIL' if p else 'ok  '}  {n}{': ' + p if p else ''}")
    liblog.print_logs(f"Preflight: {len(checks) - len(failed)} passed, {len(failed)} failed.")
    return failed


def deploy(lab_spec, part, name=None):
    s = settings(lab_spec, part, name)
    _print(s)
    if part == "VPC":
        return _vpc_deploy(lab_spec, s)
    vc = _vc(s)
    cid = _cluster_id(vc, s)
    sid, info = _summary(vc, s)
    if sid:
        liblog.print_logs(f"(SPV 1) {s['name']} is already enabled ({info.get('config_status')}).")
    else:
        spec = _enable_spec(vc, s)
        os.makedirs(SPV_DIR, exist_ok=True)
        with open(os.path.join(SPV_DIR, f"{s['name']}_enable_spec.json"), "w") as f:
            json.dump(spec, f, indent=2)
        _record(s)
        liblog.print_logs(f"(SPV 1) Enable {s['name']} (spec saved in {SPV_DIR}/{s['name']}_enable_spec.json).")
        vc.call("POST", f"/vcenter/namespace-management/supervisors/{cid}", spec,
                params={"action": "enable_on_compute_cluster"})
    _wait(vc, s, cid)
    _dns(lab_spec, s, vc, cid)
    liblog.print_logs(f"Next: -m18 SPV --certs (lab CA certificate on {s['api_fqdn']}), then -m18 SPV --report.")


def _wait(vc, s, cid, timeout_s=ENABLE_TIMEOUT):
    liblog.print_logs(f"(SPV 2) Waiting for {s['name']} to be RUNNING / READY (control plane VM deploy; 30-90 min nested).")
    deadline, last, seen = time.time() + timeout_s, None, set()
    while True:
        sid, info = _summary(vc, s)
        st = (info or {}).get("config_status"), (info or {}).get("kubernetes_status")
        if st != last:
            liblog.print_logs(f"    {st[0]} / {st[1]}")
            last = st
        for m in (_cluster_info(vc, cid).get("messages") or []):
            txt = (m.get("details") or {}).get("default_message") or m.get("default_message") or ""
            if txt and txt not in seen:
                seen.add(txt)
                liblog.print_logs(f"        {m.get('severity', '')}: {txt[:300]}")
        if st == ("RUNNING", "READY"):
            return
        if st == ("RUNNING", "WARNING"):
            liblog.print_logs("    RUNNING with a Supervisor Service warning (see the messages above): continuing.")
            return
        if time.time() > deadline:
            raise SpvError(f"{s['name']} still {st} after {timeout_s // 60} min (-m18 SPV --status keeps watching)")
        time.sleep(60)


def status(lab_spec, part, name=None, wait=False):
    s = settings(lab_spec, "SPV", name)
    vc = _vc(s)
    cid = _cluster_id(vc, s)
    if wait:
        _wait(vc, s, cid)
        return _dns(lab_spec, s, vc, cid)
    sid, info = _summary(vc, s)
    liblog.print_logs(f"{s['name']}: {info.get('config_status') if info else 'not enabled'} / "
                      f"{info.get('kubernetes_status') if info else '-'}")
    ci = _cluster_info(vc, cid)
    liblog.print_logs(f"    API endpoint {_api_vip(ci)}")
    for m in ci.get("messages") or []:
        liblog.print_logs(f"    {m.get('severity', '')}: {((m.get('details') or {}).get('default_message') or m.get('default_message') or '')[:300]}")


# ---------------------------------------------------------------- DNS (Module 4 Technitium) and certificate

def _dns(lab_spec, s, vc, cid):
    vip = _api_vip(_cluster_info(vc, cid))
    if not vip:
        liblog.print_logs("(SPV 3) No API endpoint reported yet: rerun -m18 SPV --status --wait later for the DNS record.")
        return
    from python_lib import dns_management as libdns
    fq = lab_spec["domain"]["fqdns"][0]
    gw = lab_spec["network"][fq["assign_ip_from_this_network"]]["default_gateway"]
    dns_ip = libwld._range(gw, fq["assign_ip_from_this_range_start"], fq["assign_ip_from_this_range_end"])[0]
    auth = lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]
    liblog.print_logs(f"(SPV 3) DNS {s['api_fqdn']} -> {vip} (A + PTR on {dns_ip}).")
    token = libdns.get_technitium_token(auth["username"], auth["password"], dns_ip)
    libdns.createdns_record(token, dns_ip, s["api_fqdn"], s["domain"], vip)
    os.makedirs(SPV_DIR, exist_ok=True)
    with open(os.path.join(SPV_DIR, f"{s['name']}_api.json"), "w") as f:
        json.dump({"fqdn": s["api_fqdn"], "vip": vip}, f, indent=2)
    liblog.print_logs("    Note: a Module 4 DNS refresh recreates the zone; rerun -m18 SPV --dns afterwards.")


def dns(lab_spec, name=None):
    s = settings(lab_spec, "SPV", name)
    vc = _vc(s)
    _dns(lab_spec, s, vc, _cluster_id(vc, s))


def certs(lab_spec, name=None):
    """Lab CA certificate on the Supervisor API: CSR from WCP (API, or saved from the UI to conf/spv/<name>.csr),
    signed by step-ca (Module 10), installed with the clusters update call (KB 450791 documents the DCLI form)."""
    from python_lib import ca as libca
    s = settings(lab_spec, "SPV", name)
    vc = _vc(s)
    cid = _cluster_id(vc, s)
    ca = libca.ca_settings(lab_spec)
    csr_file = os.path.join(SPV_DIR, f"{s['name']}.csr")
    csr, tried = None, []
    if os.path.exists(csr_file):
        csr = open(csr_file).read()
        liblog.print_logs(f"(Certs 1) CSR from {csr_file} (saved from the UI).")
    else:
        liblog.print_logs(f"(Certs 1) CSR for {s['api_fqdn']} from WCP.")
        spec = {"common_name": s["api_fqdn"], "organization_name": ca.get("organization", "Hesiod"),
                "organization_unit_name": "MPC", "locality": "Lab", "state_or_province": "Lab", "country": "US",
                "email_address": f"admin@{s['domain']}", "key_size": 2048}
        for path, params in ((f"/vcenter/namespace-management/certificate-management/tls-csr", {"cluster": cid}),
                             (f"/vcenter/namespace-management/clusters/{cid}/certificate-management/tls-csr", None),
                             (f"/vcenter/namespace-management/clusters/{cid}/csr/tls-endpoint", None)):
            for body in ({"spec": spec}, {"cluster": cid, "spec": spec}, spec):
                try:
                    r = vc.call("POST", path, body, params=params)
                except SpvError as e:
                    tried.append(str(e)[:120])
                    if "404" in str(e):
                        break                      # wrong path: next path
                    continue
                csr = r if isinstance(r, str) else (r or {}).get("csr") or (r or {}).get("value")
                if csr:
                    break
            if csr:
                break
    if not csr or "CERTIFICATE REQUEST" not in csr:
        raise SpvError("WCP did not return a CSR through the API on this build. Generate it in the UI: vCenter > "
                       f"Workload Management > Supervisors > {s['name']} > Configure > Certificates > Workload "
                       f"platform management > Generate CSR (common name {s['api_fqdn']}), save the PEM text as "
                       f"{csr_file} and rerun --certs. (Tried: {' | '.join(tried[-3:])})")
    from cryptography import x509 as _x509
    req = _x509.load_pem_x509_csr(csr.encode())
    try:
        has_san = bool(req.extensions.get_extension_for_class(_x509.SubjectAlternativeName).value)
    except _x509.ExtensionNotFound:
        has_san = False
    vip = (json.load(open(os.path.join(SPV_DIR, f"{s['name']}_api.json"))) if os.path.exists(
        os.path.join(SPV_DIR, f"{s['name']}_api.json")) else {}).get("vip")
    if has_san:
        leaf, inter, root = libca.sign_csr(lab_spec, csr)
    else:   # a UI CSR has only a CN; kubectl (Go) needs SANs: add the API name and VIP
        sans = [s["api_fqdn"]] + ([vip] if vip else [])
        liblog.print_logs(f"    the CSR has no SANs: signing with SANs {', '.join(sans)}")
        leaf, inter, root = libca.sign_csr_with_sans(lab_spec, csr, sans)
    chain = leaf.strip() + "\n" + inter.strip() + "\n"
    os.makedirs(SPV_DIR, exist_ok=True)
    open(os.path.join(SPV_DIR, f"{s['name']}_api_chain.pem"), "w").write(chain)
    liblog.print_logs("(Certs 2) Signed by the lab CA; installing the chain (leaf + intermediate).")
    try:
        vc.call("PATCH", f"/vcenter/namespace-management/clusters/{cid}", {"tls_endpoint_certificate": chain})
    except SpvError as e:
        raise SpvError(f"install failed ({e}). The signed chain is in {SPV_DIR}/{s['name']}_api_chain.pem: paste it in "
                       f"the UI under Workload platform management > Replace")
    if os.path.exists(csr_file):
        os.rename(csr_file, csr_file + ".used")
    liblog.print_logs("    Installed. The API restarts its listener: give it a minute, then -m18 SPV --report.")


def _cert_check(host, port=443):
    """(ok, detail): TLS to host with the lab CA chain and hostname verification."""
    if not os.path.exists(CA_CHAIN):
        return False, f"{CA_CHAIN} missing (Module 10)"
    ctx = ssl.create_default_context(cafile=CA_CHAIN)
    try:
        with socket.create_connection((host, port), timeout=15) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as t:
                c = t.getpeercert()
        issuer = dict(x[0] for x in c.get("issuer", ()))
        return True, f"issuer {issuer.get('commonName', issuer)}; expires {c.get('notAfter')}"
    except ssl.SSLCertVerificationError as e:
        return False, f"not trusted: {e.verify_message}"
    except OSError as e:
        return False, e.__class__.__name__


# ---------------------------------------------------------------- kubectl as the admin-group user

def _kubectl(s, vip):
    """kubectl + vsphere plugin downloaded from the Supervisor (bin/ in conf/spv), its own kubeconfig."""
    bindir = os.path.join(SPV_DIR, "bin")
    kc, kv = os.path.join(bindir, "kubectl"), os.path.join(bindir, "kubectl-vsphere")
    if not (os.path.exists(kc) and os.path.exists(kv)):
        os.makedirs(bindir, exist_ok=True)
        r = requests.get(f"https://{vip}/wcp/plugin/linux-amd64/vsphere-plugin.zip", verify=False, timeout=120)
        r.raise_for_status()
        zf = os.path.join(SPV_DIR, "vsphere-plugin.zip")
        open(zf, "wb").write(r.content)
        with zipfile.ZipFile(zf) as z:
            for m in z.namelist():
                if os.path.basename(m) in ("kubectl", "kubectl-vsphere"):
                    open(os.path.join(bindir, os.path.basename(m)), "wb").write(z.read(m))
        for f in (kc, kv):
            os.chmod(f, 0o755)
    env = {**os.environ, "KUBECONFIG": os.path.abspath(os.path.join(SPV_DIR, "kubeconfig")),
           "PATH": os.path.abspath(bindir) + os.pathsep + os.environ.get("PATH", "")}
    return kc, kv, env


def _kube_login(s, vip):
    if not s["test_user"]:
        raise SpvError("supervisor.test_user.use_ldap_user: no ldap.users entry to log in with")
    kc, kv, env = _kubectl(s, vip)
    env["KUBECTL_VSPHERE_PASSWORD"] = s["test_user"]["password"]
    trusted, _ = _cert_check(s["api_fqdn"])
    cmd = [kv, "login", f"--server={s['api_fqdn']}", f"--vsphere-username={s['test_user']['login']}"]
    if not trusted:
        cmd.append("--insecure-skip-tls-verify")
    p = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=120)
    if p.returncode:
        raise SpvError(f"kubectl vsphere login as {s['test_user']['login']} failed: {(p.stderr or p.stdout).strip()[:300]}")
    return kc, env


def _k(kc, env, *args, timeout=120):
    p = subprocess.run([kc, *args], env=env, capture_output=True, text=True, timeout=timeout)
    return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()


# ---------------------------------------------------------------- VPC: namespace with its own VPC

def _vpc_plan(s):
    ns = s["namespace"]
    liblog.print_logs(f"Namespace {ns['name']} on {s['name']}: its own VPC "
                      f"({', '.join(map(str, ns['private_cidrs'])) or 'private CIDRs from the Supervisor default'}), "
                      f"owner group {s['admin_group'] or '(none: vCenter administrators only)'}, test image {ns['image']}")
    return []


def _ns_exists(vc, name):
    return vc.call("GET", f"/vcenter/namespaces/instances/{name}", ok404=True)


def _vpc_deploy(lab_spec, s):
    vc = _vc(s)
    sid, info = _summary(vc, s)
    if not sid or (info or {}).get("config_status") != "RUNNING":
        raise SpvError(f"{s['name']} is not RUNNING: -m18 SPV --deploy first")
    ns = s["namespace"]
    if _ns_exists(vc, ns["name"]):
        liblog.print_logs(f"(VPC 1) Namespace {ns['name']} exists.")
    else:
        body = {"namespace": ns["name"], "supervisor": sid, "storage_specs": [{"policy": _policy_id(vc, s)}]}
        if ns["private_cidrs"]:
            body["network_spec"] = {"network_provider": "NSX_VPC",
                                    "vpc_network": {"vpc_config": {"private_cidrs": [_cidr(n) for n in ns["private_cidrs"]]}}}
        vc.call("POST", "/vcenter/namespaces/instances/v2", body)
        liblog.print_logs(f"(VPC 1) Namespace {ns['name']} created (NSX creates its VPC).")
    if s["admin_group"]:
        try:
            vc.call("POST", f"/vcenter/namespaces/instances/{ns['name']}/access/{s['group_domain']}/{s['admin_group']}",
                    {"role": "OWNER", "type": "GROUP"})
            liblog.print_logs(f"    {s['admin_group']}@{s['group_domain']} is OWNER")
        except SpvError as e:
            if "already" not in str(e).lower():
                liblog.print_logs(f"    owner grant: {str(e)[:200]}")
    for i in range(30):
        st = (_ns_exists(vc, ns["name"]) or {}).get("config_status")
        if st == "RUNNING":
            break
        time.sleep(20)
    liblog.print_logs(f"    namespace {st}")
    vip = json.load(open(os.path.join(SPV_DIR, f"{s['name']}_api.json")))["vip"]
    kc, env = _kube_login(s, vip)
    liblog.print_logs(f"(VPC 2) Test workload in {ns['name']}: deployment hw-nginx + LoadBalancer service.")
    _k(kc, env, "config", "use-context", ns["name"])
    _k(kc, env, "-n", ns["name"], "create", "deployment", "hw-nginx", f"--image={ns['image']}", "--port=80")
    _k(kc, env, "-n", ns["name"], "expose", "deployment", "hw-nginx", "--type=LoadBalancer", "--port=80")
    for i in range(30):
        rc, out, _ = _k(kc, env, "-n", ns["name"], "get", "svc", "hw-nginx", "-o",
                        "jsonpath={.status.loadBalancer.ingress[0].ip}")
        if out:
            liblog.print_logs(f"    LoadBalancer VIP {out}")
            break
        time.sleep(20)
    liblog.print_logs(f"Done. -m18 VPC --report writes the evidence; -m18 VPC --cleanup removes the test workload.")


def vpc_cleanup(lab_spec, name=None):
    s = settings(lab_spec, "VPC", name)
    vip = json.load(open(os.path.join(SPV_DIR, f"{s['name']}_api.json")))["vip"]
    kc, env = _kube_login(s, vip)
    for kind in ("svc", "deployment"):
        _k(kc, env, "-n", s["namespace"]["name"], "delete", kind, "hw-nginx", "--ignore-not-found")
    liblog.print_logs("Test workload removed (the namespace and its VPC stay).")


# ---------------------------------------------------------------- report

def report(lab_spec, part, name=None):
    s = settings(lab_spec, part, name)
    rep = {"generated": datetime.datetime.now().isoformat(timespec="seconds"),
           "title": f"{'US-021' if part == 'SPV' else 'US-021 (namespace VPC)'} evidence: {s['name']}", "checks": []}

    def add(check, ok, detail=""):
        rep["checks"].append({"check": check, "result": ok if isinstance(ok, str) else ("PASS" if ok else "FAIL"),
                              "detail": detail})
    vc = _vc(s)
    cid = _cluster_id(vc, s)
    for i in range(6):          # a failing Supervisor Service makes it flap RUNNING <-> CONFIGURING: sample ~3 min
        sid, info = _summary(vc, s)
        st = ((info or {}).get("config_status"), (info or {}).get("kubernetes_status"))
        if st[0] == "RUNNING":
            break
        time.sleep(30)
    warn = ""
    if st[1] == "WARNING":
        msgs = [(m.get("details") or {}).get("default_message") or m.get("default_message") or ""
                for m in _cluster_info(vc, cid).get("messages") or [] if m.get("severity") in ("WARNING", "ERROR")]
        warn = "; Supervisor Service warning: " + " / ".join(x[:160] for x in msgs if x)[:400]
    add(f"Supervisor {s['name']} Running", st[0] == "RUNNING" and st[1] in ("READY", "WARNING"), f"{st[0]} / {st[1]}{warn}")
    vip = _api_vip(_cluster_info(vc, cid))
    try:
        got = socket.gethostbyname(s["api_fqdn"])
    except OSError:
        got = None
    add(f"API resolves at {s['api_fqdn']}", bool(vip) and got == vip, f"{got or 'no answer'} (API VIP {vip})")
    ok, d = _cert_check(s["api_fqdn"])
    add(f"API certificate trusted (lab CA, hostname {s['api_fqdn']})", ok, d)
    try:
        kc, env = _kube_login(s, vip)
        rc, out, err = _k(kc, env, "get", "ns")
        add(f"kubectl get ns as {s['test_user']['login']}", rc == 0,
            (f"{len(out.splitlines()) - 1} namespaces" if rc == 0 else err[:200]))
        if part == "VPC":
            n = s["namespace"]["name"]
            rc, out, err = _k(kc, env, "-n", n, "get", "pods", "-l", "app=hw-nginx", "-o",
                              "jsonpath={range .items[*]}{.status.phase}{' '}{.status.podIP}{'\\n'}{end}")
            add(f"Pod running in {n} with a VPC private IP", rc == 0 and "Running" in out, out or err[:200])
            rc, lb, err = _k(kc, env, "-n", n, "get", "svc", "hw-nginx", "-o",
                             "jsonpath={.status.loadBalancer.ingress[0].ip}")
            add("LoadBalancer VIP from the external block", bool(lb), lb or err[:200])
            if lb:
                try:
                    r = requests.get(f"http://{lb}/", timeout=15)
                    add(f"http://{lb}/ answers from hesthe001", r.status_code < 500, f"HTTP {r.status_code}")
                except requests.RequestException as e:
                    add(f"http://{lb}/ answers from hesthe001", False, e.__class__.__name__)
    except (SpvError, requests.RequestException, OSError) as e:
        add("kubectl as the admin-group user", False, str(e)[:300])
    if part == "VPC":
        try:
            nsx = libnsxnet._nsx(libnsxnet.edge_settings(lab_spec, s["wld"]["name"]))
            vpcs = [v.get("display_name") or v.get("id") for v in nsx.results(f"{s['project']}/vpcs")]
            mine = [v for v in vpcs if s["namespace"]["name"] in str(v)]
            add(f"NSX VPC for namespace {s['namespace']['name']}", bool(mine), ", ".join(mine) or f"VPCs: {', '.join(vpcs)[:200]}")
        except Exception as e:
            add("NSX VPC for the namespace", False, str(e)[:200])
    for e in s["exceptions"]:
        if str(e.get("part", "SPV")).upper() in (part, "ALL"):
            add(e["criterion"], "EXCEPTION", e.get("reason", ""))
    res = [c["result"] for c in rep["checks"]]
    rep["result"] = "FAIL" if "FAIL" in res else "PASS" + (f" ({res.count('EXCEPTION')} exception)" if "EXCEPTION" in res else "")
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    base = os.path.join(EVIDENCE_DIR, f"spv_{part.lower()}_{s['name']}_evidence_{datetime.datetime.now():%Y%m%d-%H%M%S}")
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2, default=str)
    L = [f"# {rep['title']}", "", f"Generated {rep['generated']}. Result: **{rep['result']}**.", "",
         "| Check | Result | Detail |", "|---|---|---|"]
    L += [f"| {c['check']} | {c['result']} | {str(c['detail']).replace('|', '/')} |" for c in rep["checks"]]
    with open(base + ".md", "w") as f:
        f.write("\n".join(L) + "\n")
    for c in rep["checks"]:
        liblog.print_logs(f"    {c['result']:9}  {c['check']}{': ' + str(c['detail']) if c['detail'] else ''}")
    liblog.print_logs(f"Evidence report: {rep['result']}  ->  {base}.md  (+ .json)")
    return rep
