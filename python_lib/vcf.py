# Hesiod VCF Fleet Management Domain
# Description: Builds the VCF Installer deployment spec (SddcSpec) from lab_spec, runs local preflight checks,
#              and validates it through the VCF Installer API. (Pass 2 will add deploy / monitor / retry.)
#              Shape of the spec: json_lib/vcf9.1_spec.json.  Values: lab_spec only.
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.0
#
# IP plan (management network = the nested ESXi hosts' network):
#   - Every component FQDN gets its own IP, in lab_spec["vcf"]["components"] order, starting right after
#     nested_esxi_servers[0].assign_ip_from_this_range_end. Its FQDN is the name Module 4 created for that IP.
#   - IP pools (management services runtime, VCF Automation nodes) need no DNS and must not overlap any FQDN,
#     so they are taken from the addresses after the Module 4 (domain.fqdns) range.
#
# Public functions
#   get_vcf_plan(lab_spec)                       Component -> FQDN/IP allocation table (no network calls).
#   render_sddc_spec(lab_spec)                   Full SddcSpec dict (needs the nested hosts up for thumbprints).
#   preflight(lab_spec, spec)                    Local checks: passwords, DNS fwd/rev, free IPs, gateways, hosts, installer.
#   validate_sddc_spec(lab_spec, spec)           POST /v1/sddcs/validations and wait for the result.
#   run_pass1(lab_spec, force=False)             render -> preflight -> validate (what -m8 runs).
#
# Every failure raises VcfError(stage, message).
# Dry run (allocation plan only):  python3 -m python_lib.vcf conf/lab_spec.json

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import vmware as libvmw
from python_lib import esxi as libesxi

import copy
import ipaddress
import json
import os
import re
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3

SPEC_TEMPLATE = "json_lib/vcf9.1_spec.json"
OUTPUT_DIR = "conf"
VALIDATION_TIMEOUT = 3600

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class VcfError(Exception):
    def __init__(self, stage, message):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.message = message


# --------------------------------------------------------------------------------------------
# Component catalog: how many FQDNs and pool IPs each component needs, and which spec fields they fill.
# "count" in lab_spec overrides the number of nodes (NSX managers, VCF Operations nodes).
# --------------------------------------------------------------------------------------------
CATALOG = {
    "vcenter":                  {"fqdns": ["vcenter"]},
    "sddc_manager":             {"fqdns": ["sddc_manager"]},
    "nsx":                      {"fqdns": ["vip"], "nodes": "manager", "default_count": 1},
    "vcf_operations":           {"fqdns": [], "nodes": "node", "default_count": 1},
    "vcf_operations_collector": {"fqdns": ["collector"]},
    "vsp":                      {"fqdns": ["platform", "instance", "fleet"], "pool": 12},
    "vcf_automation":           {"fqdns": ["hostname", "platform"], "pool": 5},
    "license_server":           {"fqdns": ["license_server"]},
    "vidb":                     {"fqdns": ["vidb"]},
    "fleet_lcm":                {"fqdns": ["fleet_lcm"]},
    "sddc_lcm":                 {"fqdns": ["sddc_lcm"]},
}


def _auth(lab_spec, ref, system):
    if isinstance(ref, int):
        return lab_spec["authentication"][ref]
    for a in lab_spec["authentication"]:
        if a.get("system") == system:
            return a
    raise VcfError("lab_spec", f"no authentication entry for '{system}'")


def _net(lab_spec, idx):
    n = lab_spec["network"][idx]
    iface = ipaddress.ip_interface(f"{n['default_gateway']}/{n['cidr']}")
    return {"index": idx, "name": n["name"], "gateway": n["default_gateway"], "cidr": int(n["cidr"]),
            "mask": n["subnet_mask"], "vlan": int(str(n.get("vlan", "0")) or 0), "subnet": str(iface.network)}


def _naming(lab_spec):
    v = lab_spec["vcf"]["naming_convention"]
    objs = {o["name"]: o["value"] for o in v.get("object", [])}
    root = v["root"]
    return {"root": root,
            "datacenter": f"{root}-{objs.get('datacenter', 'dc')}",
            "cluster": f"{root}-{objs.get('management-cluster', 'mcl')}"}


def get_vcf_plan(lab_spec):
    """Allocate IPs/FQDNs for every component in lab_spec['vcf']['components']."""
    vcf, domain = lab_spec["vcf"], lab_spec["domain"]
    esx = next((g for g in lab_spec["nested_esxi_servers"] if str(g.get("nested_esxi_type", "")).upper() == "MGT"),
               lab_spec["nested_esxi_servers"][0])
    mgmt_idx = esx["assign_ip_from_this_network"]

    plan, next_fqdn_ip, next_pool_ip = [], {}, {}
    for comp in vcf["components"]:
        name = comp["name"]
        if name not in CATALOG:
            raise VcfError("lab_spec", f"vcf.components: unknown component '{name}' (known: {', '.join(CATALOG)})")
        cat = CATALOG[name]
        net_idx = comp.get("assign_ip_from_this_network", mgmt_idx)
        net = _net(lab_spec, net_idx)
        gw = net["gateway"]

        # where FQDN IPs and pool IPs start on this network
        if net_idx not in next_fqdn_ip:
            start = int(esx["assign_ip_from_this_range_end"]) + 1 if net_idx == mgmt_idx else int(comp.get("assign_ip_from_this_range_start", 10))
            next_fqdn_ip[net_idx] = start
            fq = next((f for f in domain["fqdns"] if f["assign_ip_from_this_network"] == net_idx), None)
            next_pool_ip[net_idx] = int(fq["assign_ip_from_this_range_end"]) + 1 if fq else start + 64

        labels = list(cat["fqdns"])
        if "nodes" in cat:
            labels += [f"{cat['nodes']}{i + 1}" for i in range(int(comp.get("count", cat["default_count"])))]
        entry = {"component": name, "network": net, "fqdns": {}, "pool": [], "size": comp.get("size")}
        for label in labels:
            ip = libvmw.get_ip_range(gw, str(next_fqdn_ip[net_idx]), str(next_fqdn_ip[net_idx]))[0]
            next_fqdn_ip[net_idx] += 1
            short = libesxi._dns_name_for_ip(lab_spec, ip)
            if not short:
                raise VcfError("lab_spec", f"{name}/{label}: {ip} has no Module 4 FQDN; widen domain.fqdns range")
            entry["fqdns"][label] = {"ip": ip, "short": short, "fqdn": f"{short}.{domain['name']}"}
        pool_size = int(comp.get("pool_size", cat.get("pool", 0)))
        if pool_size:
            entry["pool"] = libvmw.get_ip_range(gw, str(next_pool_ip[net_idx]), str(next_pool_ip[net_idx] + pool_size - 1))
            next_pool_ip[net_idx] += pool_size
            for ip in (entry["pool"][0], entry["pool"][-1]):
                if ipaddress.ip_address(ip) not in ipaddress.ip_network(net["subnet"]):
                    raise VcfError("lab_spec", f"{name}: pool runs past {net['subnet']}")
        plan.append(entry)
    return plan


# --------------------------------------------------------------------------------------------
# Spec rendering
# --------------------------------------------------------------------------------------------
def _role(lab_spec, role):
    r = lab_spec["vcf"]["networks"].get(role)
    if r is None:
        return None
    if isinstance(r, int):
        r = {"network": r}
    out = _net(lab_spec, r["network"])
    if "range_start" in r:
        out["range"] = libvmw.get_ip_range(out["gateway"], r["range_start"], r["range_end"])
    return out


def _ssh_thumbprint(ip, timeout=10):
    """OpenSSH-style RSA SHA256 fingerprint of the host key (SddcHostSpec.sshThumbprint)."""
    import base64, hashlib, socket, paramiko
    sock = socket.create_connection((ip, 22), timeout=timeout)
    t = paramiko.Transport(sock)
    try:
        t.get_security_options().key_types = ["rsa-sha2-512", "rsa-sha2-256", "ssh-rsa"]
        t.start_client(timeout=timeout)
        key = t.get_remote_server_key()
        return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")
    finally:
        t.close()


def render_sddc_spec(lab_spec, plan=None, host_thumbprints=True):
    vcf, domain = lab_spec["vcf"], lab_spec["domain"]
    plan = plan or get_vcf_plan(lab_spec)
    by = {p["component"]: p for p in plan}
    names = _naming(lab_spec)
    pw = _auth(lab_spec, vcf.get("use_these_credentials"), "vcf_components")["password"]
    with open(SPEC_TEMPLATE) as f:
        spec = json.load(f)

    spec["sddcId"] = vcf.get("sddc_id", names["cluster"])
    spec["vcfInstanceName"] = vcf.get("instance_name", f"{names['root']}-instance-01")
    spec["version"] = vcf.get("version", spec.get("version"))
    spec["ceipEnabled"] = False
    spec["workflowType"] = "VCF"
    spec["dnsSpec"] = {"subdomain": domain["name"], "nameservers": [s for s in domain["server_ips"]][:2]}
    spec["ntpServers"] = [x.strip() for x in str(domain["ntp"]).split(",") if x.strip()]

    # Networks (MANAGEMENT = ESXi vmk0, VM_MANAGEMENT = appliances, VMOTION/VSAN with IP ranges)
    net_specs = []
    for role, ntype, mtu in (("management", "MANAGEMENT", 1500), ("vm_management", "VM_MANAGEMENT", 1500),
                             ("vmotion", "VMOTION", 9000), ("vsan", "VSAN", 9000)):
        r = _role(lab_spec, role)
        if not r:
            raise VcfError("lab_spec", f"vcf.networks.{role} is missing")
        ns = {"networkType": ntype, "ipAddressVersion": "IPv4", "subnet": r["subnet"], "gateway": r["gateway"],
              "subnetMask": r["mask"], "vlanId": r["vlan"], "mtu": mtu, "teamingPolicy": "loadbalance_loadbased",
              "activeUplinks": ["uplink1", "uplink2"], "standbyUplinks": [],
              "portGroupKey": f"{names['cluster']}-vds01-pg-{role.replace('_', '-')}"}
        if ntype in ("VMOTION", "VSAN"):
            if "range" not in r:
                raise VcfError("lab_spec", f"vcf.networks.{role} needs range_start / range_end")
            ns["includeIpAddressRanges"] = [{"startIpAddress": r["range"][0], "endIpAddress": r["range"][-1]}]
        net_specs.append(ns)
    spec["networkSpecs"] = net_specs

    # Hosts: the MGT nested ESXi hosts from Module 7, with live thumbprints
    hosts = []
    for h in libesxi.get_nested_esxi_specs(lab_spec, types=["MGT"]):
        hs = {"hostname": h["fqdn"].split(".")[0], "credentials": {"username": "root", "password": h["password"]}}
        if host_thumbprints:
            try:
                hs["sslThumbprint"] = libesxi._served_cert(h["ip"])[1]
                hs["sshThumbprint"] = _ssh_thumbprint(h["ip"])
            except Exception as e:
                raise VcfError("hosts", f"{h['fqdn']} ({h['ip']}): cannot read thumbprints: {e}")
        hosts.append(hs)
    spec["hostSpecs"] = hosts

    # vCenter / cluster / vSAN / VDS
    c = vcf.get("cluster", {})
    if "vcenter" not in by:
        raise VcfError("lab_spec", "vcf.components must include vcenter")
    spec["vcenterSpec"].update({"vcenterHostname": by["vcenter"]["fqdns"]["vcenter"]["short"], "rootVcenterPassword": pw,
                                "adminUserSsoPassword": pw, "vmSize": by["vcenter"]["size"] or spec["vcenterSpec"].get("vmSize", "small")})
    spec["clusterSpec"] = {"datacenterName": names["datacenter"], "clusterName": names["cluster"]}
    esa = str(c.get("vsan_type", "OSA")).upper() == "ESA"
    spec["datastoreSpec"] = {"vsanSpec": {"datastoreName": f"{names['cluster']}-vsan01", "vsanDedup": False,
                                          "failuresToTolerate": int(c.get("failures_to_tolerate", 1)),
                                          "esaConfig": {"enabled": esa}}}
    tep = _role(lab_spec, "host_tep")
    vmnics = c.get("vmnics", ["vmnic0", "vmnic1"])
    spec["dvsSpecs"] = [{
        "dvsName": f"{names['cluster']}-vds01", "mtu": 9000,
        "networks": ["MANAGEMENT", "VM_MANAGEMENT", "VMOTION", "VSAN"],
        "vmnicsToUplinks": [{"id": v, "uplink": f"uplink{i + 1}"} for i, v in enumerate(vmnics)],
        "nsxtSwitchConfig": {"transportZones": [{"name": f"{names['root']}-overlay-tz", "transportType": "OVERLAY"},
                                                {"name": f"{names['root']}-vlan-tz", "transportType": "VLAN"}],
                             "hostSwitchOperationalMode": "STANDARD"},
        "nsxTeamings": [{"policy": "LOADBALANCE_SRCID", "activeUplinks": [f"uplink{i + 1}" for i in range(len(vmnics))],
                         "standByUplinks": []}]}]

    # SDDC Manager
    if "sddc_manager" in by:
        spec["sddcManagerSpec"].update({"hostname": by["sddc_manager"]["fqdns"]["sddc_manager"]["short"],
                                        "rootPassword": pw, "sshPassword": pw, "localUserPassword": pw})
    # NSX
    if "nsx" in by:
        n = by["nsx"]["fqdns"]
        ns = spec["nsxtSpec"]
        ns.update({"vipFqdn": n["vip"]["fqdn"], "nsxtManagerSize": by["nsx"]["size"] or ns.get("nsxtManagerSize", "medium"),
                   "nsxtManagers": [{"hostname": v["short"]} for k, v in n.items() if k.startswith("manager")],
                   "rootNsxtManagerPassword": pw, "nsxtAdminPassword": pw, "nsxtAuditPassword": pw})
        if not tep or "range" not in tep:
            raise VcfError("lab_spec", "vcf.networks.host_tep needs network, range_start, range_end")
        ns["transportVlanId"] = tep["vlan"]
        ns["ipAddressPoolSpec"] = {"name": f"{names['cluster']}-tep01", "description": f"{names['cluster']} host TEP pool",
                                   "subnets": [{"cidr": tep["subnet"], "gateway": tep["gateway"],
                                                "ipAddressPoolRanges": [{"start": tep["range"][0], "end": tep["range"][-1]}]}]}
        vpc = vcf.get("vpc")
        if vpc:
            ns["vpcSpec"] = {"dtgwSpec": {"vlan": int(vpc["vlan"]), "gatewayCidr": vpc["gateway_cidr"],
                                          "externalIpBlockCidr": vpc["external_ip_block_cidr"],
                                          "privateTgwIpBlockCidr": vpc.get("private_tgw_ip_block_cidr", "172.31.0.0/16")}}
        else:
            ns.pop("vpcSpec", None)
    # VCF Operations + collector
    if "vcf_operations" in by:
        nodes = [v for k, v in by["vcf_operations"]["fqdns"].items() if k.startswith("node")]
        spec["vcfOperationsSpec"].update({
            "adminUserPassword": pw, "applianceSize": by["vcf_operations"]["size"] or "small",
            "nodes": [{"hostname": v["short"], "rootUserPassword": pw, "type": "master" if i == 0 else "replica"}
                      for i, v in enumerate(nodes)]})
    if "vcf_operations_collector" in by:
        spec["vcfOperationsCollectorSpec"].update({"hostname": by["vcf_operations_collector"]["fqdns"]["collector"]["short"],
                                                   "rootUserPassword": pw,
                                                   "applianceSize": by["vcf_operations_collector"]["size"] or "small"})
    # Management services runtime (VSP)
    if "vsp" in by:
        v = by["vsp"]
        spec["vspClusterSpec"].update({
            "name": f"{names['root']}-vsp01", "size": v["size"] or "small", "systemUserPassword": pw,
            "platformFqdn": v["fqdns"]["platform"]["fqdn"], "instanceFqdn": v["fqdns"]["instance"]["fqdn"],
            "fleetFqdn": v["fqdns"]["fleet"]["fqdn"],
            "ipv4Pool": {"ipRange": {"startIpAddress": v["pool"][0], "endIpAddress": v["pool"][-1]}}})
    # VCF Automation
    if "vcf_automation" in by:
        a = by["vcf_automation"]
        spec["vcfAutomationSpec"].update({"hostname": a["fqdns"]["hostname"]["fqdn"], "platformFqdn": a["fqdns"]["platform"]["fqdn"],
                                          "ipPool": a["pool"], "nodePrefix": f"{names['root']}-vcfa", "adminUserPassword": pw,
                                          "size": a["size"] or "small"})
    else:
        spec.pop("vcfAutomationSpec", None)
    # Services with a single hostname
    for comp, key in (("license_server", "licenseServerSpec"), ("vidb", "vidbSpec"),
                      ("fleet_lcm", "fleetLcmSpec"), ("sddc_lcm", "sddcLcmSpec")):
        if comp in by:
            spec.setdefault(key, {})["hostname"] = by[comp]["fqdns"][comp]["fqdn"]
    return spec


def redact(spec):
    s = copy.deepcopy(spec)
    def walk(o):
        if isinstance(o, dict):
            for k in o:
                if "password" in k.lower() and o[k]:
                    o[k] = "********"
                else:
                    walk(o[k])
        elif isinstance(o, list):
            for i in o:
                walk(i)
    walk(s)
    return s


# --------------------------------------------------------------------------------------------
# Preflight (local, fast)
# --------------------------------------------------------------------------------------------
def _password_problems(pw):
    problems = []
    if not 15 <= len(pw) <= 20:
        problems.append("length must be 15-20 (vCenter root max 20, SDDC Manager/VCFA/VSP min 15)")
    if not re.search(r"[A-Z]", pw): problems.append("needs an uppercase letter")
    if not re.search(r"[a-z]", pw): problems.append("needs a lowercase letter")
    if not re.search(r"[0-9]", pw): problems.append("needs a digit")
    if not re.search(r"[!$%^]", pw): problems.append("needs one of ! $ % ^ (the only specials every component accepts)")
    if re.search(r"(.)\1\1", pw): problems.append("no character 3+ times in a row")
    if " " in pw or not pw.isascii(): problems.append("ASCII only, no spaces")
    return problems


def _dns_check(server, fqdn, ip):
    import dns.resolver, dns.reversename
    r = dns.resolver.Resolver(configure=False)
    r.nameservers, r.lifetime = [server], 3
    try:
        fwd = sorted(a.to_text() for a in r.resolve(fqdn, "A"))
    except Exception as e:
        return f"no A record ({type(e).__name__})"
    try:
        rev = [p.to_text().rstrip(".").lower() for p in r.resolve(dns.reversename.from_address(ip), "PTR")]
    except Exception as e:
        return f"no PTR record ({type(e).__name__})"
    if fwd != [ip]:
        return f"A = {fwd}, expected {ip}"
    if fqdn.lower() not in rev:
        return f"PTR = {rev}, expected {fqdn}"
    return None


def _pings(ip):
    try:
        return subprocess.run(["ping", "-c", "1", "-W", "1", ip], stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL).returncode == 0
    except FileNotFoundError:
        raise VcfError("preflight", "ping is not installed (sudo apt -y install iputils-ping)")


def preflight(lab_spec, spec, plan):
    vcf, domain = lab_spec["vcf"], lab_spec["domain"]
    results = []
    add = lambda name, problem: results.append((name, problem))

    pw = _auth(lab_spec, vcf.get("use_these_credentials"), "vcf_components")["password"]
    add("component password policy", "; ".join(_password_problems(pw)) or None)

    dns_server = domain["server_ips"][0]
    names = [(f["fqdn"], f["ip"]) for p in plan for f in p["fqdns"].values()]
    names += [(h["fqdn"], h["ip"]) for h in libesxi.get_nested_esxi_specs(lab_spec, types=["MGT"])]
    with ThreadPoolExecutor(16) as ex:
        for (fqdn, ip), problem in zip(names, ex.map(lambda n: _dns_check(dns_server, *n), names)):
            add(f"DNS {fqdn} <-> {ip}", problem)
        free = [f["ip"] for p in plan for f in p["fqdns"].values()] + [ip for p in plan for ip in p["pool"]]
        for ip, used in zip(free, ex.map(_pings, free)):
            add(f"IP {ip} is free", "something already answers ping on this IP" if used else None)
        gws = sorted({_role(lab_spec, r)["gateway"] for r in ("management", "vm_management", "vmotion", "vsan", "host_tep")
                      if vcf["networks"].get(r) is not None})
        for gw, ok in zip(gws, ex.map(_pings, gws)):
            add(f"gateway {gw} answers", None if ok else "no reply")

    for h in spec["hostSpecs"]:
        add(f"host {h['hostname']} thumbprints", None if h.get("sslThumbprint") and h.get("sshThumbprint") else "missing")

    try:
        api = _installer(lab_spec)
        depot = api.get("/v1/system/settings/depot")
        add("installer login + depot configured", None if depot else "no depot settings returned")
    except VcfError as e:
        add("installer login + depot configured", e.message)

    failed = [r for r in results if r[1]]
    for name, problem in results:
        liblog.print_logs(f"  {'FAIL' if problem else 'ok  '}  {name}{': ' + problem if problem else ''}")
    liblog.print_logs(f"Preflight: {len(results) - len(failed)} passed, {len(failed)} failed.")
    return failed


# --------------------------------------------------------------------------------------------
# VCF Installer API
# --------------------------------------------------------------------------------------------
class _Installer:
    def __init__(self, base, username, password):
        self.base, self.username, self.password, self.token = base, username, password, None
        self.http = requests.Session()
        self.http.trust_env = False  # lab-internal API: never route through HTTP(S)_PROXY from the environment
        self.http.verify = False
        self.login()

    def login(self):
        try:
            r = self.http.post(f"{self.base}/v1/tokens", json={"username": self.username, "password": self.password},
                               timeout=30)
        except requests.RequestException as e:
            raise VcfError("installer", f"cannot reach {self.base}: {e}")
        if r.status_code >= 300:
            raise VcfError("installer", f"login as {self.username} failed: HTTP {r.status_code} {r.text[:200]}")
        self.token = r.json()["accessToken"]

    def _call(self, method, path, **kw):
        for attempt in (1, 2):
            r = self.http.request(method, f"{self.base}{path}", timeout=120,
                                  headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json"}, **kw)
            if r.status_code == 401 and attempt == 1:
                self.login()  # access token expired during a long poll
                continue
            if r.status_code >= 300:
                raise VcfError("installer", f"{method} {path}: HTTP {r.status_code} {r.text[:400]}")
            return r.json() if r.content else {}

    def get(self, path): return self._call("GET", path)
    def post(self, path, body): return self._call("POST", path, json=body)


def _installer(lab_spec):
    inst = lab_spec["vcf"]["installer"]
    auth = _auth(lab_spec, inst.get("use_these_credentials"), "vcf_installer")
    host = libesxi._dns_name_for_ip(lab_spec, inst["ip_address"])
    target = f"{host}.{lab_spec['domain']['name']}" if host else inst["ip_address"]
    return _Installer(f"https://{target}", auth["username"], auth["password"])


def _print_checks(checks, depth=0, out=None):
    out = out if out is not None else []
    for c in checks or []:
        status = c.get("resultStatus", "")
        if status in ("FAILED", "WARNING"):
            msg = c.get("errorResponse", {}) or {}
            text = msg.get("message") or ""
            fix = msg.get("remediationMessage") or ""
            liblog.print_logs(f"  {'  ' * depth}{status:7} {c.get('description', '')}{' - ' + text if text else ''}"
                              f"{' | fix: ' + fix if fix else ''}")
            out.append((status, c.get("description", ""), text))
        _print_checks(c.get("nestedValidationChecks"), depth + 1, out)
    return out


def validate_sddc_spec(lab_spec, spec):
    api = _installer(lab_spec)
    v = api.post("/v1/sddcs/validations", spec)
    vid = v["id"]
    liblog.print_logs(f"Installer validation {vid} started.")
    deadline, last = time.time() + VALIDATION_TIMEOUT, None
    while v.get("executionStatus") in ("IN_PROGRESS", None) and time.time() < deadline:
        time.sleep(15)
        v = api.get(f"/v1/sddcs/validations/{vid}")
        running = [c.get("description") for c in v.get("validationChecks", []) if c.get("resultStatus") == "IN_PROGRESS"]
        if running and running[0] != last:
            last = running[0]
            liblog.print_logs(f"  running: {last}")
    if v.get("executionStatus") == "IN_PROGRESS":
        raise VcfError("validate", f"validation {vid} still running after {VALIDATION_TIMEOUT}s")

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    report = os.path.join(OUTPUT_DIR, "vcf_mgmt_domain_validation.json")
    with open(report, "w") as f:
        json.dump(v, f, indent=2)
    issues = _print_checks(v.get("validationChecks"))
    result = v.get("resultStatus")
    liblog.print_logs(f"Installer validation {vid}: {v.get('executionStatus')} / {result} "
                      f"({sum(1 for i in issues if i[0] == 'FAILED')} failed, {sum(1 for i in issues if i[0] == 'WARNING')} warnings). "
                      f"Full report: {report}")
    return result, issues


def save_spec(spec):
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    path = os.path.join(OUTPUT_DIR, "vcf_mgmt_domain_spec.redacted.json")
    with open(path, "w") as f:
        json.dump(redact(spec), f, indent=2)
    return path


def print_plan(plan):
    for p in plan:
        for label, f in p["fqdns"].items():
            liblog.print_logs(f"  {p['component']:25} {label:15} {f['ip']:15} {f['fqdn']}")
        if p["pool"]:
            liblog.print_logs(f"  {p['component']:25} {'pool':15} {p['pool'][0]} - {p['pool'][-1]} ({len(p['pool'])} IPs, no DNS)")


def run_pass1(lab_spec, force=False):
    liblog.print_logs("Building the VCF management domain plan.")
    plan = get_vcf_plan(lab_spec)
    print_plan(plan)
    spec = render_sddc_spec(lab_spec, plan)
    liblog.print_logs(f"Spec written (passwords redacted): {save_spec(spec)}")
    failed = preflight(lab_spec, spec, plan)
    if failed and not force:
        raise VcfError("preflight", f"{len(failed)} check(s) failed; fix them or rerun with --force")
    result, issues = validate_sddc_spec(lab_spec, spec)
    if result == "FAILED":
        raise VcfError("validate", f"installer validation failed ({sum(1 for i in issues if i[0] == 'FAILED')} errors); "
                                   f"see the log above and conf/vcf_mgmt_domain_validation.json")
    return result


# Dry run: python3 -m python_lib.vcf conf/lab_spec.json   (plan only; no network calls)
if __name__ == "__main__":
    with open(sys.argv[1] if len(sys.argv) > 1 else "conf/lab_spec.json") as f:
        ls = json.load(f)
    p = get_vcf_plan(ls)
    print_plan(p)
    s = render_sddc_spec(ls, p, host_thumbprints=False)
    print(json.dumps(redact(s), indent=2))
