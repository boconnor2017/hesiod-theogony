# Hesiod VCF Log Management and Real-Time Metrics (Module 16)
# Description: US-019. Deploys the two day-N observability components onto the VCF services runtime through the VCF
#              Fleet Lifecycle service API (the same call the VCF Operations wizard Build > Lifecycle > VCF Management >
#              Components > Add Component makes):
#                LOG  Log Management   componentType OPS_LOGS           (FQDN, size, node count)
#                RTM  Real-Time Metrics componentType OPS_DATA_PLATFORM
#              Both add worker nodes to the services runtime (scale-out), so each run needs free addresses in the
#              runtime's IP pool and spare CPU/RAM in the management cluster.
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.8 (stop before the upload when productVersionCatalog.json is missing: the tool requires it)
#         1.7 (VCF Download Tool gets absolute paths: it runs from its own bin/ folder)
#         1.6 (--upload reads depot_store itself: no inbox; multi-GB files hard-linked, not copied;
#              a download that is already a depot file (PROD/...) is uploaded as is)
#         1.5 (--upload: side-load portal downloads into the Fleet depot with the VCF Download Tool, no token)
#         1.4 (hint when the component binary is missing from the fleet depot)
#         1.3 (default Fleet lifecycle FQDN = the services runtime fleet FQDN; login is admin@vsp.local)
#         1.2 (an empty lab_spec value counts as unset, e.g. fleet_lcm_fqdn: "")
#         1.1 (Fleet lifecycle login from observability.use_these_credentials, like every other module)
#         1.0
#
# API (VCF 9.1): https://<fleet lifecycle FQDN>
#   POST /api/v1/identity/token (form: grant_type=password, username, password) -> access_token
#   GET  /fleet-lcm/v1/sddc-lcms                       primary SDDC lifecycle id (isPrimary)
#   GET  /fleet-lcm/v1/components                      what is deployed (and at which version)
#   POST /fleet-lcm/v1/components/validations          validate a componentSpecs payload -> task id
#   POST /fleet-lcm/v1/components                      deploy -> task id
#   GET  /fleet-lcm/v1/tasks/<id>                      task status
#
# lab_spec["observability"] (see json_lib/lab_spec.json):
#   fleet_lcm_fqdn                    default: the vcf plan's fleet_lcm FQDN
#   use_these_credentials             index into lab_spec["authentication"] (the vcf_fleet_lcm entry: admin@vsp.local,
#                                     the services runtime API account)
#   log_management.fqdn               "auto" = next free address in the Module 4 DNS range (recorded like -m14/-m15)
#   log_management.size / .nodes      small / 1 (lab); version "auto" = the version the fleet already runs
#   real_time_metrics.version         "auto"
#
# Public functions
#   settings(lab_spec, part)          resolve lab_spec (no network calls)
#   plan(lab_spec, part)              -m16 LOG|RTM: plan + preflight (fleet API, DNS, already deployed?, validation)
#   deploy(lab_spec, part)            -m16 LOG|RTM --deploy: validate, deploy, follow the task to the end
#   status(lab_spec, part)            -m16 LOG|RTM --status: the last deployment task (resume watching with --wait)
#   report(lab_spec, part)            -m16 LOG|RTM --report: US-019 evidence for the part
#   upload(lab_spec, part)            -m16 LOG|RTM --upload: side-load binaries downloaded by hand from the Broadcom
#                                     portal into the Fleet depot (Software Depot in disconnected mode, no token):
#                                     drop the files in <depot_store>, the module lays out PROD/COMP/<id>/ and
#                                     PROD/metadata/..., checks them against productVersionCatalog.json, and runs
#                                     vcf-download-tool depot binaries upload (VCF Operations login, no token)
#
# Every failure raises ObsError.

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import vcf as libvcf
from python_lib import wld as libwld

# Import Standard Python Libraries
import collections
import datetime
import json
import os
import shutil
import subprocess
import time

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

OBS_DIR = "conf/obs"
EVIDENCE_DIR = "conf/evidence"
TERMINAL = {"SUCCEEDED", "SUCCESSFUL", "COMPLETED", "COMPLETED_WITH_WARNING", "FAILED", "CANCELLED", "TIMED_OUT", "ERROR"}
OK = {"SUCCEEDED", "SUCCESSFUL", "COMPLETED", "COMPLETED_WITH_WARNING"}
DEPLOY_TIMEOUT = 4 * 3600
PARTS = {
    "LOG": {"type": "OPS_LOGS", "title": "Log Management", "key": "log_management", "depot": ["VRLI"]},
    "RTM": {"type": "OPS_DATA_PLATFORM", "title": "Real-Time Metrics", "key": "real_time_metrics",
            "depot": ["VCF_OBSERVABILITY_DATA_PLATFORM", "VCFMS_METRICS_STORE"]},
}


class ObsError(Exception):
    pass


# ---------------------------------------------------------------- Fleet Lifecycle API

class Fleet:
    def __init__(self, fqdn, user, password):
        self.fqdn, self.base = fqdn, f"https://{fqdn}"
        self.user, self.password, self.token = user, password, None
        self.http = requests.Session()
        self.http.verify = False

    def login(self):
        try:
            r = self.http.post(f"{self.base}/api/v1/identity/token", timeout=30,
                               data={"grant_type": "password", "username": self.user, "password": self.password},
                               headers={"Content-Type": "application/x-www-form-urlencoded", "Accept": "application/json"})
        except requests.RequestException as e:
            raise ObsError(f"Fleet lifecycle {self.fqdn} not reachable: {e.__class__.__name__}")
        if r.status_code != 200 or "access_token" not in r.text:
            raise ObsError(f"Fleet lifecycle {self.fqdn}: login as {self.user} failed (HTTP {r.status_code}): {r.text[:200]}")
        self.token = r.json()["access_token"]
        return self

    def _call(self, method, path, body=None, ok404=False):
        for attempt in range(4):
            if not self.token:
                self.login()
            try:
                r = self.http.request(method, self.base + path, json=body, timeout=120,
                                      headers={"Authorization": f"Bearer {self.token}", "Accept": "application/json",
                                               "Content-Type": "application/json"})
            except requests.RequestException as e:
                if attempt == 3:
                    raise ObsError(f"{method} {path}: {e.__class__.__name__}")
                time.sleep(10)
                continue
            if r.status_code == 401 and attempt < 3:
                self.token = None
                continue
            if r.status_code == 404 and ok404:
                return None
            if r.status_code >= 500 and attempt < 3:
                time.sleep(10)
                continue
            if r.status_code >= 400:
                raise ObsError(f"{method} {path}: HTTP {r.status_code}: {_errors(r)}")
            return r.json() if r.text.strip() else {}
        raise ObsError(f"{method} {path}: gave up")

    def get(self, path, ok404=False):
        return self._call("GET", path, ok404=ok404)

    def post(self, path, body):
        return self._call("POST", path, body)


def _errors(r):
    try:
        j = r.json()
    except ValueError:
        return r.text[:400]
    msgs = []
    for k in ("message", "errorMessage", "error", "details"):
        if isinstance(j.get(k), str):
            msgs.append(j[k])
    for e in j.get("errors") or j.get("nestedErrors") or []:
        if isinstance(e, dict):
            msgs.append(e.get("message") or e.get("errorCode") or json.dumps(e)[:200])
    return "; ".join(msgs)[:600] or json.dumps(j)[:400]


def _walk(o):
    """Every dict inside a JSON answer (the component list's exact shape is not documented)."""
    if isinstance(o, dict):
        yield o
        for v in o.values():
            yield from _walk(v)
    elif isinstance(o, list):
        for v in o:
            yield from _walk(v)


def _components(fleet):
    seen = []
    for d in _walk(fleet.get("/fleet-lcm/v1/components") or {}):
        ctype = d.get("componentType") or d.get("type")
        if isinstance(ctype, str) and ctype.isupper():
            seen.append({"type": ctype, "version": d.get("version"), "fqdn": d.get("fqdn") or d.get("hostname"),
                         "status": d.get("status") or d.get("state") or d.get("health"), "id": d.get("id")})
    return seen


def _primary_sddc(fleet):
    lcms = [d for d in _walk(fleet.get("/fleet-lcm/v1/sddc-lcms") or {}) if "isPrimary" in d]
    p = next((d for d in lcms if d.get("isPrimary")), None)
    if not p:
        raise ObsError("no primary SDDC lifecycle in GET /fleet-lcm/v1/sddc-lcms")
    return p["id"]


def _auto_version(comps):
    """The version the fleet already runs: the most common 4-part version among deployed components."""
    vs = [str(c["version"]).split("-")[0] for c in comps if c.get("version")]
    vs = [".".join(v.split(".")[:4]) for v in vs if v.count(".") >= 3]
    return collections.Counter(vs).most_common(1)[0][0] if vs else None


def _task(fleet, tid):
    return fleet.get(f"/fleet-lcm/v1/tasks/{tid}") or {}


def _task_status(t):
    return str(t.get("status") or t.get("state") or "").upper()


def _task_errors(t):
    msgs = []
    for d in _walk(t):
        st = str(d.get("status") or d.get("state") or "").upper()
        for k in ("errorMessage", "message", "failureMessage"):
            if isinstance(d.get(k), str) and (st in ("FAILED", "ERROR") or k != "message"):
                msgs.append(f"{d.get('name') or d.get('description') or ''}: {d[k]}".strip(": "))
        for e in d.get("errors") or []:
            if isinstance(e, dict) and e.get("message"):
                msgs.append(e["message"])
    out = []
    for m in msgs:
        if m not in out:
            out.append(m)
    return out


def _subtasks(t):
    return [(d.get("name") or d.get("description"), _task_status(d)) for d in _walk(t.get("subTasks") or t.get("subtasks") or [])
            if (d.get("name") or d.get("description")) and _task_status(d)]


def _follow(fleet, tid, what, timeout_s, poll_s):
    deadline, last, seen = time.time() + timeout_s, None, {}
    while True:
        t = _task(fleet, tid)
        s = _task_status(t)
        if s != last:
            liblog.print_logs(f"    {what}: {s or '?'}")
            last = s
        for name, st in _subtasks(t):
            if seen.get(name) != st:
                seen[name] = st
                liblog.print_logs(f"        {st:10} {name}")
        if s in TERMINAL:
            return t
        if time.time() > deadline:
            raise ObsError(f"{what}: task {tid} still {s} after {timeout_s // 60} min (-m16 ... --status to keep watching)")
        time.sleep(poll_s)


# ---------------------------------------------------------------- settings

def _placeholder(v):
    return v is None or not str(v).strip() or str(v).strip().startswith("<")


def settings(lab_spec, part):
    part = part.upper()
    if part not in PARTS:
        raise ObsError(f"unknown part {part} (LOG or RTM)")
    o = lab_spec.get("observability") or {}
    plan = {e["component"]: e for e in libvcf.get_vcf_plan(lab_spec)}
    fleet_fqdn = o.get("fleet_lcm_fqdn")
    if _placeholder(fleet_fqdn):
        # the API answers on the services runtime's fleet FQDN (vspClusterSpec.fleetFqdn); the separate fleet_lcm
        # hostname in the bring-up spec is not where it listens
        if "vsp" in plan:
            fleet_fqdn = plan["vsp"]["fqdns"]["fleet"]["fqdn"]
        elif "fleet_lcm" in plan:
            fleet_fqdn = plan["fleet_lcm"]["fqdns"]["fleet_lcm"]["fqdn"]
        else:
            raise ObsError('set observability.fleet_lcm_fqdn (VCF Operations > Build > Lifecycle > VCF Management > Components)')
    ref = o.get("use_these_credentials")
    if ref is None or _placeholder(ref):
        raise ObsError('set observability.use_these_credentials (index of the "vcf_fleet_lcm" entry in authentication)')
    try:
        auth = lab_spec["authentication"][int(ref)]
    except (IndexError, ValueError, TypeError):
        raise ObsError(f"observability.use_these_credentials={ref!r}: no such authentication entry")
    if _placeholder(auth.get("username")) or _placeholder(auth.get("password")):
        raise ObsError(f"authentication[{ref}] ({auth.get('system')}) still has a <sample> username or password")
    c = o.get(PARTS[part]["key"]) or {}
    if _placeholder(fleet_fqdn):
        raise ObsError("the Fleet lifecycle FQDN is empty: set observability.fleet_lcm_fqdn")
    s = {"part": part, **PARTS[part], "fleet_fqdn": fleet_fqdn, "user": auth["username"],
         "password": auth["password"], "version": None if _placeholder(c.get("version")) or str(c.get("version")).lower() == "auto"
         else str(c["version"]), "pool": plan.get("vsp", {}).get("pool", []),
         "nameservers": lab_spec["vcf"].get("nameservers") or lab_spec["domain"].get("server_ips", [])}
    if part == "LOG":
        s["size"] = str(c.get("size", "small")).lower()
        s["nodes"] = int(c.get("nodes", 1))
        fq = c.get("fqdn", "auto")
        pf = libwld._plan_file("fleet-logs")
        if os.path.exists(pf):
            s["address"], s["recorded"] = json.load(open(pf))["addresses"]["logs"], True
        elif _placeholder(fq) or str(fq).lower() == "auto":
            s["address"], s["recorded"] = libwld._allocate(lab_spec, {"name": "fleet-logs"}, ["logs"])["logs"], False
        else:
            short = str(fq).split(".")[0]
            dom = lab_spec["domain"]["name"]
            ip = next((r["ip"] for r in _dns_records(lab_spec) if r["short"] == short), None)
            if not ip:
                raise ObsError(f"observability.log_management.fqdn {fq}: not a Module 4 DNS name")
            s["address"], s["recorded"] = {"ip": ip, "short": short, "fqdn": f"{short}.{dom}"}, False
        s["fqdn"] = s["address"]["fqdn"]
    return s


def _dns_records(lab_spec):
    out = []
    for f in lab_spec["domain"]["fqdns"]:
        try:
            ips = libwld._range(lab_spec["network"][f["assign_ip_from_this_network"]]["default_gateway"],
                                f["assign_ip_from_this_range_start"], f["assign_ip_from_this_range_end"])
        except (KeyError, IndexError):
            continue
        for ip in ips:
            short = libwld.libesxi._dns_name_for_ip(lab_spec, ip)
            if short:
                out.append({"ip": ip, "short": short})
    return out


def _record(s):
    pf = libwld._plan_file("fleet-logs")
    if s["part"] == "LOG" and not os.path.exists(pf):
        os.makedirs(os.path.dirname(pf), exist_ok=True)
        with open(pf, "w") as f:
            json.dump({"name": "fleet-logs", "recorded": time.strftime("%Y-%m-%d %H:%M"),
                       "addresses": {"logs": s["address"]}}, f, indent=2)
        liblog.print_logs(f"    Recorded {s['fqdn']} ({s['address']['ip']}) in {pf} (Module 7, 14 and 15 IPAM now skip it).")


def _payload(s, sddc_id, version):
    spec = {"sddcLcmId": sddc_id, "componentType": s["type"], "deploymentType": "VspComponentSpec", "version": version}
    if s["part"] == "LOG":
        spec["fqdn"] = s["fqdn"]
        spec["configSpec"] = {"size": s["size"], "numberOfNodes": s["nodes"]}
    return {"componentSpecs": [spec]}


def _state_file(part):
    return os.path.join(OBS_DIR, f"{part.lower()}_task.json")


def _print_plan(s):
    liblog.print_logs(f"{s['title']} ({s['type']}) through Fleet lifecycle {s['fleet_fqdn']} as {s['user']}:")
    if s["part"] == "LOG":
        liblog.print_logs(f"    FQDN {s['fqdn']} ({s['address']['ip']}){' (recorded)' if s['recorded'] else ''}, "
                          f"size {s['size']}, {s['nodes']} node(s)")
    liblog.print_logs(f"    version {s['version'] or 'auto (what the fleet already runs)'}")
    if s["pool"]:
        liblog.print_logs(f"    services runtime IP pool {s['pool'][0]}-{s['pool'][-1]} ({len(s['pool'])} addresses): the new "
                          "worker nodes take their addresses from it")


def _connect(s):
    fleet = Fleet(s["fleet_fqdn"], s["user"], s["password"]).login()
    sddc = _primary_sddc(fleet)
    comps = _components(fleet)
    version = s["version"] or _auto_version(comps)
    if not version:
        raise ObsError("could not tell the fleet's version from GET /fleet-lcm/v1/components: set "
                       f"observability.{s['key']}.version (e.g. 9.1.1.0)")
    return fleet, sddc, comps, version


# ---------------------------------------------------------------- plan / deploy / status

def plan(lab_spec, part):
    s = settings(lab_spec, part)
    _print_plan(s)
    checks = []
    if s["part"] == "LOG":
        p = next((f"{n}: {x}" for n in s["nameservers"] for x in [libvcf._dns_check(n, s["fqdn"], s["address"]["ip"])] if x), None)
        checks.append((f"DNS {s['fqdn']} <-> {s['address']['ip']}", p))
    try:
        fleet, sddc, comps, version = _connect(s)
        checks.append((f"Fleet lifecycle {s['fleet_fqdn']}: login, primary SDDC lifecycle {sddc}", None))
        liblog.print_logs(f"    deployed components: " + ", ".join(sorted({f"{c['type']} {c['version'] or ''}".strip() for c in comps})))
        have = [c for c in comps if c["type"] == s["type"]]
        checks.append((f"{s['title']} not deployed yet", f"already deployed ({have[0].get('fqdn') or have[0].get('status')})" if have else None))
        if not have:
            body = _payload(s, sddc, version)
            liblog.print_logs(f"    validating (version {version}) ...")
            t = _follow(fleet, fleet.post("/fleet-lcm/v1/components/validations", body)["id"], "validation", 900, 5)
            ok = _task_status(t) in OK
            checks.append((f"Fleet lifecycle validation of the {s['type']} payload", None if ok else
                           "; ".join(_task_errors(t))[:600] or _task_status(t)))
    except ObsError as e:
        checks.append(("Fleet lifecycle API", str(e)[:300]))
    failed = [c for c in checks if c[1]]
    for n, p in checks:
        liblog.print_logs(f"  {'FAIL' if p else 'ok  '}  {n}{': ' + p if p else ''}")
    liblog.print_logs(f"Preflight: {len(checks) - len(failed)} passed, {len(failed)} failed.")
    return failed


def deploy(lab_spec, part, force=False):
    s = settings(lab_spec, part)
    _print_plan(s)
    fleet, sddc, comps, version = _connect(s)
    if any(c["type"] == s["type"] for c in comps):
        liblog.print_logs(f"{s['title']} is already deployed: nothing to do (-m16 {s['part']} --report).")
        return
    body = _payload(s, sddc, version)
    liblog.print_logs(f"(1) Validate {s['type']} {version}.")
    t = _follow(fleet, fleet.post("/fleet-lcm/v1/components/validations", body)["id"], "validation", 900, 5)
    if _task_status(t) not in OK:
        errs = _task_errors(t)
        for e in errs[:10]:
            liblog.print_logs(f"        {e}")
        if not force:
            raise ObsError(f"validation {_task_status(t)}: " + ("; ".join(errs)[:400] or "see above") + " (--force deploys anyway)")
    _record(s)
    liblog.print_logs(f"(2) Deploy {s['title']}: adds worker nodes to the services runtime (30-60 min; the runtime's "
                      "management services may be briefly disrupted).")
    tid = fleet.post("/fleet-lcm/v1/components", body)["id"]
    os.makedirs(OBS_DIR, exist_ok=True)
    with open(_state_file(s["part"]), "w") as f:
        json.dump({"task": tid, "started": time.strftime("%Y-%m-%d %H:%M:%S"), "payload": body}, f, indent=2)
    _finish(s, fleet, tid)


def _finish(s, fleet, tid):
    t = _follow(fleet, tid, f"{s['title']} deployment", DEPLOY_TIMEOUT, 60)
    st = _task_status(t)
    if st not in OK:
        errs = _task_errors(t)
        for e in errs[:12]:
            liblog.print_logs(f"        {e}")
        if any("resolve component repository" in e for e in errs):
            liblog.print_logs(f"    The {s['title']} binary for that version is not in the fleet depot. Download it in VCF Operations >"
                              " Build > Lifecycle > VCF Management > Binary Management, then set observability."
                              f"{s['key']}.version to the exact version shown there (validation does not check binaries).")
        raise ObsError(f"{s['title']} deployment {st} (task {tid}). Retry from VCF Operations > Build > Lifecycle > "
                       "VCF Management (task details > Retry), or rerun --deploy")
    liblog.print_logs(f"{s['title']} deployed. -m16 {s['part']} --report writes the US-019 evidence.")


def status(lab_spec, part, wait=False):
    s = settings(lab_spec, part)
    sf = _state_file(s["part"])
    if not os.path.exists(sf):
        raise ObsError(f"no deployment recorded in {sf}: run -m16 {s['part']} --deploy")
    tid = json.load(open(sf))["task"]
    fleet = Fleet(s["fleet_fqdn"], s["user"], s["password"]).login()
    if wait:
        return _finish(s, fleet, tid)
    t = _task(fleet, tid)
    liblog.print_logs(f"{s['title']} deployment task {tid}: {_task_status(t)}")
    for name, st in _subtasks(t):
        liblog.print_logs(f"        {st:10} {name}")
    for e in _task_errors(t)[:12]:
        liblog.print_logs(f"        {e}")


# ---------------------------------------------------------------- report

def report(lab_spec, part):
    s = settings(lab_spec, part)
    rep = {"generated": datetime.datetime.now().isoformat(timespec="seconds"),
           "title": f"US-019 evidence: {s['title']}", "checks": []}

    def add(check, ok, detail=""):
        rep["checks"].append({"check": check, "result": "PASS" if ok else "FAIL", "detail": detail})
    fleet, sddc, comps, version = _connect(s)
    have = [c for c in comps if c["type"] == s["type"]]
    rep["component"] = have
    add(f"{s['title']} ({s['type']}) deployed in the fleet", bool(have),
        ", ".join(f"{c.get('fqdn') or ''} {c.get('version') or ''} {c.get('status') or ''}".strip() for c in have) or "not found")
    if s["part"] == "LOG":
        p = next((x for n in s["nameservers"] for x in [libvcf._dns_check(n, s["fqdn"], s["address"]["ip"])] if x), None)
        add(f"{s['fqdn']} resolves", not p, p or "")
        try:
            r = requests.get(f"https://{s['fqdn']}", verify=False, timeout=15, allow_redirects=False)
            add(f"https://{s['fqdn']} answers", r.status_code < 500, f"HTTP {r.status_code}")
        except requests.RequestException as e:
            add(f"https://{s['fqdn']} answers", False, e.__class__.__name__)
    rep["result"] = "PASS" if all(c["result"] == "PASS" for c in rep["checks"]) else "FAIL"
    os.makedirs(EVIDENCE_DIR, exist_ok=True)
    base = os.path.join(EVIDENCE_DIR, f"obs_{s['part'].lower()}_evidence_{datetime.datetime.now():%Y%m%d-%H%M%S}")
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2, default=str)
    L = [f"# {rep['title']}", "", f"Generated {rep['generated']}. Result: **{rep['result']}**.", "",
         "| Check | Result | Detail |", "|---|---|---|"]
    L += [f"| {c['check']} | {c['result']} | {str(c['detail']).replace('|', '/')} |" for c in rep["checks"]]
    with open(base + ".md", "w") as f:
        f.write("\n".join(L) + "\n")
    for c in rep["checks"]:
        liblog.print_logs(f"    {c['result']:4}  {c['check']}{': ' + str(c['detail']) if c['result'] != 'PASS' and c['detail'] else ''}")
    liblog.print_logs(f"Evidence report: {rep['result']}  ->  {base}.md  (+ .json)")
    return rep


# ---------------------------------------------------------------- side-load into the Fleet depot (no token)

# metadata file -> paths under the depot store (VCF Download Tool reads both vSAN HCL copies)
METADATA = {
    "productVersionCatalog.json": ["PROD/metadata/productVersionCatalog/v1"],
    "productVersionCatalog.sig": ["PROD/metadata/productVersionCatalog/v1"],
    "vcfManifest.json": ["PROD/metadata/manifest/v1"],
    "VmwareCompatibilityData.json": ["PROD/metadata/Compatibility/v1", "PROD/metadata/Compatibility/v2"],
    "all.json": ["PROD/metadata/vsan/hcl", "PROD/vsan/hcl"],
    "lastupdatedtime.json": ["PROD/metadata/vsan/hcl", "PROD/vsan/hcl"],
}
# file-name prefixes, used only when productVersionCatalog.json does not say which component a file belongs to
PREFIXES = [("salt-raas-", "VCF_SALT_RAAS"), ("salt-", "VCF_SALT"), ("vcf-fleet-lcm-", "VCF_FLEET_LCM"),
            ("vcf-sddc-lcm-", "VCF_SDDC_LCM"), ("vcf-fleet-depot-", "DEPOT_SERVICE"), ("vidb-", "VIDB"),
            ("vcfa-", "VRA"), ("telemetry-acceptor-", "TELEMETRY_ACCEPTOR"), ("vmsp-", "VSP"),
            ("vcf-services-platform-", "VSP"), ("vcd-migrator-", "VCF_SERVICE_VCD_MIGRATION_BACKEND"),
            ("operations-logs-", "VRLI"), ("vcf-obs-data-platform-", "VCF_OBSERVABILITY_DATA_PLATFORM"),
            ("vcfms-metrics-store-", "VCFMS_METRICS_STORE"), ("metrics-store-", "VCFMS_METRICS_STORE")]
KNOWN = {c for _, c in PREFIXES} | {"VROPS", "VRLI", "VRNI", "VCF_OBSERVABILITY_DATA_PLATFORM", "VCFMS_METRICS_STORE",
                                    "VCENTER", "NSX_T_MANAGER", "SDDC_MANAGER_VCF", "VCF_OPS_CLOUD_PROXY", "VCF_LICENSE_SERVER"}


def _depot_settings(lab_spec, s):
    d = (lab_spec.get("observability") or {}).get("depot") or {}
    plan = {e["component"]: e for e in libvcf.get_vcf_plan(lab_spec)}
    ops = d.get("ops_fqdn")
    if _placeholder(ops):
        nodes = [v for k, v in plan.get("vcf_operations", {}).get("fqdns", {}).items() if k.startswith("node")]
        if not nodes:
            raise ObsError("set observability.depot.ops_fqdn (the VCF Operations FQDN)")
        ops = nodes[0]["fqdn"]
    ref = d.get("use_these_credentials", lab_spec["vcf"]["use_these_credentials"])
    auth = lab_spec["authentication"][int(ref)]
    user = d.get("ops_user") or "admin"
    tool = d.get("vcfdt_path") if not _placeholder(d.get("vcfdt_path")) else "/usr/local/vcfdt"
    exe = os.path.join(tool, "bin", "vcf-download-tool")
    return {"store": d.get("depot_store") if not _placeholder(d.get("depot_store")) else "/usr/local/hesiod-depot",
            "exe": exe, "ops": ops, "ops_user": user, "ops_password": auth["password"],
            "vcf_version": d.get("vcf_version") if not _placeholder(d.get("vcf_version")) else "9.1.1.0",
            "depot_fqdn": s["fleet_fqdn"]}


def _catalog_bundles(store):
    """INSTALL bundles from productVersionCatalog.json: [{"id", "component", "version", "files": {name: size}}]."""
    pf = os.path.join(store, "PROD/metadata/productVersionCatalog/v1/productVersionCatalog.json")
    if not os.path.exists(pf):
        return []
    out = []
    for d in _walk(json.load(open(pf))):
        if isinstance(d.get("binaries"), list) and "id" in d:
            files = {b["fileName"]: b.get("size") for b in d["binaries"] if isinstance(b, dict) and b.get("fileName")}
            comp = next((v for v in d.values() if isinstance(v, str) and v in KNOWN), None)
            if not comp:      # the component id may sit in the bundle id or a binary's path
                blob = json.dumps(d)
                comp = next((k for k in sorted(KNOWN, key=len, reverse=True) if f"/{k}/" in blob), None)
            out.append({"id": d["id"], "type": str(d.get("type", "")).upper(), "component": comp,
                        "version": d.get("version") or d.get("productVersion"), "files": files})
    return out


def _depot_file(path):
    """True when a downloaded archive is already a VCF Download Tool depot file (its tree starts at PROD/)."""
    import tarfile
    if not path.endswith((".tar", ".tgz", ".tar.gz")):
        return False
    try:
        with tarfile.open(path, "r:*") as t:
            first = t.next()
        return bool(first) and first.name.lstrip("./").startswith("PROD")
    except (tarfile.TarError, OSError):
        return False


def _place(src, dest_dir):
    """Hard-link (no second copy of multi-GB files) or copy src into dest_dir."""
    os.makedirs(dest_dir, exist_ok=True)
    dst = os.path.join(dest_dir, os.path.basename(src))
    if os.path.exists(dst) and os.path.getsize(dst) == os.path.getsize(src):
        return
    if os.path.exists(dst):
        os.remove(dst)
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def upload(lab_spec, part):
    s = settings(lab_spec, part)
    d = _depot_settings(lab_spec, s)
    store = os.path.abspath(d["store"])
    if not os.path.isdir(store):
        raise ObsError(f"observability.depot.depot_store {store} does not exist")
    if not os.access(d["exe"], os.X_OK):
        raise ObsError(f"{d['exe']} not found: extract vcf-download-tool-<version>.tar.gz (Broadcom portal > VCF "
                       "9.1.1 > Drivers & Tools) into observability.depot.vcfdt_path")
    liblog.print_logs(f"{s['title']}: side-load into the Fleet depot {d['depot_fqdn']} (VCF Operations {d['ops']} as "
                      f"{d['ops_user']}), depot store {store}, VCF {d['vcf_version']}.")

    # what was dropped: files at the top of depot_store, plus subfolders named after a component id
    files = [os.path.join(store, f) for f in sorted(os.listdir(store)) if os.path.isfile(os.path.join(store, f))]
    for sub in sorted(os.listdir(store)):
        if sub in KNOWN and os.path.isdir(os.path.join(store, sub)):
            files += [os.path.join(store, sub, f) for f in sorted(os.listdir(os.path.join(store, sub)))
                      if os.path.isfile(os.path.join(store, sub, f))]

    # (1) metadata to its fixed paths (the catalog sorts and checks the binaries)
    liblog.print_logs("(Upload 1) Metadata.")
    for f in files:
        for dest in METADATA.get(os.path.basename(f), []):
            _place(f, os.path.join(store, dest))
            liblog.print_logs(f"    {os.path.basename(f)} -> {dest}/")
    bundles = _catalog_bundles(store)
    if not bundles:
        liblog.print_logs("    no productVersionCatalog.json: binaries are matched by file name and not size-checked.")
    owner = {name: b["component"] for b in bundles if b["component"] for name in b["files"]}

    # (2) this part's binaries to PROD/COMP/<component>/ (other files in depot_store are left alone)
    liblog.print_logs(f"(Upload 2) {s['title']} binaries ({', '.join(s['depot'])}).")
    mine, depot_files = [], []
    for f in files:
        name = os.path.basename(f)
        if name in METADATA:
            continue
        sub = os.path.basename(os.path.dirname(f))
        stem = name
        for pre in ("configuration-schema-", "depot-manifest-"):
            stem = stem[len(pre):] if stem.startswith(pre) else stem
        comp = sub if sub in KNOWN else owner.get(name) or next((c for p, c in PREFIXES if stem.startswith(p)), None)
        if comp not in s["depot"]:
            continue
        if _depot_file(f):
            depot_files.append(f)
            liblog.print_logs(f"    {name}: a ready-made depot file (uploaded as is)")
            continue
        _place(f, os.path.join(store, "PROD/COMP", comp))
        mine.append(comp)
        liblog.print_logs(f"    {name} -> PROD/COMP/{comp}/")
    if not mine and not depot_files:
        raise ObsError(f"no {s['title']} binaries in {store}: expected files starting with "
                       + " or ".join(p for p, c in PREFIXES if c in s["depot"])
                       + f" (or put them in a subfolder named {s['depot'][0]})")

    # (3) check the part's INSTALL bundles against the catalog (a bundle with a missing file is skipped silently)
    liblog.print_logs("(Upload 3) Check against productVersionCatalog.json.")
    want = [b for b in bundles if b["component"] in s["depot"] and b["type"] == "INSTALL"
            and any(os.path.exists(os.path.join(store, "PROD/COMP", b["component"], n)) for n in b["files"])]
    if mine and not bundles:
        raise ObsError(f"VCF Download Tool needs productVersionCatalog.json (+ .sig) in {store} to upload binaries from a "
                       "depot store: download the VCF 9.1.1 metadata files from the Broadcom portal (productVersionCatalog"
                       ".json, productVersionCatalog.sig, vcfManifest.json) into it and rerun --upload")
    if mine and not want:
        liblog.print_logs("    the catalog has no INSTALL bundle for these files: uploading them unchecked.")
    ready = set()
    for b in want:
        bad = []
        for name, size in b["files"].items():
            p = os.path.join(store, "PROD/COMP", b["component"], name)
            if not os.path.exists(p):
                bad.append(f"MISSING {name}")
            elif size and int(size) != os.path.getsize(p):
                bad.append(f"WRONG SIZE {name} ({os.path.getsize(p)} != {size})")
        liblog.print_logs(f"    {'OK  ' if not bad else 'FAIL'}  {b['component']} {b['version'] or ''} ({b['id']})")
        for x in bad:
            liblog.print_logs(f"            {x}")
        if not bad:
            ready.add(b["component"])
    comps = sorted(ready) if want else sorted(set(mine))
    if not comps and not depot_files:
        raise ObsError(f"nothing complete to upload for {s['title']} ({', '.join(s['depot'])}): see the list above")

    # (4) upload with the VCF Download Tool (answers its certificate prompt in this terminal on the first run)
    os.makedirs(OBS_DIR, exist_ok=True)
    pwf = os.path.abspath(os.path.join(OBS_DIR, ".ops_password"))   # the tool runs from its own bin/ folder
    fd = os.open(pwf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(d["ops_password"])
    common = ["--ops-fqdn", d["ops"], "--ops-auth-source", "LOCAL", "--ops-user", d["ops_user"],
              "--ops-user-password-file", pwf, "--depot-fqdn", d["depot_fqdn"], "--vcf-version", d["vcf_version"]]
    try:
        for f in depot_files:
            liblog.print_logs(f"(Upload 4) vcf-download-tool depot binaries upload --depot-file {os.path.basename(f)}")
            rc = subprocess.run([d["exe"], "depot", "binaries", "upload", *[x for x in common if x not in ("--vcf-version",
                                 d["vcf_version"])], "--depot-file", f], cwd=os.path.dirname(d["exe"])).returncode
            if rc:
                raise ObsError(f"vcf-download-tool upload of {os.path.basename(f)} exited {rc}")
        for c in comps:
            liblog.print_logs(f"(Upload 4) vcf-download-tool depot binaries upload --component {c}")
            rc = subprocess.run([d["exe"], "depot", "binaries", "upload", *common, "--sku", "VCF", "--type", "INSTALL",
                                 "--depot-store", store, "--component", c], cwd=os.path.dirname(d["exe"])).returncode
            if rc:
                raise ObsError(f"vcf-download-tool upload of {c} exited {rc} (see its output above; 'Unknown options:"
                               " --ops-fqdn' means a VCF Download Tool older than 9.1.1)")
        liblog.print_logs("(Upload 5) What the Fleet depot now has:")
        subprocess.run([d["exe"], "depot", "binaries", "list", *common], cwd=os.path.dirname(d["exe"]))
    finally:
        os.remove(pwf)
    liblog.print_logs(f"Set observability.{s['key']}.version to the {s['title']} version listed above, then -m16 "
                      f"{s['part']} --deploy.")
