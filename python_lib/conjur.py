# Hesiod Password Vault (Conjur OSS)
# Description: REST client for Conjur OSS and the password export used by Module 9.
#              Deployment of Conjur itself lives in python_lib/k8_management.py (deploy_conjur), following the
#              same pattern as deploy_lldap / deploy_technitium.
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.1 (evidence report: -m9 --report)
#
# What gets exported (-m9 and -m9 --export):
#   vcf/<resourceType>/<resourceName>/<credentialType>/<username>   every credential SDDC Manager manages
#                                                                   (GET /v1/credentials on SDDC Manager)
#   lab/<system>                                                    every lab_spec["authentication"] entry
# Each variable carries annotations (username, resource, IP, type) so the vault is browsable without guessing.
# Values are written only when they differ from what Conjur already holds, so re-runs don't pile up versions.
# Passwords are never printed or written to disk.
#
# Public functions
#   ConjurClient(base_url, account, login, password=None, api_key=None)
#   validate_admin_password(password)          Conjur's password rules (raises ConjurError)
#   set_admin_password(base_url, account, api_key, password)
#   wait_until_ready(base_url, timeout_s)
#   get_sddc_manager_credentials(lab_spec)     list of dicts from SDDC Manager
#   export_passwords(lab_spec)                 load policy + write every secret (what -m9 runs after the deploy)
#   evidence_report(lab_spec)                  readiness + inventory + coverage report, no secret values
#                                              (-m9 --report; writes conf/evidence/conjur_evidence_<timestamp>.md/.json)

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import vcf as libvcf

import base64
import datetime
import hashlib
import json
import os
import re
import socket
import ssl
import time
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CONJUR_ROOT_POLICY = "root"
MASKED = {"", "*", "****", "*****", "********", "<masked>", "redacted"}


class ConjurError(Exception):
    pass


def _session():
    s = requests.Session()
    s.trust_env = False   # lab-internal: never route through HTTP(S)_PROXY from the environment
    s.verify = False      # self-signed certificate created by deploy_conjur (copy kept in conf/conjur_tls.crt)
    return s


def conjur_settings(lab_spec):
    """Resolved Conjur settings from lab_spec["conjur"] (with defaults)."""
    c = lab_spec.get("conjur") or {}
    if not c.get("ip_address") or not c.get("account"):
        raise ConjurError('lab_spec["conjur"] needs ip_address and account (see json_lib/lab_spec.json).')
    idx = c.get("use_these_credentials")
    if idx is None or idx >= len(lab_spec["authentication"]):
        raise ConjurError('lab_spec["conjur"]["use_these_credentials"] must point at an authentication entry.')
    creds = lab_spec["authentication"][idx]
    hostname = c.get("hostname", "conjur")
    return {
        "ip": c["ip_address"],
        "account": c["account"],
        "hostname": hostname,
        "fqdn": f"{hostname}.{lab_spec['domain']['name']}",
        "username": creds.get("username") or "admin",
        "password": creds["password"],
        "base_url": f"https://{c['ip_address']}",
        "node": None if str(c.get("node") or "").startswith("<") else c.get("node"),
        "data_path": c.get("data_path", "/var/lib/hesiod/conjur/pgdata"),
    }


def validate_admin_password(password):
    # Conjur rejects anything else: 12-128 chars, 2 upper, 2 lower, 1 digit, 1 special
    problems = []
    if not 12 <= len(password) <= 128: problems.append("12-128 characters")
    if len(re.findall(r"[A-Z]", password)) < 2: problems.append("2 uppercase letters")
    if len(re.findall(r"[a-z]", password)) < 2: problems.append("2 lowercase letters")
    if not re.search(r"[0-9]", password): problems.append("1 digit")
    if not re.search(r"[^A-Za-z0-9]", password): problems.append("1 special character")
    if problems:
        raise ConjurError("the Conjur admin password (lab_spec authentication entry used by conjur) needs: "
                          + ", ".join(problems))


def wait_until_ready(base_url, timeout_s=600):
    """Poll until Conjur answers through nginx (the root page returns 200 once the server is up)."""
    s, deadline, last = _session(), time.time() + timeout_s, None
    while time.time() < deadline:
        try:
            r = s.get(f"{base_url}/", timeout=10)
            if r.status_code == 200:
                return True
            last = f"HTTP {r.status_code}"
        except requests.RequestException as e:
            last = str(e)[:120]
        time.sleep(10)
    raise ConjurError(f"Conjur at {base_url} not answering after {timeout_s}s (last: {last}). "
                      "Check: kubectl -n conjur get pods; kubectl -n conjur logs deploy/conjur -c conjur")


def set_admin_password(base_url, account, api_key, password):
    """PUT /authn/{account}/password, authenticated with the API key printed by conjurctl account create."""
    r = _session().put(f"{base_url}/authn/{quote(account, safe='')}/password", data=password.encode(),
                       auth=("admin", api_key), timeout=30)
    if r.status_code >= 300:
        raise ConjurError(f"setting the Conjur admin password failed: HTTP {r.status_code} {r.text[:200]}")


class ConjurClient:
    def __init__(self, base_url, account, login, password=None, api_key=None):
        self.base, self.account, self.login_name = base_url.rstrip("/"), account, login
        self.http = _session()
        self.acct = quote(account, safe="")
        if api_key is None:
            api_key = self._login(password)
        self.api_key = api_key
        self.token, self.token_time = None, 0

    def _login(self, password):
        try:
            r = self.http.get(f"{self.base}/authn/{self.acct}/login", auth=(self.login_name, password), timeout=30)
        except requests.RequestException as e:
            raise ConjurError(f"cannot reach Conjur at {self.base}: {e}")
        if r.status_code == 401:
            raise ConjurError(f"Conjur login as {self.login_name} on account '{self.account}' was refused (401). "
                              "The password in lab_spec does not match the vault. If it was changed in Conjur, put "
                              "the current one in lab_spec.")
        if r.status_code >= 300:
            raise ConjurError(f"Conjur login failed: HTTP {r.status_code} {r.text[:200]}")
        return r.text.strip()

    def _auth_header(self):
        # Access tokens last 8 minutes; refresh well before that
        if not self.token or time.time() - self.token_time > 300:
            r = self.http.post(f"{self.base}/authn/{self.acct}/{quote(self.login_name, safe='')}/authenticate",
                               data=self.api_key.encode(), headers={"Accept-Encoding": "base64"}, timeout=30)
            if r.status_code >= 300:
                raise ConjurError(f"Conjur authenticate failed: HTTP {r.status_code} {r.text[:200]}")
            tok = r.text.strip()
            if tok.startswith("{"):  # server ignored Accept-Encoding: encode the raw JSON token ourselves
                tok = base64.b64encode(tok.encode()).decode()
            self.token, self.token_time = tok, time.time()
        return {"Authorization": f'Token token="{self.token}"'}

    def _call(self, method, path, **kw):
        r = self.http.request(method, f"{self.base}{path}", headers={**self._auth_header(), **kw.pop("headers", {})},
                              timeout=60, **kw)
        return r

    def load_policy(self, policy_yaml, policy_id=CONJUR_ROOT_POLICY, mode="PATCH"):
        # PATCH adds new objects and updates annotations, and never deletes what the YAML doesn't mention
        r = self._call(mode, f"/policies/{self.acct}/policy/{quote(policy_id, safe='')}",
                       data=policy_yaml.encode(), headers={"Content-Type": "text/yaml"})
        if r.status_code >= 300:
            raise ConjurError(f"policy load failed: HTTP {r.status_code} {r.text[:400]}")
        return r.json() if r.content else {}

    def whoami(self):
        r = self._call("GET", "/whoami")
        if r.status_code >= 300:
            raise ConjurError(f"whoami failed: HTTP {r.status_code} {r.text[:200]}")
        return r.json()

    def list_variables(self):
        out, offset = [], 0
        while True:
            r = self._call("GET", f"/resources/{self.acct}?kind=variable&limit=100&offset={offset}")
            if r.status_code >= 300:
                raise ConjurError(f"listing variables failed: HTTP {r.status_code} {r.text[:200]}")
            page = r.json()
            out.extend(page)
            if len(page) < 100:
                return out
            offset += 100

    def get_secret(self, var_id):
        r = self._call("GET", f"/secrets/{self.acct}/variable/{quote(var_id, safe='')}")
        if r.status_code == 404:
            return None   # variable has no value yet
        if r.status_code >= 300:
            raise ConjurError(f"read of {var_id} failed: HTTP {r.status_code} {r.text[:200]}")
        return r.content.decode()

    def set_secret(self, var_id, value):
        r = self._call("POST", f"/secrets/{self.acct}/variable/{quote(var_id, safe='')}",
                       data=value.encode(), headers={"Content-Type": "application/octet-stream"})
        if r.status_code >= 300:
            raise ConjurError(f"write of {var_id} failed: HTTP {r.status_code} {r.text[:200]}")


# ---------------------------------------------------------------- what to export

def _sddc_manager_fqdn(lab_spec):
    plan = {e["component"]: e for e in libvcf.get_vcf_plan(lab_spec)}
    if "sddc_manager" not in plan:
        raise ConjurError('lab_spec["vcf"]["components"] has no sddc_manager.')
    return plan["sddc_manager"]["fqdns"]["sddc_manager"]["fqdn"]


def get_sddc_manager_credentials(lab_spec):
    """Every credential SDDC Manager manages, with the password in plaintext."""
    fqdn = _sddc_manager_fqdn(lab_spec)
    vcf_pw = lab_spec["authentication"][lab_spec["vcf"]["use_these_credentials"]]["password"]
    sddc = None
    # administrator@vsphere.local has the ADMIN role in SDDC Manager; admin@local is the break-glass fallback
    for user in (lab_spec["vcf"].get("sddc_manager_api_user"), "administrator@vsphere.local", "admin@local"):
        if not user:
            continue
        try:
            sddc = libvcf._Installer(f"https://{fqdn}", user, vcf_pw)
            liblog.print_logs(f"    SDDC Manager {fqdn}: logged in as {user}.")
            break
        except libvcf.VcfError as e:
            liblog.print_logs(f"    SDDC Manager {fqdn}: login as {user} failed ({str(e)[:150]}).")
    if sddc is None:
        raise ConjurError(f"cannot log in to SDDC Manager {fqdn} with the vcf_components password.")

    creds, page = [], 0
    while True:
        body = sddc.get(f"/v1/credentials?pageNumber={page}&pageSize=100") if page else sddc.get("/v1/credentials")
        elements = body.get("elements", [])
        creds.extend(elements)
        meta = body.get("pageMetadata") or {}
        total = meta.get("totalElements", len(creds))
        if not elements or len(creds) >= total:
            break
        page = (meta.get("pageNumber", page) or 0) + 1
    # De-duplicate (a page restart from 0 would repeat entries)
    seen, out = set(), []
    for c in creds:
        key = c.get("id") or json.dumps(c, sort_keys=True)
        if key not in seen:
            seen.add(key)
            out.append(c)
    masked = [c for c in out if (c.get("password") or "").strip().lower() in MASKED]
    if out and len(masked) == len(out):
        raise ConjurError("SDDC Manager returned the credentials with the passwords masked/empty. The API user needs "
                          "the ADMIN role (try lab_spec vcf.sddc_manager_api_user = administrator@vsphere.local).")
    if masked:
        liblog.print_logs(f"    WARNING: {len(masked)} credential(s) came back without a password; they are skipped.")
    return [c for c in out if c not in masked]


def _clean(s):
    # Conjur IDs: keep them readable but free of whitespace and policy-path surprises
    return re.sub(r"[^A-Za-z0-9@._\-]", "_", str(s or "unknown"))


def _yaml_str(s):
    return json.dumps(str(s))   # JSON strings are valid YAML double-quoted scalars


def build_secret_list(lab_spec, sddc_creds):
    """[(variable_id, value, annotations)] for every secret to store."""
    items = []
    for c in sddc_creds:
        res = c.get("resource") or {}
        rtype = _clean(res.get("resourceType") or c.get("resourceType")).lower()
        rname = _clean(res.get("resourceName") or res.get("resourceIp"))
        vid = f"vcf/{rtype}/{rname}/{_clean(c.get('credentialType')).lower()}/{_clean(c.get('username'))}"
        ann = {"hesiod/source": "sddc-manager",
               "hesiod/username": c.get("username", ""),
               "hesiod/resource-name": res.get("resourceName", ""),
               "hesiod/resource-ip": res.get("resourceIp", ""),
               "hesiod/resource-type": res.get("resourceType", ""),
               "hesiod/domain": res.get("domainName") or ",".join(res.get("domainNames") or []),
               "hesiod/credential-type": c.get("credentialType", ""),
               "hesiod/account-type": c.get("accountType", "")}
        items.append((vid, c["password"], ann))

    used = set()
    for i, a in enumerate(lab_spec.get("authentication", [])):
        if not a.get("password") or a["password"].startswith("<sample"):
            continue
        base = f"lab/{_clean(a.get('system') or f'entry{i}')}"
        vid = base if base not in used else f"{base}-{i}"
        used.add(vid)
        username = a.get("username", "")
        ann = {"hesiod/source": "lab_spec", "hesiod/authentication-index": str(i),
               "hesiod/username": "" if username.startswith("<") else username}
        items.append((vid, a["password"], ann))

    ids = [v for v, _, _ in items]
    dupes = {v for v in ids if ids.count(v) > 1}
    if dupes:
        raise ConjurError(f"two secrets map to the same Conjur id: {sorted(dupes)}")
    return items


def build_policy(items):
    """Conjur policy YAML (loaded under root) declaring every variable with its annotations."""
    by_branch = {}
    for vid, _, ann in items:
        branch, rest = vid.split("/", 1)
        by_branch.setdefault(branch, []).append((rest, ann))
    lines = []
    for branch in sorted(by_branch):
        lines += ["- !policy", f"  id: {branch}", "  body:"]
        for rest, ann in by_branch[branch]:
            lines += ["  - !variable", f"    id: {_yaml_str(rest)}", "    annotations:"]
            lines += [f"      {_yaml_str(k)}: {_yaml_str(v)}" for k, v in ann.items()]
    return "\n".join(lines) + "\n"


def export_passwords(lab_spec, include_vcf=True):
    """Load the policy and write every secret into Conjur. Returns a summary dict."""
    cfg = conjur_settings(lab_spec)
    liblog.print_logs(f"(Export 1) Log in to Conjur {cfg['base_url']} (account {cfg['account']}).")
    cj = ConjurClient(cfg["base_url"], cfg["account"], cfg["username"], password=cfg["password"])

    sddc_creds = []
    if include_vcf:
        liblog.print_logs("(Export 2) Read the VCF credentials from SDDC Manager.")
        sddc_creds = get_sddc_manager_credentials(lab_spec)
        liblog.print_logs(f"    {len(sddc_creds)} credential(s) returned.")
    items = build_secret_list(lab_spec, sddc_creds)

    liblog.print_logs(f"(Export 3) Load policy: {len(items)} variable(s) under vcf/ and lab/.")
    cj.load_policy(build_policy(items))

    liblog.print_logs("(Export 4) Write secrets (only values that changed).")
    written = unchanged = 0
    for vid, value, ann in items:
        current = cj.get_secret(vid)
        if current == value:
            unchanged += 1
            continue
        cj.set_secret(vid, value)
        if cj.get_secret(vid) != value:
            raise ConjurError(f"read-back of {vid} does not match what was written.")
        written += 1
        liblog.print_logs(f"    stored {vid}  (user: {ann.get('hesiod/username') or '-'})")
    liblog.print_logs(f"Password export complete: {written} written, {unchanged} already current, "
                      f"{len(items)} total in account '{cfg['account']}'.")
    return {"written": written, "unchanged": unchanged, "total": len(items), "ids": [v for v, _, _ in items]}


# ---------------------------------------------------------------- evidence report (-m9 --report)

READINESS_VAR = "evidence/vault-readiness-test"


def _served_cert(ip, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    with socket.create_connection((ip, port), timeout=10) as sock:
        with ctx.wrap_socket(sock) as tls:
            der = tls.getpeercert(binary_form=True)
    info = {"sha256": ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())}
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        info["subject"] = cert.subject.rfc4514_string()
        info["not_after"] = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        info["san"] = [str(n.value) for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except Exception:
        pass
    return info


def _ann(var, name):
    return next((a.get("value", "") for a in var.get("annotations", []) if a.get("name") == name), "")


def evidence_report(lab_spec, include_vcf=True, out_dir="conf/evidence"):
    """Readiness check, inventory and coverage of the vault. Never prints or stores a secret value."""
    cfg = conjur_settings(lab_spec)
    now = datetime.datetime.now()
    rep = {"generated": now.strftime("%Y-%m-%d %H:%M:%S"), "conjur": {"url": cfg["base_url"], "fqdn": cfg["fqdn"],
           "account": cfg["account"]}, "checks": []}

    def check(name, ok, detail=""):
        rep["checks"].append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
        liblog.print_logs(f"    {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
        return ok

    # 1. Readiness (US-005)
    liblog.print_logs("(Report 1) Vault readiness.")
    try:
        r = _session().get(f"{cfg['base_url']}/", timeout=15)
        m = re.search(r"version\D{0,100}?(\d+\.\d+\.\d+)", r.text, re.I | re.S)
        rep["conjur"]["version"] = m.group(1) if m else "unknown"
        check("Conjur answers over HTTPS", r.status_code == 200, f"HTTP {r.status_code}, version {rep['conjur']['version']}")
    except requests.RequestException as e:
        check("Conjur answers over HTTPS", False, str(e)[:120])
    try:
        rep["conjur"]["tls"] = _served_cert(cfg["ip"])
        check("TLS certificate served", True, f"{rep['conjur']['tls'].get('subject', '?')}, expires "
                                               f"{rep['conjur']['tls'].get('not_after', '?')}")
    except Exception as e:
        check("TLS certificate served", False, str(e)[:120])
    dns_ip = next((x for x in lab_spec["domain"].get("server_ips", []) if re.fullmatch(r"[0-9.]+", x)), None)
    try:  # ask the lab DNS (Technitium) directly, so the result doesn't depend on hesthe001's resolver
        import dns.resolver
        res = dns.resolver.Resolver(configure=False)
        res.nameservers, res.lifetime = [dns_ip], 5
        resolved = res.resolve(cfg["fqdn"], "A")[0].to_text()
        check("DNS name resolves", resolved == cfg["ip"], f"{cfg['fqdn']} -> {resolved} (via {dns_ip})")
    except Exception as e:
        check("DNS name resolves", False, f"{cfg['fqdn']} via {dns_ip}: {str(e)[:100]}")

    cj = ConjurClient(cfg["base_url"], cfg["account"], cfg["username"], password=cfg["password"])
    who = cj.whoami()
    check("Admin authentication", who.get("account") == cfg["account"],
          f"account {who.get('account')}, user {who.get('username')}")
    marker = f"readiness-{now.strftime('%Y%m%d-%H%M%S')}"
    cj.load_policy("- !policy\n  id: evidence\n  body:\n  - !variable\n    id: vault-readiness-test\n"
                   "    annotations:\n      hesiod/purpose: \"US-005 readiness test (not a real secret)\"\n")
    cj.set_secret(READINESS_VAR, marker)
    check("Write + read-back of a test secret", cj.get_secret(READINESS_VAR) == marker,
          f"{READINESS_VAR} = {marker}")

    # 2. Inventory (no values)
    liblog.print_logs("(Report 2) Inventory.")
    inventory = []
    for v in cj.list_variables():
        vid = v["id"].split(":", 2)[2]
        secrets = v.get("secrets") or []
        inventory.append({"id": vid, "username": _ann(v, "hesiod/username"), "source": _ann(v, "hesiod/source"),
                          "resource_type": _ann(v, "hesiod/resource-type"), "resource_ip": _ann(v, "hesiod/resource-ip"),
                          "credential_type": _ann(v, "hesiod/credential-type"), "versions": len(secrets),
                          "latest_version": secrets[-1]["version"] if secrets else None,
                          "created": v.get("created_at", "")})
    inventory.sort(key=lambda x: x["id"])
    rep["inventory"] = inventory
    vcf_stored = [i for i in inventory if i["id"].startswith("vcf/")]
    check("VCF variables hold a value", bool(vcf_stored) and all(i["versions"] > 0 for i in vcf_stored),
          f"{sum(i['versions'] > 0 for i in vcf_stored)}/{len(vcf_stored)} vcf/ variables have a stored version")

    # 3. Coverage (US-008): what SDDC Manager manages now vs what the vault holds. Compared in memory only.
    liblog.print_logs("(Report 3) Coverage against the source systems.")
    sddc = get_sddc_manager_credentials(lab_spec) if include_vcf else []
    expected = build_secret_list(lab_spec, sddc)
    coverage = []
    for vid, value, ann in expected:
        stored = cj.get_secret(vid)
        coverage.append({"id": vid, "source": ann.get("hesiod/source"), "username": ann.get("hesiod/username", ""),
                         "stored": stored is not None, "matches_source": stored == value})
    rep["coverage"] = coverage
    vcf_cov = [c for c in coverage if c["id"].startswith("vcf/")]
    if include_vcf:
        check("Every SDDC Manager credential is in the vault", all(c["stored"] for c in vcf_cov),
              f"{sum(c['stored'] for c in vcf_cov)}/{len(vcf_cov)} stored")
        check("Vault matches SDDC Manager's current passwords", all(c["matches_source"] for c in vcf_cov),
              f"{sum(c['matches_source'] for c in vcf_cov)}/{len(vcf_cov)} in sync"
              + ("" if all(c["matches_source"] for c in vcf_cov) else "; run -m9 --export"))
    lab_cov = [c for c in coverage if c["id"].startswith("lab/")]
    check("lab_spec credentials are in the vault", all(c["matches_source"] for c in lab_cov),
          f"{sum(c['matches_source'] for c in lab_cov)}/{len(lab_cov)} in sync")

    rep["result"] = "PASS" if all(c["result"] == "PASS" for c in rep["checks"]) else "FAIL"
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"conjur_evidence_{now.strftime('%Y%m%d-%H%M%S')}")
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2)
    with open(base + ".md", "w") as f:
        f.write(_report_markdown(rep))
    liblog.print_logs(f"Evidence report: {rep['result']}  ->  {base}.md  (+ .json)")
    return rep


def _report_markdown(rep):
    c = rep["conjur"]
    tls = c.get("tls", {})
    L = [f"# Password vault evidence: Conjur OSS", "",
         f"Generated {rep['generated']} by Theogony -m9 --report. **Overall: {rep['result']}**. "
         "No secret values appear in this report; coverage compares values in memory only.", "",
         "| | |", "|---|---|",
         f"| Endpoint | {c['url']} ({c['fqdn']}) |", f"| Account | {c['account']} |",
         f"| Conjur version | {c.get('version', 'unknown')} |",
         f"| TLS certificate | {tls.get('subject', '?')}, SAN {', '.join(tls.get('san', [])) or '?'}, "
         f"expires {tls.get('not_after', '?')} |",
         f"| TLS SHA-256 | `{tls.get('sha256', '?')}` |", "",
         "## Checks", "", "| Result | Check | Detail |", "|---|---|---|"]
    L += [f"| {x['result']} | {x['check']} | {x['detail']} |" for x in rep["checks"]]
    L += ["", "## US-005: vault ready to accept secrets", "",
          "Readiness rows above: HTTPS endpoint answering, TLS certificate, DNS, admin authentication, and a test "
          f"secret (`{READINESS_VAR}`, a timestamp, not a real credential) written and read back.", "",
          "## US-008: VCF credentials stored", "",
          "| Variable | Username | Type | Stored | Matches SDDC Manager |", "|---|---|---|---|---|"]
    inv = {i["id"]: i for i in rep["inventory"]}
    for x in rep["coverage"]:
        if x["id"].startswith("vcf/"):
            i = inv.get(x["id"], {})
            L.append(f"| `{x['id']}` | {x['username'] or '-'} | {i.get('credential_type') or '-'} | "
                     f"{'yes (v' + str(i.get('latest_version')) + ')' if x['stored'] else 'NO'} | "
                     f"{'yes' if x['matches_source'] else 'NO'} |")
    L += ["", "## Full inventory", "", "| Variable | Username | Source | Versions | Created |", "|---|---|---|---|---|"]
    L += [f"| `{i['id']}` | {i['username'] or '-'} | {i['source'] or '-'} | {i['versions']} | {i['created'][:19]} |"
          for i in rep["inventory"]]
    return "\n".join(L) + "\n"
