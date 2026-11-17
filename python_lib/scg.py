# Hesiod Security Configuration Guide (SCG) compliance
# Description: Audits the management domain against the VCF 9.1 Security Configuration Guide using Broadcom's own
#              PowerCLI audit scripts (vmware/vcf-security-and-compliance-guidelines), applies the lab's accepted
#              exceptions and manual attestations, and writes the evidence for US-014.
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.0 (audit only; remediation follows once the failure list and exceptions are agreed)
#
# -m13 --setup     install PowerShell + VCF.PowerCLI + VMware.vSphere.SsoAdmin on this appliance, fetch the SCG
# -m13             audit vCenter, every ESX host and every VM (read-only), then the report
# -m13 --report    rebuild the report from the last audit (e.g. after editing json_lib/scg_exceptions.json)
#
# Results per control and object:
#   PASS        the script's check passed
#   EXCEPTED    FAIL/WARNING covered by an entry in json_lib/scg_exceptions.json (with justification)
#   ATTESTED    a control the scripts cannot assess, recorded as manually verified in the same file
#   APPLIANCE   VCF/VMware appliance VMs: Broadcom's support policy does not permit changing them; the script skips them
#   FAIL        needs remediation (or an exception)
#   REVIEW      [WARNING] from the script: needs a human look
# Compliance (TR-007 / US-014) = (PASS + EXCEPTED + ATTESTED + APPLIANCE) / all results.

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import vcf as libvcf

import csv
import datetime
import fnmatch
import glob
import json
import os
import re
import shutil
import subprocess

SCG_REPO = "https://github.com/vmware/vcf-security-and-compliance-guidelines"
SCG_PATH = "security-configuration-hardening-guide/cloud-foundation/9.1"
STATE_DIR = "conf/scg"
PWSH_VERSION = "7.6.10"
PWSH_DIR = "/opt/microsoft/powershell/7"


class ScgError(Exception):
    pass


def scg_settings(lab_spec):
    s = lab_spec.get("scg") or {}
    plan = {e["component"]: e for e in libvcf.get_vcf_plan(lab_spec)}
    return {"version": s.get("version", "910-20260612-01"),
            "exceptions_file": s.get("exceptions_file", "json_lib/scg_exceptions.json"),
            "components": [c.lower() for c in s.get("components", ["esx-9", "vcenter-9", "vm-9", "vsan-9", "nsx-9", "sddc-9"])],
            "vcenter": plan["vcenter"]["fqdns"]["vcenter"]["fqdn"],
            "password": lab_spec["authentication"][lab_spec["vcf"]["use_these_credentials"]]["password"]}


def _run(cmd, timeout=1800, env=None, check=True):
    p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    if check and p.returncode != 0:
        raise ScgError(f"{' '.join(cmd[:3])}... failed (rc={p.returncode}): {(p.stderr or p.stdout).strip()[-600:]}")
    return p


# ---------------------------------------------------------------- tools

def _pwsh():
    return shutil.which("pwsh") or (f"{PWSH_DIR}/pwsh" if os.path.exists(f"{PWSH_DIR}/pwsh") else None)


def setup_tools(lab_spec):
    """PowerShell (GitHub release tarball), VCF.PowerCLI >= 9.0, VMware.vSphere.SsoAdmin >= 1.4, and the SCG itself."""
    cfg = scg_settings(lab_spec)
    pwsh = _pwsh()
    if not pwsh:
        liblog.print_logs(f"(Setup 1) Installing PowerShell {PWSH_VERSION} to {PWSH_DIR}.")
        url = (f"https://github.com/PowerShell/PowerShell/releases/download/v{PWSH_VERSION}/"
               f"powershell-{PWSH_VERSION}-linux-x64.tar.gz")
        os.makedirs(PWSH_DIR, exist_ok=True)
        tgz = "/tmp/hesiod-powershell.tar.gz"
        _run(["curl", "-sSLf", "-o", tgz, url], 600)
        _run(["tar", "-xzf", tgz, "-C", PWSH_DIR])
        os.chmod(f"{PWSH_DIR}/pwsh", 0o755)
        if not os.path.exists("/usr/bin/pwsh"):
            os.symlink(f"{PWSH_DIR}/pwsh", "/usr/bin/pwsh")
        os.remove(tgz)
        pwsh = f"{PWSH_DIR}/pwsh"
    else:
        liblog.print_logs(f"(Setup 1) PowerShell present: {pwsh}")
    ver = _run([pwsh, "-NoProfile", "-c", "$PSVersionTable.PSVersion.ToString()"]).stdout.strip()
    liblog.print_logs(f"    PowerShell {ver}")

    liblog.print_logs("(Setup 2) PowerCLI modules (PowerShell Gallery, all users).")
    script = r'''
$ErrorActionPreference = "Stop"
Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
foreach ($m in @(@{n="VCF.PowerCLI"; v="9.0.0"}, @{n="VMware.vSphere.SsoAdmin"; v="1.4.0"})) {
  $have = Get-Module -ListAvailable -Name $m.n | Where-Object { $_.Version -ge [version]$m.v } | Select-Object -First 1
  if ($have) { Write-Output "present $($m.n) $($have.Version)" }
  else { Install-Module -Name $m.n -MinimumVersion $m.v -Scope AllUsers -Force -AllowClobber; Write-Output "installed $($m.n)" }
}
Set-PowerCLIConfiguration -Scope AllUsers -ParticipateInCEIP $false -Confirm:$false | Out-Null
'''
    out = _run([pwsh, "-NoProfile", "-NonInteractive", "-c", script], 3600).stdout
    for line in out.splitlines():
        if line.startswith(("present", "installed")):
            liblog.print_logs("    " + line)

    fetch_scg(cfg)
    liblog.print_logs("Setup complete.")
    return pwsh


def fetch_scg(cfg):
    """Sparse clone of the 9.1 SCG folder into conf/scg/repo; checks the pinned VERSION."""
    repo = f"{STATE_DIR}/repo"
    if not os.path.isdir(f"{repo}/.git"):
        liblog.print_logs(f"(Setup 3) Fetching the VCF 9.1 SCG from {SCG_REPO}.")
        os.makedirs(STATE_DIR, exist_ok=True)
        _run(["git", "clone", "-q", "--depth", "1", "--filter=blob:none", "--sparse", SCG_REPO, repo], 600)
        _run(["git", "-C", repo, "sparse-checkout", "set", SCG_PATH], 600)
    else:
        liblog.print_logs("(Setup 3) Updating the SCG checkout.")
        _run(["git", "-C", repo, "pull", "-q", "--ff-only"], 600, check=False)
    base = f"{repo}/{SCG_PATH}"
    version = open(f"{base}/VERSION").read().strip()
    if version != cfg["version"]:
        liblog.print_logs(f"    WARNING: SCG version is {version}; lab_spec pins {cfg['version']}. Review the changelog "
                          f"({base}/tools/CHANGELOG.txt), then update scg.version in lab_spec.")
    else:
        liblog.print_logs(f"    SCG version {version} (matches lab_spec).")
    return base, version


def _scg_base():
    base = f"{STATE_DIR}/repo/{SCG_PATH}"
    if not os.path.exists(f"{base}/tools/audit-esx-9.ps1"):
        raise ScgError("the SCG is not fetched yet: run -m13 --setup")
    return base


# ---------------------------------------------------------------- audit

DRIVER = r'''
# Hesiod -m13 driver: connect, then run Broadcom's per-object audit scripts with CSV output (read-only).
param([string]$Tools, [string]$Out)
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -ParticipateInCEIP $false -Confirm:$false | Out-Null
$sec = ConvertTo-SecureString $env:HESIOD_VC_PASSWORD -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:HESIOD_VC_USER, $sec)
Connect-VIServer -Server $env:HESIOD_VC -Credential $cred -ErrorAction Stop | Out-Null
try { Connect-CisServer -Server $env:HESIOD_VC -Credential $cred -ErrorAction Stop | Out-Null } catch { Write-Output "HESIOD-WARN CIS: $_" }
try { Connect-SsoAdminServer -Server $env:HESIOD_VC -Credential $cred -SkipCertificateCheck -ErrorAction Stop | Out-Null } catch { Write-Output "HESIOD-WARN SSO: $_" }
function Safe([string]$n) { $bad = [regex]::Escape(-join [System.IO.Path]::GetInvalidFileNameChars()); return ($n -replace "[$bad]", '_') }
$vms = Get-VM | Sort-Object Name
$hosts = Get-VMHost | Sort-Object Name
Write-Output "HESIOD-INVENTORY vms=$($vms.Count) hosts=$($hosts.Count)"
foreach ($vm in $vms) {
  $f = Join-Path $Out ("vm__" + (Safe "$vm") + ".csv")
  try { & (Join-Path $Tools "audit-vm-9.ps1") -Name "$vm" -AcceptEULA -NoSafetyChecksExceptAppliances -CSVOutputFileName $f -ErrorAction Stop *> $null }
  catch { Write-Output "HESIOD-ERROR vm $vm : $_" }
}
foreach ($h in $hosts) {
  $f = Join-Path $Out ("esx__" + (Safe "$h") + ".csv")
  try { & (Join-Path $Tools "audit-esx-9.ps1") -Name "$h" -AcceptEULA -NoSafetyChecks -CSVOutputFileName $f -ErrorAction Stop *> $null }
  catch { Write-Output "HESIOD-ERROR esx $h : $_" }
}
$vc = $global:DefaultVIServers.Name
$f = Join-Path $Out ("vcenter__" + (Safe "$vc") + ".csv")
try { & (Join-Path $Tools "audit-vcenter-9.ps1") -Name "$vc" -AcceptEULA -NoSafetyChecks -CSVOutputFileName $f -ErrorAction Stop *> $null }
catch { Write-Output "HESIOD-ERROR vcenter $vc : $_" }
Disconnect-VIServer -Server * -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Write-Output "HESIOD-DONE"
'''


def run_audit(lab_spec):
    cfg = scg_settings(lab_spec)
    pwsh = _pwsh()
    if not pwsh:
        raise ScgError("PowerShell is not installed: run -m13 --setup")
    tools = os.path.abspath(f"{_scg_base()}/tools")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = os.path.abspath(f"{STATE_DIR}/runs/{stamp}")
    os.makedirs(out)
    driver = f"{STATE_DIR}/driver.ps1"
    with open(driver, "w") as f:
        f.write(DRIVER)
    liblog.print_logs(f"(Audit) {cfg['vcenter']}: all VMs, all ESX hosts, vCenter (read-only). This takes several minutes.")
    env = {**os.environ, "HESIOD_VC": cfg["vcenter"], "HESIOD_VC_USER": "administrator@vsphere.local",
           "HESIOD_VC_PASSWORD": cfg["password"]}
    p = _run([pwsh, "-NoProfile", "-NonInteractive", "-File", driver, "-Tools", tools, "-Out", out], 7200, env, check=False)
    with open(f"{out}/driver.log", "w") as f:
        f.write(p.stdout + "\n" + p.stderr)
    for line in p.stdout.splitlines():
        if line.startswith("HESIOD-"):
            liblog.print_logs("    " + line.replace("HESIOD-", ""))
    if "HESIOD-DONE" not in p.stdout:
        raise ScgError(f"the audit did not finish (rc={p.returncode}); see {out}/driver.log: {(p.stderr or p.stdout).strip()[-400:]}")
    with open(f"{STATE_DIR}/latest", "w") as f:
        f.write(out)
    liblog.print_logs(f"    Raw results: {out}")
    return out


# ---------------------------------------------------------------- results

def _controls_catalog():
    base = _scg_base()
    path = glob.glob(f"{base}/*controls.csv")
    if not path:
        return {}
    with open(path[0], encoding="utf-8-sig") as f:
        return {r["SCG ID"]: r for r in csv.DictReader(f)}


def _load_exceptions(cfg):
    path = cfg["exceptions_file"]
    if not os.path.exists(path):
        return []
    data = json.load(open(path))
    out = []
    for i, e in enumerate(data.get("entries", [])):
        if not e.get("control") or not e.get("justification"):
            raise ScgError(f"{path} entry {i}: control and justification are required")
        if e.get("expires"):
            if datetime.date.fromisoformat(e["expires"]) < datetime.date.today():
                liblog.print_logs(f"    Exception expired, ignored: {e['control']} ({e['expires']})")
                continue
        out.append({"control": e["control"], "objects": e.get("objects", ["*"]), "type": e.get("type", "exception"),
                    "justification": e["justification"], "approved_by": e.get("approved_by", ""),
                    "expires": e.get("expires", ""), "reference": e.get("reference", "")})
    return out


def _match(exceptions, control, obj, kinds=("exception",)):
    for e in exceptions:
        if e["type"] in kinds and fnmatch.fnmatch(control, e["control"]) and any(fnmatch.fnmatch(obj, o) for o in e["objects"]):
            return e
    return None


_LINE = re.compile(r"^(?P<obj>[^:]+?):\s*(?P<text>.*?)(?:\s*\((?P<value>[^()]*)\))?\s*$")


def parse_run(run_dir):
    """Rows from the per-object CSVs: {kind, object, control, level, text, value}."""
    rows, appliances = [], []
    for path in sorted(glob.glob(f"{run_dir}/*.csv")):
        kind, obj = os.path.basename(path)[:-4].split("__", 1)
        with open(path, encoding="utf-8-sig") as f:
            for r in csv.DictReader(f):
                level, control, msg = r.get("Level", ""), r.get("Control", ""), r.get("Message", "")
                if kind == "vm" and level == "ERROR" and "appliance" in msg.lower():
                    appliances.append(obj)
                if level not in ("PASS", "FAIL", "WARNING") or not control:
                    continue
                m = _LINE.match(msg)
                rows.append({"kind": kind, "object": obj, "control": control, "level": level,
                             "text": (m.group("text") if m else msg)[:200], "value": (m.group("value") or "") if m else ""})
    return rows, sorted(set(appliances))


def evaluate(lab_spec, run_dir=None):
    cfg = scg_settings(lab_spec)
    run_dir = run_dir or (open(f"{STATE_DIR}/latest").read().strip() if os.path.exists(f"{STATE_DIR}/latest") else None)
    if not run_dir or not os.path.isdir(run_dir):
        raise ScgError("no audit run found: run -m13 first")
    rows, appliances = parse_run(run_dir)
    exceptions = _load_exceptions(cfg)
    catalog = _controls_catalog()
    for r in rows:
        r["status"], r["exception"] = {"PASS": "PASS", "FAIL": "FAIL", "WARNING": "REVIEW"}[r["level"]], None
        if r["status"] != "PASS":
            e = _match(exceptions, r["control"], r["object"])
            if e:
                r["status"], r["exception"] = "EXCEPTED", e
    for a in appliances:
        rows.append({"kind": "vm", "object": a, "control": "vm-9.*", "level": "SKIPPED", "status": "APPLIANCE",
                     "text": "VMware/VCF appliance: Broadcom support policy does not permit changes; not audited", "value": "",
                     "exception": None})
    # Controls the scripts never assess, in the components in scope: attested, excepted, or open for manual review
    assessed = {r["control"] for r in rows}
    manual = []
    for cid, c in sorted(catalog.items()):
        prefix = cid.split(".")[0].lower()
        if prefix not in cfg["components"] or cid in assessed:
            continue
        e = _match(exceptions, cid, "*", ("attested", "exception"))
        manual.append({"control": cid, "component": c.get("Component Name", ""), "title": c.get("Description/Title", ""),
                       "priority": c.get("Implementation Priority", ""), "action": c.get("Action Needed", ""),
                       "status": ("ATTESTED" if e and e["type"] == "attested" else "EXCEPTED" if e else "MANUAL"),
                       "exception": e})
    return {"run": run_dir, "rows": rows, "manual": manual, "appliances": appliances, "catalog": catalog,
            "exceptions": exceptions}


def report(lab_spec, run_dir=None, out_dir="conf/evidence"):
    cfg = scg_settings(lab_spec)
    ev = evaluate(lab_spec, run_dir)
    rows, manual, catalog = ev["rows"], ev["manual"], ev["catalog"]
    counts = {}
    for r in rows:
        counts[r["status"]] = counts.get(r["status"], 0) + 1
    good = sum(counts.get(s, 0) for s in ("PASS", "EXCEPTED", "APPLIANCE"))
    total = len(rows)
    pct = round(100.0 * good / total, 1) if total else 0.0
    open_manual = [m for m in manual if m["status"] == "MANUAL"]
    def _unapproved(e):
        return e and (not e["approved_by"].strip() or e["approved_by"].startswith("<"))
    unapproved = sorted({r["exception"]["control"] for r in rows if _unapproved(r.get("exception"))}
                        | {m["exception"]["control"] for m in manual if _unapproved(m.get("exception"))})
    result = "PASS" if counts.get("FAIL", 0) == 0 and counts.get("REVIEW", 0) == 0 and not open_manual and not unapproved else "FAIL"

    liblog.print_logs(f"SCG audit: {pct}% compliant or excepted ({good}/{total} results)  "
                      + "  ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    liblog.print_logs(f"    Controls not assessable by script: {len(manual)} ({len(open_manual)} still open)")
    by_control = {}
    for r in rows:
        if r["status"] in ("FAIL", "REVIEW"):
            by_control.setdefault((r["status"], r["control"]), []).append(r["object"])
    for (st, cid), objs in sorted(by_control.items(), key=lambda x: (x[0][0], -len(x[1]), x[0][1])):
        liblog.print_logs(f"    {st:<6} {cid:<40} {len(objs):>3} object(s)  {catalog.get(cid, {}).get('Description/Title', '')[:60]}")
    if unapproved:
        liblog.print_logs(f"    Exceptions without approval: {', '.join(unapproved)} (set approved_by in {cfg['exceptions_file']})")

    now = datetime.datetime.now()
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"scg_evidence_{now.strftime('%Y%m%d-%H%M%S')}")
    rep = {"generated": now.strftime("%Y-%m-%d %H:%M:%S"), "scg_version": open(f"{_scg_base()}/VERSION").read().strip(),
           "vcenter": cfg["vcenter"], "run": ev["run"], "result": result, "percent": pct, "counts": counts,
           "rows": [{k: v for k, v in r.items() if k != "exception"} | {"exception": (r["exception"] or {}).get("justification")} for r in rows],
           "manual": [{k: v for k, v in m.items() if k != "exception"} | {"exception": (m["exception"] or {}).get("justification")} for m in manual],
           "exceptions": ev["exceptions"]}
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2, default=str)
    with open(base + ".md", "w") as f:
        f.write(_markdown(rep, catalog, by_control, unapproved))
    shutil.copy(base + ".md", f"{ev['run']}/report.md")
    liblog.print_logs(f"Evidence report: {result} ({pct}%)  ->  {base}.md  (+ .json)")
    return rep


def _markdown(rep, catalog, by_control, unapproved):
    c = rep["counts"]
    L = ["# Security Configuration Guide evidence: VCF 9.1 management domain", "",
         f"Generated {rep['generated']} by Theogony -m13 from Broadcom's SCG audit scripts (SCG {rep['scg_version']}) "
         f"against `{rep['vcenter']}`. **Overall: {rep['result']}, {rep['percent']}% compliant or excepted.**", "",
         "| Status | Results | Meaning |", "|---|---|---|",
         f"| PASS | {c.get('PASS', 0)} | the script's check passed |",
         f"| EXCEPTED | {c.get('EXCEPTED', 0)} | failed, covered by an accepted exception (below) |",
         f"| APPLIANCE | {c.get('APPLIANCE', 0)} | VCF/VMware appliance VM; changes not permitted by Broadcom support policy |",
         f"| FAIL | {c.get('FAIL', 0)} | needs remediation or an exception |",
         f"| REVIEW | {c.get('REVIEW', 0)} | script warning; needs a human decision |", ""]
    if by_control:
        L += ["## Open findings", "", "| Status | Control | Priority | Title | Objects |", "|---|---|---|---|---|"]
        for (st, cid), objs in sorted(by_control.items(), key=lambda x: (x[0][0], -len(x[1]), x[0][1])):
            meta = catalog.get(cid, {})
            L.append(f"| {st} | `{cid}` | {meta.get('Implementation Priority', '')} | {meta.get('Description/Title', '')[:90]} | "
                     f"{', '.join(sorted(set(objs)))[:200]} |")
        L.append("")
    used = {}
    for r in rep["rows"]:
        if r["status"] == "EXCEPTED":
            used.setdefault(r["control"], set()).add(r["object"])
    if rep["exceptions"]:
        L += ["## Exceptions and attestations", "", "| Control | Type | Objects | Justification | Approved by | Expires |",
              "|---|---|---|---|---|---|"]
        for e in rep["exceptions"]:
            L.append(f"| `{e['control']}` | {e['type']} | {', '.join(e['objects'])} | {e['justification']} | "
                     f"{e['approved_by'] if e['approved_by'] and not e['approved_by'].startswith('<') else '**not approved**'} | {e['expires'] or '-'} |")
        L.append("")
    m = rep["manual"]
    if m:
        L += [f"## Controls the scripts cannot assess ({len(m)})", "",
              "| Control | Component | Priority | Status | Title |", "|---|---|---|---|---|"]
        L += [f"| `{x['control']}` | {x['component']} | {x['priority']} | {x['status']} | {x['title'][:90]} |"
              for x in sorted(m, key=lambda x: (x["status"] != "MANUAL", x["control"]))]
        L.append("")
    objs = {}
    for r in rep["rows"]:
        o = objs.setdefault((r["kind"], r["object"]), {})
        o[r["status"]] = o.get(r["status"], 0) + 1
    L += ["## Per object", "", "| Type | Object | PASS | EXCEPTED | FAIL | REVIEW | APPLIANCE |", "|---|---|---|---|---|---|---|"]
    L += [f"| {k} | {n} | {v.get('PASS', 0)} | {v.get('EXCEPTED', 0)} | {v.get('FAIL', 0)} | {v.get('REVIEW', 0)} | {v.get('APPLIANCE', 0)} |"
          for (k, n), v in sorted(objs.items())]
    L += ["", f"Raw per-object CSVs: `{rep['run']}`"]
    return "\n".join(L) + "\n"
