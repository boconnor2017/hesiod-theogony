# Hesiod Security Configuration Guide (SCG) compliance
# Description: Audits the management domain against the VCF 9.1 Security Configuration Guide using Broadcom's own
#              PowerCLI audit scripts (vmware/vcf-security-and-compliance-guidelines), applies the lab's accepted
#              exceptions and manual attestations, and writes the evidence for US-014.
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.5 (appliance_vms in scg.json; SSO admin on PowerCLI 9 via SsoAdmin's own dependencies; Theogony fixes for
#              settings the scripts can't create)
#
# -m13 --setup     install PowerShell + VCF.PowerCLI + VMware.vSphere.SsoAdmin on this appliance, fetch the SCG
# -m13             audit vCenter, every ESX host and every VM (read-only), then the report
# -m13 --report    rebuild the report from the last audit (e.g. after editing json_lib/scg.json)
# -m13 --remediate [--defcon N] [--dry-run] [--controls a,b]
#                  fix the failing controls graded DEFCON N or safer (default: "defcon" in json_lib/scg.json, 5 = safest
#                  only, 1 = everything), with Broadcom's remediation scripts limited to those controls, then audit again.
#                  VMs are only touched when listed in scg.json remediate_vms (VCF appliances never: Broadcom's notes
#                  check plus scg.json appliance_vms).
# Configuration: json_lib/scg.json (SCG version, default DEFCON, control grades, exceptions/attestations).
#
# Results per control and object:
#   PASS        the script's check passed
#   EXCEPTED    FAIL/WARNING covered by an entry in json_lib/scg.json (with justification)
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
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import zipfile

SCG_REPO = "https://github.com/vmware/vcf-security-and-compliance-guidelines"
SCG_PATH = "security-configuration-hardening-guide/cloud-foundation/9.1"
STATE_DIR = "conf/scg"
PWSH_VERSION = "7.6.10"
PWSH_DIR = "/opt/microsoft/powershell/7"

# VMware.vSphere.SsoAdmin 1.4.0 is built against PowerCLI 12's VMware.VimAutomation.Common and loads these from it.
# VCF.PowerCLI 9 no longer ships them, so Connect-SsoAdminServer fails with "Could not load file or assembly
# 'VMware.System.Private.ServiceModel, Version=4.4.4.0'". --setup fetches the exact packages from the SsoAdmin source
# tree (pinned commit, SHA-256 checked) and the PowerShell driver resolves them from SSO_DEPS_DIR.
SSO_DEPS_DIR = f"{STATE_DIR}/ssoadmin-deps"
SSO_DEPS_URL = ("https://raw.githubusercontent.com/vmware/PowerCLI-Example-Scripts/097172029b710036232f3937dd7c04bbb6a760ad/"
                "Modules/VMware.vSphere.SsoAdmin/src/VMware.vSphere.SsoAdmin.Client/packages/")
SSO_DEPS = [  # (package, sha256, dll inside the package)
    ("VMware.System.Private.ServiceModel.4.4.4.nupkg", "d6bc8f12f94ee6ae6c4a52697b6a344f72762ae4ab9e5e262c2a722b3e9b8ff9",
     "lib/netcoreapp2.0/VMware.System.Private.ServiceModel.dll"),
    ("VMware.Binding.Sts.12.0.0.15939652.nupkg", "e3305b573fb847344c18fbab9518d8f9a887421e091899d1a3d7c0f004c94e79",
     "lib/netcoreapp2.0/VMware.Binding.Sts.dll"),
    ("VMware.Binding.WsTrust.12.0.0.15939652.nupkg", "78c727f3d2753146578406aff3a4febcd7868584484ebf3e8c26c679d107ab58",
     "lib/netcoreapp2.0/VMware.Binding.WsTrust.dll"),
    ("VMware.Http.Handlers.12.0.0.15939652.nupkg", "12de27357b127b2b362b44404044d1085e3ccd4726ebbd7a9a7f912ae98078a0",
     "lib/netstandard2.0/VMware.Http.Handlers.dll"),
    ("VMware.Util.Sspi.12.0.0.15939652.nupkg", "d716f489652074a9876e5c854f7bd331d241aff818c5afaad3bf7a4731e84055",
     "lib/netstandard2.0/VMware.Util.Sspi.dll"),
]


class ScgError(Exception):
    pass


CONFIG_FILE = "json_lib/scg.json"


def scg_settings(lab_spec):
    """json_lib/scg.json (static config: SCG version, default DEFCON, control grades, exceptions) + vCenter from lab_spec.
    lab_spec["scg"]["config_file"] can point at another copy (e.g. one in conf/ with lab-specific approvals)."""
    path = (lab_spec.get("scg") or {}).get("config_file", CONFIG_FILE)
    try:
        s = json.load(open(path))
    except FileNotFoundError:
        raise ScgError(f"{path} not found (the SCG configuration for -m13)")
    except ValueError as e:
        raise ScgError(f"{path} is not valid JSON: {e}")
    defcon = int(s.get("defcon", 5))
    if defcon not in (1, 2, 3, 4, 5):
        raise ScgError(f"{path}: defcon must be 1-5")
    plan = {e["component"]: e for e in libvcf.get_vcf_plan(lab_spec)}
    return {"config_file": path, "version": s.get("scg_version", "910-20260612-01"), "defcon": defcon,
            "components": [c.lower() for c in s.get("components", ["esx-9", "vcenter-9", "vm-9", "vsan-9", "nsx-9", "sddc-9"])],
            "controls": s.get("controls", {}), "exceptions": s.get("exceptions", []),
            "remediate_vms": [v for v in s.get("remediate_vms", []) if not str(v).startswith("<")],
            "appliance_vms": [v for v in s.get("appliance_vms", []) if not str(v).startswith("<")],
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

    sso_dependencies()
    trust_lab_root()
    fetch_scg(cfg)
    liblog.print_logs("Setup complete.")
    return pwsh


def sso_dependencies(quiet=False):
    """The five .NET assemblies SsoAdmin 1.4.0 needs that VCF.PowerCLI 9 does not ship (see SSO_DEPS)."""
    want = [os.path.join(SSO_DEPS_DIR, os.path.basename(inner)) for _, _, inner in SSO_DEPS]
    if all(os.path.exists(f) for f in want):
        if not quiet:
            liblog.print_logs(f"(Setup 2b) SsoAdmin dependencies present ({SSO_DEPS_DIR}).")
        return True
    liblog.print_logs("(Setup 2b) Fetching SsoAdmin's .NET dependencies (VMware.System.Private.ServiceModel 4.4.4, "
                      "VMware.Binding.Sts/WsTrust 12.0) from the SsoAdmin source tree.")
    os.makedirs(SSO_DEPS_DIR, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        for pkg, sha, inner in SSO_DEPS:
            path = os.path.join(tmp, pkg)
            _run(["curl", "-sSLf", "-o", path, SSO_DEPS_URL + pkg], 300)
            got = hashlib.sha256(open(path, "rb").read()).hexdigest()
            if got != sha:
                raise ScgError(f"{pkg}: SHA-256 mismatch ({got}); not using it")
            with zipfile.ZipFile(path) as z, open(os.path.join(SSO_DEPS_DIR, os.path.basename(inner)), "wb") as f:
                f.write(z.read(inner))
    liblog.print_logs(f"    {len(SSO_DEPS)} assemblies in {SSO_DEPS_DIR} (SHA-256 verified).")
    return True


def trust_lab_root():
    """Add the lab root CA (Module 10) to this appliance's trust store, so PowerCLI's SSO admin connection can validate
    vCenter's certificate (its -SkipCertificateCheck does not work on Linux)."""
    src, dst = "conf/ca/root_ca.crt", "/usr/local/share/ca-certificates/hesiod-lab-root-ca.crt"
    if not os.path.exists(src):
        liblog.print_logs("(Setup) WARNING: conf/ca/root_ca.crt missing (Module 10); SSO policy checks may not run.")
        return False
    if os.path.exists(dst) and open(dst).read() == open(src).read():
        liblog.print_logs("(Setup) Lab root CA already trusted by this appliance.")
        return False
    shutil.copy(src, dst)
    _run(["update-ca-certificates"], 120)
    liblog.print_logs(f"(Setup) Lab root CA added to this appliance's trust store ({dst}).")
    return True


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

CONNECT = r'''
param([string]$Tools, [string]$Out, [string]$Jobs)
$ErrorActionPreference = "Continue"
$ProgressPreference = "SilentlyContinue"
# SsoAdmin 1.4.0 needs VMware.System.Private.ServiceModel 4.4.4 and VMware.Binding.Sts/WsTrust 12.0, which VCF.PowerCLI 9
# no longer ships. Resolve them from the copies -m13 --setup put in conf/scg/ssoadmin-deps (only when .NET can't find them).
$deps = $env:HESIOD_SSO_DEPS
if ($deps -and (Test-Path $deps)) {
  try {
    Add-Type -TypeDefinition @"
using System; using System.IO; using System.Reflection;
public static class HesiodSsoResolver {
  static string dir;
  public static void Register(string d) { dir = d; AppDomain.CurrentDomain.AssemblyResolve += Resolve; }
  static Assembly Resolve(object s, ResolveEventArgs e) {
    var f = Path.Combine(dir, new AssemblyName(e.Name).Name + ".dll");
    if (!File.Exists(f)) return null;
    foreach (var a in AppDomain.CurrentDomain.GetAssemblies()) { try { if (a.Location == f) return a; } catch {} }
    return Assembly.LoadFrom(f);
  }
}
"@
    [HesiodSsoResolver]::Register($deps)
  } catch { Write-Output "HESIOD-WARN SsoAdmin dependency resolver: $_" }
} else { Write-Output "HESIOD-WARN SsoAdmin dependencies missing ($deps): run -m13 --setup" }
try { Import-Module VMware.vSphere.SsoAdmin -ErrorAction Stop } catch { Write-Output "HESIOD-WARN SsoAdmin import: $_" }
Set-PowerCLIConfiguration -Scope Session -InvalidCertificateAction Ignore -ParticipateInCEIP $false -Confirm:$false | Out-Null
$sec = ConvertTo-SecureString $env:HESIOD_VC_PASSWORD -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential($env:HESIOD_VC_USER, $sec)
Connect-VIServer -Server $env:HESIOD_VC -Credential $cred -ErrorAction Stop | Out-Null
try { Connect-CisServer -Server $env:HESIOD_VC -Credential $cred -ErrorAction Stop | Out-Null } catch { Write-Output "HESIOD-WARN CIS: $_" }
# Normal TLS validation first (-m13 --setup puts the lab root CA from Module 10 in this appliance's trust store),
# then -SkipCertificateCheck.
$sso = $false
try { Connect-SsoAdminServer -Server $env:HESIOD_VC -Credential $cred -ErrorAction Stop | Out-Null; $sso = $true } catch { Write-Output "HESIOD-WARN SSO (validated TLS): $_" }
if (-not $sso) { try { Connect-SsoAdminServer -Server $env:HESIOD_VC -Credential $cred -SkipCertificateCheck -ErrorAction Stop | Out-Null; $sso = $true } catch { Write-Output "HESIOD-WARN SSO: $_" } }
Write-Output "HESIOD-SSO connected=$sso"
function Safe([string]$n) { $bad = [regex]::Escape(-join [System.IO.Path]::GetInvalidFileNameChars()); return ($n -replace "[$bad]", '_') }
'''

DRIVER = CONNECT + r'''
# Audit: Broadcom's per-object audit scripts with CSV output (read-only)
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

REMEDIATE_DRIVER = CONNECT + r'''
# Remediation: Broadcom's remediation scripts, one job per object, limited to the selected controls (-Controls)
# (not $jobs: PowerShell names are case-insensitive and $Jobs is a [string] parameter, which would flatten the list)
$jobList = Get-Content $Jobs -Raw | ConvertFrom-Json
foreach ($j in $jobList) {
  $f = Join-Path $Out ($j.kind + "__" + (Safe $j.name) + ".csv")
  $a = @{ AcceptEULA = $true; Controls = [string[]]$j.controls; CSVOutputFileName = $f; ErrorAction = "Stop" }
  if ($j.kind -ne "vcenter") { $a.Name = $j.name } else { $a.Name = $global:DefaultVIServers.Name }
  if ($j.kind -eq "vm") { $a.NoSafetyChecksExceptAppliances = $true } else { $a.NoSafetyChecks = $true }
  foreach ($sw in $j.switches) { $a[$sw] = $true }
  Write-Output ("HESIOD-JOB " + $j.kind + " " + $j.name + ": " + ($j.controls -join ",") + $(if ($j.switches) { " [" + ($j.switches -join ",") + "]" } else { "" }))
  try { & (Join-Path $Tools $j.script) @a *> $null } catch { Write-Output "HESIOD-ERROR $($j.kind) $($j.name) : $_" }
}
Disconnect-VIServer -Server * -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
Write-Output "HESIOD-DONE"
'''


def _sso_warning(stdout):
    if "HESIOD-SSO connected=False" in stdout:
        liblog.print_logs("    WARNING: no SSO admin connection: the vCenter SSO password/lockout controls cannot be read "
                          "(they report FAIL) or changed. See the SSO lines below.")


def _env(cfg):
    return {**os.environ, "HESIOD_VC": cfg["vcenter"], "HESIOD_VC_USER": "administrator@vsphere.local",
            "HESIOD_VC_PASSWORD": cfg["password"], "HESIOD_SSO_DEPS": os.path.abspath(SSO_DEPS_DIR)}


def run_audit(lab_spec):
    cfg = scg_settings(lab_spec)
    pwsh = _pwsh()
    if not pwsh:
        raise ScgError("PowerShell is not installed: run -m13 --setup")
    tools = os.path.abspath(f"{_scg_base()}/tools")
    try:
        sso_dependencies(quiet=True)
    except Exception as e:  # the audit still runs; only the SSO controls need these
        liblog.print_logs(f"    WARNING: SsoAdmin dependencies not available ({e}); SSO controls will report FAIL.")
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = os.path.abspath(f"{STATE_DIR}/runs/{stamp}")
    os.makedirs(out)
    driver = f"{STATE_DIR}/driver.ps1"
    with open(driver, "w") as f:
        f.write(DRIVER)
    liblog.print_logs(f"(Audit) {cfg['vcenter']}: all VMs, all ESX hosts, vCenter (read-only). This takes several minutes.")
    previous = open(f"{STATE_DIR}/latest").read().strip() if os.path.exists(f"{STATE_DIR}/latest") else ""
    p = _run([pwsh, "-NoProfile", "-NonInteractive", "-File", driver, "-Tools", tools, "-Out", out], 7200, _env(cfg), check=False)
    with open(f"{out}/driver.log", "w") as f:
        f.write(p.stdout + "\n" + p.stderr)
    _sso_warning(p.stdout)
    for line in p.stdout.splitlines():
        if line.startswith("HESIOD-"):
            liblog.print_logs("    " + line.replace("HESIOD-", ""))
    if "HESIOD-DONE" not in p.stdout:
        raise ScgError(f"the audit did not finish (rc={p.returncode}); see {out}/driver.log: {(p.stderr or p.stdout).strip()[-400:]}")
    with open(f"{STATE_DIR}/latest", "w") as f:
        f.write(out)
    if previous:
        with open(f"{out}/previous", "w") as f:
            f.write(previous)
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
    out = []
    for i, e in enumerate(cfg["exceptions"]):
        if not e.get("control") or not e.get("justification"):
            raise ScgError(f"{cfg['config_file']} exceptions[{i}]: control and justification are required")
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
    # VCF appliances Broadcom's check misses (it only looks for "VMware" in the VM notes): scg.json appliance_vms.
    # Same treatment as the ones it finds: one APPLIANCE result per VM, never remediated.
    listed = sorted({r["object"] for r in rows if r["kind"] == "vm"
                     and any(fnmatch.fnmatch(r["object"], p) for p in cfg["appliance_vms"])})
    rows = [r for r in rows if not (r["kind"] == "vm" and r["object"] in listed)]
    appliances = sorted(set(appliances) | set(listed))
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

    delta = _delta(ev)
    if delta:
        liblog.print_logs(f"    Since the previous audit: {len(delta['fixed'])} result(s) fixed, {len(delta['regressed'])} regressed.")
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
        liblog.print_logs(f"    Exceptions without approval: {', '.join(unapproved)} (set approved_by in {cfg['config_file']} exceptions)")

    now = datetime.datetime.now()
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"scg_evidence_{now.strftime('%Y%m%d-%H%M%S')}")
    rep = {"generated": now.strftime("%Y-%m-%d %H:%M:%S"), "scg_version": open(f"{_scg_base()}/VERSION").read().strip(),
           "vcenter": cfg["vcenter"], "run": ev["run"], "result": result, "percent": pct, "counts": counts,
           "rows": [{k: v for k, v in r.items() if k != "exception"} | {"exception": (r["exception"] or {}).get("justification")} for r in rows],
           "manual": [{k: v for k, v in m.items() if k != "exception"} | {"exception": (m["exception"] or {}).get("justification")} for m in manual],
           "exceptions": ev["exceptions"], "delta": delta}
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2, default=str)
    with open(base + ".md", "w") as f:
        f.write(_markdown(rep, catalog, by_control, unapproved))
    shutil.copy(base + ".md", f"{ev['run']}/report.md")
    liblog.print_logs(f"Evidence report: {result} ({pct}%)  ->  {base}.md  (+ .json)")
    return rep


def _delta(ev):
    prev_file = f"{ev['run']}/previous"
    if not os.path.exists(prev_file):
        return None
    prev_dir = open(prev_file).read().strip()
    if not os.path.isdir(prev_dir):
        return None
    before = {(r["object"], r["control"]): r["level"] for r in parse_run(prev_dir)[0]}
    after = {(r["object"], r["control"]): r["level"] for r in parse_run(ev["run"])[0]}
    fixed = sorted(f"{c} on {o}" for (o, c), lv in after.items() if lv == "PASS" and before.get((o, c)) in ("FAIL", "WARNING"))
    regressed = sorted(f"{c} on {o}" for (o, c), lv in after.items() if lv == "FAIL" and before.get((o, c)) == "PASS")
    return {"previous_run": prev_dir, "fixed": fixed, "regressed": regressed}


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
    if rep.get("delta"):
        d = rep["delta"]
        L += ["", "## Since the previous audit", "", f"Previous run `{d['previous_run']}`: {len(d['fixed'])} result(s) fixed, "
              f"{len(d['regressed'])} regressed.", ""]
        L += [f"- fixed: `{x}`" for x in d["fixed"][:200]] + [f"- **regressed**: `{x}`" for x in d["regressed"]]
    L += ["", f"Raw per-object CSVs: `{rep['run']}`"]
    return "\n".join(L) + "\n"


# ---------------------------------------------------------------- remediation (-m13 --remediate --defcon N)

GUARD_TEXT = re.compile(r"production environment|operational issues|host reboots|remove or comment|accept any and all risk|"
                        r"may pose to your environment")   # Broadcom's standing warning lines, logged on every run
SCRIPT_FOR = {"esx": "remediate-esx-9.ps1", "vcenter": "remediate-vcenter-9.ps1", "vm": "remediate-vm-9.ps1"}
VM_SWITCHES = {"vm-9.remove-unnecessary-devices": "RemoveExtraDevices", "vm-9.virtual-hardware": "UpdateHardwareVersion"}


def _defcon_map(cfg):
    return cfg["controls"]


def _level(dmap, control):
    if control in dmap:
        return dmap[control]
    for k, v in dmap.items():
        if "*" in k and fnmatch.fnmatch(control, k):
            return v
    return None


def plan_remediation(lab_spec, defcon, only=None):
    """Failing (not excepted) results from the last audit, graded DEFCON >= defcon, grouped into per-object jobs."""
    cfg = scg_settings(lab_spec)
    ev = evaluate(lab_spec)
    dmap = _defcon_map(cfg)
    jobs, python_actions, manual, skipped = {}, set(), {}, {}
    for r in ev["rows"]:
        if r["status"] not in ("FAIL", "REVIEW") or (only and r["control"] not in only):
            continue
        d = _level(dmap, r["control"])
        if d is None:
            skipped.setdefault(f"not graded in {cfg['config_file']} controls", set()).add(r["control"])
            continue
        if d["level"] < defcon:
            skipped.setdefault(f"DEFCON {d['level']} (run with --defcon {d['level']} to include)", set()).add(r["control"])
            continue
        if d["via"] == "manual":
            manual.setdefault(r["control"], set()).add(r["object"])
            continue
        if d["via"] == "python":
            python_actions.add(r["control"])
            continue
        if r["kind"] == "vm" and (not any(fnmatch.fnmatch(r["object"], p) for p in cfg["remediate_vms"])
                                  or any(fnmatch.fnmatch(r["object"], p) for p in cfg["appliance_vms"])):
            skipped.setdefault(f"VM not in {cfg['config_file']} remediate_vms", set()).add(f"{r['control']} on {r['object']}")
            continue
        j = jobs.setdefault((r["kind"], r["object"]), {"kind": r["kind"], "name": r["object"],
                                                      "script": SCRIPT_FOR[r["kind"]], "controls": [], "switches": []})
        if r["control"] not in j["controls"]:
            j["controls"].append(r["control"])
        sw = d.get("switch") or (VM_SWITCHES.get(r["control"]) if r["kind"] == "vm" else None)
        if sw and sw not in j["switches"]:
            j["switches"].append(sw)
    for j in jobs.values():
        if j["kind"] == "vm":
            j["switches"].append("TakeSnapshot")
        j["controls"].sort()
    return {"jobs": sorted(jobs.values(), key=lambda j: ({"esx": 0, "vcenter": 1, "vm": 2}[j["kind"]], j["name"])),
            "python": sorted(python_actions), "manual": manual, "skipped": skipped, "dmap": dmap}


def _patched_tools():
    """Working copy of Broadcom's tools with the deliberate 'Exit' guard removed from the remediation scripts
    (their README asks for exactly that); everything else, including the opt-in switches, is unchanged."""
    src = f"{_scg_base()}/tools"
    dst = os.path.abspath(f"{STATE_DIR}/remediate-tools")
    shutil.rmtree(dst, ignore_errors=True)
    shutil.copytree(src, dst)
    guard = re.compile(r'(Log-Message "script and these commands may pose to your environment\." -Level "ERROR"\r?\n)Exit\r?\n')
    for name in SCRIPT_FOR.values():
        path = f"{dst}/{name}"
        text = open(path, encoding="utf-8-sig").read()
        new, n = guard.subn(r"\1# Exit  (guard removed by Theogony -m13 --remediate: scope limited with -Controls)\n", text)
        if n != 1:
            raise ScgError(f"{name}: the remediation guard was not found exactly once; the SCG scripts changed, review them first")
        with open(path, "w", encoding="utf-8") as f:
            f.write(new)
    return dst


def _vsan_rebalance(lab_spec):
    from python_lib import kms as libkms       # vCenter + vSAN API helpers (Module 12)
    from pyVmomi import vim
    si = libkms._vc_connect(lab_spec)
    try:
        cluster = libkms._cluster(si, {**lab_spec, "key_management": lab_spec.get("key_management") or {"ip_address": "-"}})
        vccs = libkms._vsan_config_system(si, libkms._names(lab_spec)["vcenter"])
        spec = vim.vsan.ReconfigSpec(modify=True, extendedConfig=vim.vsan.VsanExtendedConfig(
            proactiveRebalanceInfo=vim.vsan.ProactiveRebalanceInfo(enabled=True, threshold=30)))
        task = vccs.ReconfigureEx(cluster, spec)
        libkms._wait(vim.Task(task._moId, si._stub), "vSAN automatic rebalance", 1800)
        liblog.print_logs(f"    vsan-9.automatic-rebalance: enabled on {cluster.name} (threshold 30%).")
    finally:
        from pyVim.connect import Disconnect
        Disconnect(si)


def _vc_option(si, key, value):
    """Set (or create) a vCenter advanced setting. Broadcom's script pipes Get-AdvancedSetting into Set-AdvancedSetting,
    which silently does nothing when the key does not exist yet, but still logs UPDATE."""
    from pyVmomi import vim
    om = si.content.setting
    try:
        current = om.QueryView(key)[0].value
    except vim.fault.InvalidName:
        current = None
    if current is not None and str(current) == str(value):
        return f"already {current}"
    om.UpdateValues([vim.option.OptionValue(key=key, value=str(value))])
    return f"{'missing' if current is None else current} -> {value}"


def _vpxuser_length(lab_spec, si):
    liblog.print_logs(f"    vcenter-9.vpxuser-length: config.vpxd.hostPasswordLength "
                      f"{_vc_option(si, 'config.vpxd.hostPasswordLength', 32)}.")


def _esx_option_all_hosts(si, control, key, value):
    """Set an ESX advanced setting on every host, keeping the option's own type. ESX cannot create options, so a
    host without the key is reported (attest it in json_lib/scg.json if it does not apply)."""
    from pyVmomi import vim, VmomiSupport
    view = si.content.viewManager.CreateContainerView(si.content.rootFolder, [vim.HostSystem], True)
    try:
        hosts = sorted(view.view, key=lambda h: h.name)
    finally:
        view.Destroy()
    for h in hosts:
        om = h.configManager.advancedOption
        try:
            cur = om.QueryView(key)[0].value
        except vim.fault.InvalidName:
            liblog.print_logs(f"    {control}: {h.name}: {key} does not exist on this host; not changed.")
            continue
        if cur == value:
            liblog.print_logs(f"    {control}: {h.name}: {key} already {cur}.")
            continue
        typed = VmomiSupport.long(value) if isinstance(cur, int) and not isinstance(cur, bool) else type(cur)(value)
        om.UpdateOptions([vim.option.OptionValue(key=key, value=typed)])
        liblog.print_logs(f"    {control}: {h.name}: {key} {cur} -> {value}.")


def _esx_memory_tiering_encryption(lab_spec, si):
    _esx_option_all_hosts(si, "esx-9.memory-tiering-encryption", "Mem.EncryptTierNvme", 1)


def _vsan_rebalance_fix(lab_spec, si):
    _vsan_rebalance(lab_spec)


# Controls Theogony fixes itself ("via": "python" in json_lib/scg.json)
PYTHON_FIXES = {
    "vsan-9.automatic-rebalance": _vsan_rebalance_fix,
    "vcenter-9.vpxuser-length": _vpxuser_length,
    "esx-9.memory-tiering-encryption": _esx_memory_tiering_encryption,
}


def _python_fixes(lab_spec, controls):
    from python_lib import kms as libkms
    from pyVim.connect import Disconnect
    si = libkms._vc_connect(lab_spec)
    try:
        for c in controls:
            fix = PYTHON_FIXES.get(c)
            if not fix:
                liblog.print_logs(f"    {c}: graded via python in json_lib/scg.json, but Theogony has no fix for it.")
                continue
            try:
                fix(lab_spec, si)
            except Exception as e:
                liblog.print_logs(f"    {c}: not changed: {e}")
    finally:
        Disconnect(si)


def remediate(lab_spec, defcon=None, dry_run=False, only=None):
    cfg = scg_settings(lab_spec)
    defcon = cfg["defcon"] if defcon is None else defcon
    if defcon not in (1, 2, 3, 4, 5):
        raise ScgError("--defcon must be 1-5 (5 = safest controls only, 1 = everything)")
    plan = plan_remediation(lab_spec, defcon, only)
    names = {5: "DEFCON 5 (settings and policies)", 4: "DEFCON 4 (service/feature state)", 3: "DEFCON 3 (power cycles, switch security)",
             2: "DEFCON 2 (lock-out risk)", 1: "DEFCON 1 (reboots, TLS cut-over)"}
    liblog.print_logs(f"(Remediate) Scope: {' + '.join(names[l] for l in range(5, defcon - 1, -1))}"
                      f"{'' if defcon != cfg['defcon'] else ' (default from ' + cfg['config_file'] + ')'}.")
    for j in plan["jobs"]:
        lv = sorted({_level(plan["dmap"], c)["level"] for c in j["controls"]})
        liblog.print_logs(f"    {j['kind']:<7} {j['name']:<34} {len(j['controls']):>2} control(s), DEFCON {','.join(map(str, lv))}"
                          + (f"  [{', '.join(j['switches'])}]" if j["switches"] else ""))
    for c in plan["python"]:
        liblog.print_logs(f"    theogony {c}")
    for c, objs in sorted(plan["manual"].items()):
        liblog.print_logs(f"    manual  {c} ({len(objs)} object(s)): {_level(plan['dmap'], c).get('note', '')}")
    for why, items in sorted(plan["skipped"].items()):
        liblog.print_logs(f"    skipped, {why}: {', '.join(sorted(items))}")
    if dry_run or (not plan["jobs"] and not plan["python"]):
        liblog.print_logs("Dry run: nothing changed." if dry_run else "Nothing to remediate at this DEFCON level.")
        return plan

    updated, failed = {}, {}
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = os.path.abspath(f"{STATE_DIR}/remediations/{stamp}")
    os.makedirs(out)
    with open(f"{out}/jobs.json", "w") as f:
        json.dump(plan["jobs"], f, indent=2)
    if plan["jobs"]:
        tools = _patched_tools()
        driver = f"{STATE_DIR}/remediate.ps1"
        with open(driver, "w") as f:
            f.write(REMEDIATE_DRIVER)
        liblog.print_logs(f"(Remediate) Running {len(plan['jobs'])} job(s) with Broadcom's remediation scripts.")
        p = _run([_pwsh(), "-NoProfile", "-NonInteractive", "-File", driver, "-Tools", tools, "-Out", out,
                  "-Jobs", f"{out}/jobs.json"], 14400, _env(cfg), check=False)
        with open(f"{out}/driver.log", "w") as f:
            f.write(p.stdout + "\n" + p.stderr)
        _sso_warning(p.stdout)
        for line in p.stdout.splitlines():
            if line.startswith(("HESIOD-ERROR", "HESIOD-WARN", "HESIOD-SSO")):
                liblog.print_logs("    " + line.replace("HESIOD-", ""))
        for path in glob.glob(f"{out}/*.csv"):
            obj = os.path.basename(path)[:-4].split("__", 1)[1]
            with open(path, encoding="utf-8-sig") as f:
                for r in csv.DictReader(f):
                    if r.get("Level") == "UPDATE":
                        updated.setdefault(obj, set()).add(r.get("Control"))
                    elif r.get("Level") in ("FAIL", "ERROR") and not GUARD_TEXT.search(r.get("Message", "")):
                        failed.setdefault(obj, []).append(f"{r.get('Control') or '-'}: {r.get('Message', '')[:120]}")
        for obj in sorted(set(updated) | set(failed)):
            liblog.print_logs(f"    {obj}: {len(updated.get(obj, []))} control(s) updated"
                              + (f", {len(failed[obj])} not changed" if obj in failed else ""))
            for msg in failed.get(obj, [])[:6]:
                liblog.print_logs(f"        {msg}")
        if "HESIOD-DONE" not in p.stdout:
            raise ScgError(f"remediation did not finish; see {out}/driver.log")
    if plan["python"]:
        liblog.print_logs(f"(Remediate) Theogony fixes: {', '.join(plan['python'])}.")
        _python_fixes(lab_spec, plan["python"])
    liblog.print_logs("(Remediate) Auditing again to record the result.")
    run_audit(lab_spec)
    rep = report(lab_spec)
    # Broadcom's scripts log UPDATE even when Set-AdvancedSetting had nothing to act on; call those out.
    still = sorted({(r["control"], r["object"]) for r in evaluate(lab_spec)["rows"] if r["status"] == "FAIL"}
                   & {(c, obj) for obj, cs in (updated if plan["jobs"] else {}).items() for c in cs})
    if still:
        liblog.print_logs(f"    WARNING: {len(still)} result(s) the scripts reported as updated still FAIL:")
        for c, obj in still[:10]:
            liblog.print_logs(f"        {c} on {obj}")
    with open(f"{out}/result.json", "w") as f:
        json.dump({"defcon": defcon, "jobs": plan["jobs"], "python": plan["python"], "after": rep["counts"],
                   "percent_after": rep["percent"]}, f, indent=2)
    return rep
