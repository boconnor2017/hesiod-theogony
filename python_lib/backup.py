# Hesiod Backup Target (SFTP) and VCF backup configuration
# Description: SFTP backup target on HKS (deployed by python_lib/k8_management.py deploy_sftp) and the VCF API calls
#              that point the management domain's backups at it.
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.2 (NSX manual backup is long-running; NSX folder recognised in the report)
#
# Why SFTP: SDDC Manager and NSX Manager back up only to SFTP (VCF 9.1 sets this in SDDC Manager, which is also what
# VCF Operations > Administration > SDDC Manager > Backup Settings writes to). vCenter's file-based backup also speaks SFTP,
# so one target serves all three.
#
# Layout on the target (chrooted, as the backup user sees it):
#   <directory>/             SDDC Manager + NSX (SDDC Manager pushes the same SFTP settings to NSX: .../backups/NSX/)
#   <directory>/vcenter/     vCenter file-based backups (VAMI)
#
# -m11                  deploy SFTP, then the US-006 test (ECDSA-256 key login, write/read/delete, host key + MAC check)
# -m11 --configure      SDDC Manager (+NSX) backup configuration and the vCenter schedule; --dry-run = validations only
# -m11 --backup-now     manual backup of SDDC Manager, NSX and vCenter, each waited on
# -m11 --report         evidence: US-006 test, configuration, last backups per component, consecutive daily successes
#
# Public functions
#   backup_settings(lab_spec), new_host_keys(), record_host_keys(keys), host_fingerprint(), client_key()
#   wait_until_ready(ip, timeout_s), test_target(lab_spec)
#   configure(lab_spec, dry_run=False), backup_now(lab_spec), evidence_report(lab_spec)

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import conjur as libconjur
from python_lib import vcf as libvcf

import base64
import datetime
import hashlib
import json
import os
import re
import socket
import stat
import time

import paramiko
import requests
import urllib3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

STATE_DIR = "conf/sftp"
TERMINAL = {"SUCCESSFUL", "FAILED", "CANCELLED", "COMPLETED_WITH_WARNING", "SKIPPED", "TIMED_OUT"}
DAYS = ["SUNDAY", "MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY", "SATURDAY"]


class BackupError(Exception):
    pass


# ---------------------------------------------------------------- settings

def _secret(lab_spec, idx, what):
    if idx is None or idx >= len(lab_spec["authentication"]):
        raise BackupError(f'lab_spec["backup"]["{what}"] must point at an authentication entry.')
    pw = lab_spec["authentication"][idx]["password"]
    if pw.startswith("<"):
        raise BackupError(f"authentication entry {idx} ({what}) still holds its sample value.")
    return pw


def backup_settings(lab_spec):
    b = lab_spec.get("backup") or {}
    if not b.get("ip_address"):
        raise BackupError('lab_spec["backup"] needs ip_address (see json_lib/lab_spec.json).')
    hostname = b.get("hostname", "sftp")
    directory = "/" + b.get("directory", "/backup/mpc").strip("/")
    parts = directory.strip("/").split("/")
    if len(parts) < 2:
        raise BackupError('lab_spec["backup"]["directory"] needs two levels, e.g. "/backup/mpc".')
    password = _secret(lab_spec, b.get("use_these_credentials"), "use_these_credentials")
    if ":" in password or "\n" in password:
        raise BackupError("the SFTP user's password may not contain ':' (atmoz/sftp user file format).")
    passphrase = _secret(lab_spec, b.get("passphrase_credentials"), "passphrase_credentials")
    problems = []
    if not 12 <= len(passphrase) <= 20: problems.append("12-20 characters (SDDC Manager minimum 12, vCenter maximum 20)")
    if not re.search(r"[A-Z]", passphrase): problems.append("an uppercase letter")
    if not re.search(r"[a-z]", passphrase): problems.append("a lowercase letter")
    if not re.search(r"[0-9]", passphrase): problems.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", passphrase): problems.append("a special character")
    if problems:
        raise BackupError("the backup encryption passphrase needs " + ", ".join(problems) + ".")
    sched = b.get("schedule") or {}
    node = b.get("node")
    return {
        "ip": b["ip_address"], "hostname": hostname, "fqdn": f"{hostname}.{lab_spec['domain']['name']}",
        "username": b.get("username", "svc-mpc-backup"), "uid": int(b.get("uid", 1001)),
        "password": password, "passphrase": passphrase,
        "directory": directory, "mount_dir": parts[0], "chroot_dirs": "/".join(parts),
        "vcenter_dir": directory + "/vcenter",
        "hour": int(sched.get("hour", 2)), "minute": int(sched.get("minute", 0)),
        "vcenter_minute": int(sched.get("vcenter_minute", 15)),
        "retain": int(sched.get("retain", 7)),
        "use_fqdn": bool(b.get("vcf_uses_fqdn", True)),
        "node": None if str(node or "").startswith("<") else node,
        "data_path": b.get("data_path", "/var/lib/hesiod/sftp"),
    }


# ---------------------------------------------------------------- keys

def new_host_keys():
    """Fresh ECDSA-256 + RSA-2048 host keys (OpenSSH format). Only used if the cluster has none yet."""
    def ossh(key):
        return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                 serialization.NoEncryption()).decode()
    return {"ssh_host_ecdsa_key": ossh(ec.generate_private_key(ec.SECP256R1())),
            "ssh_host_rsa_key": ossh(rsa.generate_private_key(public_exponent=65537, key_size=2048))}


def _fingerprint(public_key):
    blob = base64.b64decode(public_key.public_bytes(serialization.Encoding.OpenSSH,
                                                    serialization.PublicFormat.OpenSSH).split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def record_host_keys(keys):
    """Keep the PUBLIC host keys + fingerprints in conf/sftp/ (used to pin the server in VCF and in tests)."""
    os.makedirs(STATE_DIR, exist_ok=True)
    out = {}
    for name, pem in keys.items():
        pub = serialization.load_ssh_private_key(pem.encode(), password=None).public_key()
        out[name] = {"public": pub.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode(),
                     "fingerprint": _fingerprint(pub)}
    with open(f"{STATE_DIR}/host_keys.json", "w") as f:
        json.dump(out, f, indent=2)
    return out


def _host_keys():
    try:
        return json.load(open(f"{STATE_DIR}/host_keys.json"))
    except (OSError, ValueError):
        raise BackupError("conf/sftp/host_keys.json missing: run -m11 first.")


def host_fingerprint():
    return _host_keys()["ssh_host_ecdsa_key"]["fingerprint"]


def client_key():
    """ECDSA-256 key pair for key login as the backup user (US-006). Created once in conf/sftp/."""
    os.makedirs(STATE_DIR, exist_ok=True)
    path = f"{STATE_DIR}/client_ecdsa"
    if not os.path.exists(path):
        key = ec.generate_private_key(ec.SECP256R1())
        with open(path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                                      serialization.NoEncryption()))
        os.chmod(path, 0o600)
    key = serialization.load_ssh_private_key(open(path, "rb").read(), password=None)
    pub = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    with open(path + ".pub", "w") as f:
        f.write(pub + " hesiod-backup-test\n")
    return {"private_path": path, "public": pub + " hesiod-backup-test"}


def vault_secrets(lab_spec):
    """Best effort: the client private key in Conjur (passwords already go there through -m9 --export)."""
    if not lab_spec.get("conjur"):
        return
    try:
        cfg = libconjur.conjur_settings(lab_spec)
        cj = libconjur.ConjurClient(cfg["base_url"], cfg["account"], cfg["username"], password=cfg["password"])
        cj.load_policy("- !policy\n  id: backup\n  body:\n  - !variable\n    id: sftp/client-ecdsa-key\n"
                       "    annotations:\n      hesiod/source: \"m11\"\n"
                       "      hesiod/purpose: \"ECDSA-256 key login to the SFTP backup target\"\n")
        key = open(client_key()["private_path"]).read()
        if cj.get_secret("backup/sftp/client-ecdsa-key") != key:
            cj.set_secret("backup/sftp/client-ecdsa-key", key)
        liblog.print_logs("    SFTP client key vaulted in Conjur (backup/sftp/client-ecdsa-key).")
    except Exception as e:
        liblog.print_logs(f"    WARNING: could not vault the SFTP client key in Conjur ({str(e)[:150]}).")


# ---------------------------------------------------------------- SFTP checks

def wait_until_ready(ip, timeout_s=300):
    deadline, last = time.time() + timeout_s, None
    while time.time() < deadline:
        try:
            with socket.create_connection((ip, 22), timeout=5) as s:
                banner = s.recv(64)
                if banner.startswith(b"SSH-"):
                    return banner.decode(errors="replace").strip()
                last = repr(banner)
        except OSError as e:
            last = str(e)
        time.sleep(5)
    raise BackupError(f"SFTP at {ip}:22 not answering after {timeout_s}s (last: {last}). "
                      "Check: kubectl -n sftp logs deploy/sftp")


def _connect(lab_spec, use_key=True):
    """SSH transport with the server's host key pinned to the one we generated."""
    cfg = backup_settings(lab_spec)
    expected = {k: v["public"].split()[1] for k, v in _host_keys().items()}
    t = paramiko.Transport((cfg["ip"], 22))
    t.get_security_options().key_types = ["ecdsa-sha2-nistp256"]   # ask for the ECDSA host key VCF pins
    t.start_client(timeout=15)
    server_key = t.get_remote_server_key()
    if server_key.get_base64() not in expected.values():
        t.close()
        raise BackupError("the SFTP server presented an unexpected host key (not the one in conf/sftp/host_keys.json).")
    if use_key:
        t.auth_publickey(cfg["username"], paramiko.ECDSAKey.from_private_key_file(client_key()["private_path"]))
    else:
        t.auth_password(cfg["username"], cfg["password"])
    return t


def test_target(lab_spec, ensure_dirs=True):
    """US-006: ECDSA-256 key login as the backup user, write/read/delete under the backup directory."""
    cfg = backup_settings(lab_spec)
    checks = []

    def check(name, ok, detail=""):
        checks.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
        liblog.print_logs(f"    {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
        return ok

    banner = wait_until_ready(cfg["ip"], 30)
    check("SFTP answers on port 22", True, f"{cfg['ip']}: {banner}")
    try:
        t = _connect(lab_spec, use_key=True)
    except Exception as e:
        check("ECDSA-256 key login as " + cfg["username"], False, str(e)[:150])
        return {"checks": checks}
    try:
        hk = t.get_remote_server_key()
        check("Host key is ECDSA-256 and matches the pinned fingerprint",
              hk.get_name() == "ecdsa-sha2-nistp256", f"{hk.get_name()} {host_fingerprint()}")
        check("ECDSA-256 key login as " + cfg["username"], t.is_authenticated(), "publickey (ecdsa-sha2-nistp256)")
        mac = getattr(t, "local_mac", None) or ""
        check("Negotiated MAC is SHA-2", "sha2" in mac or mac == "", mac or "AEAD cipher (MAC built in)")
        sftp = paramiko.SFTPClient.from_transport(t)
        if ensure_dirs:
            for d in (cfg["directory"], cfg["vcenter_dir"]):
                try:
                    sftp.stat(d)
                except IOError:
                    sftp.mkdir(d)
        name = f"{cfg['directory']}/.hesiod-write-test-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
        payload = os.urandom(64 * 1024)
        with sftp.open(name, "wb") as f:
            f.write(payload)
        with sftp.open(name, "rb") as f:
            back = f.read()
        sftp.remove(name)
        check("Write, read-back and delete in " + cfg["directory"], back == payload, f"64 KiB, sha256 {hashlib.sha256(payload).hexdigest()[:16]}")
        st = sftp.statvfs(cfg["directory"]) if hasattr(sftp, "statvfs") else None
        if st is not None:
            free_gb = st.f_bavail * st.f_frsize / 1e9
            check("Free space on the backup volume", free_gb > 20, f"{free_gb:.0f} GB free")
        sftp.close()
    except BackupError:
        raise
    except Exception as e:
        check("SFTP operations", False, str(e)[:150])
    finally:
        t.close()
    try:
        t2 = _connect(lab_spec, use_key=False)
        ok = t2.is_authenticated()
        t2.close()
    except Exception as e:
        ok = False
    check("Password login (what VCF uses)", ok, cfg["username"])
    return {"checks": checks}


def list_backups(lab_spec):
    """Every file under the backup directory: [{path, size, mtime}] (key login)."""
    cfg = backup_settings(lab_spec)
    t = _connect(lab_spec, use_key=True)
    out = []
    try:
        sftp = paramiko.SFTPClient.from_transport(t)
        stack = [cfg["directory"]]
        while stack and len(out) < 20000:
            d = stack.pop()
            try:
                entries = sftp.listdir_attr(d)
            except IOError:
                continue
            for e in entries:
                p = f"{d}/{e.filename}"
                if stat.S_ISDIR(e.st_mode):
                    stack.append(p)
                elif not e.filename.startswith(".hesiod-write-test"):
                    out.append({"path": p, "size": e.st_size, "mtime": e.st_mtime})
    finally:
        t.close()
    return out


# ---------------------------------------------------------------- VCF

def _plan(lab_spec):
    plan = {e["component"]: e for e in libvcf.get_vcf_plan(lab_spec)}
    return {"vcenter": plan["vcenter"]["fqdns"]["vcenter"]["fqdn"], "nsx": plan["nsx"]["fqdns"]["vip"]["fqdn"]}


def _vcf_password(lab_spec):
    return lab_spec["authentication"][lab_spec["vcf"]["use_these_credentials"]]["password"]


def _target_host(cfg):
    return cfg["fqdn"] if cfg["use_fqdn"] else cfg["ip"]


def _wait_task(sddc, task, what, timeout_s=3600):
    tid = (task or {}).get("id")
    if not tid:
        return task
    deadline, last = time.time() + timeout_s, None
    while time.time() < deadline:
        t = sddc.get_patiently(f"/v1/tasks/{tid}")
        status = str(t.get("status", "")).upper()
        if status != last:
            liblog.print_logs(f"    {what}: {status}")
            last = status
        if status in TERMINAL:
            if status not in ("SUCCESSFUL", "COMPLETED_WITH_WARNING"):
                errs = [e.get("message") for e in t.get("errors") or []]
                for st in t.get("subTasks") or []:
                    if str(st.get("status", "")).upper() == "FAILED":
                        errs += [f"{st.get('name')}: " + "; ".join(e.get("message", "") for e in st.get("errors") or [])]
                raise BackupError(f"{what} {status}: " + " | ".join(e for e in errs if e)[:800])
            return t
        time.sleep(15)
    raise BackupError(f"{what}: task {tid} still running after {timeout_s}s")


class _Vcenter:
    """vCenter Appliance (VAMI) REST API: /api/appliance/recovery/backup/*"""
    def __init__(self, fqdn, password):
        self.base = f"https://{fqdn}"
        self.s = requests.Session()
        self.s.trust_env, self.s.verify = False, False
        r = self.s.post(f"{self.base}/api/session", auth=("administrator@vsphere.local", password), timeout=30)
        if r.status_code >= 300:
            raise BackupError(f"vCenter {fqdn} login failed: HTTP {r.status_code} {r.text[:200]}")
        self.s.headers["vmware-api-session-id"] = r.json()

    def call(self, method, path, body=None, ok=(200, 201, 202, 204)):
        r = self.s.request(method, f"{self.base}{path}", json=body, timeout=120)
        if r.status_code not in ok:
            raise BackupError(f"vCenter {method} {path}: HTTP {r.status_code} {r.text[:400]}")
        return r.json() if r.content and "json" in r.headers.get("Content-Type", "") else None


def _vc_location(cfg):
    return f"sftp://{_target_host(cfg)}:22{cfg['vcenter_dir']}"


def configure(lab_spec, dry_run=False):
    """SDDC Manager (+NSX) backup configuration and the vCenter file-based backup schedule."""
    cfg = backup_settings(lab_spec)
    names = _plan(lab_spec)
    fp = host_fingerprint()
    sddc = libconjur.sddc_manager_client(lab_spec)

    # 1. SDDC Manager (SDDC Manager pushes the same SFTP settings to NSX Manager)
    location = {"server": _target_host(cfg), "port": 22, "protocol": "SFTP", "username": cfg["username"],
                "password": cfg["password"], "directoryPath": cfg["directory"], "sshFingerprint": fp}
    spec = {"encryption": {"passphrase": cfg["passphrase"]},
            "backupLocations": [location],
            "backupSchedules": [{"resourceType": "SDDC_MANAGER", "takeScheduledBackups": True,
                                 "frequency": "WEEKLY", "daysOfWeek": DAYS,
                                 "hourOfDay": cfg["hour"], "minuteOfHour": cfg["minute"],
                                 "takeBackupOnStateChange": True,
                                 "retentionPolicy": {"numberOfMostRecentBackups": cfg["retain"],
                                                     "numberOfDaysOfDailyBackups": cfg["retain"],
                                                     "numberOfDaysOfHourlyBackups": 1}}]}
    liblog.print_logs(f"(Configure 1) SDDC Manager + NSX: sftp://{cfg['username']}@{location['server']}{cfg['directory']}, "
                      f"daily {cfg['hour']:02d}:{cfg['minute']:02d}, keep {cfg['retain']}, host key {fp}")
    try:
        v = sddc.post("/v1/system/backup-configuration/validations", spec)
        v = _wait_validation(sddc, v)
        liblog.print_logs("    SDDC Manager validation passed.")
    except libvcf.VcfError as e:
        if re.search(r"HTTP 40[45]", str(e)):
            liblog.print_logs(f"    WARNING: SDDC Manager validation endpoint not usable here ({str(e)[:120]}); "
                              + ("dry run cannot check SDDC Manager." if dry_run else "the save itself will validate."))
        else:
            raise BackupError(f"SDDC Manager rejected the backup configuration: {str(e)[:600]}")
    if not dry_run:
        task = sddc._call("PUT", "/v1/system/backup-configuration", json=spec)
        _wait_task(sddc, task, "SDDC Manager backup configuration", 1800)
        current = sddc.get("/v1/system/backup-configuration")
        loc = (current.get("backupLocations") or [{}])[0]
        if loc.get("server") != location["server"] or loc.get("directoryPath") != cfg["directory"]:
            raise BackupError(f"SDDC Manager did not keep the backup location (now: {json.dumps(loc)[:200]}). "
                              "If VCF Operations shows the same, see Broadcom KB 436354 (stale SDDC Manager locks).")
        liblog.print_logs("    SDDC Manager backup configuration saved and read back.")

    # 2. vCenter file-based backup (VAMI)
    liblog.print_logs(f"(Configure 2) vCenter {names['vcenter']}: {_vc_location(cfg)}, "
                      f"daily {cfg['hour']:02d}:{cfg['vcenter_minute']:02d}, keep {cfg['retain']}")
    vc = _Vcenter(names["vcenter"], _vcf_password(lab_spec))
    target = {"location_type": "SFTP", "location": _vc_location(cfg), "location_user": cfg["username"],
              "location_password": cfg["password"], "backup_password": cfg["passphrase"], "parts": []}
    result = vc.call("POST", "/api/appliance/recovery/backup?action=validate", target) or {}
    errs = [m.get("default_message", str(m)) for m in result.get("errors") or []]
    warns = [m.get("default_message", str(m)) for m in result.get("warnings") or []]
    for w in warns:
        liblog.print_logs(f"    vCenter warning: {w}")
    if errs:
        raise BackupError("vCenter rejected the backup location: " + " | ".join(errs))
    liblog.print_logs("    vCenter validation passed.")
    if not dry_run:
        schedule = {"location": target["location"], "location_user": cfg["username"],
                    "location_password": cfg["password"], "backup_password": cfg["passphrase"], "enable": True,
                    "parts": [], "recurrence_info": {"hour": cfg["hour"], "minute": cfg["vcenter_minute"],
                                                     "days": [d for d in DAYS]},
                    "retention_info": {"max_count": cfg["retain"]}}
        # vCenter keeps one schedule. Create: POST .../schedules {schedule, spec}. Update: PATCH .../schedules/{id} with the spec.
        existing = vc.call("GET", "/api/appliance/recovery/backup/schedules") or {}
        sid = "default" if "default" in existing else next(iter(existing), None)
        if sid:
            vc.call("PATCH", f"/api/appliance/recovery/backup/schedules/{sid}", schedule)
            liblog.print_logs(f"    vCenter backup schedule '{sid}' updated.")
        else:
            vc.call("POST", "/api/appliance/recovery/backup/schedules", {"schedule": "default", "spec": schedule})
            liblog.print_logs("    vCenter backup schedule 'default' created.")

    done = "validated (dry run, nothing saved)" if dry_run else "configured"
    liblog.print_logs(f"Backups {done}: SDDC Manager, NSX (pushed by SDDC Manager), vCenter.")


def _wait_validation(sddc, v, timeout_s=900):
    vid = (v or {}).get("id")
    deadline = time.time() + timeout_s
    while vid and str(v.get("executionStatus", "")).upper() in ("", "IN_PROGRESS", "PENDING") and time.time() < deadline:
        time.sleep(10)
        v = sddc.get(f"/v1/system/backup-configuration/validations/{vid}")
    result = str(v.get("resultStatus", "")).upper()
    if result and result not in ("SUCCEEDED", "SUCCESSFUL", "WARNING"):
        checks = [f"{c.get('description')}: {c.get('errorResponse', {}).get('message', c.get('resultStatus'))}"
                  for c in v.get("validationChecks") or [] if str(c.get("resultStatus", "")).upper() not in ("SUCCEEDED", "")]
        raise BackupError("SDDC Manager backup validation failed: " + (" | ".join(checks) or json.dumps(v)[:500]))
    return v


def _nsx_session(lab_spec):
    fqdn = _plan(lab_spec)["nsx"]
    s = requests.Session()
    s.trust_env, s.verify = False, False
    s.auth = ("admin", _vcf_password(lab_spec))
    return fqdn, s


def nsx_backup_state(lab_spec):
    fqdn, s = _nsx_session(lab_spec)
    out = {"fqdn": fqdn}
    r = s.get(f"https://{fqdn}/api/v1/cluster/backups/config", timeout=30)
    if r.status_code == 200:
        c = r.json()
        srv = c.get("remote_file_server") or {}
        out.update({"enabled": c.get("backup_enabled"), "server": srv.get("server"),
                    "directory": srv.get("directory_path"), "schedule": c.get("backup_schedule")})
    r = s.get(f"https://{fqdn}/api/v1/cluster/backups/history", timeout=30)
    if r.status_code == 200:
        hist = sorted(r.json().get("cluster_backup_statuses") or [], key=lambda x: x.get("end_time") or 0)
        out["history"] = [{"end": datetime.datetime.fromtimestamp((h.get("end_time") or 0) / 1000).strftime("%Y-%m-%d %H:%M"),
                           "end_ms": h.get("end_time") or 0, "success": h.get("success"),
                           "error": h.get("error_message")} for h in hist[-14:]]
    return out


def backup_now(lab_spec):
    """Manual backup of SDDC Manager, NSX and vCenter (the US-013 'a manual backup of each succeeds')."""
    cfg = backup_settings(lab_spec)
    names = _plan(lab_spec)
    results = {}

    liblog.print_logs("(Backup 1) SDDC Manager.")
    sddc = libconjur.sddc_manager_client(lab_spec)
    task = sddc.post("/v1/backups/tasks", {"elements": [{"resourceType": "SDDC_MANAGER"}]})
    _wait_task(sddc, task, "SDDC Manager backup", 3600)
    results["SDDC_MANAGER"] = "SUCCESSFUL"

    liblog.print_logs("(Backup 2) NSX Manager.")
    fqdn, s = _nsx_session(lab_spec)
    before = max([h["end_ms"] for h in nsx_backup_state(lab_spec).get("history") or []] or [0])
    # NSX holds this call open while it backs up, so a read timeout only means "still running": keep polling history.
    try:
        r = s.post(f"https://{fqdn}/api/v1/cluster?action=backup_to_remote", json={}, timeout=(15, 120))
    except requests.exceptions.ReadTimeout:
        liblog.print_logs("    NSX backup started (NSX is still answering the request); following its backup history.")
        r = None
    if r is not None and r.status_code >= 300:
        raise BackupError(f"NSX backup_to_remote: HTTP {r.status_code} {r.text[:300]} "
                          "(is the backup location configured? run -m11 --configure)")
    deadline = time.time() + 1800
    while time.time() < deadline:
        time.sleep(20)
        try:
            newer = [h for h in nsx_backup_state(lab_spec).get("history") or [] if h["end_ms"] > before]
        except requests.RequestException:
            continue   # NSX can be slow to answer mid-backup

        if newer:
            last = newer[-1]
            if not last["success"]:
                raise BackupError(f"NSX backup failed: {last.get('error')}")
            liblog.print_logs(f"    NSX backup: SUCCESSFUL ({last['end']})")
            results["NSXT_MANAGER"] = "SUCCESSFUL"
            break
    else:
        raise BackupError("NSX backup did not finish within 30 minutes (check NSX > System > Backup & Restore).")

    liblog.print_logs("(Backup 3) vCenter.")
    vc = _Vcenter(names["vcenter"], _vcf_password(lab_spec))
    job = vc.call("POST", "/api/appliance/recovery/backup/job",
                  {"location_type": "SFTP", "location": _vc_location(cfg), "location_user": cfg["username"],
                   "location_password": cfg["password"], "backup_password": cfg["passphrase"], "parts": [],
                   "comment": "Hesiod -m11 --backup-now"})
    job_id = job.get("id") if isinstance(job, dict) else job
    deadline, last = time.time() + 3600, None
    while time.time() < deadline:
        time.sleep(20)
        st = vc.call("GET", f"/api/appliance/recovery/backup/job/{job_id}")
        state = st.get("state")
        if state != last:
            liblog.print_logs(f"    vCenter backup: {state} ({st.get('progress', '?')}%)")
            last = state
        if state in ("SUCCEEDED", "FAILED", "CANCELED"):
            if state != "SUCCEEDED":
                msgs = [m.get("default_message", "") for m in st.get("messages") or []]
                raise BackupError(f"vCenter backup {state}: " + " | ".join(msgs)[:500])
            results["VCENTER"] = "SUCCESSFUL"
            break
    else:
        raise BackupError("vCenter backup did not finish within 60 minutes.")

    liblog.print_logs("Manual backups complete: " + ", ".join(f"{k} {v}" for k, v in results.items()))
    return results


# ---------------------------------------------------------------- evidence report (-m11 --report)

def _component_of(path, cfg, nsx_dir=None):
    rel = path[len(cfg["directory"]):].lstrip("/").lower()
    if rel.startswith("vcenter/"):
        return "vCenter"
    # SDDC Manager gives NSX its own folder: <directory>/<nsx fqdn>/ (cluster-node-backups/, inventory-summary/ ...)
    if (nsx_dir and path.startswith(nsx_dir.rstrip("/") + "/")) or "/nsx/" in "/" + rel \
            or "cluster-node-backups" in rel or "inventory-summary" in rel:
        return "NSX Manager"
    if "/lcm/" in "/" + rel:
        return "VCF Management (LCM)"
    if "sddc" in rel or "vcf-backup" in rel or rel.endswith(".tar.gz"):
        return "SDDC Manager"
    return "Other"


def evidence_report(lab_spec, out_dir="conf/evidence"):
    cfg = backup_settings(lab_spec)
    now = datetime.datetime.now()
    rep = {"generated": now.strftime("%Y-%m-%d %H:%M:%S"),
           "target": {"url": f"sftp://{cfg['username']}@{cfg['fqdn']}:22{cfg['directory']}", "ip": cfg["ip"],
                      "host_keys": {k: v["fingerprint"] for k, v in _host_keys().items()}},
           "checks": []}

    def check(name, ok, detail=""):
        rep["checks"].append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
        liblog.print_logs(f"    {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))

    liblog.print_logs("(Report 1) Backup target (US-006).")
    t = test_target(lab_spec, ensure_dirs=False)
    rep["us006"] = t["checks"]
    rep["checks"] += t["checks"]

    liblog.print_logs("(Report 2) VCF backup configuration (US-013).")
    try:
        sddc = libconjur.sddc_manager_client(lab_spec)
        conf = sddc.get("/v1/system/backup-configuration")
        loc = (conf.get("backupLocations") or [{}])[0]
        sch = (conf.get("backupSchedules") or [{}])[0]
        rep["sddc_manager"] = {"server": loc.get("server"), "directory": loc.get("directoryPath"),
                               "fingerprint": loc.get("sshFingerprint"), "frequency": sch.get("frequency"),
                               "days": sch.get("daysOfWeek"), "time": f"{sch.get('hourOfDay', 0):02d}:{sch.get('minuteOfHour', 0):02d}",
                               "retention": sch.get("retentionPolicy"), "encrypted": bool(conf.get("isConfigured", True))}
        check("SDDC Manager backs up to the lab SFTP target",
              loc.get("server") in (cfg["fqdn"], cfg["ip"]) and loc.get("directoryPath") == cfg["directory"],
              f"{loc.get('server')}:{loc.get('directoryPath')}")
        check("SDDC Manager pins the SFTP host key", loc.get("sshFingerprint") == host_fingerprint(), str(loc.get("sshFingerprint")))
        check("SDDC Manager schedule is daily", sch.get("takeScheduledBackups") and len(sch.get("daysOfWeek") or []) == 7,
              f"{sch.get('frequency')} {len(sch.get('daysOfWeek') or [])} days at {rep['sddc_manager']['time']}")
    except Exception as e:
        check("SDDC Manager backup configuration readable", False, str(e)[:150])
    try:
        nsx = nsx_backup_state(lab_spec)
        rep["nsx"] = nsx
        check("NSX Manager backs up to the lab SFTP target", nsx.get("server") in (cfg["fqdn"], cfg["ip"]),
              f"{nsx.get('fqdn')} -> {nsx.get('server')}:{nsx.get('directory')}, enabled={nsx.get('enabled')}")
    except Exception as e:
        check("NSX Manager backup configuration readable", False, str(e)[:150])
    try:
        names = _plan(lab_spec)
        vc = _Vcenter(names["vcenter"], _vcf_password(lab_spec))
        all_sched = vc.call("GET", "/api/appliance/recovery/backup/schedules") or {}
        sched = all_sched.get("default") or next(iter(all_sched.values()), {})
        rep["vcenter"] = {"fqdn": names["vcenter"], "location": sched.get("location"), "enabled": sched.get("enable"),
                          "recurrence": sched.get("recurrence_info"), "retention": sched.get("retention_info")}
        check("vCenter backs up to the lab SFTP target", bool(sched.get("enable")) and cfg["vcenter_dir"] in (sched.get("location") or ""),
              f"{names['vcenter']} -> {sched.get('location')}")
    except Exception as e:
        check("vCenter backup schedule readable", False, str(e)[:150])

    liblog.print_logs("(Report 3) Backups on the target.")
    files = list_backups(lab_spec)
    per = {}
    for f in files:
        per.setdefault(_component_of(f["path"], cfg, (rep.get("nsx") or {}).get("directory")), []).append(f)
    rep["backups"] = {}
    for comp, fl in sorted(per.items()):
        days = sorted({datetime.date.fromtimestamp(f["mtime"]) for f in fl})
        streak, d = 0, datetime.date.today()
        while d in days:
            streak, d = streak + 1, d - datetime.timedelta(days=1)
        newest = max(fl, key=lambda f: f["mtime"])
        rep["backups"][comp] = {"files": len(fl), "size_mb": round(sum(f["size"] for f in fl) / 1e6, 1),
                                "newest": datetime.datetime.fromtimestamp(newest["mtime"]).strftime("%Y-%m-%d %H:%M"),
                                "newest_file": newest["path"], "days_with_backups": len(days),
                                "consecutive_days_to_today": streak}
    for comp in ("SDDC Manager", "NSX Manager", "vCenter"):
        b = rep["backups"].get(comp)
        check(f"{comp} backup present on the target", bool(b),
              f"newest {b['newest']}, {b['consecutive_days_to_today']} consecutive day(s)" if b else "none found")
    rep["result"] = "PASS" if all(c["result"] == "PASS" for c in rep["checks"]) else "FAIL"
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"backup_evidence_{now.strftime('%Y%m%d-%H%M%S')}")
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2, default=str)
    with open(base + ".md", "w") as f:
        f.write(_report_markdown(rep))
    liblog.print_logs(f"Evidence report: {rep['result']}  ->  {base}.md  (+ .json)")
    return rep


def _report_markdown(rep):
    L = ["# Backup evidence: SFTP target and VCF management backups", "",
         f"Generated {rep['generated']} by Theogony -m11 --report. **Overall: {rep['result']}**. "
         "No passwords or passphrases appear in this report.", "",
         f"Target: `{rep['target']['url']}` ({rep['target']['ip']})", "",
         "| Host key | SHA-256 fingerprint |", "|---|---|"]
    L += [f"| {k.replace('ssh_host_', '').replace('_key', '').upper()} | `{v}` |" for k, v in rep["target"]["host_keys"].items()]
    L += ["", "## Checks", "", "| Result | Check | Detail |", "|---|---|---|"]
    L += [f"| {c['result']} | {c['check']} | {c['detail']} |" for c in rep["checks"]]
    if rep.get("sddc_manager"):
        s = rep["sddc_manager"]
        L += ["", "## Configuration", "", "| Component | Target | Schedule | Retention |", "|---|---|---|---|",
              f"| SDDC Manager | {s['server']}:{s['directory']} | {s['frequency']}, {len(s.get('days') or [])} days at {s['time']} | {s.get('retention')} |"]
        if rep.get("nsx"):
            n = rep["nsx"]
            L.append(f"| NSX Manager ({n['fqdn']}) | {n.get('server')}:{n.get('directory')} | set by SDDC Manager | NSX keeps all (KB 448811) |")
        if rep.get("vcenter"):
            v = rep["vcenter"]
            L.append(f"| vCenter ({v['fqdn']}) | {v.get('location')} | {v.get('recurrence')} | {v.get('retention')} |")
    if rep.get("backups"):
        L += ["", "## Backups on the target", "",
              "| Component | Files | Size (MB) | Newest | Days with backups | Consecutive days to today |", "|---|---|---|---|---|---|"]
        L += [f"| {c} | {b['files']} | {b['size_mb']} | {b['newest']} | {b['days_with_backups']} | {b['consecutive_days_to_today']} |"
              for c, b in rep["backups"].items()]
    if rep.get("nsx", {}).get("history"):
        L += ["", "## NSX backup history (latest 14)", "", "| Finished | Result |", "|---|---|"]
        L += [f"| {h['end']} | {'success' if h['success'] else 'FAILED: ' + str(h.get('error'))} |" for h in rep["nsx"]["history"]]
    return "\n".join(L) + "\n"
