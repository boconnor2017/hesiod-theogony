# Hesiod Key Management (KMIP) and vSAN encryption
# Description: KMIP key server on HKS (PyKMIP, deployed by python_lib/k8_management.py deploy_kmip), registered in the
#              management vCenter as a Standard Key Provider, then used for vSAN data-at-rest encryption.
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.0
#
# Why PyKMIP: vSAN encryption needs a KMIP server. OpenBao's KMIP support is a client (seal) only, and the KMIP
# secrets engine is a Vault Enterprise feature. PyKMIP is the open-source KMIP reference server: fine for a lab,
# not a production KMS (single node, keys in a SQLite file). The design (TR-003/US-009) names the vSphere Native Key
# Provider; this lab exercises the Standard (KMIP) Key Provider path instead.
#
# Trust: everything is issued by the lab CA (Module 10).
#   KMS server certificate  -> Secret kmip-tls (server.crt = leaf + intermediate, server.key, ca_bundle.crt)
#   vCenter client cert     -> conf/kmip/vcenter_client.crt/.key, uploaded to vCenter (KMS trusts vCenter)
#   Lab root                -> uploaded to vCenter as the KMS certificate (vCenter trusts the KMS)
#
# -m12                     deploy the KMIP server, then test it (mutual TLS, KMIP create/get/destroy)
# -m12 --configure         register the key provider in vCenter, establish trust both ways, test a key
# -m12 --encrypt-vsan      vSAN data-at-rest + data-in-transit encryption on the management cluster
#                          (OSA: rolling disk-group reformat, about an hour per host)
# -m12 --in-transit-only   vSAN data-in-transit encryption only (no reformat)
# -m12 --backup-keys       copy the key database to conf/kmip/ and the SFTP backup target (Module 11)
# -m12 --report            evidence: KMS tests, key provider status, vSAN encryption state, key backups

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import ca as libca
from python_lib import conjur as libconjur
from python_lib import k8_management as libk8
from python_lib import vcf as libvcf

import base64
import datetime
import json
import os
import re
import socket
import ssl
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim, VmomiSupport, SoapStubAdapter

STATE_DIR = "conf/kmip"


class KmsError(Exception):
    pass


# ---------------------------------------------------------------- settings / certificates

def kms_settings(lab_spec):
    k = lab_spec.get("key_management") or {}
    if not k.get("ip_address"):
        raise KmsError('lab_spec["key_management"] needs ip_address (see json_lib/lab_spec.json).')
    hostname = k.get("hostname", "kmip")
    node, cluster = k.get("node"), k.get("cluster")
    return {
        "ip": k["ip_address"], "hostname": hostname, "fqdn": f"{hostname}.{lab_spec['domain']['name']}",
        "provider": k.get("provider_name", "kms-mpc"), "server_name": k.get("server_name", "kmip01"),
        "set_default": bool(k.get("set_default", True)),
        "cluster": None if str(cluster or "").startswith("<") else cluster,
        "allow_reduced_redundancy": bool(k.get("allow_reduced_redundancy", False)),
        "dit_rekey_minutes": int(k.get("dit_rekey_minutes", 1440)),
        "node": None if str(node or "").startswith("<") else node,
        "data_path": k.get("data_path", "/var/lib/hesiod/kmip"),
        "kube": lab_spec["kubernetes"]["kube_config_path"],
    }


def _issue(lab_spec, cn, sans_dns, sans_ip=()):
    """New RSA 2048 key + certificate from the lab CA. Returns (key_pem, leaf_pem, intermediate_pem, root_pem)."""
    import ipaddress
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    names = [x509.DNSName(d) for d in sans_dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in sans_ip]
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
           .add_extension(x509.SubjectAlternativeName(names), critical=False)
           .sign(key, hashes.SHA256()))
    leaf, inter, root = libca.sign_csr(lab_spec, csr.public_bytes(serialization.Encoding.PEM).decode())
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()).decode()
    return key_pem, leaf, inter, root


def _days_left(pem):
    cert = x509.load_pem_x509_certificate(pem.encode())
    return (cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).days


def server_tls(lab_spec, current=None):
    """Secret kmip-tls content. Keeps the current certificate unless missing, expiring (<30d) or for another name/IP."""
    cfg = kms_settings(lab_spec)
    if current and current.get("server.crt"):
        cert = x509.load_pem_x509_certificate(current["server.crt"].encode())
        try:
            san = [str(n.value) for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
        except x509.ExtensionNotFound:
            san = []
        if _days_left(current["server.crt"]) > 30 and cfg["fqdn"] in san and cfg["ip"] in san:
            liblog.print_logs(f"    KMIP server certificate current ({_days_left(current['server.crt'])} days left). Keeping it.")
            return current
    key, leaf, inter, root = _issue(lab_spec, cfg["fqdn"], [cfg["fqdn"], "localhost"], [cfg["ip"], "127.0.0.1"])
    liblog.print_logs(f"    KMIP server certificate issued by the lab CA for {cfg['fqdn']} / {cfg['ip']}.")
    return {"server.crt": leaf.strip() + "\n" + inter.strip() + "\n", "server.key": key,
            "ca_bundle.crt": inter.strip() + "\n" + root.strip() + "\n"}


def vcenter_client_cert(lab_spec):
    """vCenter's KMIP client certificate (lab CA), kept in conf/kmip/ and Conjur. Re-issued when within 30 days."""
    os.makedirs(STATE_DIR, exist_ok=True)
    crt, keyp = f"{STATE_DIR}/vcenter_client.crt", f"{STATE_DIR}/vcenter_client.key"
    if os.path.exists(crt) and os.path.exists(keyp) and _days_left(open(crt).read()) > 30:
        return open(crt).read(), open(keyp).read(), False
    vc = _names(lab_spec)["vcenter"]
    key, leaf, inter, root = _issue(lab_spec, f"{vc} KMIP client", [vc])
    with open(crt, "w") as f:
        f.write(leaf.strip() + "\n")
    with open(keyp, "w") as f:
        f.write(key)
    os.chmod(keyp, 0o600)
    _vault(lab_spec, "kms/vcenter-kmip-client-key", key, "vCenter KMIP client private key (lab CA certificate in conf/kmip/)")
    return leaf.strip() + "\n", key, True


def _vault(lab_spec, var_id, value, purpose):
    if not lab_spec.get("conjur"):
        return
    try:
        cfg = libconjur.conjur_settings(lab_spec)
        cj = libconjur.ConjurClient(cfg["base_url"], cfg["account"], cfg["username"], password=cfg["password"])
        branch, rest = var_id.split("/", 1)
        cj.load_policy(f"- !policy\n  id: {branch}\n  body:\n  - !variable\n    id: {json.dumps(rest)}\n"
                       f"    annotations:\n      hesiod/source: \"m12\"\n      hesiod/purpose: {json.dumps(purpose)}\n")
        if cj.get_secret(var_id) != value:
            cj.set_secret(var_id, value)
        liblog.print_logs(f"    Vaulted in Conjur: {var_id}")
    except Exception as e:
        liblog.print_logs(f"    WARNING: could not vault {var_id} in Conjur ({str(e)[:150]}).")


# ---------------------------------------------------------------- KMS checks

def wait_until_ready(ip, timeout_s=600):
    deadline, last = time.time() + timeout_s, None
    while time.time() < deadline:
        try:
            with socket.create_connection((ip, 5696), timeout=5):
                return True
        except OSError as e:
            last = str(e)
        time.sleep(10)
    raise KmsError(f"KMIP server {ip}:5696 not answering after {timeout_s}s (last: {last}). "
                   "First start installs PyKMIP from PyPI. Check: kubectl -n kmip logs deploy/kmip")


def _mtls(host, ip, client=None):
    """TLS handshake to the KMS trusting only the lab root (hostname checked). client=(crt_path, key_path) or None."""
    ctx = ssl.create_default_context(cafile=f"{libca.CA_DIR}/root_ca.crt")
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2    # PyKMIP's auth suite; TLS 1.3 defers client-cert checks
    if client:
        ctx.load_cert_chain(*client)
    with socket.create_connection((ip, 5696), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            # PyKMIP rejects a missing client cert after the handshake: try a read to surface it
            tls.settimeout(3)
            try:
                tls.recv(1)
            except socket.timeout:
                pass
            return libca.cert_info(x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))), tls.version()


def _pod_kmip_test(lab_spec):
    """Create/get/activate/revoke/destroy an AES-256 key with PyKMIP's own client inside the pod."""
    script = r'''export PYTHONPATH=/data/pylib
python - <<'PY'
from kmip.pie.client import ProxyKmipClient
from kmip.core import enums
c = ProxyKmipClient(hostname="127.0.0.1", port=5696, cert="/etc/pykmip/tls/server.crt", key="/etc/pykmip/tls/server.key",
                    ca="/etc/pykmip/tls/ca_bundle.crt", config_file="/dev/null")
with c:
    uid = c.create(enums.CryptographicAlgorithm.AES, 256)
    key = c.get(uid)
    c.activate(uid)
    c.revoke(enums.RevocationReasonCode.CESSATION_OF_OPERATION, uid)
    c.destroy(uid)
    print("KMIP_OK", uid, len(key.value) * 8)
PY'''
    rc, out = libk8.exec_in_pod(kms_settings(lab_spec)["kube"], "kmip", "app=kmip", "kmip", script, 120)
    m = re.search(r"KMIP_OK (\S+) (\d+)", out)
    return (rc == 0 and m is not None and m.group(2) == "256"), (f"AES-{m.group(2)} key {m.group(1)} created, read, "
                                                                 "activated, revoked, destroyed" if m else out.strip()[-200:])


def test_kms(lab_spec):
    cfg = kms_settings(lab_spec)
    checks = []

    def check(name, ok, detail=""):
        checks.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
        liblog.print_logs(f"    {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))

    crt, key, _ = vcenter_client_cert(lab_spec)
    try:
        info, ver = _mtls(cfg["fqdn"], cfg["ip"], (f"{STATE_DIR}/vcenter_client.crt", f"{STATE_DIR}/vcenter_client.key"))
        check("KMIP endpoint chain verifies to the lab root", True,
              f"{cfg['fqdn']}:5696 {ver}, {info['subject']}, expires {info['not_after']}")
        check("Mutual TLS with the vCenter client certificate", True, "accepted")
    except Exception as e:
        check("Mutual TLS with the vCenter client certificate", False, str(e)[:150])
    try:
        _mtls(cfg["fqdn"], cfg["ip"], None)
        check("Connection without a client certificate is refused", False, "accepted (client auth not enforced)")
    except (ssl.SSLError, ConnectionResetError, OSError) as e:
        check("Connection without a client certificate is refused", True, type(e).__name__)
    ok, detail = _pod_kmip_test(lab_spec)
    check("KMIP operations (PyKMIP client)", ok, detail)
    return {"checks": checks}


def backup_key_db(lab_spec):
    """Consistent copy of the key database (SQLite backup API) to conf/kmip/ and, if Module 11 exists, to SFTP."""
    script = r'''export PYTHONPATH=/data/pylib
python - <<'PY'
import sqlite3, base64, os
src = sqlite3.connect("/data/db/pykmip.db"); dst = sqlite3.connect("/tmp/hesiod-keys.db"); src.backup(dst); dst.close(); src.close()
n = sqlite3.connect("/tmp/hesiod-keys.db").execute("select count(*) from managed_objects").fetchone()[0]
print("OBJECTS", n); print("B64", base64.b64encode(open("/tmp/hesiod-keys.db","rb").read()).decode()); os.remove("/tmp/hesiod-keys.db")
PY'''
    rc, out = libk8.exec_in_pod(kms_settings(lab_spec)["kube"], "kmip", "app=kmip", "kmip", script, 120)
    m, n = re.search(r"B64 (\S+)", out), re.search(r"OBJECTS (\d+)", out)
    if rc != 0 or not m:
        raise KmsError(f"key database backup failed: {out.strip()[-300:]}")
    data = base64.b64decode(m.group(1))
    os.makedirs(STATE_DIR, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    path = f"{STATE_DIR}/pykmip_{stamp}.db"
    with open(path, "wb") as f:
        f.write(data)
    os.chmod(path, 0o600)
    old = sorted(p for p in os.listdir(STATE_DIR) if p.startswith("pykmip_") and p.endswith(".db"))
    for p in old[:-14]:
        os.remove(f"{STATE_DIR}/{p}")
    result = {"local": path, "objects": int(n.group(1)) if n else None, "bytes": len(data), "sftp": None}
    liblog.print_logs(f"    Key database: {result['objects']} objects, {len(data)} bytes -> {path}")
    if lab_spec.get("backup"):
        try:
            from python_lib import backup as libbackup
            bcfg = libbackup.backup_settings(lab_spec)
            t = libbackup._connect(lab_spec, use_key=True)
            sftp = __import__("paramiko").SFTPClient.from_transport(t)
            d = bcfg["directory"] + "/kmip"
            try:
                sftp.stat(d)
            except IOError:
                sftp.mkdir(d)
            with sftp.open(f"{d}/pykmip_{stamp}.db", "wb") as f:
                f.write(data)
            sftp.close(); t.close()
            result["sftp"] = f"{d}/pykmip_{stamp}.db"
            liblog.print_logs(f"    Copied to the SFTP backup target: {result['sftp']}")
        except Exception as e:
            liblog.print_logs(f"    WARNING: could not copy the key database to SFTP ({str(e)[:150]}).")
    return result


# ---------------------------------------------------------------- vCenter / vSAN

def _names(lab_spec):
    plan = {e["component"]: e for e in libvcf.get_vcf_plan(lab_spec)}
    return {"vcenter": plan["vcenter"]["fqdns"]["vcenter"]["fqdn"], "cluster": libvcf._naming(lab_spec)["cluster"]}


def _vc_connect(lab_spec):
    fqdn = _names(lab_spec)["vcenter"]
    pw = lab_spec["authentication"][lab_spec["vcf"]["use_these_credentials"]]["password"]
    try:
        return SmartConnect(host=fqdn, user="administrator@vsphere.local", pwd=pw,
                            sslContext=ssl._create_unverified_context())
    except Exception as e:
        raise KmsError(f"cannot log in to vCenter {fqdn}: {e}")


def _wait(task, what, timeout_s=3600, every_s=10, progress=False):
    deadline, last = time.time() + timeout_s, None
    while task.info.state in (vim.TaskInfo.State.queued, vim.TaskInfo.State.running):
        if time.time() > deadline:
            raise KmsError(f"{what}: still running after {timeout_s}s (it carries on in vCenter)")
        if progress and task.info.progress != last:
            last = task.info.progress
            liblog.print_logs(f"    {what}: {last if last is not None else 0}%")
        time.sleep(every_s)
    if task.info.state != vim.TaskInfo.State.success:
        raise KmsError(f"{what} failed: {getattr(task.info.error, 'msg', None) or task.info.error}")
    return task.info.result


def _cluster(si, lab_spec):
    cfg = kms_settings(lab_spec)
    want = cfg["cluster"] or _names(lab_spec)["cluster"]
    view = si.content.viewManager.CreateContainerView(si.content.rootFolder, [vim.ClusterComputeResource], True)
    try:
        clusters = list(view.view)
    finally:
        view.Destroy()
    c = next((c for c in clusters if c.name == want), None) or (clusters[0] if len(clusters) == 1 else None)
    if not c:
        raise KmsError(f"cluster {want} not found in vCenter (have: {[x.name for x in clusters]}); "
                       'set lab_spec["key_management"]["cluster"].')
    return c


def _vsan_config_system(si, host):
    if not hasattr(vim, "vsan") or not hasattr(vim.cluster, "VsanVcClusterConfigSystem"):
        raise KmsError("this pyVmomi has no vSAN API bindings: pip install --break-system-packages 'pyvmomi>=9.0'")
    try:
        version = VmomiSupport.newestVersions.Get("vsan")
    except Exception:
        version = "vsan.version.version3"
    stub = SoapStubAdapter(host=host, port=443, path="/vsanHealth", version=version,
                           sslContext=ssl._create_unverified_context())
    stub.cookie = si._stub.cookie
    return vim.cluster.VsanVcClusterConfigSystem("vsan-cluster-config-system", stub)


def provider_status(si, provider):
    cm = si.content.cryptoManager
    clusters = [c for c in cm.ListKmipServers() if c.clusterId.id == provider]
    if not clusters:
        return None
    status = (_wait(cm.RetrieveKmipServersStatus_Task(clusters=clusters), "key provider status", 300) or [None])[0]
    if status is None:
        return None
    servers = [{"name": s.name, "status": str(s.status), "connection": s.connectionStatus,
                "client_trusts_server": s.clientTrustServer, "server_trusts_client": s.serverTrustClient,
                "server_cert_expires": getattr(s.certInfo, "notAfter", None) and str(s.certInfo.notAfter)[:10]}
               for s in status.servers or []]
    return {"provider": provider, "overall": str(status.overallStatus), "servers": servers,
            "default": bool(clusters[0].useAsDefault),
            "client_cert_expires": getattr(status.clientCertInfo, "notAfter", None) and str(status.clientCertInfo.notAfter)[:10]}


def configure(lab_spec):
    """Register the KMIP server as a Standard Key Provider in the management vCenter and establish trust."""
    cfg = kms_settings(lab_spec)
    si = _vc_connect(lab_spec)
    try:
        cm = si.content.cryptoManager
        pid = vim.encryption.KeyProviderId(id=cfg["provider"])
        liblog.print_logs(f"(Configure 1) Key provider {cfg['provider']} -> {cfg['fqdn']}:5696 in {_names(lab_spec)['vcenter']}.")
        server = vim.encryption.KmipServerSpec(clusterId=pid, info=vim.encryption.KmipServerInfo(
            name=cfg["server_name"], address=cfg["fqdn"], port=5696))
        existing = next((c for c in cm.ListKmipServers() if c.clusterId.id == cfg["provider"]), None)
        known = next((s for s in (existing.servers if existing else []) if s.name == cfg["server_name"]), None)
        if known is None:
            cm.RegisterKmipServer(server=server)
            liblog.print_logs("    Registered.")
        elif known.address != cfg["fqdn"] or known.port != 5696:
            cm.UpdateKmipServer(server=server)
            liblog.print_logs("    Address updated.")
        else:
            liblog.print_logs("    Already registered.")

        liblog.print_logs("(Configure 2) Trust: vCenter trusts the lab root; the KMS trusts vCenter's lab-CA client certificate.")
        root_pem = open(f"{libca.CA_DIR}/root_ca.crt").read()
        cm.UploadKmipServerCert(cluster=pid, certificate=root_pem)
        crt, key, new = vcenter_client_cert(lab_spec)
        cm.UploadClientCert(cluster=pid, certificate=crt, privateKey=key)
        liblog.print_logs(f"    Client certificate {'issued and ' if new else ''}uploaded "
                          f"(expires {libca.cert_info(x509.load_pem_x509_certificate(crt.encode()))['not_after']}).")
        if cfg["set_default"]:
            cm.MarkDefault(clusterId=pid)
            liblog.print_logs("    Marked as the default key provider.")

        liblog.print_logs("(Configure 3) Status.")
        st = None
        for _ in range(12):        # vCenter takes a moment to reconnect after the certificate changes
            st = provider_status(si, cfg["provider"])
            if st and st["overall"] == "green":
                break
            time.sleep(10)
        for s in (st or {}).get("servers", []):
            liblog.print_logs(f"    {s['name']}: {s['status']}, {s['connection']}, vCenter trusts KMS: {s['client_trusts_server']}, "
                              f"KMS trusts vCenter: {s['server_trusts_client']}")
        if not st or st["overall"] != "green":
            raise KmsError(f"key provider {cfg['provider']} is {st and st['overall']}, not green. "
                           "Check: kubectl -n kmip exec deploy/kmip -- tail -50 /data/log/server.log")

        liblog.print_logs("(Configure 4) Generate a test key through vCenter.")
        res = cm.GenerateKey(keyProvider=pid)
        if not res.success:
            raise KmsError(f"vCenter could not generate a key: {res.reason}")
        liblog.print_logs(f"    Key {res.keyId.keyId} generated by {cfg['provider']}.")
        try:
            cm.RemoveKeys(keys=[res.keyId], force=True)    # vCenter's cache only; the KMS keeps it
        except Exception:
            pass
    finally:
        Disconnect(si)
    backup_key_db(lab_spec)
    liblog.print_logs(f"Key provider {cfg['provider']} is green and issuing keys.")


def vsan_state(lab_spec, si=None):
    own = si is None
    si = si or _vc_connect(lab_spec)
    try:
        cluster = _cluster(si, lab_spec)
        info = _vsan_config_system(si, _names(lab_spec)["vcenter"]).GetConfigInfoEx(cluster)
        dek = info.dataEncryptionConfig
        dit = info.dataInTransitEncryptionConfig
        return {"cluster": cluster.name, "vsan_enabled": bool(info.enabled),
                "esa": bool(getattr(info, "vsanEsaEnabled", False)),
                "data_at_rest": bool(dek and dek.encryptionEnabled),
                "provider": dek.kmsProviderId.id if dek and dek.kmsProviderId else None,
                "changing": bool(dek and getattr(dek, "changing", False)),
                "in_transit": bool(dit and dit.enabled),
                "rekey_minutes": dit.rekeyInterval if dit else None}
    finally:
        if own:
            Disconnect(si)


def encrypt_vsan(lab_spec, in_transit_only=False):
    cfg = kms_settings(lab_spec)
    si = _vc_connect(lab_spec)
    try:
        before = vsan_state(lab_spec, si)
        liblog.print_logs(f"(Encrypt 1) {before['cluster']}: data-at-rest={before['data_at_rest']} "
                          f"(provider {before['provider']}), in-transit={before['in_transit']}, "
                          f"{'ESA' if before['esa'] else 'OSA'}.")
        if not before["vsan_enabled"]:
            raise KmsError(f"vSAN is not enabled on {before['cluster']}.")
        spec = vim.vsan.ReconfigSpec(modify=True)
        if not before["in_transit"]:
            spec.dataInTransitEncryptionConfig = vim.vsan.DataInTransitEncryptionConfig(
                enabled=True, rekeyInterval=cfg["dit_rekey_minutes"])
        rest_needed = not in_transit_only and not (before["data_at_rest"] and before["provider"] == cfg["provider"])
        if rest_needed:
            st = provider_status(si, cfg["provider"])
            if not st or st["overall"] != "green":
                raise KmsError(f"key provider {cfg['provider']} is not green ({st and st['overall']}): run -m12 --configure first.")
            spec.dataEncryptionConfig = vim.vsan.DataEncryptionConfig(
                encryptionEnabled=True, kmsProviderId=vim.encryption.KeyProviderId(id=cfg["provider"]),
                eraseDisksBeforeUse=False)
            spec.allowReducedRedundancy = cfg["allow_reduced_redundancy"]
            if not before["esa"]:
                liblog.print_logs("    vSAN OSA: enabling data-at-rest reformats each disk group in turn "
                                  "(about an hour per host). VMs keep running.")
        if spec.dataInTransitEncryptionConfig is None and spec.dataEncryptionConfig is None:
            liblog.print_logs("Nothing to do: the requested vSAN encryption is already on.")
            return before
        what = " + ".join(x for x, on in (("data-in-transit", spec.dataInTransitEncryptionConfig is not None),
                                          ("data-at-rest", spec.dataEncryptionConfig is not None)) if on)
        liblog.print_logs(f"(Encrypt 2) Enable {what} on {before['cluster']}.")
        task = _vsan_config_system(si, _names(lab_spec)["vcenter"]).ReconfigureEx(_cluster(si, lab_spec), spec)
        _wait(vim.Task(task._moId, si._stub), f"vSAN {what}", 48 * 3600, every_s=60, progress=True)
        after = vsan_state(lab_spec, si)
        liblog.print_logs(f"(Encrypt 3) {after['cluster']}: data-at-rest={after['data_at_rest']} "
                          f"(provider {after['provider']}), in-transit={after['in_transit']}.")
    finally:
        Disconnect(si)
    if spec.dataEncryptionConfig is not None:
        backup_key_db(lab_spec)     # the cluster's key-encryption key now lives in the KMS database
    return after


# ---------------------------------------------------------------- evidence report (-m12 --report)

def evidence_report(lab_spec, out_dir="conf/evidence"):
    cfg = kms_settings(lab_spec)
    now = datetime.datetime.now()
    rep = {"generated": now.strftime("%Y-%m-%d %H:%M:%S"), "kms": {"endpoint": f"{cfg['fqdn']}:5696", "ip": cfg["ip"],
           "provider": cfg["provider"], "software": "PyKMIP 0.10.0 (lab-grade KMIP server)"}, "checks": []}

    def check(name, ok, detail=""):
        rep["checks"].append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
        liblog.print_logs(f"    {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))

    liblog.print_logs("(Report 1) KMIP server.")
    rep["checks"] += test_kms(lab_spec)["checks"]
    liblog.print_logs("(Report 2) Key provider in vCenter.")
    si = _vc_connect(lab_spec)
    try:
        st = provider_status(si, cfg["provider"])
        rep["provider"] = st
        check(f"Key provider {cfg['provider']} registered", st is not None)
        if st:
            check("Key provider health is green", st["overall"] == "green", st["overall"])
            for s in st["servers"]:
                check(f"{s['name']}: vCenter trusts the KMS and the KMS trusts vCenter",
                      bool(s["client_trusts_server"] and s["server_trusts_client"]),
                      f"{s['connection']}, server cert expires {s['server_cert_expires']}, "
                      f"client cert expires {st['client_cert_expires']}")
        liblog.print_logs("(Report 3) vSAN encryption.")
        vs = vsan_state(lab_spec, si)
        rep["vsan"] = vs
        check("vSAN data-at-rest encryption enabled with this key provider",
              vs["data_at_rest"] and vs["provider"] == cfg["provider"] and not vs["changing"],
              f"{vs['cluster']}: provider {vs['provider']}" + (", still converting" if vs["changing"] else ""))
        check("vSAN data-in-transit encryption enabled", vs["in_transit"], f"rekey every {vs['rekey_minutes']} min")
    finally:
        Disconnect(si)
    liblog.print_logs("(Report 4) Key database backup.")
    try:
        b = backup_key_db(lab_spec)
        rep["key_backup"] = b
        check("Key database backed up", True, f"{b['objects']} objects -> {b['local']}" + (f" and {b['sftp']}" if b["sftp"] else ""))
    except Exception as e:
        check("Key database backed up", False, str(e)[:150])

    rep["result"] = "PASS" if all(c["result"] == "PASS" for c in rep["checks"]) else "FAIL"
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"kms_evidence_{now.strftime('%Y%m%d-%H%M%S')}")
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2, default=str)
    with open(base + ".md", "w") as f:
        f.write(_report_markdown(rep))
    liblog.print_logs(f"Evidence report: {rep['result']}  ->  {base}.md  (+ .json)")
    return rep


def _report_markdown(rep):
    k = rep["kms"]
    L = ["# Key management evidence: KMIP key provider and vSAN encryption", "",
         f"Generated {rep['generated']} by Theogony -m12 --report. **Overall: {rep['result']}**. No keys appear in this report.", "",
         f"KMS: `{k['endpoint']}` ({k['ip']}), {k['software']}, registered in vCenter as Standard Key Provider `{k['provider']}`. "
         "Certificates on both sides are issued by the lab CA. Note: the design (TR-003/US-009) specifies the vSphere "
         "Native Key Provider; this lab uses a KMIP Standard Key Provider instead.", "",
         "## Checks", "", "| Result | Check | Detail |", "|---|---|---|"]
    L += [f"| {c['result']} | {c['check']} | {c['detail']} |" for c in rep["checks"]]
    if rep.get("vsan"):
        v = rep["vsan"]
        L += ["", "## vSAN", "", "| Cluster | Architecture | Data-at-rest | Key provider | Data-in-transit | Rekey |",
              "|---|---|---|---|---|---|",
              f"| {v['cluster']} | {'ESA' if v['esa'] else 'OSA'} | {'on' if v['data_at_rest'] else 'off'} | {v['provider'] or '-'} | "
              f"{'on' if v['in_transit'] else 'off'} | {v['rekey_minutes']} min |"]
    return "\n".join(L) + "\n"
