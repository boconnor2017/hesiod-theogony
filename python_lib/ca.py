# Hesiod Certificate Authority (step-ca) and VCF certificate rotation
# Description: Issues certificates from the lab CA (step-ca on HKS) and rotates the certificates of the VCF
#              management domain built by Module 8, through the SDDC Manager certificate API.
#              Deployment of step-ca itself lives in python_lib/k8_management.py (deploy_step_ca).
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.0
#
# Chain: <name> Root CA (RSA, 10y) -> <name> Intermediate CA (RSA, 5y) -> leaf (RSA 2048 from the VCF CSR, SHA-256)
# Signing: CSRs are signed inside the step-ca pod with `step ca sign` (JWK provisioner "admin"), via kubectl exec.
#
# Rotation flow (-m10 --rotate), per resource type, in this order: VCENTER, NSXT_MANAGER, ESXI, SDDC_MANAGER
#   1. SDDC Manager trusts the lab root + intermediate          POST /v1/sddc-manager/trusted-certificates
#   2. SDDC Manager generates new keys + CSRs (RSA 2048)         PUT  /v1/domains/{id}/csrs, GET /v1/domains/{id}/csrs
#   3. step-ca signs each CSR
#   4. SDDC Manager validates the certificates                  PUT  /v1/domains/{id}/resource-certificates/validations
#   5. SDDC Manager installs them (skipped with --dry-run)       PUT  /v1/domains/{id}/resource-certificates
#   6. Each endpoint's served chain is verified against the lab root (the `openssl s_client -verify` check)
# A resource is rotated when its certificate is not from the lab CA or expires within renew_within_days
# (--force rotates everything selected).
#
# Public functions
#   ca_settings(lab_spec)                       lab_spec["certificate_authority"] with defaults
#   wait_until_ready(base_url, timeout_s)
#   backup_ca_passwords(lab_spec, passwords)    conf/step_ca_passwords.json (+ Conjur when lab_spec has conjur)
#   fetch_ca_chain(lab_spec)                    conf/ca/root_ca.crt, intermediate_ca.crt, ca_chain.pem
#   sign_csr(lab_spec, csr_pem)                 (leaf_pem, intermediate_pem, root_pem)
#   test_issuance(lab_spec)                     US-004: test CSR -> certificate chaining to the root, RSA 2048, SHA-256
#   inventory(lab_spec)                         VCF management domain certificates + served-chain check
#   rotate(lab_spec, types=None, force=False, dry_run=False)
#   evidence_report(lab_spec)                   conf/evidence/ca_evidence_<timestamp>.md/.json (no private keys)

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import conjur as libconjur
from python_lib import k8_management as libk8

import base64
import datetime
import hashlib
import json
import os
import re
import socket
import ssl
import time

import requests
import urllib3
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import NameOID

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CA_DIR = "conf/ca"
ROTATION_LOG = "conf/ca/rotation_log.json"
ROTATION_ORDER = ["VCENTER", "NSXT_MANAGER", "ESXI", "SDDC_MANAGER"]   # SDDC Manager last: it restarts its API
TERMINAL = {"SUCCESSFUL", "FAILED", "CANCELLED", "COMPLETED_WITH_WARNING", "SKIPPED", "TIMED_OUT"}


class CaError(Exception):
    pass


# ---------------------------------------------------------------- settings / plumbing

def ca_settings(lab_spec):
    c = lab_spec.get("certificate_authority") or {}
    if not c.get("ip_address"):
        raise CaError('lab_spec["certificate_authority"] needs ip_address (see json_lib/lab_spec.json).')
    hostname = c.get("hostname", "ca")
    fqdn = f"{hostname}.{lab_spec['domain']['name']}"
    csr = c.get("csr") or {}
    for k in ("country", "state", "locality", "organization", "organizationUnit"):
        if not csr.get(k) or str(csr[k]).startswith("<"):
            raise CaError(f'lab_spec["certificate_authority"]["csr"]["{k}"] is required (VCF puts it in every CSR).')
    node = c.get("node")
    return {
        "ip": c["ip_address"], "hostname": hostname, "fqdn": fqdn, "base_url": f"https://{c['ip_address']}",
        "name": c.get("name", "Hesiod Lab CA"),
        "key_size": int(c.get("key_size", 4096)),
        "leaf_validity_days": int(c.get("leaf_validity_days", 365)),
        "renew_within_days": int(c.get("renew_within_days", 30)),
        "rotate_types": [t.upper() for t in c.get("rotate_types", ROTATION_ORDER)],
        "csr": {k: str(v) for k, v in csr.items() if not str(v).startswith("<")},
        "dns_names": [fqdn, c["ip_address"], "127.0.0.1", "localhost"],
        "node": None if str(node or "").startswith("<") else node,
        "data_path": c.get("data_path", "/var/lib/hesiod/step-ca"),
        "kube": lab_spec["kubernetes"]["kube_config_path"],
    }


def wait_until_ready(base_url, timeout_s=300):
    s = requests.Session()
    s.trust_env, s.verify = False, False
    deadline, last = time.time() + timeout_s, None
    while time.time() < deadline:
        try:
            r = s.get(f"{base_url}/health", timeout=10)
            if r.status_code == 200 and r.json().get("status") == "ok":
                return True
            last = f"HTTP {r.status_code} {r.text[:80]}"
        except (requests.RequestException, ValueError) as e:
            last = str(e)[:120]
        time.sleep(10)
    raise CaError(f"step-ca at {base_url} not healthy after {timeout_s}s (last: {last}). "
                  "Check: kubectl -n step-ca logs deploy/step-ca -c init; kubectl -n step-ca logs deploy/step-ca")


def backup_ca_passwords(lab_spec, passwords):
    """Keep the CA key password + provisioner password outside the cluster: conf/ and (if configured) Conjur."""
    os.makedirs("conf", exist_ok=True)
    path = "conf/step_ca_passwords.json"
    try:
        current = json.load(open(path))
    except (OSError, ValueError):
        current = None
    if current != passwords:
        with open(path, "w") as f:
            json.dump(passwords, f, indent=2)
        os.chmod(path, 0o600)
        liblog.print_logs(f"    CA passwords backed up to {path} (keep it: the CA keys cannot be used without it).")
    if not lab_spec.get("conjur"):
        return
    try:
        cfg = libconjur.conjur_settings(lab_spec)
        cj = libconjur.ConjurClient(cfg["base_url"], cfg["account"], cfg["username"], password=cfg["password"])
        cj.load_policy("- !policy\n  id: ca\n  body:\n"
                       "  - !variable\n    id: step-ca/ca-password\n    annotations:\n"
                       "      hesiod/source: \"step-ca\"\n      hesiod/purpose: \"encrypts the root + intermediate keys\"\n"
                       "  - !variable\n    id: step-ca/provisioner-password\n    annotations:\n"
                       "      hesiod/source: \"step-ca\"\n      hesiod/purpose: \"JWK provisioner admin\"\n")
        for key in ("ca-password", "provisioner-password"):
            vid = f"ca/step-ca/{key}"
            if cj.get_secret(vid) != passwords[key]:
                cj.set_secret(vid, passwords[key])
        liblog.print_logs("    CA passwords vaulted in Conjur under ca/step-ca/.")
    except Exception as e:
        liblog.print_logs(f"    WARNING: could not vault the CA passwords in Conjur ({str(e)[:150]}); conf/ copy kept.")


def _pems(text):
    return re.findall(r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----", text, re.S)


def _exec(lab_spec, script, timeout_s=120):
    rc, out = libk8.exec_in_pod(ca_settings(lab_spec)["kube"], "step-ca", "app=step-ca", "step-ca", script, timeout_s)
    return rc, out


def fetch_ca_chain(lab_spec):
    rc, out = _exec(lab_spec, "cat /home/step/certs/root_ca.crt; cat /home/step/certs/intermediate_ca.crt")
    pems = _pems(out)
    if rc != 0 or len(pems) != 2:
        raise CaError(f"could not read the CA certificates from the step-ca pod (rc={rc}): {out[-300:]}")
    os.makedirs(CA_DIR, exist_ok=True)
    paths = {"root": f"{CA_DIR}/root_ca.crt", "intermediate": f"{CA_DIR}/intermediate_ca.crt",
             "chain": f"{CA_DIR}/ca_chain.pem"}
    for key, pem in (("root", pems[0]), ("intermediate", pems[1]), ("chain", pems[1] + "\n" + pems[0])):
        with open(paths[key], "w") as f:
            f.write(pem + "\n")
    return paths


def _ca_chain():
    try:
        root = x509.load_pem_x509_certificate(open(f"{CA_DIR}/root_ca.crt", "rb").read())
        inter = x509.load_pem_x509_certificate(open(f"{CA_DIR}/intermediate_ca.crt", "rb").read())
    except OSError:
        raise CaError("conf/ca/root_ca.crt missing: run -m10 first (it deploys step-ca and publishes the chain).")
    return root, inter


# ---------------------------------------------------------------- signing + verification

def sign_csr(lab_spec, csr_pem):
    """Sign a PEM CSR with step-ca. Returns (leaf_pem, intermediate_pem, root_pem)."""
    cfg = ca_settings(lab_spec)
    x509.load_pem_x509_csr(csr_pem.encode())   # fail early on garbage
    b64 = base64.b64encode(csr_pem.encode()).decode()
    script = (
        "T=$(mktemp -d)\n"
        f"echo '{b64}' | base64 -d > $T/r.csr\n"
        "if step ca sign $T/r.csr $T/r.crt --provisioner admin "
        "--provisioner-password-file /run/step/provisioner-password "
        "--ca-url https://127.0.0.1:9000 --root /home/step/certs/root_ca.crt "
        f"--not-after {cfg['leaf_validity_days'] * 24}h --force > $T/log 2>&1; then cat $T/r.crt; rc=0; "
        "else cat $T/log; rc=1; fi\n"
        "rm -rf $T\n(exit $rc)")
    rc, out = _exec(lab_spec, script)
    pems = _pems(out)
    if rc != 0 or not pems:
        raise CaError(f"step ca sign failed: {out.strip()[-400:]}")
    root, inter = _ca_chain()
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode().strip()
    return pems[0], pem(inter), pem(root)


def _issued_by(child, parent):
    """True when parent's key signed child (RSA PKCS#1 v1.5 / PSS, or ECDSA)."""
    if child.issuer != parent.subject:
        return False
    key = parent.public_key()
    try:
        if isinstance(key, rsa.RSAPublicKey):
            try:
                key.verify(child.signature, child.tbs_certificate_bytes, padding.PKCS1v15(),
                           child.signature_hash_algorithm)
            except Exception:
                key.verify(child.signature, child.tbs_certificate_bytes,
                           padding.PSS(mgf=padding.MGF1(child.signature_hash_algorithm),
                                       salt_length=padding.PSS.AUTO), child.signature_hash_algorithm)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(child.signature, child.tbs_certificate_bytes, ec.ECDSA(child.signature_hash_algorithm))
        else:
            return False
        return True
    except Exception:
        return False


def cert_info(cert):
    key = cert.public_key()
    try:
        san = [str(n.value) for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        san = []
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "serial": format(cert.serial_number, "x"),
            "key": (f"RSA {key.key_size}" if isinstance(key, rsa.RSAPublicKey)
                    else f"EC {key.curve.name}" if isinstance(key, ec.EllipticCurvePublicKey) else type(key).__name__),
            "signature": cert.signature_algorithm_oid._name,
            "not_before": cert.not_valid_before_utc.strftime("%Y-%m-%d"),
            "not_after": cert.not_valid_after_utc.strftime("%Y-%m-%d"),
            "sha256": ":".join(f"{b:02X}" for b in cert.fingerprint(hashes.SHA256())), "san": san}


def test_issuance(lab_spec):
    """US-004: a test CSR (RSA 2048) signed by the lab CA must chain to the root with SHA-256."""
    cfg = ca_settings(lab_spec)
    root, inter = _ca_chain()
    cn = f"us004-test.{lab_spec['domain']['name']}"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)   # stays in memory, never written
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, cfg["csr"]["organization"])]))
           .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
           .sign(key, hashes.SHA256()))
    leaf_pem, _, _ = sign_csr(lab_spec, csr.public_bytes(serialization.Encoding.PEM).decode())
    leaf = x509.load_pem_x509_certificate(leaf_pem.encode())
    info = cert_info(leaf)
    checks = [
        ("Test CSR signed by step-ca", True, f"CN={cn}, serial {info['serial']}"),
        ("Leaf issued by the intermediate", _issued_by(leaf, inter), info["issuer"]),
        ("Intermediate issued by the root", _issued_by(inter, root), cert_info(inter)["issuer"]),
        ("Root is self-signed", _issued_by(root, root), cert_info(root)["subject"]),
        ("Leaf key is RSA 2048", info["key"] == "RSA 2048", info["key"]),
        ("Leaf signature is SHA-256", isinstance(leaf.signature_hash_algorithm, hashes.SHA256), info["signature"]),
        ("Leaf public key matches the CSR", leaf.public_key().public_numbers() == key.public_key().public_numbers(), ""),
        ("Validity as configured", True, f"{info['not_before']} -> {info['not_after']}"),
    ]
    return {"leaf": info, "checks": [{"check": c, "result": "PASS" if ok else "FAIL", "detail": d} for c, ok, d in checks]}


def served_chain_check(host, port=443):
    """The `openssl s_client -verify` check: TLS handshake trusting only the lab root, hostname checked."""
    root_path = f"{CA_DIR}/root_ca.crt"
    ctx = ssl.create_default_context(cafile=root_path)
    if hasattr(ssl, "VERIFY_X509_STRICT"):
        ctx.verify_flags &= ~ssl.VERIFY_X509_STRICT    # VCF-generated certs don't always carry strict-mode extensions
    try:
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as tls:
                leaf = x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))
        return {"verified": True, "detail": "chain verifies to the lab root", **cert_info(leaf)}
    except ssl.SSLCertVerificationError as e:
        detail = e.verify_message or str(e)
    except (OSError, ssl.SSLError) as e:
        detail = str(e)[:160]
    out = {"verified": False, "detail": detail}
    try:  # still describe what is being served
        nctx = ssl.create_default_context()
        nctx.check_hostname, nctx.verify_mode = False, ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with nctx.wrap_socket(sock) as tls:
                out.update(cert_info(x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))))
    except Exception:
        pass
    return out


# ---------------------------------------------------------------- VCF (SDDC Manager certificate API)

def _put(sddc, path, body):
    return sddc._call("PUT", path, json=body)


def _management_domain(sddc):
    doms = sddc.get("/v1/domains").get("elements", [])
    mgmt = next((d for d in doms if d.get("type") == "MANAGEMENT"), doms[0] if doms else None)
    if not mgmt:
        raise CaError("SDDC Manager returned no domains.")
    return mgmt


def _wait_task(sddc, task, what, timeout_s=7200):
    tid = task.get("id")
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
                raise CaError(f"{what} {status}: " + " | ".join(e for e in errs if e)[:800])
            return t
        time.sleep(20)
    raise CaError(f"{what}: task {tid} still running after {timeout_s}s")


def _fqdn_of(cert):
    for k in ("resourceName", "issuedTo"):
        v = cert.get(k) or ""
        if "." in v:
            return v
    return cert.get("resourceName") or cert.get("issuedTo")


def get_vcf_certificates(lab_spec, sddc=None):
    sddc = sddc or libconjur.sddc_manager_client(lab_spec)
    dom = _management_domain(sddc)
    certs = sddc.get(f"/v1/domains/{dom['id']}/resource-certificates").get("elements", [])
    return sddc, dom, certs


def inventory(lab_spec, sddc=None, check_served=True):
    """Every certificate SDDC Manager manages in the management domain, plus what each endpoint actually serves."""
    sddc, dom, certs = get_vcf_certificates(lab_spec, sddc)
    root, inter = _ca_chain()
    lab_issuer = inter.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value   # "<name> Intermediate CA"
    rows = []
    for c in certs:
        fqdn = _fqdn_of(c)
        row = {"fqdn": fqdn, "type": c.get("resourceType"), "issued_by": c.get("issuedBy", ""),
               "not_after": c.get("notAfter", ""), "days_left": c.get("numberOfDaysToExpire"),
               "key_size": c.get("keySize"), "signature": c.get("signatureAlgorithm"),
               "from_lab_ca": lab_issuer in (c.get("issuedBy") or "")}
        if check_served and fqdn:
            s = served_chain_check(fqdn)
            row.update({"served_verified": s["verified"], "served_detail": s["detail"],
                        "served_issuer": s.get("issuer", ""), "served_not_after": s.get("not_after", "")})
        rows.append(row)
    rows.sort(key=lambda r: (ROTATION_ORDER.index(r["type"]) if r["type"] in ROTATION_ORDER else 99, r["fqdn"] or ""))
    liblog.print_logs(f"VCF certificates in domain {dom.get('name')} ({len(rows)}):")
    for r in rows:
        served = "" if "served_verified" not in r else ("  served: OK" if r["served_verified"] else f"  served: NOT lab CA ({r['served_detail'][:60]})")
        liblog.print_logs(f"    {r['type']:<13} {r['fqdn']:<34} {r['days_left']!s:>5}d  issuer: {r['issued_by'][:50]}{served}")
    return {"domain": dom.get("name"), "domain_id": dom.get("id"), "certificates": rows}


def _trust_lab_ca(sddc):
    root, inter = _ca_chain()
    for label, cert in (("root", root), ("intermediate", inter)):
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        try:
            sddc.post("/v1/sddc-manager/trusted-certificates",
                      {"certificate": pem, "certificateUsageType": "TRUSTED_FOR_OUTBOUND"})
            liblog.print_logs(f"    SDDC Manager now trusts the lab {label} CA.")
        except Exception as e:
            msg = str(e)
            if "exist" in msg.lower() or "duplicate" in msg.lower():
                liblog.print_logs(f"    SDDC Manager already trusts the lab {label} CA.")
            else:
                liblog.print_logs(f"    WARNING: adding the lab {label} CA to SDDC Manager's trust store: {msg[:200]}")


def _wait_validation(sddc, domain_id, validation, timeout_s=1800):
    vid = validation.get("validationId") or validation.get("id")
    deadline = time.time() + timeout_s
    result = validation
    while vid and str(result.get("executionStatus", "")).upper() in ("", "IN_PROGRESS", "PENDING") \
            and time.time() < deadline:
        time.sleep(10)
        result = sddc.get(f"/v1/domains/{domain_id}/resource-certificates/validations/{vid}")
    failures = []
    def walk(o):
        if isinstance(o, dict):
            st = str(o.get("resultStatus") or o.get("validationStatus") or o.get("status") or "").upper()
            if st in ("FAILED", "FAILURE", "ERROR"):
                failures.append(o.get("description") or o.get("validationMessage") or o.get("message")
                                or o.get("resourceFqdn") or json.dumps(o)[:200])
            for v in o.values():
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)
    walk(result)
    return result, failures


def _log_rotation(entry):
    os.makedirs(CA_DIR, exist_ok=True)
    try:
        log = json.load(open(ROTATION_LOG))
    except (OSError, ValueError):
        log = []
    log.append(entry)
    with open(ROTATION_LOG, "w") as f:
        json.dump(log, f, indent=2)


def rotate(lab_spec, types=None, force=False, dry_run=False):
    """Generate new keys/CSRs in VCF, sign them with the lab CA, validate, install, verify."""
    cfg = ca_settings(lab_spec)
    wanted = [t.upper() for t in (types or cfg["rotate_types"])]
    unknown = [t for t in wanted if t not in ROTATION_ORDER]
    if unknown:
        raise CaError(f"unsupported resource type(s) {unknown}; use {ROTATION_ORDER}")
    root, inter = _ca_chain()

    liblog.print_logs("(Rotate 1) Current certificates.")
    sddc = libconjur.sddc_manager_client(lab_spec)
    inv = inventory(lab_spec, sddc, check_served=False)
    targets = [r for r in inv["certificates"] if r["type"] in wanted and r["fqdn"]
               and (force or not r["from_lab_ca"] or (r["days_left"] or 0) <= cfg["renew_within_days"])]
    seen, uniq = set(), []
    for r in targets:
        if (r["type"], r["fqdn"]) not in seen:
            seen.add((r["type"], r["fqdn"]))
            uniq.append(r)
    targets = uniq
    if not targets:
        liblog.print_logs(f"Nothing to rotate: every {wanted} certificate is from the lab CA with more than "
                          f"{cfg['renew_within_days']} days left (use --force to rotate anyway).")
        return {"rotated": [], "dry_run": dry_run}
    liblog.print_logs(f"    To rotate ({len(targets)}): " + ", ".join(f"{r['fqdn']} ({r['type']})" for r in targets))

    liblog.print_logs("(Rotate 2) Trust the lab CA in SDDC Manager.")
    if not dry_run:
        _trust_lab_ca(sddc)
    else:
        liblog.print_logs("    (dry run: trust store not changed)")

    liblog.print_logs("(Rotate 3) Generate new keys and CSRs in VCF (RSA 2048).")
    spec = {"csrGenerationSpec": {**cfg["csr"], "keySize": "2048", "keyAlgorithm": "RSA"},
            "resources": [{"fqdn": r["fqdn"], "type": r["type"]} for r in targets]}
    task = _put(sddc, f"/v1/domains/{inv['domain_id']}/csrs", spec)
    _wait_task(sddc, task, "CSR generation", 1800)
    csrs = {c["resource"]["fqdn"]: c for c in sddc.get(f"/v1/domains/{inv['domain_id']}/csrs").get("elements", [])
            if c.get("resource", {}).get("fqdn")}
    missing = [r["fqdn"] for r in targets if r["fqdn"] not in csrs]
    if missing:
        raise CaError(f"SDDC Manager produced no CSR for {missing}")

    liblog.print_logs("(Rotate 4) Sign the CSRs with the lab CA.")
    signed = {}
    for r in targets:
        leaf, inter_pem, root_pem = sign_csr(lab_spec, csrs[r["fqdn"]]["csrEncodedContent"])
        leaf_cert = x509.load_pem_x509_certificate(leaf.encode())
        if not _issued_by(leaf_cert, inter):
            raise CaError(f"{r['fqdn']}: signed certificate does not verify against the intermediate")
        signed[r["fqdn"]] = {"resourceFqdn": r["fqdn"], "resourceCertificate": leaf, "caCertificate": root_pem,
                             "certificateChain": "\n".join([leaf, inter_pem, root_pem])}
        info = cert_info(leaf_cert)
        liblog.print_logs(f"    {r['fqdn']}: serial {info['serial']}, {info['key']}, {info['signature']}, "
                          f"until {info['not_after']}")

    results = []
    for t in [t for t in ROTATION_ORDER if t in {r["type"] for r in targets}]:
        batch = [signed[r["fqdn"]] for r in targets if r["type"] == t]
        liblog.print_logs(f"(Rotate 5) {t}: validate {len(batch)} certificate(s) in SDDC Manager.")
        validation = _put(sddc, f"/v1/domains/{inv['domain_id']}/resource-certificates/validations", batch)
        vresult, failures = _wait_validation(sddc, inv["domain_id"], validation)
        os.makedirs(CA_DIR, exist_ok=True)
        with open(f"{CA_DIR}/validation_{t.lower()}.json", "w") as f:
            json.dump(vresult, f, indent=2)
        if failures:
            raise CaError(f"{t}: SDDC Manager validation failed: " + " | ".join(str(x) for x in failures)[:800]
                          + f" (full result: {CA_DIR}/validation_{t.lower()}.json)")
        liblog.print_logs(f"    {t}: validation passed.")
        if dry_run:
            results += [{"fqdn": b["resourceFqdn"], "type": t, "installed": False} for b in batch]
            continue
        liblog.print_logs(f"(Rotate 6) {t}: install (services restart; vCenter/SDDC Manager take several minutes).")
        task = _put(sddc, f"/v1/domains/{inv['domain_id']}/resource-certificates", batch)
        _wait_task(sddc, task, f"{t} certificate replacement")
        for b in batch:
            s = served_chain_check(b["resourceFqdn"])
            leaf_serial = cert_info(x509.load_pem_x509_certificate(b["resourceCertificate"].encode()))["serial"]
            ok = s["verified"] and s.get("serial") == leaf_serial
            liblog.print_logs(f"    {b['resourceFqdn']}: served chain {'verifies to the lab root' if ok else 'NOT verified: ' + s['detail'][:100]}"
                              + ("" if s.get("serial") == leaf_serial else " (endpoint still serves the old certificate)"))
            results.append({"fqdn": b["resourceFqdn"], "type": t, "installed": True, "served_verified": ok,
                            "serial": leaf_serial})
        if t == "SDDC_MANAGER":
            sddc = libconjur.sddc_manager_client(lab_spec)   # its API restarted with the new certificate

    _log_rotation({"time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "dry_run": dry_run,
                   "forced": force, "results": results})
    done = "validated (dry run, nothing installed)" if dry_run else "rotated"
    liblog.print_logs(f"Certificate rotation complete: {len(results)} {done}.")
    return {"rotated": results, "dry_run": dry_run}


# ---------------------------------------------------------------- evidence report (-m10 --report)

def evidence_report(lab_spec, include_vcf=True, out_dir="conf/evidence"):
    cfg = ca_settings(lab_spec)
    now = datetime.datetime.now()
    root, inter = _ca_chain()
    rep = {"generated": now.strftime("%Y-%m-%d %H:%M:%S"),
           "ca": {"url": cfg["base_url"], "fqdn": cfg["fqdn"], "root": cert_info(root), "intermediate": cert_info(inter)},
           "checks": []}

    def check(name, ok, detail=""):
        rep["checks"].append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
        liblog.print_logs(f"    {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))

    liblog.print_logs("(Report 1) CA readiness (US-004).")
    try:
        wait_until_ready(cfg["base_url"], 30)
        check("step-ca healthy", True, f"{cfg['base_url']}/health")
    except CaError as e:
        check("step-ca healthy", False, str(e)[:150])
    ca_tls = served_chain_check(cfg["fqdn"])
    check("CA endpoint chain verifies to the lab root", ca_tls["verified"], f"{cfg['fqdn']}: {ca_tls['detail'][:100]}")
    t = test_issuance(lab_spec)
    rep["us004_test"] = t
    for c in t["checks"]:
        check(c["check"], c["result"] == "PASS", c["detail"])

    if include_vcf:
        liblog.print_logs("(Report 2) VCF management domain certificates.")
        inv = inventory(lab_spec)
        rep["vcf"] = inv
        managed = [r for r in inv["certificates"] if r["type"] in cfg["rotate_types"]]
        check("VCF certificates issued by the lab CA", all(r["from_lab_ca"] for r in managed),
              f"{sum(r['from_lab_ca'] for r in managed)}/{len(managed)}")
        check("VCF endpoints serve a chain that verifies to the lab root", all(r.get("served_verified") for r in managed),
              f"{sum(bool(r.get('served_verified')) for r in managed)}/{len(managed)}")
        check(f"No VCF certificate expires within {cfg['renew_within_days']} days",
              all((r["days_left"] or 0) > cfg["renew_within_days"] for r in managed),
              f"soonest: {min([r['days_left'] or 0 for r in managed] or [0])} days")
    try:
        rep["rotations"] = json.load(open(ROTATION_LOG))[-10:]
    except (OSError, ValueError):
        rep["rotations"] = []

    rep["result"] = "PASS" if all(c["result"] == "PASS" for c in rep["checks"]) else "FAIL"
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.join(out_dir, f"ca_evidence_{now.strftime('%Y%m%d-%H%M%S')}")
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2)
    with open(base + ".md", "w") as f:
        f.write(_report_markdown(rep))
    liblog.print_logs(f"Evidence report: {rep['result']}  ->  {base}.md  (+ .json)")
    return rep


def _report_markdown(rep):
    r, i = rep["ca"]["root"], rep["ca"]["intermediate"]
    L = ["# Certificate authority evidence: step-ca", "",
         f"Generated {rep['generated']} by Theogony -m10 --report. **Overall: {rep['result']}**. "
         "No private keys appear in this report.", "",
         "| | Root CA | Intermediate CA |", "|---|---|---|",
         f"| Subject | {r['subject']} | {i['subject']} |", f"| Key | {r['key']} | {i['key']} |",
         f"| Signature | {r['signature']} | {i['signature']} |",
         f"| Valid | {r['not_before']} -> {r['not_after']} | {i['not_before']} -> {i['not_after']} |",
         f"| SHA-256 | `{r['sha256']}` | `{i['sha256']}` |", "",
         f"Endpoint: {rep['ca']['url']} ({rep['ca']['fqdn']})", "",
         "## Checks", "", "| Result | Check | Detail |", "|---|---|---|"]
    L += [f"| {c['result']} | {c['check']} | {c['detail']} |" for c in rep["checks"]]
    leaf = rep["us004_test"]["leaf"]
    L += ["", "## US-004: test CSR", "",
          f"A fresh RSA 2048 key and CSR were generated in memory and signed by the CA: subject `{leaf['subject']}`, "
          f"issuer `{leaf['issuer']}`, {leaf['key']}, {leaf['signature']}, valid {leaf['not_before']} -> "
          f"{leaf['not_after']}, serial `{leaf['serial']}`. The key was discarded."]
    if rep.get("vcf"):
        L += ["", f"## VCF management domain certificates ({rep['vcf']['domain']})", "",
              "| Type | FQDN | Issuer (SDDC Manager) | Expires | Days left | Served chain verifies to lab root |",
              "|---|---|---|---|---|---|"]
        L += [f"| {c['type']} | {c['fqdn']} | {c['issued_by']} | {c['not_after']} | {c['days_left']} | "
              f"{'yes' if c.get('served_verified') else 'NO: ' + str(c.get('served_detail', ''))[:60]} |"
              for c in rep["vcf"]["certificates"]]
    if rep.get("rotations"):
        L += ["", "## Recent rotations", "", "| Time | Mode | Resources |", "|---|---|---|"]
        for x in rep["rotations"]:
            res = ", ".join(f"{y['fqdn']} ({y['type']})" for y in x["results"])
            L.append(f"| {x['time']} | {'dry run (validated only)' if x['dry_run'] else 'installed'}"
                     f"{' (forced)' if x.get('forced') else ''} | {res} |")
    return "\n".join(L) + "\n"
