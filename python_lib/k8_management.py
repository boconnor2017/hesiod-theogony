# Description: Contains all necessary functions to run and manage kubernetes services
# Author: Brendan O'Connor
# Version: 2.5 (wait_for_rollout after pod restarts: deploy_sftp, deploy_kmip)
# Date: November 2026

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std
from python_lib import logs_and_headers as liblog
from python_lib import os_management as libos
from python_lib import vmware as libvmw
from python_lib import dns_management as libdns

def apply_from_yaml_old(local_kube_config_path, yaml_file_path, namespace):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CustomObjectsApi()
    liblog.print_logs(f"Applying {yaml_file_path} to the cluster.")
    with open(yaml_file_path, 'r') as file:
        resources = std.yaml.safe_load_all(file)
        for resource in resources:
            if not resource:
                continue
            api_version_split = resource["apiVersion"].split("/")
            group = api_version_split[0]
            version = api_version_split[1]
            plural = resource["kind"].lower() + "s"
            namespace = resource["metadata"].get("namespace", namespace)
            name = resource["metadata"]["name"]
            try:
                v1.create_namespaced_custom_object(
                    group=group,
                    version=version,
                    namespace=namespace,
                    plural=plural,
                    body=resource
                )
                liblog.print_logs(f"Successfully created resource.")
            except std.ApiException as e:
                if e.status == 409:
                    liblog.print_logs(f"Resource {resource['kind']} '{name}' already exists. Skipping.")
                else:
                    liblog.print_logs(f"Failed to create {resource['kind']} '{name}': {e}")

def apply_from_yaml(local_kube_config_path, yaml_file_path, default_namespace="default"):
    # 1. Load configuration and create the DYNAMIC client
    std.config.load_kube_config(config_file=local_kube_config_path)
    k8s_client = std.client.ApiClient()
    dynamic_client = std.dynamic.DynamicClient(k8s_client)
    
    liblog.print_logs(f"Applying {yaml_file_path} to the cluster.")
    
    with open(yaml_file_path, 'r') as file:
        resources = std.yaml.safe_load_all(file)
        
        for resource in resources:
            if not resource or "kind" not in resource:
                continue
                
            name = resource["metadata"].get("name")
            kind = resource["kind"]
            api_version = resource["apiVersion"]
            namespace = resource["metadata"].get("namespace", default_namespace)
            
            try:
                api_resource = dynamic_client.resources.get(
                    api_version=api_version, 
                    kind=kind
                )
                
                if api_resource.namespaced:
                    api_resource.create(body=resource, namespace=namespace)
                else:
                    api_resource.create(body=resource)
                    
                liblog.print_logs(f"Successfully created {kind} '{name}'.")
                
            except std.ApiException as e:
                if e.status == 409:
                    liblog.print_logs(f"Resource {kind} '{name}' already exists. Skipping.")
                else:
                    liblog.print_logs(f"Failed to create {kind} '{name}': {e}")
            except std.ResourceNotFoundError:
                liblog.print_logs(f"CRD for API {api_version} / Kind {kind} not registered on cluster.")

def create_namespace(local_kube_config_path, namespace):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    meta = std.client.V1ObjectMeta(name=namespace)
    body = std.client.V1Namespace(metadata=meta)
    try:
        v1.create_namespace(body=body)
        liblog.print_logs(f"Namespace {namespace} created successfully.")
    except std.ApiException as e:
        if e.status == 409:
            liblog.print_logs(f"Namespace {namespace} already exists.")
        else:
            liblog.print_logs(f"Exception when creating namespace: {e}")

def delete_validating_webhook(local_kube_config_path, webhook_name):
    """
    Deletes a cluster-scoped ValidatingWebhookConfiguration if it exists.
    """
    # Load the cluster credentials
    std.config.load_kube_config(config_file=local_kube_config_path)
    
    # Initialize the Admissionregistration API client
    admission_api = std.client.AdmissionregistrationV1Api()
    
    try:
        liblog.print_logs(f"Attempting to delete webhook configuration: {webhook_name}")
        
        # Execute the deletion request
        admission_api.delete_validating_webhook_configuration(name=webhook_name)
        
        liblog.print_logs(f"Successfully deleted validating webhook: {webhook_name}")
        
    except std.ApiException as e:
        # If it's a 404, the webhook isn't there (which is perfectly fine for a clean install)
        if e.status == 404:
            liblog.print_logs(f"Webhook '{webhook_name}' not found. Skipping deletion.")
        else:
            # Re-raise or handle other unexpected API errors (e.g., 401 Unauthorized, 403 Forbidden)
            liblog.print_logs(f"Failed to delete webhook due to API error ({e.status}): {e.reason}")
            raise e
    except Exception as e:
        liblog.print_logs(f"Unexpected error while deleting webhook: {e}")
        raise e

def delete_service_if_ip_mismatch(local_kube_config_path, namespace, service_name, expected_ip):
    # Deletes the Service when its requested (metallb.universe.tf/loadBalancerIPs) or assigned IP differs from expected_ip.
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    try:
        service = v1.read_namespaced_service(name=service_name, namespace=namespace)
    except std.ApiException as e:
        if e.status == 404:
            return False
        raise
    requested_ip = (service.metadata.annotations or {}).get("metallb.universe.tf/loadBalancerIPs")
    ingress = service.status.load_balancer.ingress if service.status.load_balancer else None
    assigned_ip = ingress[0].ip if ingress else None
    if requested_ip == expected_ip and assigned_ip == expected_ip:
        return False
    liblog.print_logs(f"Service {namespace}/{service_name} requests {requested_ip}, has {assigned_ip}; expected {expected_ip}. Deleting so it is recreated.")
    v1.delete_namespaced_service(name=service_name, namespace=namespace)
    deadline = std.time.time() + 60
    while std.time.time() < deadline:
        try:
            v1.read_namespaced_service(name=service_name, namespace=namespace)
            std.time.sleep(2)
        except std.ApiException as e:
            if e.status == 404:
                return True
            raise
    raise RuntimeError(f"Timed out waiting for Service {namespace}/{service_name} to be deleted.")

def deploy_lldap(lab_spec):
    liblog.print_logs("Instantiating deploy_lldap() function.")
    # Prerequisites: MetalLB (metallb-system) and Technitium (technitium) are already running (Module 3),
    # and the DNS zone for lab_spec["domain"]["name"] exists (Module 4).
    kube_config_path = lab_spec["kubernetes"]["kube_config_path"]
    lldap_ip = lab_spec["lldap"]["ip_address"]
    lldap_hostname = lab_spec["lldap"].get("hostname", "ldap")
    lldap_credentials = lab_spec["authentication"][lab_spec["lldap"]["use_these_credentials"]]
    domain_name = lab_spec["domain"]["name"]
    lldap_fqdn = f"{lldap_hostname}.{domain_name}"
    base_dn = ",".join("dc="+part for part in domain_name.split("."))
    if len(lldap_credentials["password"]) < 8:
        raise ValueError("LLDAP requires an admin password of at least 8 characters.")

    # Step 1: Make sure MetalLB can hand out the LLDAP IP
    liblog.print_logs("(Step 1) Ensure a MetalLB IPAddressPool covers "+lldap_ip+".")
    ensure_metallb_ip_is_assignable(kube_config_path, lldap_ip, "lldap-ip-pool")

    # Step 2: Generate deploy_lldap.yaml from scripts_lib/k8_deploy_lldap_yaml.script
    # Values are JSON-encoded so they are valid quoted YAML scalars regardless of special characters.
    liblog.print_logs("(Step 2) Generate deploy_lldap.yaml file.")
    set_lldap_yaml_script_name = "deploy_lldap.yaml"
    set_lldap_yaml_script_raw = libvmw.populate_var_from_file("scripts_lib/k8_deploy_lldap_yaml.script")
    libvmw.write_script_to_script_file(set_lldap_yaml_script_raw.splitlines(), set_lldap_yaml_script_name)
    replacements = {
        "ID:LDAP-001": std.secrets.token_urlsafe(32),   # LLDAP_JWT_SECRET
        "ID:LDAP-002": std.secrets.token_urlsafe(32),   # LLDAP_KEY_SEED
        "ID:LDAP-003": lldap_credentials["username"],   # LLDAP_LDAP_USER_DN (admin username)
        "ID:LDAP-004": lldap_credentials["password"],   # LLDAP_LDAP_USER_PASS
        "ID:LDAP-005": base_dn,                         # LLDAP_LDAP_BASE_DN
        "ID:LDAP-006": f"http://{lldap_fqdn}:17170",     # LLDAP_HTTP_URL
        "ID:LDAP-007": lldap_ip,                        # metallb.universe.tf/loadBalancerIPs
    }
    for placeholder, value in replacements.items():
        libvmw.search_and_replace_in_file(placeholder, std.json.dumps(value), set_lldap_yaml_script_name)
    liblog.print_logs(f"{set_lldap_yaml_script_name} created. Base DN: {base_dn}")

    # Step 3: Deploy LLDAP
    # The Secret is only created on the first run (409 = skipped afterwards), so the key seed stays stable
    # across re-runs. The generated yaml holds secrets, so remove it once applied.
    liblog.print_logs("(Step 3) Deploy LLDAP.")
    # apply_from_yaml skips existing resources, so a Service left over from an earlier run keeps its old IP.
    # Deleting it (only if it is on the wrong IP) lets it be recreated with the current annotation; the pod is untouched.
    delete_service_if_ip_mismatch(kube_config_path, "lldap", "lldap-service", lldap_ip)
    try:
        apply_from_yaml(kube_config_path, set_lldap_yaml_script_name, "lldap")
    finally:
        libvmw.delete_script_file(set_lldap_yaml_script_name)
    pause_for_pods_until_running(kube_config_path, "lldap", 300)
    service_ip = get_load_balancer_ip(kube_config_path, "lldap", "lldap-service")
    liblog.print_logs(f"LLDAP service external IP: {service_ip}")
    if service_ip != lldap_ip:
        raise RuntimeError(f"LLDAP service got external IP {service_ip}, expected {lldap_ip}. "
                           f"Check: kubectl -n lldap describe svc lldap-service")

    # Step 4: Register LLDAP in Technitium DNS
    liblog.print_logs("(Step 4) Register "+lldap_fqdn+" in Technitium DNS.")
    try:
        dns_server_ip = lab_spec["domain"]["server_ips"][0]
        dns_credentials = lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]
        technitium_token = libdns.get_technitium_token(dns_credentials["username"], dns_credentials["password"], dns_server_ip)
        if libdns.check_zone_exists(technitium_token, dns_server_ip, domain_name):
            libdns.createdns_record(technitium_token, dns_server_ip, lldap_fqdn, domain_name, lldap_ip)
            liblog.print_logs("    Added A record: "+lldap_fqdn+" -> "+lldap_ip)
        else:
            liblog.print_logs("    Zone "+domain_name+" does not exist (run Module 4 first). Skipping DNS registration.")
    except Exception as e:
        liblog.print_logs(f"    DNS registration failed, LLDAP is still deployed: {e}")

    liblog.print_logs(f"LLDAP deployed. Web UI: http://{lldap_fqdn}:17170  LDAP: ldap://{lldap_fqdn}:3890  Base DN: {base_dn}")
    return lldap_ip

def _conjur_pick_node(local_kube_config_path, requested_node, namespace="conjur", deployment="conjur-postgres"):
    # The Postgres data lives on a hostPath, so the pod must always land on the same node.
    # Order: lab_spec["conjur"]["node"] > the node an earlier run pinned it to > first Ready worker.
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    apps = std.client.AppsV1Api()
    nodes = v1.list_node().items
    names = [(n.metadata.labels or {}).get("kubernetes.io/hostname", n.metadata.name) for n in nodes]
    if requested_node:
        if requested_node not in names:
            raise RuntimeError(f'lab_spec conjur.node "{requested_node}" is not a cluster node. Nodes: {names}')
        return requested_node
    try:
        existing = apps.read_namespaced_deployment(deployment, namespace)
        pinned = (existing.spec.template.spec.node_selector or {}).get("kubernetes.io/hostname")
        if pinned:
            return pinned
    except std.ApiException as e:
        if e.status != 404:
            raise
    def ready(n):
        return any(c.type == "Ready" and c.status == "True" for c in (n.status.conditions or []))
    def control_plane(n):
        labels = n.metadata.labels or {}
        return "node-role.kubernetes.io/control-plane" in labels or "node-role.kubernetes.io/master" in labels
    candidates = [n for n in nodes if ready(n) and not control_plane(n)] or [n for n in nodes if ready(n)]
    if not candidates:
        raise RuntimeError(f"No Ready node in the cluster to pin {namespace}/{deployment} to.")
    return (candidates[0].metadata.labels or {}).get("kubernetes.io/hostname", candidates[0].metadata.name)

def _conjur_self_signed_cert(fqdn, ip_address):
    # 10-year self-signed certificate for the nginx TLS front end (SAN: FQDN + IP)
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    import datetime as _dt
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, fqdn)])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1)).not_valid_after(now + _dt.timedelta(days=3650))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(fqdn), x509.IPAddress(std.ipaddress.ip_address(ip_address))]), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption())
    return cert_pem, key_pem

def _conjur_create_secret_once(v1, name, secret_type, string_data, namespace="conjur"):
    # Created on the first run only. Never overwritten: replacing the data key would make the vault unreadable.
    try:
        v1.read_namespaced_secret(name, namespace)
        liblog.print_logs(f"    Secret {namespace}/{name} already exists. Keeping it.")
        return False
    except std.ApiException as e:
        if e.status != 404:
            raise
    body = std.client.V1Secret(metadata=std.client.V1ObjectMeta(name=name, namespace=namespace),
                               type=secret_type, string_data=string_data)
    v1.create_namespaced_secret(namespace, body)
    liblog.print_logs(f"    Secret {namespace}/{name} created.")
    return True

def _conjur_exec(local_kube_config_path, command, timeout_seconds=300):
    # Runs a command in the conjur container (kubectl exec). Retries while Conjur is still migrating its database.
    from kubernetes.stream import stream
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    deadline = std.time.time() + timeout_seconds
    last = ""
    while std.time.time() < deadline:
        pods = [p for p in v1.list_namespaced_pod("conjur", label_selector="app=conjur").items
                if p.status.phase == "Running" and not p.metadata.deletion_timestamp]
        if pods:
            try:
                out = stream(v1.connect_get_namespaced_pod_exec, pods[0].metadata.name, "conjur", container="conjur",
                             command=command, stderr=True, stdin=False, stdout=True, tty=False)
                if "API key for" in out or "already exists" in out:
                    return out
                last = out.strip()[-300:]
            except Exception as e:
                last = str(e)[:300]
        std.time.sleep(15)
    raise RuntimeError(f"'{' '.join(command)}' did not succeed within {timeout_seconds}s. Last output: {last}")

def deploy_conjur(lab_spec):
    liblog.print_logs("Instantiating deploy_conjur() function.")
    # Prerequisites: MetalLB + Technitium (Module 3) and the DNS zone (Module 4).
    import os
    import re
    from python_lib import conjur as libconjur
    kube_config_path = lab_spec["kubernetes"]["kube_config_path"]
    cfg = libconjur.conjur_settings(lab_spec)
    libconjur.validate_admin_password(cfg["password"])
    conjur_ip, conjur_fqdn, account = cfg["ip"], cfg["fqdn"], cfg["account"]

    # Step 1: Make sure MetalLB can hand out the Conjur IP
    liblog.print_logs("(Step 1) Ensure a MetalLB IPAddressPool covers "+conjur_ip+".")
    ensure_metallb_ip_is_assignable(kube_config_path, conjur_ip, "conjur-ip-pool")

    # Step 2: Namespace + secrets (data key, Postgres password, TLS). These never go into the yaml file.
    liblog.print_logs("(Step 2) Create namespace and one-time secrets.")
    create_namespace(kube_config_path, "conjur")
    std.config.load_kube_config(config_file=kube_config_path)
    v1 = std.client.CoreV1Api()
    pg_password = std.secrets.token_hex(24)
    data_key = std.base64.b64encode(std.secrets.token_bytes(32)).decode()
    if _conjur_create_secret_once(v1, "conjur-secrets", "Opaque", {
            "data-key": data_key,
            "postgres-password": pg_password,
            "database-url": f"postgres://postgres:{pg_password}@conjur-postgres.conjur.svc.cluster.local/postgres"}):
        # The data key encrypts every secret in the vault. Keep a copy beside lab_spec (same trust level).
        with open("conf/conjur_data_key.b64", "w") as f:
            f.write(data_key+"\n")
        os.chmod("conf/conjur_data_key.b64", 0o600)
        liblog.print_logs("    Data key backup: conf/conjur_data_key.b64 (without it the vault cannot be decrypted).")
    cert_pem, key_pem = _conjur_self_signed_cert(conjur_fqdn, conjur_ip)
    if _conjur_create_secret_once(v1, "conjur-tls", "kubernetes.io/tls",
                                  {"tls.crt": cert_pem.decode(), "tls.key": key_pem.decode()}):
        with open("conf/conjur_tls.crt", "wb") as f:
            f.write(cert_pem)
        liblog.print_logs("    Certificate copy: conf/conjur_tls.crt")

    # Step 3: Generate deploy_conjur.yaml from scripts_lib/k8_deploy_conjur_yaml.script
    liblog.print_logs("(Step 3) Generate deploy_conjur.yaml file.")
    node = _conjur_pick_node(kube_config_path, cfg["node"])
    liblog.print_logs(f"    Conjur database pinned to node {node}; data in {cfg['data_path']} on that node.")
    set_conjur_yaml_script_name = "deploy_conjur.yaml"
    set_conjur_yaml_script_raw = libvmw.populate_var_from_file("scripts_lib/k8_deploy_conjur_yaml.script")
    libvmw.write_script_to_script_file(set_conjur_yaml_script_raw.splitlines(), set_conjur_yaml_script_name)
    replacements = {
        "ID:CJR-001": conjur_ip,          # metallb.universe.tf/loadBalancerIPs
        "ID:CJR-002": node,               # nodeSelector kubernetes.io/hostname (Postgres)
        "ID:CJR-003": cfg["data_path"],   # hostPath for PGDATA
    }
    for placeholder, value in replacements.items():
        libvmw.search_and_replace_in_file(placeholder, std.json.dumps(value), set_conjur_yaml_script_name)

    # Step 4: Deploy Postgres + Conjur
    liblog.print_logs("(Step 4) Deploy Conjur.")
    delete_service_if_ip_mismatch(kube_config_path, "conjur", "conjur-service", conjur_ip)
    try:
        apply_from_yaml(kube_config_path, set_conjur_yaml_script_name, "conjur")
    finally:
        libvmw.delete_script_file(set_conjur_yaml_script_name)
    pause_for_pods_until_running(kube_config_path, "conjur", 600)
    service_ip = get_load_balancer_ip(kube_config_path, "conjur", "conjur-service")
    liblog.print_logs(f"Conjur service external IP: {service_ip}")
    if service_ip != conjur_ip:
        raise RuntimeError(f"Conjur service got external IP {service_ip}, expected {conjur_ip}. "
                           f"Check: kubectl -n conjur describe svc conjur-service")
    libconjur.wait_until_ready(cfg["base_url"], 600)

    # Step 5: Create the Conjur account (first run only) and set the admin password from lab_spec
    liblog.print_logs(f"(Step 5) Conjur account '{account}' and admin password.")
    out = _conjur_exec(kube_config_path, ["conjurctl", "account", "create", account])
    match = re.search(r"API key for admin: (\S+)", out)
    if match:
        libconjur.set_admin_password(cfg["base_url"], account, match.group(1), cfg["password"])
        liblog.print_logs("    Account created; admin password set from lab_spec.")
    else:
        liblog.print_logs("    Account already exists; checking the lab_spec password still logs in.")
    libconjur.ConjurClient(cfg["base_url"], account, "admin", password=cfg["password"])
    liblog.print_logs("    Admin login OK.")

    # Step 6: Register Conjur in Technitium DNS
    liblog.print_logs("(Step 6) Register "+conjur_fqdn+" in Technitium DNS.")
    try:
        domain_name = lab_spec["domain"]["name"]
        dns_server_ip = lab_spec["domain"]["server_ips"][0]
        dns_credentials = lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]
        technitium_token = libdns.get_technitium_token(dns_credentials["username"], dns_credentials["password"], dns_server_ip)
        if libdns.check_zone_exists(technitium_token, dns_server_ip, domain_name):
            libdns.createdns_record(technitium_token, dns_server_ip, conjur_fqdn, domain_name, conjur_ip)
            liblog.print_logs("    Added A record: "+conjur_fqdn+" -> "+conjur_ip)
        else:
            liblog.print_logs("    Zone "+domain_name+" does not exist (run Module 4 first). Skipping DNS registration.")
    except Exception as e:
        liblog.print_logs(f"    DNS registration failed, Conjur is still deployed: {e}")

    liblog.print_logs(f"Conjur deployed. API: https://{conjur_fqdn}  Account: {account}  Login: admin")
    return conjur_ip

def exec_in_pod(local_kube_config_path, namespace, label_selector, container, script, timeout_seconds=120):
    # Runs a shell script in the first Running pod matching label_selector (kubectl exec). Returns (rc, output).
    from kubernetes.stream import stream
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    pods = [p for p in v1.list_namespaced_pod(namespace, label_selector=label_selector).items
            if p.status.phase == "Running" and not p.metadata.deletion_timestamp]
    if not pods:
        raise RuntimeError(f"No Running pod in {namespace} matching {label_selector}.")
    out = stream(v1.connect_get_namespaced_pod_exec, pods[0].metadata.name, namespace, container=container,
                 command=["/bin/sh", "-c", script + '\necho "__HESIOD_RC=$?"'], stderr=True, stdin=False,
                 stdout=True, tty=False, _request_timeout=timeout_seconds)
    import re
    m = re.search(r"__HESIOD_RC=(\d+)\s*$", out)
    return (int(m.group(1)) if m else 255), re.sub(r"__HESIOD_RC=\d+\s*$", "", out)

def deploy_step_ca(lab_spec):
    liblog.print_logs("Instantiating deploy_step_ca() function.")
    # Prerequisites: MetalLB + Technitium (Module 3) and the DNS zone (Module 4).
    import os
    from python_lib import ca as libca
    kube_config_path = lab_spec["kubernetes"]["kube_config_path"]
    cfg = libca.ca_settings(lab_spec)
    ca_ip, ca_fqdn = cfg["ip"], cfg["fqdn"]

    # Step 1: Make sure MetalLB can hand out the CA IP
    liblog.print_logs("(Step 1) Ensure a MetalLB IPAddressPool covers "+ca_ip+".")
    ensure_metallb_ip_is_assignable(kube_config_path, ca_ip, "step-ca-ip-pool")

    # Step 2: Namespace + one-time secrets: the password that encrypts the CA keys, and the provisioner password
    liblog.print_logs("(Step 2) Create namespace and one-time secrets.")
    create_namespace(kube_config_path, "step-ca")
    std.config.load_kube_config(config_file=kube_config_path)
    v1 = std.client.CoreV1Api()
    if _conjur_create_secret_once(v1, "step-ca-secrets", "Opaque", {
            "ca-password": std.secrets.token_urlsafe(32),
            "provisioner-password": std.secrets.token_urlsafe(32)}, namespace="step-ca"):
        liblog.print_logs("    CA key password and provisioner password generated.")
    secret = v1.read_namespaced_secret("step-ca-secrets", "step-ca")
    passwords = {k: std.base64.b64decode(v).decode() for k, v in secret.data.items()}
    libca.backup_ca_passwords(lab_spec, passwords)

    # Step 3: Generate deploy_step_ca.yaml from scripts_lib/k8_deploy_step_ca_yaml.script
    liblog.print_logs("(Step 3) Generate deploy_step_ca.yaml file.")
    node = _conjur_pick_node(kube_config_path, cfg["node"], namespace="step-ca", deployment="step-ca")
    liblog.print_logs(f"    step-ca pinned to node {node}; CA data in {cfg['data_path']} on that node.")
    yaml_name = "deploy_step_ca.yaml"
    raw = libvmw.populate_var_from_file("scripts_lib/k8_deploy_step_ca_yaml.script")
    libvmw.write_script_to_script_file(raw.splitlines(), yaml_name)
    replacements = {
        "ID:CA-001": ca_ip,                                   # metallb.universe.tf/loadBalancerIPs
        "ID:CA-002": node,                                    # nodeSelector kubernetes.io/hostname
        "ID:CA-003": cfg["data_path"],                        # hostPath for /home/step
        "ID:CA-004": cfg["name"],                             # CA name (root/intermediate subjects)
        "ID:CA-005": ",".join(cfg["dns_names"]),              # names/IPs on step-ca's own TLS certificate
        "ID:CA-006": str(cfg["key_size"]),                    # RSA size of root + intermediate
        "ID:CA-007": f"{cfg['leaf_validity_days'] * 24}h",    # leaf max + default duration
    }
    for placeholder, value in replacements.items():
        libvmw.search_and_replace_in_file(placeholder, std.json.dumps(value), yaml_name)

    # Step 4: Deploy step-ca
    liblog.print_logs("(Step 4) Deploy step-ca.")
    delete_service_if_ip_mismatch(kube_config_path, "step-ca", "step-ca-service", ca_ip)
    try:
        apply_from_yaml(kube_config_path, yaml_name, "step-ca")
    finally:
        libvmw.delete_script_file(yaml_name)
    pause_for_pods_until_running(kube_config_path, "step-ca", 600)
    service_ip = get_load_balancer_ip(kube_config_path, "step-ca", "step-ca-service")
    liblog.print_logs(f"step-ca service external IP: {service_ip}")
    if service_ip != ca_ip:
        raise RuntimeError(f"step-ca service got external IP {service_ip}, expected {ca_ip}. "
                           f"Check: kubectl -n step-ca describe svc step-ca-service")
    libca.wait_until_ready(cfg["base_url"], 300)

    # Step 5: Publish the CA chain (public certificates only) to conf/ca/
    liblog.print_logs("(Step 5) Publish root and intermediate certificates.")
    paths = libca.fetch_ca_chain(lab_spec)
    for p in paths.values():
        liblog.print_logs("    "+p)

    # Step 6: Register the CA in Technitium DNS
    liblog.print_logs("(Step 6) Register "+ca_fqdn+" in Technitium DNS.")
    try:
        domain_name = lab_spec["domain"]["name"]
        dns_server_ip = lab_spec["domain"]["server_ips"][0]
        dns_credentials = lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]
        technitium_token = libdns.get_technitium_token(dns_credentials["username"], dns_credentials["password"], dns_server_ip)
        if libdns.check_zone_exists(technitium_token, dns_server_ip, domain_name):
            libdns.createdns_record(technitium_token, dns_server_ip, ca_fqdn, domain_name, ca_ip)
            liblog.print_logs("    Added A record: "+ca_fqdn+" -> "+ca_ip)
        else:
            liblog.print_logs("    Zone "+domain_name+" does not exist (run Module 4 first). Skipping DNS registration.")
    except Exception as e:
        liblog.print_logs(f"    DNS registration failed, step-ca is still deployed: {e}")

    liblog.print_logs(f"step-ca deployed. API: https://{ca_fqdn}  Root: {paths['root']}")
    return ca_ip

def wait_for_rollout(local_kube_config_path, namespace, name, timeout_seconds=600):
    # Waits until a Deployment has finished rolling out: new pod Ready, old pod gone. A plain "pods Running" check
    # can pass on the OLD pod right after a restart and then find nothing listening once it terminates.
    std.config.load_kube_config(config_file=local_kube_config_path)
    apps, v1 = std.client.AppsV1Api(), std.client.CoreV1Api()
    deadline = std.time.time() + timeout_seconds
    while std.time.time() < deadline:
        d = apps.read_namespaced_deployment(name, namespace)
        st, want = d.status, d.spec.replicas or 1
        pods = [p for p in v1.list_namespaced_pod(namespace, label_selector=f"app={name}").items]
        if (st.observed_generation or 0) >= d.metadata.generation and (st.updated_replicas or 0) == want \
                and (st.ready_replicas or 0) == want and (st.replicas or 0) == want and len(pods) == want \
                and not any(p.metadata.deletion_timestamp for p in pods):
            liblog.print_logs(f"Deployment {namespace}/{name} rolled out.")
            return True
        std.time.sleep(5)
    raise RuntimeError(f"Deployment {namespace}/{name} not rolled out after {timeout_seconds}s. "
                       f"Check: kubectl -n {namespace} get pods; kubectl -n {namespace} describe deploy/{name}")

def _upsert_secret(v1, namespace, name, string_data):
    # Create the secret, or replace it when its content changed. Returns True when something changed.
    try:
        current = v1.read_namespaced_secret(name, namespace)
        existing = {k: std.base64.b64decode(v).decode() for k, v in (current.data or {}).items()}
        if existing == string_data:
            return False
        current.data, current.string_data = None, string_data
        v1.replace_namespaced_secret(name, namespace, current)
        liblog.print_logs(f"    Secret {namespace}/{name} updated.")
        return True
    except std.ApiException as e:
        if e.status != 404:
            raise
    v1.create_namespaced_secret(namespace, std.client.V1Secret(
        metadata=std.client.V1ObjectMeta(name=name, namespace=namespace), type="Opaque", string_data=string_data))
    liblog.print_logs(f"    Secret {namespace}/{name} created.")
    return True

def deploy_sftp(lab_spec):
    liblog.print_logs("Instantiating deploy_sftp() function.")
    # Prerequisites: MetalLB + Technitium (Module 3) and the DNS zone (Module 4).
    from python_lib import backup as libbackup
    kube_config_path = lab_spec["kubernetes"]["kube_config_path"]
    cfg = libbackup.backup_settings(lab_spec)
    sftp_ip, sftp_fqdn, user = cfg["ip"], cfg["fqdn"], cfg["username"]

    # Step 1: Make sure MetalLB can hand out the SFTP IP
    liblog.print_logs("(Step 1) Ensure a MetalLB IPAddressPool covers "+sftp_ip+".")
    ensure_metallb_ip_is_assignable(kube_config_path, sftp_ip, "sftp-ip-pool")

    # Step 2: Namespace + secrets. Host keys once (a new key would change the fingerprint VCF pins);
    # the user file every run (follows the password in lab_spec).
    liblog.print_logs("(Step 2) Create namespace, host keys and the backup user.")
    create_namespace(kube_config_path, "sftp")
    std.config.load_kube_config(config_file=kube_config_path)
    v1 = std.client.CoreV1Api()
    host_keys = libbackup.new_host_keys()
    _conjur_create_secret_once(v1, "sftp-hostkeys", "Opaque", host_keys, namespace="sftp")
    stored = v1.read_namespaced_secret("sftp-hostkeys", "sftp").data
    libbackup.record_host_keys({k: std.base64.b64decode(v).decode() for k, v in stored.items()})
    client_pub = libbackup.client_key()["public"]
    users_changed = _upsert_secret(v1, "sftp", "sftp-users", {
        "users.conf": f"{user}:{cfg['password']}:{cfg['uid']}:100:{cfg['chroot_dirs']}\n",
        "client_key.pub": client_pub + "\n"})

    # Step 3: Generate deploy_sftp.yaml from scripts_lib/k8_deploy_sftp_yaml.script
    liblog.print_logs("(Step 3) Generate deploy_sftp.yaml file.")
    node = _conjur_pick_node(kube_config_path, cfg["node"], namespace="sftp", deployment="sftp")
    liblog.print_logs(f"    SFTP pinned to node {node}; backups stored in {cfg['data_path']} on that node.")
    yaml_name = "deploy_sftp.yaml"
    raw = libvmw.populate_var_from_file("scripts_lib/k8_deploy_sftp_yaml.script")
    libvmw.write_script_to_script_file(raw.splitlines(), yaml_name)
    replacements = {
        "ID:SFTP-001": sftp_ip,                                   # metallb.universe.tf/loadBalancerIPs
        "ID:SFTP-002": node,                                      # nodeSelector kubernetes.io/hostname
        "ID:SFTP-003": cfg["data_path"],                          # hostPath for the backups
        "ID:SFTP-005": f"/home/{user}/{cfg['mount_dir']}",        # where the hostPath appears inside the chroot
        "ID:SFTP-006": f"/home/{user}/.ssh/keys/client_key.pub",  # ECDSA public key for key login
    }
    for placeholder, value in replacements.items():
        libvmw.search_and_replace_in_file(placeholder, std.json.dumps(value), yaml_name)

    # Step 4: Deploy
    liblog.print_logs("(Step 4) Deploy the SFTP server.")
    delete_service_if_ip_mismatch(kube_config_path, "sftp", "sftp-service", sftp_ip)
    try:
        apply_from_yaml(kube_config_path, yaml_name, "sftp")
    finally:
        libvmw.delete_script_file(yaml_name)
    if users_changed:
        # subPath mounts never refresh: restart the pod so a changed password/key takes effect
        try:
            apps = std.client.AppsV1Api()
            stamp = std.datetime.now().strftime("%Y%m%d%H%M%S")
            apps.patch_namespaced_deployment("sftp", "sftp", {"spec": {"template": {"metadata": {
                "annotations": {"hesiod/restarted-at": stamp}}}}})
            liblog.print_logs("    Backup user changed: SFTP pod restarted to pick it up.")
        except std.ApiException as e:
            liblog.print_logs(f"    WARNING: could not restart the SFTP pod ({e.status}); run: kubectl -n sftp rollout restart deploy/sftp")
    std.time.sleep(5)
    pause_for_pods_until_running(kube_config_path, "sftp", 300)
    wait_for_rollout(kube_config_path, "sftp", "sftp", 300)
    service_ip = get_load_balancer_ip(kube_config_path, "sftp", "sftp-service")
    liblog.print_logs(f"SFTP service external IP: {service_ip}")
    if service_ip != sftp_ip:
        raise RuntimeError(f"SFTP service got external IP {service_ip}, expected {sftp_ip}. "
                           f"Check: kubectl -n sftp describe svc sftp-service")
    libbackup.wait_until_ready(sftp_ip, 300)

    # Step 5: Register in Technitium DNS
    liblog.print_logs("(Step 5) Register "+sftp_fqdn+" in Technitium DNS.")
    try:
        domain_name = lab_spec["domain"]["name"]
        dns_server_ip = lab_spec["domain"]["server_ips"][0]
        dns_credentials = lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]
        technitium_token = libdns.get_technitium_token(dns_credentials["username"], dns_credentials["password"], dns_server_ip)
        if libdns.check_zone_exists(technitium_token, dns_server_ip, domain_name):
            libdns.createdns_record(technitium_token, dns_server_ip, sftp_fqdn, domain_name, sftp_ip)
            liblog.print_logs("    Added A record: "+sftp_fqdn+" -> "+sftp_ip)
        else:
            liblog.print_logs("    Zone "+domain_name+" does not exist (run Module 4 first). Skipping DNS registration.")
    except Exception as e:
        liblog.print_logs(f"    DNS registration failed, SFTP is still deployed: {e}")

    liblog.print_logs(f"SFTP deployed: sftp://{user}@{sftp_fqdn}:22{cfg['directory']}  "
                      f"host key {libbackup.host_fingerprint()}")
    return sftp_ip

def deploy_kmip(lab_spec):
    liblog.print_logs("Instantiating deploy_kmip() function.")
    # Prerequisites: MetalLB + Technitium (Module 3), the DNS zone (Module 4) and the lab CA (Module 10).
    from python_lib import kms as libkms
    kube_config_path = lab_spec["kubernetes"]["kube_config_path"]
    cfg = libkms.kms_settings(lab_spec)
    kmip_ip, kmip_fqdn = cfg["ip"], cfg["fqdn"]

    # Step 1: Make sure MetalLB can hand out the KMIP IP
    liblog.print_logs("(Step 1) Ensure a MetalLB IPAddressPool covers "+kmip_ip+".")
    ensure_metallb_ip_is_assignable(kube_config_path, kmip_ip, "kmip-ip-pool")

    # Step 2: Namespace + TLS from the lab CA. Re-issued when missing or within 30 days of expiry.
    liblog.print_logs("(Step 2) Create namespace and the KMIP server certificate (lab CA).")
    create_namespace(kube_config_path, "kmip")
    std.config.load_kube_config(config_file=kube_config_path)
    v1 = std.client.CoreV1Api()
    current = None
    try:
        current = {k: std.base64.b64decode(v).decode() for k, v in v1.read_namespaced_secret("kmip-tls", "kmip").data.items()}
    except std.ApiException as e:
        if e.status != 404:
            raise
    tls = libkms.server_tls(lab_spec, current)
    tls_changed = _upsert_secret(v1, "kmip", "kmip-tls", tls)

    # Step 3: Generate deploy_kmip.yaml from scripts_lib/k8_deploy_kmip_yaml.script
    liblog.print_logs("(Step 3) Generate deploy_kmip.yaml file.")
    node = _conjur_pick_node(kube_config_path, cfg["node"], namespace="kmip", deployment="kmip")
    liblog.print_logs(f"    KMIP server pinned to node {node}; key database in {cfg['data_path']}/db on that node.")
    yaml_name = "deploy_kmip.yaml"
    raw = libvmw.populate_var_from_file("scripts_lib/k8_deploy_kmip_yaml.script")
    libvmw.write_script_to_script_file(raw.splitlines(), yaml_name)
    replacements = {
        "ID:KMS-001": kmip_ip,           # metallb.universe.tf/loadBalancerIPs
        "ID:KMS-002": node,              # nodeSelector kubernetes.io/hostname
        "ID:KMS-003": cfg["data_path"],  # hostPath: key database, PyKMIP install, log
    }
    for placeholder, value in replacements.items():
        libvmw.search_and_replace_in_file(placeholder, std.json.dumps(value), yaml_name)

    # Step 4: Deploy (first start installs PyKMIP from PyPI, so allow a few minutes)
    liblog.print_logs("(Step 4) Deploy the KMIP server.")
    delete_service_if_ip_mismatch(kube_config_path, "kmip", "kmip-service", kmip_ip)
    try:
        apply_from_yaml(kube_config_path, yaml_name, "kmip")
    finally:
        libvmw.delete_script_file(yaml_name)
    if tls_changed and current is not None:
        apps = std.client.AppsV1Api()
        apps.patch_namespaced_deployment("kmip", "kmip", {"spec": {"template": {"metadata": {
            "annotations": {"hesiod/restarted-at": std.datetime.now().strftime("%Y%m%d%H%M%S")}}}}})
        liblog.print_logs("    New server certificate: KMIP pod restarted to pick it up.")
    std.time.sleep(5)
    pause_for_pods_until_running(kube_config_path, "kmip", 600)
    wait_for_rollout(kube_config_path, "kmip", "kmip", 600)
    service_ip = get_load_balancer_ip(kube_config_path, "kmip", "kmip-service")
    liblog.print_logs(f"KMIP service external IP: {service_ip}")
    if service_ip != kmip_ip:
        raise RuntimeError(f"KMIP service got external IP {service_ip}, expected {kmip_ip}. "
                           f"Check: kubectl -n kmip describe svc kmip-service")
    libkms.wait_until_ready(kmip_ip, 600)

    # Step 5: Register in Technitium DNS
    liblog.print_logs("(Step 5) Register "+kmip_fqdn+" in Technitium DNS.")
    try:
        domain_name = lab_spec["domain"]["name"]
        dns_server_ip = lab_spec["domain"]["server_ips"][0]
        dns_credentials = lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]
        technitium_token = libdns.get_technitium_token(dns_credentials["username"], dns_credentials["password"], dns_server_ip)
        if libdns.check_zone_exists(technitium_token, dns_server_ip, domain_name):
            libdns.createdns_record(technitium_token, dns_server_ip, kmip_fqdn, domain_name, kmip_ip)
            liblog.print_logs("    Added A record: "+kmip_fqdn+" -> "+kmip_ip)
        else:
            liblog.print_logs("    Zone "+domain_name+" does not exist (run Module 4 first). Skipping DNS registration.")
    except Exception as e:
        liblog.print_logs(f"    DNS registration failed, the KMIP server is still deployed: {e}")

    liblog.print_logs(f"KMIP server deployed: {kmip_fqdn}:5696 (mutual TLS, lab CA)")
    return kmip_ip

def deploy_technitium(lab_spec):
    liblog.print_logs("Instantiating deploy_technitium() function.")
    # Step 1: Edit config map, change ipvs > strictARP from false to true
    # sudo kubectl --kubeconfig=/root/.kube/config edit configmap -n kube-system kube-proxy
    liblog.print_logs("(Step 1) Editing config map.")
    #edit_kube_proxy_configmap_for_metallb(lab_spec["kubernetes"]["kube_config_path"])
    enable_strict_arp_for_metallb(lab_spec["kubernetes"]["kube_config_path"])
    
    # Step 2: Create metallb namespace
    # sudo kubectl --kubeconfig=/root/.kube/config create namespace metallb-system
    liblog.print_logs("(Step 2) Creating namespaces.")
    create_namespace(lab_spec["kubernetes"]["kube_config_path"], "metallb-system")
    create_namespace(lab_spec["kubernetes"]["kube_config_path"], "technitium")

    # Step 3: Install core Metallb
    liblog.print_logs("(Step 3) Install core metallb.")
    install_core_metallb(lab_spec["kubernetes"]["kube_config_path"])
    pause_for_pods_until_running(lab_spec["kubernetes"]["kube_config_path"], "metallb-system", 300)
    liblog.print_logs("Pausing 30 seconds for MetalLB webhook initialization...")
    std.time.sleep(30)
    liblog.print_logs("Nap is over. Back to work!")
    
    # Step 4: Replace in script file: k8_deploy_metallb_yaml.script
    liblog.print_logs("(Step 4) Generate deploy_metallb.yaml file.")
    set_metallb_yaml_script_name = "deploy_metallb.yaml"
    set_metallb_yaml_script_raw = libvmw.populate_var_from_file("scripts_lib/k8_deploy_metallb_yaml.script")
    set_metallb_yaml_script = set_metallb_yaml_script_raw.splitlines()
    libvmw.write_script_to_script_file(set_metallb_yaml_script, set_metallb_yaml_script_name)
    liblog.print_logs(f"{set_metallb_yaml_script_name} created.")
    i=0 # Hardcoded: will only pull from first group of fqdns in lab_spec.json. Expand this later.
    ip_range = libvmw.get_ip_range(lab_spec["network"][lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_network"]]["default_gateway"], lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_range_start"], lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_range_end"])
    libvmw.search_and_replace_in_file("ID:DNS-001", ip_range[0], set_metallb_yaml_script_name)
    libvmw.search_and_replace_in_file("ID:DNS-002", ip_range[len(ip_range)-1], set_metallb_yaml_script_name)

    # Step 5: Replace in script file: k8_deploy_technitium_dns_yaml.script
    liblog.print_logs("(Step 5) Generate deploy_technitium_dns.yaml file.")
    set_technitium_yaml_script_name = "deploy_technitium_dns.yaml"
    set_technitium_yaml_script_raw = libvmw.populate_var_from_file("scripts_lib/k8_deploy_technitium_dns_yaml.script")
    set_technitium_yaml_script = set_technitium_yaml_script_raw.splitlines()
    libvmw.write_script_to_script_file(set_technitium_yaml_script, set_technitium_yaml_script_name)
    liblog.print_logs(f"{set_technitium_yaml_script_name} created.")
    i=0 # Hardcoded: will only create one DNS server from the dns range, and it will be the first on the list.
    libvmw.search_and_replace_in_file("ID:DNS-001", lab_spec["domain"]["server_ips"][i], set_technitium_yaml_script_name)
    
    # Step 6: Deploy metallb
    # sudo kubectl --kubeconfig=/root/.kube/config apply -f deploy-metallb.yaml
    liblog.print_logs("(Step 6) Deploy metallb and apply custom metallb network configuration to the newly built cluster..")
    # Cleanup existing webhooks
    try:
        liblog.print_logs("Removing old validating webhook to prevent API deadlocks.")
        # If your library has a custom command or generic delete function, use it here.
        # Equivalent to: kubectl delete validatingwebhookconfiguration metallb-webhook-configuration --ignore-not-found
        delete_validating_webhook(lab_spec["kubernetes"]["kube_config_path"], "metallb-webhook-configuration")
    except Exception as e:
        liblog.print_logs(f"Webhook deletion skipped or not found: {e}")
    apply_from_yaml(lab_spec["kubernetes"]["kube_config_path"], set_metallb_yaml_script_name, "metallb-system")
    pause_for_pods_until_running(lab_spec["kubernetes"]["kube_config_path"], "metallb-system", 300)
    pool_summary = get_metallb_ip_address_pools(lab_spec["kubernetes"]["kube_config_path"])
    liblog.print_logs("Verifying metallb ip pools:")
    liblog.print_logs(pool_summary)
    
    # Step 8: Deploy technitium
    # sudo kubectl --kubeconfig=/root/.kube/config apply -f deploy-technitium-dns.yaml
    liblog.print_logs("(Step 7) Deploy technitium.")
    technitium_ip = lab_spec["domain"]["server_ips"][0]
    # dns-ip-pool has autoAssign off, so the requested IP must sit inside some pool.
    ensure_metallb_ip_is_assignable(lab_spec["kubernetes"]["kube_config_path"], technitium_ip, "technitium-ip-pool")
    # apply_from_yaml skips existing resources; recreate a stale Service so it picks up the current annotation.
    delete_service_if_ip_mismatch(lab_spec["kubernetes"]["kube_config_path"], "technitium", "technitium-dns-service", technitium_ip)
    apply_from_yaml(lab_spec["kubernetes"]["kube_config_path"], set_technitium_yaml_script_name, "technitium")
    pause_for_pods_until_running(lab_spec["kubernetes"]["kube_config_path"], "technitium", 300)
    service_ip = get_load_balancer_ip(lab_spec["kubernetes"]["kube_config_path"], "technitium", "technitium-dns-service")
    liblog.print_logs(f"Technitium service external IP: {service_ip}")
    if service_ip != technitium_ip:
        raise RuntimeError(f"Technitium service got external IP {service_ip}, expected {technitium_ip}. "
                           f"Check: kubectl -n technitium describe svc technitium-dns-service")

 
    # Step 9: Create zone and populate dns entries for VCF
    liblog.print_logs("(Step 9) Create DNS zone and populate DNS entries for VCF.")

def edit_kube_proxy_configmap_for_metallb(local_kube_config_path):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    try:
        # Hardcode name and namespace as this is a specific function for metallb
        configmap = v1.read_namespaced_config_map(name="kube-proxy", namespace="kube-system")
        if configmap.data is None:
            configmap.data = {}
        # Hardcode key value pair as this is a specific function for metallb
        configmap.data["strictARP"] = "true"
        updated_configmap = v1.replace_namespaced_config_map(
            name="kube-proxy",
            namespace="kube-system",
            body=configmap
        )
        liblog.print_logs(f"ConfigMap kube-proxy updated successfully.")
        return updated_configmap
    except std.ApiException as e:
        liblog.print_logs(f"Exception when updating configmap: {e}")

def enable_strict_arp_for_metallb(local_kube_config_path):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    try:
        # Hardcode name and namespace as this is a specific function for metallb
        # Fetch ConfigMap
        configmap = v1.read_namespaced_config_map(name="kube-proxy", namespace="kube-system")
        # Extract the nested configuration string
        config_conf_str = configmap.data.get("config.conf")
        if not config_conf_str:
            liblog.print_logs(f"Could not find 'config.conf' inside the kube-proxy ConfigMap.")
            return False
        # Parse nested YAML into Python dictionary
        proxy_config = std.yaml.safe_load(config_conf_str)
        # Navigate to ipvs > strictARP and update it
        if "ipvs" not in proxy_config:
            proxy_config["ipvs"] = {}
        proxy_config["ipvs"]["strictARP"] = True
        # Serialize the dictionary back into a YAML string
        configmap.data["config.conf"] = std.yaml.dump(proxy_config, default_flow_style=False)
        # Push the update back to the cluster
        v1.replace_namespaced_config_map(name="kube-proxy", namespace="kube-system", body=configmap)
        liblog.print_logs(f"Successfully set ipvs.strictARP to true in kube-proxy ConfigMap.")
        return True
    except std.ApiException as e:
        liblog.print_logs(f"Kubernetes API Exception: {e}")
    except std.yaml.YAMLError as e:
        liblog.print_logs(f"Error parsing the internal kube-proxy YAML configuration: {e}")

def ensure_metallb_ip_is_assignable(local_kube_config_path, ip_address, pool_name):
    # MetalLB only honors a metallb.universe.tf/loadBalancerIPs annotation if the IP sits inside an IPAddressPool.
    # If no existing pool covers the IP, create a dedicated single-IP pool (autoAssign off) + L2Advertisement.
    # Pools are not allowed to overlap, so never create a new pool for an IP that is already covered.
    std.config.load_kube_config(config_file=local_kube_config_path)
    custom_api = std.client.CustomObjectsApi()
    group, version, namespace = "metallb.io", "v1beta1", "metallb-system"
    target_ip = std.ipaddress.ip_address(ip_address)

    pools = custom_api.list_namespaced_custom_object(group=group, version=version, namespace=namespace, plural="ipaddresspools")
    for pool in pools.get("items", []):
        for address in pool.get("spec", {}).get("addresses", []):
            if "-" in address:
                start, end = (std.ipaddress.ip_address(a.strip()) for a in address.split("-"))
                covered = start <= target_ip <= end
            else:
                covered = target_ip in std.ipaddress.ip_network(address.strip(), strict=False)
            if covered:
                liblog.print_logs(f"{ip_address} is already covered by MetalLB pool '{pool['metadata']['name']}' ({address}).")
                liblog.print_logs("    WARNING: make sure no other VM or FQDN in that range uses this IP.")
                return pool["metadata"]["name"]

    liblog.print_logs(f"No MetalLB pool covers {ip_address}. Creating pool '{pool_name}'.")
    pool_body = {
        "apiVersion": f"{group}/{version}",
        "kind": "IPAddressPool",
        "metadata": {"name": pool_name, "namespace": namespace},
        "spec": {"addresses": [f"{ip_address}/32"], "autoAssign": False},
    }
    advert_body = {
        "apiVersion": f"{group}/{version}",
        "kind": "L2Advertisement",
        "metadata": {"name": pool_name+"-l2-advert", "namespace": namespace},
        "spec": {"ipAddressPools": [pool_name]},
    }
    for plural, body in (("ipaddresspools", pool_body), ("l2advertisements", advert_body)):
        try:
            custom_api.create_namespaced_custom_object(group=group, version=version, namespace=namespace, plural=plural, body=body)
            liblog.print_logs(f"Created {body['kind']} '{body['metadata']['name']}'.")
        except std.ApiException as e:
            if e.status == 409:
                liblog.print_logs(f"{body['kind']} '{body['metadata']['name']}' already exists. Skipping.")
            else:
                raise
    return pool_name

def get_load_balancer_ip(local_kube_config_path, namespace, service_name, timeout_seconds=120):
    # Poll the Service until MetalLB has populated status.loadBalancer.ingress.
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    deadline = std.time.time() + timeout_seconds
    while std.time.time() < deadline:
        service = v1.read_namespaced_service(name=service_name, namespace=namespace)
        ingress = service.status.load_balancer.ingress if service.status.load_balancer else None
        if ingress:
            return ingress[0].ip
        std.time.sleep(5)
    liblog.print_logs(f"Timed out waiting for an external IP on service {namespace}/{service_name}.")
    return None

def get_metallb_ip_address_pools(local_kube_config_path):
    std.config.load_kube_config(config_file=local_kube_config_path)
    custom_api = std.client.CustomObjectsApi()
    
    # MetalLB CRD API Details
    group = "metallb.io"
    version = "v1beta1"
    plural = "ipaddresspools"
    namespace="metallb-system"
    
    try:
        # Fetch all IPAddressPools across the cluster
        pools = custom_api.list_namespaced_custom_object(
            group=group, 
            version=version, 
            namespace=namespace, 
            plural=plural
        )
        items = pools.get("items", [])
        
        if not items:
            return f"No IPAddressPools found in namespace '{namespace}'."
            
        # Build a clean text table header
        log_output = ["\nActive MetalLB IP Address Pools:", f"{'NAME':<20} {'AUTO ASSIGN':<15} {'ADDRESSES':<30}"]
        log_output.append("-" * 68)
        
        for pool in items:
            name = pool["metadata"]["name"]
            spec = pool.get("spec", {})
            
            # Extract attributes safely with defaults
            auto_assign = str(spec.get("autoAssign", True)).lower()
            addresses = ", ".join(spec.get("addresses", []))
            
            log_output.append(f"{name:<20} {auto_assign:<15} [{addresses}]")
            
        return "\n".join(log_output)

    except std.ApiException as e:
        if e.status == 404:
            return f"Error: Either MetalLB CRDs are missing or namespace '{namespace}' does not exist."
        return f"Failed to retrieve IPAddressPools due to API error ({e.status}): {e.reason}"
    except Exception as e:
        return f"Unexpected error reading IPAddressPools: {e}"

def get_namespaces(local_kube_config_path):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    ns_list = v1.list_namespace()
    # Syntax on return:
    #    for ns in ns_list.items:
    #        print(f" - {ns.metadata.name}")
    return ns_list

def get_pods_for_all_namespaces(local_kube_config_path):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    pod_list = v1.list_pod_for_all_namespaces(watch=False)
    # Syntax on return:
    #   for pod in pod_list.items:
    #       print("%s\t%s\t%s" % (pod.status.pod_ip, pod.metadata.namespace, pod.metadata.name))
    return pod_list

def install_core_metallb(local_kube_config_path):
    std.config.load_kube_config(config_file=local_kube_config_path)
    k8s_client = std.client.ApiClient()
    
    # Official MetalLB native installation manifest URL
    # (Adjust the version v0.14.5 to match your environment if needed)
    metallb_manifest_url = "https://raw.githubusercontent.com/metallb/metallb/v0.14.5/config/manifests/metallb-native.yaml"
    
    liblog.print_logs("Installing core MetalLB manifests and CRDs.")
    try:
        # utils.create_from_yaml can accept a live URL string!
        with std.urllib.request.urlopen(metallb_manifest_url) as response:
            yaml_content = response.read()

        with std.tempfile.NamedTemporaryFile(suffix=".yaml", delete=True) as temp_file:
            temp_file.write(yaml_content)
            temp_file.flush()
            std.utils.create_from_yaml(k8s_client, temp_file.name)

        liblog.print_logs("Core MetalLB manifests applied successfully.")
        return True
    
    except std.utils.FailToCreateError as e:
        liblog.print_logs("Manifests applied with some conflicts/already existing resources, continuing.")
        return True

    except Exception as e:
        liblog.print_logs(f"Failed to install core MetalLB: {e}")
        return False

def pause_for_pods_until_running(local_kube_config_path, pod_namespace, timeout_seconds):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    w = std.watch.Watch()
    liblog.print_logs(f"Waiting for pods in namespace '{pod_namespace}' to be Running...")
    start_time = std.time.time()
    for event in w.stream(v1.list_namespaced_pod, namespace=pod_namespace, timeout_seconds=timeout_seconds):
        pod = event['object']
        status = pod.status.phase
        pods = v1.list_namespaced_pod(namespace=pod_namespace)
        if not pods.items:
            continue
        all_running = all(p.status.phase == "Running" for p in pods.items)
        if all_running:
            liblog.print_logs(f"All pods are now successfully Running!")
            w.stop()
            return True 
        if std.time.time() - start_time > timeout_seconds:
            liblog.print_logs(f"Timed out waiting for pods to be ready.")
            w.stop()
            return False 
    liblog.print_logs(f"Watch stream ended or timed out.")
    return False
