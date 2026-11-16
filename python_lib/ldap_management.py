# Description: Contains all necessary functions to run and manage ldap services
# Author: Brendan O'Connor
# Version: 1.1 (OpenLDAP for VCF SSO: refresh_openldap_users, openldap_checks, write_vcf_sso_sheet)
# Date: November 2026

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std
from python_lib import vmware as libvmw
from python_lib import logs_and_headers as liblog
from python_lib import json_management as libjson

# Groups LLDAP creates on first start; these are never deleted.
LLDAP_DEFAULT_GROUPS = ["lldap_admin", "lldap_password_manager", "lldap_strict_readonly"]
LLDAP_HTTP_PORT = 17170
LLDAP_NAMESPACE = "lldap"

def lldap_base_url(lldap_server_ip):
    return "http://"+lldap_server_ip+":"+str(LLDAP_HTTP_PORT)

def get_lldap_token(lldap_server_ip, username, password):
    # POST /auth/simple/login -> {"token": "...", "refreshToken": "..."}
    liblog.print_logs("Getting LLDAP Token.")
    api_response = std.requests.post(lldap_base_url(lldap_server_ip)+"/auth/simple/login",
                                     json={"username": username, "password": password}, timeout=30)
    if api_response.status_code != 200:
        raise RuntimeError("LLDAP login failed (HTTP "+str(api_response.status_code)+"): "+api_response.text)
    return api_response.json()["token"]

def lldap_graphql(lldap_server_ip, lldap_token, query, variables, action_description):
    # LLDAP returns HTTP 200 with an "errors" array when a GraphQL operation fails.
    api_response = std.requests.post(lldap_base_url(lldap_server_ip)+"/api/graphql",
                                     headers={"Authorization": "Bearer "+lldap_token},
                                     json={"query": query, "variables": variables}, timeout=30)
    if api_response.status_code != 200:
        liblog.print_logs("    FAILED: "+action_description+" -> HTTP "+str(api_response.status_code))
        raise RuntimeError("LLDAP API error ("+action_description+"): HTTP "+str(api_response.status_code)+" "+api_response.text)
    api_json = api_response.json()
    if api_json.get("errors"):
        error_message = "; ".join(e.get("message", str(e)) for e in api_json["errors"])
        liblog.print_logs("    FAILED: "+action_description+" -> "+error_message)
        raise RuntimeError("LLDAP API error ("+action_description+"): "+error_message)
    return api_json["data"]

def list_groups(lldap_server_ip, lldap_token):
    return lldap_graphql(lldap_server_ip, lldap_token, "query { groups { id displayName } }", {}, "List Groups")["groups"]

def list_users(lldap_server_ip, lldap_token):
    return lldap_graphql(lldap_server_ip, lldap_token, "query { users { id } }", {}, "List Users")["users"]

def create_group(lldap_server_ip, lldap_token, group_name):
    liblog.print_logs("Adding group: "+group_name+" to LDAP.")
    query = "mutation CreateGroup($name: String!) { createGroup(name: $name) { id displayName } }"
    return lldap_graphql(lldap_server_ip, lldap_token, query, {"name": group_name}, "Create Group "+group_name)["createGroup"]

def delete_group(lldap_server_ip, lldap_token, group_id, group_name=""):
    liblog.print_logs("Deleting group: "+(group_name or str(group_id))+" from LDAP.")
    query = "mutation DeleteGroup($groupId: Int!) { deleteGroup(groupId: $groupId) { ok } }"
    return lldap_graphql(lldap_server_ip, lldap_token, query, {"groupId": group_id}, "Delete Group "+(group_name or str(group_id)))

def create_user(lldap_server_ip, lldap_token, user_spec):
    liblog.print_logs("Adding user: "+user_spec["username"]+" to LDAP.")
    user_input = {"id": user_spec["username"]}
    # Only send optional fields that are actually populated.
    for spec_key, gql_key in (("email", "email"), ("display_name", "displayName"),
                              ("first_name", "firstName"), ("last_name", "lastName")):
        if user_spec.get(spec_key):
            user_input[gql_key] = user_spec[spec_key]
    query = "mutation CreateUser($user: CreateUserInput!) { createUser(user: $user) { id } }"
    return lldap_graphql(lldap_server_ip, lldap_token, query, {"user": user_input}, "Create User "+user_spec["username"])["createUser"]

def delete_user(lldap_server_ip, lldap_token, user_id):
    liblog.print_logs("Deleting user: "+user_id+" from LDAP.")
    query = "mutation DeleteUser($userId: String!) { deleteUser(userId: $userId) { ok } }"
    return lldap_graphql(lldap_server_ip, lldap_token, query, {"userId": user_id}, "Delete User "+user_id)

def add_user_to_group(lldap_server_ip, lldap_token, user_id, group_id, group_name=""):
    liblog.print_logs("    Adding user: "+user_id+" to group: "+(group_name or str(group_id))+".")
    query = "mutation AddUserToGroup($userId: String!, $groupId: Int!) { addUserToGroup(userId: $userId, groupId: $groupId) { ok } }"
    return lldap_graphql(lldap_server_ip, lldap_token, query, {"userId": user_id, "groupId": group_id}, "Add "+user_id+" to group "+(group_name or str(group_id)))

def set_user_password(kube_config_path, lldap_token, username, password):
    # LLDAP does not accept plaintext passwords over GraphQL (it uses the OPAQUE protocol),
    # so run the lldap_set_password helper that ships inside the lldap container.
    from kubernetes import client, config
    from kubernetes.stream import stream
    liblog.print_logs("    Setting password for user: "+username+".")
    config.load_kube_config(config_file=kube_config_path)
    v1 = client.CoreV1Api()
    pods = v1.list_namespaced_pod(LLDAP_NAMESPACE, label_selector="app=lldap", field_selector="status.phase=Running").items
    if not pods:
        raise RuntimeError("No running lldap pod found in namespace "+LLDAP_NAMESPACE+".")
    command = ["/app/lldap_set_password",
               "--base-url", "http://localhost:"+str(LLDAP_HTTP_PORT),
               "--token", lldap_token,
               "--username", username,
               "--password", password]
    resp = stream(v1.connect_get_namespaced_pod_exec, pods[0].metadata.name, LLDAP_NAMESPACE,
                  command=command, stderr=True, stdin=False, stdout=True, tty=False, _preload_content=False)
    resp.run_forever(timeout=60)
    output = resp.read_stdout() + resp.read_stderr()
    exit_code = resp.returncode
    resp.close()
    if exit_code != 0:
        raise RuntimeError("Setting password for "+username+" failed (exit "+str(exit_code)+"): "+output)

def refresh_vcf_ldap_users(lab_spec):
    liblog.print_logs("Instantiating refresh_vcf_ldap_users() function.")
    lldap_ip = lab_spec["lldap"]["ip_address"]
    kube_config_path = lab_spec["kubernetes"]["kube_config_path"]
    # User 0: the LLDAP admin created at deploy time (Module 5) from lab_spec["authentication"].
    lldap_credentials = lab_spec["authentication"][lab_spec["lldap"]["use_these_credentials"]]
    admin_username = lldap_credentials["username"]
    ldap_spec = lab_spec["ldap"]

    lldap_token = get_lldap_token(lldap_ip, admin_username, lldap_credentials["password"])

    # Step 1: Delete all non-default groups
    liblog.print_logs("(Step 1) Delete all non-default LDAP groups.")
    for group in list_groups(lldap_ip, lldap_token):
        if group["displayName"] not in LLDAP_DEFAULT_GROUPS:
            delete_group(lldap_ip, lldap_token, group["id"], group["displayName"])

    # Step 2: Delete every user except the admin (user 0)
    liblog.print_logs("(Step 2) Delete all LDAP users except "+admin_username+".")
    for user in list_users(lldap_ip, lldap_token):
        if user["id"].lower() != admin_username.lower():
            delete_user(lldap_ip, lldap_token, user["id"])

    # Step 3: Create groups from lab_spec["ldap"]["groups"]; keep index -> id for add_to_these_groups
    liblog.print_logs("(Step 3) Create LDAP groups from lab_spec.")
    existing_groups = {g["displayName"]: g["id"] for g in list_groups(lldap_ip, lldap_token)}
    group_ids_by_index = []
    for group_spec in ldap_spec.get("groups", []):
        name = group_spec["name"]
        if name in existing_groups:
            # Allows lab_spec to reference a default group (e.g. lldap_admin) by name.
            group_ids_by_index.append((existing_groups[name], name))
        else:
            group_ids_by_index.append((create_group(lldap_ip, lldap_token, name)["id"], name))

    # Step 4: Create users, set passwords, and assign group memberships
    liblog.print_logs("(Step 4) Create LDAP users from lab_spec.")
    for user_spec in ldap_spec.get("users", []):
        user_id = create_user(lldap_ip, lldap_token, user_spec)["id"]
        if user_spec.get("password"):
            set_user_password(kube_config_path, lldap_token, user_id, user_spec["password"])
        for group_index in user_spec.get("add_to_these_groups", []):
            group_id, group_name = group_ids_by_index[group_index]
            add_user_to_group(lldap_ip, lldap_token, user_id, group_id, group_name)

    liblog.print_logs("LDAP refresh complete: "+str(len(group_ids_by_index))+" group(s), "+str(len(ldap_spec.get("users", [])))+" user(s).")


# =====================================================================================================================
# OpenLDAP (Module 5 deploys it, Module 6 keeps it in line with lab_spec["ldap"]). Used as the VCF SSO identity source:
# LLDAP has no entry for the base DN, which the Identity Broker's domain retrieval reads, so VCF SSO cannot use it.
#
# Layout:  <base DN>                     dcObject/organization (created by the image)
#          cn=admin,<base DN>            directory admin           (lab_spec["openldap"]["use_these_credentials"])
#          cn=<readonly>,<base DN>       read-only bind for VCF    (lab_spec["openldap"]["readonly_credentials"])
#          ou=people,<base DN>           users   (inetOrgPerson, uid=...)
#          ou=groups,<base DN>           groups  (groupOfUniqueNames, cn=..., uniqueMember -> memberOf on the user)
# Module 6 reconciles instead of delete-and-recreate: entries keep their entryUUID, which is how the Identity Broker
# tracks users and groups between syncs (recreated entries would look like new users and lose their role mappings).
# =====================================================================================================================

OPENLDAP_STATE_DIR = "conf/openldap"
FFDHE2048 = """-----BEGIN DH PARAMETERS-----
MIIBCAKCAQEA//////////+t+FRYortKmq/cViAnPTzx2LnFg84tNpWp4TZBFGQz
+8yTnc4kmz75fS/jY2MMddj2gbICrsRhetPfHtXV/WVhJDP1H18GbtCFY2VVPe0a
87VXE15/V8k1mE8McODmi3fipona8+/och3xWKE2rec1MKzKT0g6eXq8CrGCsyT7
YdEIqUuyyOP7uWrat2DX9GgdT0Kj3jlN9K5W7edjcrsZCwenyO4KbXCeAvzhzffi
7MA0BM0oNC9hkXL+nOmFg/+OTxIy7vKBg8P+OxtMb61zO7X8vC7CIAXFjvGDfRaD
ssbzSibBsu/6iGtCOGEoXJf//////////wIBAg==
-----END DH PARAMETERS-----
"""   # RFC 7919 ffdhe2048: saves osixia generating DH parameters on first start (minutes)


class OpenLdapError(Exception):
    pass


def _cred(lab_spec, idx, what):
    if idx is None or idx >= len(lab_spec["authentication"]):
        raise OpenLdapError(f'lab_spec["openldap"]["{what}"] must point at an authentication entry.')
    c = lab_spec["authentication"][idx]
    if str(c.get("password", "")).startswith("<"):
        raise OpenLdapError(f"authentication entry {idx} ({what}) still holds its sample value.")
    return c


def openldap_settings(lab_spec):
    try:
        import ldap3  # noqa: F401
    except ImportError:
        raise OpenLdapError("python ldap3 is missing on this appliance: sudo pip install --break-system-packages ldap3")
    o = lab_spec.get("openldap") or {}
    if not o.get("ip_address"):
        raise OpenLdapError('lab_spec["openldap"] needs ip_address (see json_lib/lab_spec.json).')
    domain = lab_spec["domain"]["name"]
    base_dn = ",".join("dc=" + p for p in domain.split("."))
    admin = _cred(lab_spec, o.get("use_these_credentials"), "use_these_credentials")
    ro = _cred(lab_spec, o.get("readonly_credentials"), "readonly_credentials")
    ro_name = ro.get("username") if not str(ro.get("username", "")).startswith("<") else "readonly"
    hostname = o.get("hostname", "openldap")
    node = o.get("node")
    return {"ip": o["ip_address"], "hostname": hostname, "fqdn": f"{hostname}.{domain}", "domain": domain,
            "organisation": o.get("organisation", "Hesiod"), "base_dn": base_dn,
            "admin_dn": f"cn=admin,{base_dn}", "admin_password": admin["password"],
            "readonly_user": ro_name, "readonly_dn": f"cn={ro_name},{base_dn}", "readonly_password": ro["password"],
            "people_dn": f"ou=people,{base_dn}", "groups_dn": f"ou=groups,{base_dn}",
            "node": None if str(node or "").startswith("<") else node,
            "data_path": o.get("data_path", "/var/lib/hesiod/openldap"),
            "kube": lab_spec["kubernetes"]["kube_config_path"]}


def openldap_tls(lab_spec, current=None):
    """Secret openldap-tls: LDAPS certificate from the lab CA (Module 10) for the FQDN + IP. Kept until <30 days left.
    Without the lab CA, a self-signed certificate is used and -m5 should be re-run after -m10."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import datetime, ipaddress, os
    cfg = openldap_settings(lab_spec)
    lab_ca = os.path.exists("conf/ca/root_ca.crt")
    if current and current.get("ldap.crt"):
        cert = x509.load_pem_x509_certificate(current["ldap.crt"].encode())
        left = (cert.not_valid_after_utc - datetime.datetime.now(datetime.timezone.utc)).days
        self_signed = cert.issuer == cert.subject
        san = [str(n.value) for n in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
        if left > 30 and cfg["fqdn"] in san and cfg["ip"] in san and not (self_signed and lab_ca):
            liblog.print_logs(f"    LDAPS certificate current ({left} days left). Keeping it.")
            return current
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption()).decode()
    sans = [x509.DNSName(cfg["fqdn"]), x509.IPAddress(ipaddress.ip_address(cfg["ip"]))]
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cfg["fqdn"])])
    if lab_ca:
        from python_lib import ca as libca
        csr = (x509.CertificateSigningRequestBuilder().subject_name(name)
               .add_extension(x509.SubjectAlternativeName(sans), critical=False).sign(key, hashes.SHA256()))
        leaf, inter, root = libca.sign_csr(lab_spec, csr.public_bytes(serialization.Encoding.PEM).decode())
        liblog.print_logs(f"    LDAPS certificate issued by the lab CA for {cfg['fqdn']} / {cfg['ip']}.")
        return {"ldap.crt": leaf.strip() + "\n" + inter.strip() + "\n", "ldap.key": key_pem,
                "ca.crt": inter.strip() + "\n" + root.strip() + "\n", "dhparam.pem": FFDHE2048}
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=825))
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    liblog.print_logs("    WARNING: no lab CA (conf/ca/root_ca.crt): LDAPS uses a self-signed certificate. "
                      "Re-run -m5 after -m10 to switch to the lab CA.")
    return {"ldap.crt": pem, "ldap.key": key_pem, "ca.crt": pem, "dhparam.pem": FFDHE2048}


def _ldap_conn(cfg, who="admin", ldaps=False, timeout=10):
    import ldap3, ssl
    if ldaps:
        tls = ldap3.Tls(validate=ssl.CERT_REQUIRED, ca_certs_file=_ldaps_trust_file(cfg))
        server = ldap3.Server(cfg["fqdn"] if who != "ip" else cfg["ip"], port=636, use_ssl=True, tls=tls,
                              connect_timeout=timeout, get_info=ldap3.NONE)
    else:
        server = ldap3.Server(cfg["ip"], port=389, connect_timeout=timeout, get_info=ldap3.NONE)
    dn, pw = {"admin": (cfg["admin_dn"], cfg["admin_password"]),
              "readonly": (cfg["readonly_dn"], cfg["readonly_password"])}.get(who, (cfg["readonly_dn"], cfg["readonly_password"]))
    conn = ldap3.Connection(server, user=dn, password=pw, receive_timeout=timeout, raise_exceptions=False)
    if not conn.bind():
        raise OpenLdapError(f"bind as {dn} to {server.host}:{server.port} failed: {conn.result.get('description')} "
                            f"{conn.result.get('message', '')}".strip())
    return conn


def _ldaps_trust_file(cfg):
    import os
    return "conf/ca/root_ca.crt" if os.path.exists("conf/ca/root_ca.crt") else f"{OPENLDAP_STATE_DIR}/ldaps_ca.pem"


def wait_until_openldap_ready(cfg, timeout_s=600):
    deadline, last = std.time.time() + timeout_s, None
    while std.time.time() < deadline:
        try:
            _ldap_conn(cfg, "admin").unbind()
            return True
        except Exception as e:
            last = str(e)[:150]
        std.time.sleep(10)
    raise OpenLdapError(f"OpenLDAP at {cfg['ip']}:389 not answering after {timeout_s}s (last: {last}). "
                        "Check: kubectl -n openldap logs deploy/openldap")


def _ensure_ou(conn, dn):
    import ldap3
    if conn.search(dn, "(objectClass=*)", search_scope=ldap3.BASE):
        return False
    if not conn.add(dn, ["organizationalUnit", "top"], {"ou": dn.split(",")[0].split("=")[1]}):
        raise OpenLdapError(f"cannot create {dn}: {conn.result}")
    liblog.print_logs(f"    Created {dn}")
    return True


def _check(conn, what):
    if conn.result.get("result") not in (0, 68):     # 68 = already exists
        raise OpenLdapError(f"{what}: {conn.result.get('description')} {conn.result.get('message', '')}")


def refresh_openldap_users(lab_spec):
    """Make OpenLDAP match lab_spec["ldap"]: add/update/remove users and groups, set passwords, fix memberships."""
    import ldap3
    from ldap3 import MODIFY_REPLACE
    from ldap3.utils.dn import escape_rdn
    liblog.print_logs("Instantiating refresh_openldap_users() function.")
    cfg = openldap_settings(lab_spec)
    spec = lab_spec.get("ldap") or {}
    users_spec = [u for u in spec.get("users", []) if not str(u.get("username", "")).startswith("<")]
    groups_spec = [g for g in spec.get("groups", []) if not str(g.get("name", "")).startswith("<")]
    conn = _ldap_conn(cfg, "admin")
    summary = {"users_added": 0, "users_updated": 0, "users_removed": 0, "passwords_set": 0,
               "groups_added": 0, "groups_updated": 0, "groups_removed": 0}

    liblog.print_logs("(Step 1) Organisational units.")
    _ensure_ou(conn, cfg["people_dn"])
    _ensure_ou(conn, cfg["groups_dn"])

    liblog.print_logs("(Step 2) Users from lab_spec.")
    wanted = {}
    for u in users_spec:
        uid = u["username"]
        dn = f"uid={escape_rdn(uid)},{cfg['people_dn']}"
        attrs = {"cn": u.get("display_name") or " ".join(x for x in (u.get("first_name"), u.get("last_name")) if x) or uid,
                 "sn": u.get("last_name") or uid}
        for k, a in (("first_name", "givenName"), ("display_name", "displayName"), ("email", "mail")):
            if u.get(k) and not str(u[k]).startswith("<"):
                attrs[a] = u[k]
        wanted[dn.lower()] = (dn, uid, attrs, u)
    conn.search(cfg["people_dn"], "(objectClass=inetOrgPerson)", search_scope=ldap3.LEVEL,
                attributes=["uid", "cn", "sn", "givenName", "displayName", "mail"])
    existing = {e.entry_dn.lower(): e for e in conn.entries}
    for key, e in existing.items():
        if key not in wanted:
            conn.delete(e.entry_dn)
            _check(conn, f"delete {e.entry_dn}")
            summary["users_removed"] += 1
            liblog.print_logs(f"    Removed user {e.entry_dn}")
    for key, (dn, uid, attrs, u) in wanted.items():
        if key not in existing:
            conn.add(dn, ["inetOrgPerson", "organizationalPerson", "person", "top"], {"uid": uid, **attrs})
            _check(conn, f"add {dn}")
            summary["users_added"] += 1
            liblog.print_logs(f"    Added user {uid}")
        else:
            e = existing[key]
            changes = {}
            for a in ("cn", "sn", "givenName", "displayName", "mail"):
                cur = e[a].value if a in e.entry_attributes else None
                cur = cur[0] if isinstance(cur, list) and len(cur) == 1 else cur
                new = attrs.get(a)
                if (cur or None) != (new or None):
                    changes[a] = [(MODIFY_REPLACE, [new] if new else [])]
            if changes:
                conn.modify(dn, changes)
                _check(conn, f"update {dn}")
                summary["users_updated"] += 1
                liblog.print_logs(f"    Updated user {uid}: {', '.join(changes)}")
        if u.get("password") and not str(u["password"]).startswith("<"):
            probe = ldap3.Connection(conn.server, user=dn, password=u["password"], raise_exceptions=False)
            ok = probe.bind()
            probe.unbind()
            if not ok:
                conn.extend.standard.modify_password(dn, new_password=u["password"])
                _check(conn, f"set password for {uid}")
                summary["passwords_set"] += 1
                liblog.print_logs(f"    Password set for {uid}")

    liblog.print_logs("(Step 3) Groups and memberships from lab_spec.")
    members_by_index = {i: [] for i in range(len(spec.get("groups", [])))}
    for u in users_spec:
        dn = f"uid={escape_rdn(u['username'])},{cfg['people_dn']}"
        for gi in u.get("add_to_these_groups", []):
            if gi not in members_by_index:
                raise OpenLdapError(f"user {u['username']}: add_to_these_groups index {gi} has no group in lab_spec")
            members_by_index[gi].append(dn)
    wanted_g = {}
    for i, g in enumerate(spec.get("groups", [])):
        if str(g.get("name", "")).startswith("<"):
            continue
        dn = f"cn={escape_rdn(g['name'])},{cfg['groups_dn']}"
        # groupOfUniqueNames needs at least one member: an empty group holds the admin DN (not a person, so VCF skips it)
        wanted_g[dn.lower()] = (dn, g["name"], sorted(members_by_index[i]) or [cfg["admin_dn"]])
    conn.search(cfg["groups_dn"], "(objectClass=groupOfUniqueNames)", search_scope=ldap3.LEVEL,
                attributes=["cn", "uniqueMember"])
    existing_g = {e.entry_dn.lower(): e for e in conn.entries}
    for key, e in existing_g.items():
        if key not in wanted_g:
            conn.delete(e.entry_dn)
            _check(conn, f"delete {e.entry_dn}")
            summary["groups_removed"] += 1
            liblog.print_logs(f"    Removed group {e.entry_dn}")
    for key, (dn, name, members) in wanted_g.items():
        if key not in existing_g:
            conn.add(dn, ["groupOfUniqueNames", "top"], {"cn": name, "uniqueMember": members})
            _check(conn, f"add {dn}")
            summary["groups_added"] += 1
            liblog.print_logs(f"    Added group {name} ({len(members)} member(s))")
        else:
            cur = sorted(m.lower() for m in existing_g[key]["uniqueMember"].values)
            if cur != sorted(m.lower() for m in members):
                conn.modify(dn, {"uniqueMember": [(MODIFY_REPLACE, members)]})
                _check(conn, f"update {dn}")
                summary["groups_updated"] += 1
                liblog.print_logs(f"    Updated group {name} members")
    conn.unbind()
    liblog.print_logs("LDAP refresh complete: " + ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in summary.items()))
    return summary


def openldap_checks(lab_spec, include_users=True):
    """What VCF SSO needs from the directory. Returns [{check, result, detail}]."""
    import ldap3, ssl, socket
    cfg = openldap_settings(lab_spec)
    checks = []

    def check(name, ok, detail=""):
        checks.append({"check": name, "result": "PASS" if ok else "FAIL", "detail": detail})
        liblog.print_logs(f"    {'PASS' if ok else 'FAIL'}  {name}" + (f"  ({detail})" if detail else ""))
        return ok

    try:
        ro = _ldap_conn(cfg, "readonly")
        check("Read-only bind (what VCF uses)", True, cfg["readonly_dn"])
    except Exception as e:
        check("Read-only bind (what VCF uses)", False, str(e)[:150])
        return checks
    ok = ro.search(cfg["base_dn"], "(objectClass=dcObject)", search_scope=ldap3.BASE, attributes=["dc", "o"])
    check("Base DN entry exists (Identity Broker domain retrieval)", ok and len(ro.entries) == 1,
          f"{cfg['base_dn']}" + (f", dc={ro.entries[0]['dc'].value}" if ok and ro.entries else ": No such object"))
    w = ro.add(f"cn=hesiod-write-test,{cfg['base_dn']}", ["organizationalRole"], {"cn": "hesiod-write-test"})
    check("Read-only account cannot write", not w, ro.result.get("description"))
    if w:
        ro.delete(f"cn=hesiod-write-test,{cfg['base_dn']}")
    spec = lab_spec.get("ldap") or {}
    groups = [g["name"] for g in spec.get("groups", [])]
    for u in [u for u in spec.get("users", []) if include_users and not str(u.get("username", "")).startswith("<")]:
        ro.search(cfg["people_dn"], f"(uid={ldap3.utils.conv.escape_filter_chars(u['username'])})",
                  attributes=["entryUUID", "memberOf"])
        if not ro.entries:
            check(f"User {u['username']} present", False, "not found (run -m6)")
            continue
        e = ro.entries[0]
        member_of = sorted(str(x).split(",")[0].split("=", 1)[1].lower() for x in (e["memberOf"].values if "memberOf" in e.entry_attributes else []))
        want = sorted(groups[i].lower() for i in u.get("add_to_these_groups", []) if i < len(groups))
        check(f"User {u['username']}: entryUUID and memberOf", bool(e["entryUUID"].value) and member_of == want,
              f"entryUUID {str(e['entryUUID'].value)[:8]}..., memberOf {member_of or '-'}")
    try:
        s = _ldap_conn(cfg, "readonly", ldaps=True)
        check("LDAPS (636) chain verifies to the lab root, hostname checked", True, f"{cfg['fqdn']}:636")
        s.unbind()
    except Exception as e:
        check("LDAPS (636) chain verifies to the lab root, hostname checked", False, str(e)[:150])
    ro.unbind()
    return checks


def write_vcf_sso_sheet(lab_spec):
    """The exact values for the VCF Operations SSO wizard (OpenLDAP identity provider). No passwords in the file."""
    import os
    cfg = openldap_settings(lab_spec)
    os.makedirs(OPENLDAP_STATE_DIR, exist_ok=True)
    groups = [g["name"] for g in (lab_spec.get("ldap") or {}).get("groups", []) if not str(g.get("name", "")).startswith("<")]
    trust = _ldaps_trust_file(cfg)
    rows = [("Identity provider", "OpenLDAP"),
            ("Directory name", f"{cfg['domain']} (OpenLDAP)"),
            ("Primary domain controller", f"ldaps://{cfg['fqdn']}:636"),
            ("Certificate", f"contents of {trust} (PEM, BEGIN/END lines included)"),
            ("Directory search attribute", "Custom Attribute"),
            ("Custom search attribute for Users", "uid"),
            ("Custom search attribute for Groups", "cn"),
            ("Base DN", cfg["base_dn"]),
            ("Bind user name", cfg["readonly_dn"]),
            ("Bind user password", f"lab_spec authentication entry {lab_spec['openldap']['readonly_credentials']} (also in Conjur after -m9 --export)"),
            ("Groups filter", "(objectClass=groupOfUniqueNames)"),
            ("Bind user filter", "(objectClass=organizationalRole)"),
            ("Users filter", "(objectClass=inetOrgPerson)"),
            ("Object UUID", "entryUUID"),
            ("Membership", "memberOf"),
            ("Group provisioning: base group DN", cfg["groups_dn"]),
            ("Groups to select", ", ".join(groups) or "(none in lab_spec)"),
            ("User provisioning: base user DN", "leave empty (users come from the selected groups)"),
            ("Login format", f"<uid>@{cfg['domain']}")]
    md = ["# VCF SSO wizard values (OpenLDAP)", "",
          "VCF Operations > Fleet Management > Identity and Access > Configure SSO. Generated by Theogony -m5.", "",
          "| Field | Value |", "|---|---|"] + [f"| {k} | `{v}` |" for k, v in rows]
    path = f"{OPENLDAP_STATE_DIR}/vcf_sso_wizard.md"
    with open(path, "w") as f:
        f.write("\n".join(md) + "\n")
    liblog.print_logs(f"VCF SSO wizard values: {path}")
    for k, v in rows:
        liblog.print_logs(f"    {k:<36} {v}")
    return path


def write_ldap_evidence(lab_spec, checks):
    """conf/evidence/ldap_evidence_<timestamp>.md/.json: directory checks + users/groups with entryUUID (no passwords)."""
    import ldap3, json, os
    cfg = openldap_settings(lab_spec)
    now = std.datetime.now()
    conn = _ldap_conn(cfg, "readonly")
    conn.search(cfg["people_dn"], "(objectClass=inetOrgPerson)", search_scope=ldap3.LEVEL,
                attributes=["uid", "mail", "entryUUID", "memberOf"])
    users = [{"uid": e["uid"].value, "mail": e["mail"].value if "mail" in e.entry_attributes else "",
              "entryUUID": str(e["entryUUID"].value),
              "groups": sorted(str(g).split(",")[0].split("=", 1)[1] for g in (e["memberOf"].values if "memberOf" in e.entry_attributes else []))}
             for e in conn.entries]
    conn.search(cfg["groups_dn"], "(objectClass=groupOfUniqueNames)", search_scope=ldap3.LEVEL,
                attributes=["cn", "entryUUID", "uniqueMember"])
    groups = [{"cn": e["cn"].value, "entryUUID": str(e["entryUUID"].value),
               "members": sorted(str(m).split(",")[0].split("=", 1)[1] for m in e["uniqueMember"].values
                                 if str(m).lower().startswith("uid="))} for e in conn.entries]
    conn.unbind()
    rep = {"generated": now.strftime("%Y-%m-%d %H:%M:%S"), "directory": f"ldaps://{cfg['fqdn']}:636",
           "base_dn": cfg["base_dn"], "bind_dn": cfg["readonly_dn"], "checks": checks,
           "users": sorted(users, key=lambda u: u["uid"]), "groups": sorted(groups, key=lambda g: g["cn"]),
           "result": "PASS" if all(c["result"] == "PASS" for c in checks) else "FAIL"}
    os.makedirs("conf/evidence", exist_ok=True)
    base = f"conf/evidence/ldap_evidence_{now.strftime('%Y%m%d-%H%M%S')}"
    with open(base + ".json", "w") as f:
        json.dump(rep, f, indent=2)
    L = ["# Directory evidence: OpenLDAP identity source for VCF SSO", "",
         f"Generated {rep['generated']} by Theogony -m6. **Overall: {rep['result']}**. No passwords appear in this report.", "",
         f"Directory `{rep['directory']}`, base DN `{rep['base_dn']}`, VCF bind account `{rep['bind_dn']}` (read-only).", "",
         "## Checks", "", "| Result | Check | Detail |", "|---|---|---|"]
    L += [f"| {c['result']} | {c['check']} | {c['detail']} |" for c in checks]
    L += ["", "## Groups", "", "| Group | entryUUID | Members |", "|---|---|---|"]
    L += [f"| {g['cn']} | `{g['entryUUID']}` | {', '.join(g['members']) or '-'} |" for g in rep["groups"]]
    L += ["", "## Users", "", "| User | Login | entryUUID | Groups (memberOf) |", "|---|---|---|---|"]
    L += [f"| {u['uid']} | {u['uid']}@{cfg['domain']} | `{u['entryUUID']}` | {', '.join(u['groups']) or '-'} |" for u in rep["users"]]
    L += ["", "## US-010: what this covers", "",
          "- The identity source VCF SSO syncs from, with the groups and memberships from lab_spec (re-run -m6 after any change).",
          "- Removing a user from a group in lab_spec and running -m6 removes the membership here; the Identity Broker "
          "drops the access at its next sync (users and groups keep their entryUUID, so role mappings survive -m6 runs).",
          "- Still manual: the VCF Operations SSO wizard (values in conf/openldap/vcf_sso_wizard.md), role assignment "
          "per component, and the login screenshots per group per component."]
    with open(base + ".md", "w") as f:
        f.write("\n".join(L) + "\n")
    liblog.print_logs(f"Evidence report: {rep['result']}  ->  {base}.md  (+ .json)")
    return rep
