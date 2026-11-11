# Description: Contains all necessary functions to run and manage ldap services
# Author: Brendan O'Connor
# Version: 1.0
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
