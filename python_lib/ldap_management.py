# Description: Contains all necessary functions to run and manage ldap services
# Author: Brendan O'Connor
# Version: 1.0
# Date: November 2026

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std
from python_lib import vmware as libvmw
from python_lib import logs_and_headers as liblog
from python_lib import json_management as libjson

def add_user(username, password, isAdmin: bool = False):
    liblog.print_logs("Adding user: "+username+" to LDAP.")
    return lldap_api("GET", lldap_server_ip, "graphql", {"user": {"id": username, "password": password, "isAdmin": isAdmin} }, "Add User")

def lldap_api(method, lldap_server_ip, endpoint, params, action_description):
    # Returns HTTP 200 even on failure; the real result is in the JSON "status" field.
    # params are passed via requests so values (passwords, tokens) are URL-encoded properly.
    api_url = "http://"+lldap_server_ip+":8443/api/"+endpoint
    api_response = std.requests.request(method, api_url, params=params, timeout=30)
    api_response.raise_for_status()
    api_json = api_response.json()
    if api_json.get("status") != "ok":
        error_message = api_json.get("errorMessage", str(api_json))
        liblog.print_logs("    FAILED: "+action_description+" -> "+error_message)
        raise RuntimeError("LLDAP API error ("+action_description+"): "+error_message)
    return api_json

def get_lldap_token(lldap_server_ip, username, password):
    liblog.print_logs("Getting LLDAP Token.")
    return lldap_api("GET", lldap_server_ip, "auth/simple/login", {"username": username, "password": password }, "Get Token")

def refresh_vcf_ldap_users(lab_spec):
    api_json = get_lldap_token(lab_spec["lldap"]["ip_address"], lab_spec["authentication"][lab_spec["lldap"]["use_these_credentials"]]["username"], lab_spec["authentication"][lab_spec["lldap"]["use_these_credentials"]]["password"])
    lldap_token = api_json["token"]
    liblog.print_logs("Token: "+lldap_token)


