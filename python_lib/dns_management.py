# Hesiod Technitium DNS Server Management
# Author: Brendan O'Connor
# Date: June 2026
# Version: 4.0

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std
from python_lib import vmware as libvmw
from python_lib import logs_and_headers as liblog
from python_lib import json_management as libjson

def technitium_api(method, ip, endpoint, params, action_description):
    # Technitium returns HTTP 200 even on failure; the real result is in the JSON "status" field.
    # params are passed via requests so values (passwords, tokens) are URL-encoded properly.
    api_url = "http://"+ip+":5380/api/"+endpoint
    api_response = std.requests.request(method, api_url, params=params, timeout=30)
    api_response.raise_for_status()
    api_json = api_response.json()
    if api_json.get("status") != "ok":
        error_message = api_json.get("errorMessage", str(api_json))
        liblog.print_logs("    FAILED: "+action_description+" -> "+error_message)
        raise RuntimeError("Technitium API error ("+action_description+"): "+error_message)
    return api_json

def change_technitium_password(token, ip, current_password, new_password):
    # Current Technitium API: "pass" is the CURRENT password, "newPass" is the new one.
    liblog.print_logs("Changing default password to "+new_password)
    return technitium_api("POST", ip, "user/changePassword", {"token": token, "pass": current_password, "newPass": new_password}, "change password")

def check_zone_exists(technitium_token, dns_server_ip, zone_name):
    liblog.print_logs("Checking if zone name "+zone_name+" exists.")
    api_json = technitium_api("GET", dns_server_ip, "zones/list", {"token": technitium_token}, "list zones")
    zones = api_json.get("response", {}).get("zones", [])
    zone_exists = any(z.get("name", "").lower() == zone_name.lower() for z in zones)
    liblog.print_logs("Zone Exists? "+("Yes." if zone_exists else "No."))
    return zone_exists

def create_tsig_key(technitium_token, dns_server_ip, key_name="tsig-key", algorithm="hmac-sha256"):
    # Technitium has no dedicated TSIG endpoint: keys live in the server settings.
    # settings/set "tsigKeys" REPLACES the whole list, so read the existing keys first and append.
    liblog.print_logs("Creating TSIG key: "+key_name+" ("+algorithm+")")
    settings_json = technitium_api("GET", dns_server_ip, "settings/get", {"token": technitium_token}, "get settings")
    existing_keys = settings_json.get("response", {}).get("tsigKeys") or []
    for key in existing_keys:
        if key.get("keyName", "").lower() == key_name.lower():
            liblog.print_logs("    TSIG key "+key_name+" already exists. Skipping creation.")
            return {"keyName": key["keyName"], "sharedSecret": key.get("sharedSecret"), "algorithmName": key.get("algorithmName")}
    shared_secret = std.base64.b64encode(std.secrets.token_bytes(32)).decode()
    new_key = {"keyName": key_name, "sharedSecret": shared_secret, "algorithmName": algorithm}
    # Pipe-separated table: keyName|sharedSecret|algorithm|keyName|sharedSecret|algorithm...
    tsig_table = "|".join(f"{k['keyName']}|{k['sharedSecret']}|{k['algorithmName']}" for k in existing_keys + [new_key])
    technitium_api("POST", dns_server_ip, "settings/set", {"token": technitium_token, "tsigKeys": tsig_table}, "create TSIG key "+key_name)
    liblog.print_logs("    TSIG key "+key_name+" created.")
    return new_key

def create_dns_zone(technitium_token, dns_ip, zone_name):
    params = {"token": technitium_token, "zone": zone_name, "type": "Primary"}
    return technitium_api("POST", dns_ip, "zones/create", params, "create zone "+zone_name)

def createdns_record(technitium_token, dns_ip, fqdn, dns_zone, ip_address, dns_type="A", dns_ttl="3600", dns_overwrite="true", dns_ptr="true", dns_create_ptr_zone="true"):
    # fqdn is the full record name, e.g. "vcf-01.lab.local"
    params = {
        "token": technitium_token,
        "domain": fqdn,
        "zone": dns_zone,
        "type": dns_type,
        "ttl": dns_ttl,
        "overwrite": dns_overwrite,
        "ipAddress": ip_address,
        "ptr": dns_ptr,
        "createPtrZone": dns_create_ptr_zone,
    }
    return technitium_api("POST", dns_ip, "zones/records/add", params, "add "+dns_type+" record "+fqdn)

def delete_dns_zone(technitium_token, dns_ip, zone_name):
    params = {"token": technitium_token, "zone": zone_name}
    return technitium_api("POST", dns_ip, "zones/delete", params, "delete zone "+zone_name)

def generate_fqdns_from_ip_range(domain, naming_convention, assign_ip_from_this_range_start, assign_ip_from_this_range_end, default_gateway):
    liblog.print_logs("Generating FQDNs from ip Range.")
    liblog.print_logs("(Step 1) Define the Fqdn Class.")
    class Fqdn:
        def __init__(self, name, ip_address):
            self.name = name
            self.ip_address = ip_address
    liblog.print_logs("(Step 2) Instantiate fqdn_list[].")
    fqdn_list = []
    liblog.print_logs("(Step 3) Get IP Range.")
    ip_range = libvmw.get_ip_range(default_gateway, assign_ip_from_this_range_start, assign_ip_from_this_range_end)
    i=0
    while i < len(ip_range):
        if i == 0:
            liblog.print_logs("    Reserve the first IP for the domain server: "+ip_range[i])
            dns_server_ip = ip_range[i]
        elif i < 10:
            fqdn = f"{naming_convention}-0{str(i)}.{domain}"
            fqdn_list.append(Fqdn(fqdn, ip_range[i]))
            liblog.print_logs(f"    Appending {fqdn} : {ip_range[i]}")
        else:
            fqdn = f"{naming_convention}-{str(i)}.{domain}"
            fqdn_list.append(Fqdn(fqdn, ip_range[i]))
            liblog.print_logs(f"    Appending {fqdn} : {ip_range[i]}")
        i=i+1
    liblog.print_logs("Finished. Returning fqdn_list[].")
    return fqdn_list, dns_server_ip

def get_technitium_token(username, password, ip):
    liblog.print_logs("Getting Technitium Token.")
    params = {"user": username, "pass": password, "includeInfo": "true"}
    technitium_token_json = technitium_api("GET", ip, "user/login", params, "login as "+username)
    return technitium_token_json["token"]

def get_theo_database():
    liblog.print_logs("Updating theo database.")
    theogony_db_str = libjson.populate_var_from_json_file("conf", "theogony_db.json")
    theogony_db_py = libjson.load_json_variable(theogony_db_str)
    liblog.print_logs("Runs: "+str(theogony_db_py["technitium_token"]))
    return theogony_db_py["technitium_token"]

def update_theo_database():
    liblog.print_logs("Updating theo database.")
    theogony_db_str = libjson.populate_var_from_json_file("conf", "theogony_db.json")
    theogony_db_py = libjson.load_json_variable(theogony_db_str)
    theogony_db_py["technitium_token"] = theogony_db_py["technitium_token"]+1
    libjson.dump_json_to_file(theogony_db_py, "conf/theogony_db.json")
    liblog.print_logs("Runs: "+str(theogony_db_py["technitium_token"]))
    return 


def refresh_vcf_dns_entries(lab_spec):
    liblog.print_logs("Refreshing VCF DNS entries.")
    i=0 #Hardcoded: use the first FQDNs list, expand later
    fqdn_list, dns_server_ip = generate_fqdns_from_ip_range(lab_spec["domain"]["name"], lab_spec["domain"]["fqdns"][i]["naming_convention"], lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_range_start"], lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_range_end"], lab_spec["network"][lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_network"]]["default_gateway"])
    # Step 1: Login and get token
    token_runs = get_theo_database()
    if token_runs == 0:
        liblog.print_logs("Getting temp token with first time login credentials.")
        first_time_password = "admin"
        technitium_token = get_technitium_token(lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]["username"], first_time_password, dns_server_ip)
        liblog.print_logs("Temp Token: "+technitium_token)
        change_technitium_password(technitium_token, dns_server_ip, first_time_password, lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]["password"])
        technitium_token = get_technitium_token(lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]["username"], lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]["password"], dns_server_ip)
        liblog.print_logs("Generated Technitium token. Token: "+technitium_token)
        create_tsig_key(technitium_token, dns_server_ip)
        liblog.print_logs("Generated TSIG Key.")
    else:
        technitium_token = get_technitium_token(lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]["username"], lab_spec["authentication"][lab_spec["domain"]["use_these_credentials"]]["password"], dns_server_ip)
        liblog.print_logs("Generated Technitium token. Token: "+technitium_token)

    # Step 2: Refresh zone: delete existing zone and FQDNs and recreate
    zone_name = lab_spec["domain"]["name"]
    zone_exists = check_zone_exists(technitium_token, dns_server_ip, zone_name)
    if zone_exists:
        liblog.print_logs("    Deleting zone: "+zone_name)
        delete_dns_zone(technitium_token, dns_server_ip, zone_name)
    liblog.print_logs("    Creating zone: "+zone_name)
    create_dns_zone(technitium_token, dns_server_ip, zone_name)

    # Step 3: Create DNS records using fqdn_list[].name and fqdn_list[].ip_address
    for fqdn in fqdn_list:
        liblog.print_logs("    Adding A record: "+fqdn.name+" -> "+fqdn.ip_address)
        createdns_record(technitium_token, dns_server_ip, fqdn.name, zone_name, fqdn.ip_address)
    liblog.print_logs("Finished refreshing "+str(len(fqdn_list))+" DNS entries in zone "+zone_name+".")
    
    #Step 4: Update Database
    update_theo_database() 
