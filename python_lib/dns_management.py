# Hesiod Technitium DNS Server Management
# Author: Brendan O'Connor
# Date: June 2026
# Version: 4.0

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std
from python_lib import vmware as libvmw
from python_lib import logs_and_headers as liblog

def get_tanium_token(username, password, ip):
    api_url = "http://"+ip+":5380"+"/api/user/login?user="+username+"&pass="+password+"&includeInfo=true"
    api_response = std.requests.get(api_url)
    tanium_token = (api_response.json()['token'])
    return tanium_token

def change_tanium_password(token, ip, new_password):
    api_url = "http://"+ip+":5380"+"/api/user/changePassword?token="+token+"&pass="+new_password
    api_response = std.requests.get(api_url)
    return api_response

def create_dns_zone(tanium_token, dns_ip, zone_name):
    api_url = "http://"+dns_ip+":5380/api/zones/create?token="+tanium_token+"&zone="+zone_name+"&type=Primary"
    api_response = std.requests.get(api_url)
    return api_response

def createdns_record(tanium_token, dns_ip, dns_record, dns_zone, ip_address, dns_type, dns_ttl, dns_overwrite, dns_ptr, dns_create_ptr_zone):
    api_url = "http://"+dns_ip+":5380/api/zones/records/add?"
    api_url = api_url+"token="+tanium_token
    api_url = api_url+"&domain="+dns_record+"."+dns_zone
    api_url = api_url+"&zone="+dns_zone
    api_url = api_url+"&type="+dns_type
    api_url = api_url+"&ttl="+dns_ttl
    api_url = api_url+"&overwrite="+dns_overwrite
    api_url = api_url+"&ipAddress="+ip_address
    api_url = api_url+"&ptr="+dns_ptr
    api_url = api_url+"&createPtrZone="+dns_create_ptr_zone
    api_response = std.requests.get(api_url)
    return api_response

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
            liblog.print_logs("    Skip first IP as this is reserved for Technitium DNS Server.")
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
    return fqdn_list

def refresh_vcf_dns_entries(lab_spec):
    liblog.print_logs("Refreshing VCF DNS entries.")
    i=0 #Hardcoded: use the first FQDNs list, expand later
    fqdn_list = generate_fqdns_from_ip_range(lab_spec["domain"]["name"], lab_spec["domain"]["fqdns"][i]["naming_convention"], lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_range_start"], lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_range_end"], lab_spec["network"][lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_network"]]["default_gateway"])
    # Step 1: Login and get token, add to theogony db first time default vs. set pw
    #
    # Step 2: Refresh zone: delete existing zone and FQDNs and recreate
    #
    # Step 3: Create DNS records using fqdn_list[].name and fqdn_list[].ip_address
