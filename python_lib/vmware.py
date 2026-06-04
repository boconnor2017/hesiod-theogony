# Hesiod VMware Management
# Author: Brendan O'Connor
# Date: June 2026
# Version: 4.0

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std
from python_lib import logs_and_headers as liblog

# Local Functions
def delete_script_file(script_file_name):
    if std.os.path.exists(script_file_name):
        std.os.remove(script_file_name)

def get_ip_range(default_gateway, assign_ip_from_this_range_start, assign_ip_from_this_range_end):
    subnet = default_gateway.split(".")
    range_end = int(assign_ip_from_this_range_end)
    range_start = int(assign_ip_from_this_range_start)
    range_end=(range_end+1) # (+1) because you want to include the end in the range
    ip_count = (range_end-range_start)
    ip_range = []
    i = 0
    while i < ip_count:
        ip_range.append(subnet[0]+"."+subnet[1]+"."+subnet[2]+"."+str(range_start+i))
        i=i+1
    return ip_range

def hello_world():
    print("Works.")

def pcli_create_ubuntu_server_from_iso(lab_spec):
    liblog.print_logs("Initiating pcli_create_ubuntu_server_from_iso(lab_spec) function.")
    # Import Keystrokes powershell script
    set_vm_keystrokes_script_name = "Set-VMKeystrokes.ps1"
    set_vm_keystrokes_script_raw = populate_var_from_file("scripts_lib/pcli_set_vm_keystrokes.script")
    set_vm_keystrokes_script = set_vm_keystrokes_script_raw.splitlines()
    write_script_to_script_file(set_vm_keystrokes_script, set_vm_keystrokes_script_name)
    liblog.print_logs("Set-VMKeystrokes.ps1 created.")
    # Import create Ubuntu Server from ISO script
    create_ubuntu_from_iso_script_name = "pcli_create_ubuntu_from_iso.ps1"
    create_ubuntu_from_iso_script_raw = populate_var_from_file("scripts_lib/pcli_create_ubuntu_server_from_iso.script")
    create_ubuntu_from_iso_script = create_ubuntu_from_iso_script_raw.splitlines()
    write_script_to_script_file(create_ubuntu_from_iso_script, create_ubuntu_from_iso_script_name)
    liblog.print_logs("pcli_create_ubuntu_from_iso.ps1 script created.")
    # Create temp scripts for parallelization
    temp_script = []
    i=0
    while i < len(lab_spec["ubuntu_servers"]):
        liblog.print_logs("Creating Ubuntu Servers of type: "+lab_spec["ubuntu_servers"][i]["ubuntu_type"])
        u=0
        while u < lab_spec["ubuntu_servers"][i]["deploy_this_many"]:
            # Create Temporary PowerCLI script for each VM by copying master script
            std.shutil.copy(create_ubuntu_from_iso_script_name, str(u)+"_"+create_ubuntu_from_iso_script_name)
            temp_script.append(str(u)+"_"+create_ubuntu_from_iso_script_name)
            # Find and Replace Server Input Variables with given values from lab_spec
            search_and_replace_in_file("ID:SIV-001", lab_spec["physical_esxi_servers"][lab_spec["ubuntu_servers"][i]["deploy_to_this_physical_host"]]["ip_address"], temp_script[u])
            search_and_replace_in_file("ID:SIV-002", lab_spec["authentication"][lab_spec["physical_esxi_servers"][lab_spec["ubuntu_servers"][i]["deploy_to_this_physical_host"]]["use_these_credentials"]]["username"], temp_script[u])
            search_and_replace_in_file("ID:SIV-003", lab_spec["authentication"][lab_spec["physical_esxi_servers"][lab_spec["ubuntu_servers"][i]["deploy_to_this_physical_host"]]["use_these_credentials"]]["password"], temp_script[u])
            search_and_replace_in_file("ID:SIV-004", lab_spec["physical_esxi_servers"][lab_spec["ubuntu_servers"][i]["deploy_to_this_physical_host"]]["deploy_vms_to_these_datastores"][lab_spec["ubuntu_servers"][i]["deploy_to_this_datastore"]], temp_script[u])
            search_and_replace_in_file("ID:SIV-005", lab_spec["ubuntu_servers"][i]["CD_path"], temp_script[u])
            # Find and Replace VM Input Variables with given values from lab_spec
            search_and_replace_in_file("ID:VIV-001", lab_spec["ubuntu_servers"][i]["naming_convention"]+"00"+str(u+2), temp_script[u])
            search_and_replace_in_file("ID:VIV-002", lab_spec["ubuntu_servers"][i]["numCPU"], temp_script[u])
            search_and_replace_in_file("ID:VIV-003", lab_spec["ubuntu_servers"][i]["memoryGB"], temp_script[u])
            search_and_replace_in_file("ID:VIV-004", lab_spec["ubuntu_servers"][i]["harddisks"][0]["storage_GB"], temp_script[u])
            search_and_replace_in_file("ID:VIV-005", lab_spec["physical_esxi_servers"][lab_spec["ubuntu_servers"][i]["deploy_to_this_physical_host"]]["deploy_vms_to_these_networks"][lab_spec["ubuntu_servers"][i]["deploy_to_this_network"]], temp_script[u])
            # Find and Replace Ubuntu Input Variables with given values from lab_spec
            ip_range = get_ip_range(lab_spec["network"][lab_spec["ubuntu_servers"][i]["assign_ip_from_this_network"]]["default_gateway"], lab_spec["ubuntu_servers"][i]["assign_ip_from_this_range_start"], lab_spec["ubuntu_servers"][i]["assign_ip_from_this_range_end"])
            search_and_replace_in_file("ID:EIV-001", ip_range[u], temp_script[u])
            search_and_replace_in_file("ID:EIV-002", lab_spec["network"][lab_spec["ubuntu_servers"][i]["assign_ip_from_this_network"]]["subnet_mask"],temp_script[u])
            search_and_replace_in_file("ID:EIV-003", lab_spec["network"][lab_spec["ubuntu_servers"][i]["assign_ip_from_this_network"]]["default_gateway"], temp_script[u])
            # Build Ubuntu Servers
            liblog.print_logs("Executing script "+temp_script[u])
            pcli_execute(temp_script[u])
            liblog.print_logs("Finished. Cleaning up "+temp_script[u])
            # Cleanup
            delete_script_file(temp_script[u])
            liblog.print_logs("Finished cleanup. Proceeding to the next vm.")
            u=u+1
        i=i+1


def pcli_execute(script_file_name):
    cmd = []
    cmd = ["pwsh", script_file_name]
    err = std.subprocess.run(cmd, capture_output=True)
    return err


def populate_var_from_file(file_name):
    with open(file_name) as file:
        file_txt = file.read()
        return file_txt

def search_and_replace_in_file(searchtext, replacewithtext, filename):
    line = populate_var_from_file(filename)
    newline = line.replace(searchtext, replacewithtext)
    delete_script_file(filename)
    filename = open(filename, "a")
    for line in newline:
        filename.writelines(line)
    filename.close()

def write_script_to_script_file(script, script_file_name):
    delete_script_file(script_file_name)
    script_file_name = open(script_file_name, "a")
    for line in script:
        script_file_name.writelines(line+'\n')
    script_file_name.close()