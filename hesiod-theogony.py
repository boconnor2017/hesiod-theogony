# Description: Primary launch for Theogony
# Author: Brendan O'Connor
# Date: June 2026
# Version: 1.0

# Menu:
#  -help or blank: return menu

# Import Hesiod Libraries
from python_lib import standard_imports as std
from python_lib import logs_and_headers as liblog
from python_lib import file_management as libfile
from python_lib import os_management as libos
from python_lib import json_management as libjson 
from python_lib import vmware as libvmw
from python_lib import k8_management as libk8

# Local Functions
def _main_(args):
    liblog.hesiod_print_header()
    update_theo_database()

    if '-init' in args:
        install_pip_packages()
        std.sys.exit()

    if '--help' in args:
        help_menu()
        std.sys.exit()

    if '-m1' in args:
        m1()
        std.sys.exit()
    
    if '-m2' in args:
        m2()
        std.sys.exit()

    if '-m3' in args:
        m3()
        std.sys.exit()

    if '-m4' in args:
        m4()
        std.sys.exit()

    if '-m5' in args:
        m5()
        std.sys.exit()

    else:
        help_menu()
        std.sys.exit()

def help_menu():
    print("=========================================================")
    print("Hesiod Main Menu:")
    print("    --help: this menu page")
    print("    -m1: (Module 1) Create Lab Spec JSON file.")
    print("    -m2: (Module 2) Deploy Hesiod K8 Cluster.")
    print("    -m3: (Module 3) Deploy Technitium DNS Server.")
    print("    -m4: (Module 4) Create VCF Spec JSON file.")
    print("    -m5: (Module 5) Deploy VCF 9.1 Ready Nested ESXi Hosts")
    print("")
    print("For further details and documentation, please see https://github.com/boconnor2017/hesiod-theogony")
    print("")
    print("=========================================================") 
    print("")
    print("")
    print("")

def import_lab_configuration_parameters():
    # Check for Required Configuration Parameters
    liblog.print_logs("Checking for required lab configuration parameters.")
    lab_spec_doesexist = libfile.check_if_file_exists("conf/lab_spec.json")

    # Import Configuration Parameters
    if lab_spec_doesexist == 1:
        liblog.print_logs("LAB_SPEC CHECK: exists.")
        lab_spec_str = libjson.populate_var_from_json_file("conf", "lab_spec.json")
        lab_spec_py = libjson.load_json_variable(lab_spec_str)
        liblog.print_logs("lab_spec_py variable populated.")
        liblog.print_logs("Validation check: "+lab_spec_py["validation_check"])
        return lab_spec_py
    else:
        print("")
        print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
        print("    ERR: lab_spec.json does not exist in the /conf folder. To resolve this you have two options:")
        print("        Option 1: Manually copy the contents from json_lib/lab_spec.json and paste into conf/lab_spec.json. Edit conf/lab_spec.json accordingly.")
        print("        Option 2: Rerun this script using the -m1 parameter. This will launch a prompt wizard that will populate conf/lab_spec.json for you.")
        print("")
        print("        If you have already completed Module 1, upload the json file to conf/lab_spec.json and run again.")
        print("")
        print("* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *")
        print("")

def install_pip_packages():
    print("=========================================================")
    print("First time run. Initializing required python packages.")
    print("=========================================================")
    libfile.append_text_to_file(" \n"+"import requests", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"import urllib3", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"import urllib", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"import time", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"import os", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"from datetime import datetime", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"import yaml", "python_lib/standard_imports.py")
    libos.install_package("docker")
    libfile.append_text_to_file(" \n"+"import docker", "python_lib/standard_imports.py")
    libos.install_package("paramiko")
    libfile.append_text_to_file(" \n"+"import paramiko", "python_lib/standard_imports.py")
    libos.install_package("fabric")
    libfile.append_text_to_file(" \n"+"from fabric import Connection, Group", "python_lib/standard_imports.py")
    libos.install_package("invoke")
    libfile.append_text_to_file(" \n"+"from invoke import Responder", "python_lib/standard_imports.py")
    libos.install_package("kubernetes")
    libfile.append_text_to_file(" \n"+"import kubernetes", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"from kubernetes import client, config, utils, watch, dynamic", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"from kubernetes.client.rest import ApiException", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"from kubernetes.dynamic.exceptions import ResourceNotFoundError", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"import tempfile", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n", "python_lib/standard_imports.py")
    print("=========================================================")
    print("Init completed.")
    print("=========================================================")
    print("")
    print("")
    print("")

def m1():
    print("=========================================================")
    print("Launching Theogony: MODULE 1")
    print("=========================================================")

def m2():
    print("=========================================================")
    print("Launching Theogony: MODULE 2 (21min)")
    print("=========================================================")
    lab_spec_py = import_lab_configuration_parameters()
    libvmw.pcli_create_ubuntu_server_from_iso(lab_spec_py)
    libos.setup_hesiod_k8_nodes(lab_spec_py)
    print("=========================================================")
    print("Module 2 runtime is completed.")
    print("=========================================================")
    print("")
    print("")
    print("")
    return

def m3():
    print("=========================================================")
    print("Launching Theogony: MODULE 3 (6min)")
    print("=========================================================")
    lab_spec_py = import_lab_configuration_parameters()
    libos.setup_os_for_technitium(lab_spec_py)
    libk8.deploy_technitium(lab_spec_py)
    print("=========================================================")
    print("Module 3 runtime is completed.")
    print("=========================================================")
    print("")
    print("")
    print("")
    return

def m4():
    print("=========================================================")
    print("Launching Theogony: MODULE 4")
    print("=========================================================")

def m5():
    print("=========================================================")
    print("Launching Theogony: MODULE 5")
    print("=========================================================")

def update_theo_database():
    liblog.print_logs("Updating theo database.")
    existcheck = libfile.check_if_file_exists("conf/theogony_db.json")
    if existcheck == 1:
        theogony_db_str = libjson.populate_var_from_json_file("conf", "theogony_db.json")
        theogony_db_py = libjson.load_json_variable(theogony_db_str)
        theogony_db_py["runs"] = theogony_db_py["runs"]+1
        libjson.dump_json_to_file(theogony_db_py, "conf/theogony_db.json")
        liblog.print_logs("Runs: "+str(theogony_db_py["runs"]))
        return
    else:
       libfile.copy_file_from_srcdir_to_destdir("json_lib/theogony_db.json", "conf/theogony_db.json")
       install_pip_packages()


# Program Launch
_main_(std.sys.argv)