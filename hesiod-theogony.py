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
from python_lib import pip_install as libpip
from python_lib import json_management as libjson


# Local Functions
def _main_(args):
    liblog.hesiod_print_header()
    update_theo_database()

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
    print("Main Menu:")
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

def install_pip_packages():
    print("=========================================================")
    print("First time run. Initializing required python packages.")
    print("=========================================================")
    libpip.install_package("docker")
    libfile.append_text_to_file("import docker"+" \n", "python_lib/standard_imports.py")
    libpip.install_package("paramiko")
    libfile.append_text_to_file("import paramiko"+" \n", "python_lib/standard_imports.py")
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
    print("Launching Theogony: MODULE 2")
    print("=========================================================")

def m3():
    print("=========================================================")
    print("Launching Theogony: MODULE 3")
    print("=========================================================")

def m4():
    print("=========================================================")
    print("Launching Theogony: MODULE 4")
    print("=========================================================")

def m5():
    print("=========================================================")
    print("Launching Theogony: MODULE 5")
    print("=========================================================")

def update_theo_database():
    existcheck = libfile.check_if_file_exists("conf/theogony_db.json")
    if existcheck == 1:
        theogony_db_str = libjson.populate_var_from_json_file("conf", "theogony_db.json")
        theogony_db_py = libjson.load_json_variable(theogony_db_str)
        theogony_db_py["runs"] = theogony_db_py["runs"]+1
        libjson.dump_json_to_file(theogony_db_py, "conf/theogony_db.json")
        return
    else:
       libfile.copy_file_from_srcdir_to_destdir("json_lib/theogony_db.json", "conf/theogony_db.json")
       install_pip_packages()


# Program Launch
_main_(std.sys.argv)