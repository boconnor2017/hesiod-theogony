# Description: Primary launch for Theogony
# Author: Brendan O'Connor
# Date: November 2026
# Version: 2.0

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
from python_lib import dns_management as libdns
from python_lib import ubuntu as libubuntu
from python_lib import ldap_management as libldap
from python_lib import esxi as libesxi
from python_lib import vcf as libvcf
from python_lib import conjur as libconjur
from python_lib import ca as libca
from python_lib import backup as libbackup
from python_lib import kms as libkms

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

    if '-m6' in args:
        m6()
        std.sys.exit()

    if '-m8' in args:
        m8(args)
        std.sys.exit()

    if '-m7' in args:
        m7(args)
        std.sys.exit()

    if '-m9' in args:
        m9(args)
        std.sys.exit()

    if '-m10' in args:
        m10(args)
        std.sys.exit()

    if '-m11' in args:
        m11(args)
        std.sys.exit()

    if '-m12' in args:
        m12(args)
        std.sys.exit()

    else:
        help_menu()
        std.sys.exit()

def help_menu():
    print("=========================================================")
    print("Hesiod Main Menu:")
    print("    --help: this menu page")
    print("    -m1: (Module 1) Create Lab Spec JSON file.")
    print("    -m2: (Module 2) Deploy Hesiod Kubernetes Services (HKS) Cluster.")
    print("    -m3: (Module 3) Deploy Technitium on HKS.")
    print("    -m4: (Module 4) Create DNS Zone and FQDNs on Technitium.")
    print("    -m5: (Module 5) Deploy LLDAP on HKS.")
    print("    -m6: (Module 6) Create Users/Groups on LLDAP.")
    print("    -m7: (Module 7) Build nested ESXi hosts from ISO (kickstart).")
    print("         MGT to build hosts for a Management cluster")
    print("         VI to build hosts for a VI cluster")
    print("         --replace to rebuild")
    print("         --dns-ntp to re-apply DNS/NTP only")
    print("    -m8: (Module 8) VCF Fleet management domain. Default: precheck on the VCF Installer.")
    print("         --deploy  validate, then deploy and monitor (attaches if a deployment is already running)")
    print("         --retry   resume the newest failed deployment with the spec rebuilt from lab_spec")
    print("         --status  attach to the newest deployment and follow it")
    print("         --force   continue past local preflight failures")
    print("    -m9: (Module 9) Deploy Conjur OSS password vault on HKS and export lab passwords into it.")
    print("         --export       export only (Conjur already deployed)")
    print("         --deploy-only  deploy Conjur, skip the export")
    print("         --lab-only     export lab_spec credentials only (skip SDDC Manager)")
    print("         --report       evidence report only: readiness, inventory, coverage (no secret values)")
    print("    -m10: (Module 10) Deploy step-ca on HKS, test issuance, list VCF certificates (no VCF changes).")
    print("         --rotate [TYPE ...]  rotate VCF certificates to the lab CA (VCENTER NSXT_MANAGER ESXI SDDC_MANAGER)")
    print("         --dry-run            with --rotate: new CSRs + signing + SDDC Manager validation, nothing installed")
    print("         --force              with --rotate: rotate even certificates that are current and from the lab CA")
    print("         --test               US-004 issuance test only")
    print("         --report             evidence report: CA, US-004 test, VCF certificates, rotation history")
    print("    -m11: (Module 11) Deploy the SFTP backup target on HKS and test it (US-006). No VCF changes.")
    print("         --configure          point SDDC Manager, NSX and vCenter backups at it (daily, retention from lab_spec)")
    print("         --dry-run            with --configure: VCF validations only, nothing saved")
    print("         --backup-now         manual backup of SDDC Manager, NSX and vCenter, each waited on")
    print("         --report             evidence report: target test, configuration, backups on the target")
    print("    -m12: (Module 12) Deploy the KMIP key server on HKS (PyKMIP, lab CA certificates) and test it. No VCF changes.")
    print("         --configure          register it in the management vCenter as a Standard Key Provider, trust both ways")
    print("         --encrypt-vsan       vSAN data-at-rest + data-in-transit encryption (OSA: rolling reformat, ~1h/host)")
    print("         --in-transit-only    vSAN data-in-transit encryption only (no reformat)")
    print("         --backup-keys        copy the key database to conf/kmip/ and the SFTP backup target")
    print("         --report             evidence report: KMS tests, key provider status, vSAN encryption, key backup")
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
    libfile.append_text_to_file(" \n"+"import base64", "python_lib/standard_imports.py")
    libfile.append_text_to_file(" \n"+"import secrets", "python_lib/standard_imports.py")
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
    libos.install_package("pyvmomi")
    libos.install_package("cryptography")
    std.subprocess.check_call(["apt", "-y", "install", "xorriso"])
    libos.install_package("dnspython")
    std.subprocess.check_call(["apt", "-y", "install", "iputils-ping"])
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
    lab_spec_py = import_lab_configuration_parameters()
    #libvmw.pcli_create_ubuntu_server_from_iso(lab_spec_py)
    libubuntu.create_ubuntu_servers(lab_spec_py)
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
    print("Launching Theogony: MODULE 3")
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
    lab_spec_py = import_lab_configuration_parameters()
    libdns.refresh_vcf_dns_entries(lab_spec_py)
    print("=========================================================")
    print("Module 4 runtime is completed.")
    print("=========================================================")
    print("")
    print("")
    print("")
    return

def m5():
    print("=========================================================")
    print("Launching Theogony: MODULE 5")
    print("=========================================================")
    lab_spec_py = import_lab_configuration_parameters()
    libk8.deploy_lldap(lab_spec_py)
    print("=========================================================")
    print("Module 5 runtime is completed.")
    print("=========================================================")
    print("")
    print("")
    print("")
    return

def m6():
    print("=========================================================")
    print("Launching Theogony: MODULE 6")
    print("=========================================================")
    lab_spec_py = import_lab_configuration_parameters()
    libldap.refresh_vcf_ldap_users(lab_spec_py)
    print("=========================================================")
    print("Module 5 runtime is completed.")
    print("=========================================================")
    print("")
    print("")
    print("")
    return

def m7(args):
    print("=========================================================")
    print("Launching Theogony: MODULE 7 (20-30min)")
    print("=========================================================")
    lab_spec_py = import_lab_configuration_parameters()
    types = [t for t in ("MGT", "VI") if t in args] or None
    try:
        if "--dns-ntp" in args:  # re-apply DNS + NTP to hosts that are already built
            libesxi.configure_dns_ntp(lab_spec_py, types=types)
            return
        results = libesxi.create_nested_esxi_hosts(lab_spec_py, types=types, replace_existing=("--replace" in args))
    except libesxi.EsxiBuildError as e:
        liblog.print_logs("Module 7 stopped: "+str(e))
        std.sys.exit(1)
    for r in results:
        liblog.print_logs("    "+r["fqdn"]+" ("+r["ip"]+")  SHA-256 "+r["ssl_thumbprint"])
    print("=========================================================")
    print("Module 7 runtime is completed.")
    print("=========================================================")
    print("")
    print("")
    print("")
    return

def m8(args):
    print("=========================================================")
    print("Launching Theogony: MODULE 8 (3-4 hours)")
    print("=========================================================")
    lab_spec_py = import_lab_configuration_parameters()
    try:
        if "--deploy" in args:
            libvcf.deploy(lab_spec_py, force=("--force" in args))
        elif "--retry" in args:
            libvcf.retry(lab_spec_py)
        elif "--status" in args:
            libvcf.status(lab_spec_py)
        else:
            result = libvcf.run_pass1(lab_spec_py, force=("--force" in args))
            liblog.print_logs("VCF Installer validation result: "+str(result))
    except (libvcf.VcfError, libesxi.EsxiBuildError) as e:
        liblog.print_logs("Module 8 stopped: "+str(e))
        std.sys.exit(1)
    print("=========================================================")
    print("Module 8 runtime is completed.")
    print("=========================================================")
    print("")
    print("")
    print("")
    return

def m9(args):
    print("=========================================================")
    print("Launching Theogony: MODULE 9 (5-10min)")
    print("=========================================================")
    lab_spec_py = import_lab_configuration_parameters()
    try:
        if "--report" in args:
            report = libconjur.evidence_report(lab_spec_py, include_vcf=("--lab-only" not in args))
            if report["result"] != "PASS":
                std.sys.exit(1)
            return
        if "--export" not in args:
            libk8.deploy_conjur(lab_spec_py)
        if "--deploy-only" not in args:
            libconjur.export_passwords(lab_spec_py, include_vcf=("--lab-only" not in args))
    except (libconjur.ConjurError, libvcf.VcfError, RuntimeError) as e:
        liblog.print_logs("Module 9 stopped: "+str(e))
        std.sys.exit(1)
    print("=========================================================")
    print("Module 9 runtime is completed.")
    print("=========================================================")
    print("")
    print("")
    print("")
    return

def m10(args):
    print("=========================================================")
    print("Launching Theogony: MODULE 10")
    print("=========================================================")
    lab_spec_py = import_lab_configuration_parameters()
    types = [a.upper() for a in args if a.upper() in libca.ROTATION_ORDER] or None
    try:
        if "--report" in args:
            report = libca.evidence_report(lab_spec_py)
            if report["result"] != "PASS":
                std.sys.exit(1)
            return
        if "--test" in args:
            result = libca.test_issuance(lab_spec_py)
            for c in result["checks"]:
                liblog.print_logs(f"    {c['result']}  {c['check']}  {c['detail']}")
            if any(c["result"] != "PASS" for c in result["checks"]):
                std.sys.exit(1)
            return
        if "--rotate" in args:
            libca.rotate(lab_spec_py, types=types, force=("--force" in args), dry_run=("--dry-run" in args))
            return
        libk8.deploy_step_ca(lab_spec_py)
        liblog.print_logs("US-004 issuance test:")
        for c in libca.test_issuance(lab_spec_py)["checks"]:
            liblog.print_logs(f"    {c['result']}  {c['check']}  {c['detail']}")
        libca.inventory(lab_spec_py)
    except (libca.CaError, libconjur.ConjurError, libvcf.VcfError, RuntimeError) as e:
        liblog.print_logs("Module 10 stopped: "+str(e))
        std.sys.exit(1)
    finally:
        print("=========================================================")
        print("Module 10 runtime is completed.")
        print("=========================================================")
        print("")

def m11(args):
    print("=========================================================")
    print("Launching Theogony: MODULE 11")
    print("=========================================================")
    lab_spec_py = import_lab_configuration_parameters()
    try:
        if "--report" in args:
            report = libbackup.evidence_report(lab_spec_py)
            if report["result"] != "PASS":
                std.sys.exit(1)
            return
        if "--configure" in args:
            libbackup.configure(lab_spec_py, dry_run=("--dry-run" in args))
            return
        if "--backup-now" in args:
            libbackup.backup_now(lab_spec_py)
            return
        libk8.deploy_sftp(lab_spec_py)
        libbackup.vault_secrets(lab_spec_py)
        liblog.print_logs("US-006 backup target test:")
        result = libbackup.test_target(lab_spec_py)
        if any(c["result"] != "PASS" for c in result["checks"]):
            std.sys.exit(1)
    except (libbackup.BackupError, libconjur.ConjurError, libvcf.VcfError, RuntimeError) as e:
        liblog.print_logs("Module 11 stopped: "+str(e))
        std.sys.exit(1)
    finally:
        print("=========================================================")
        print("Module 11 runtime is completed.")
        print("=========================================================")
        print("")

def m12(args):
    print("=========================================================")
    print("Launching Theogony: MODULE 12")
    print("=========================================================")
    lab_spec_py = import_lab_configuration_parameters()
    try:
        if "--report" in args:
            report = libkms.evidence_report(lab_spec_py)
            if report["result"] != "PASS":
                std.sys.exit(1)
            return
        if "--configure" in args:
            libkms.configure(lab_spec_py)
            return
        if "--encrypt-vsan" in args or "--in-transit-only" in args:
            libkms.encrypt_vsan(lab_spec_py, in_transit_only=("--in-transit-only" in args))
            return
        if "--backup-keys" in args:
            libkms.backup_key_db(lab_spec_py)
            return
        libk8.deploy_kmip(lab_spec_py)
        liblog.print_logs("KMIP server test:")
        result = libkms.test_kms(lab_spec_py)
        if any(c["result"] != "PASS" for c in result["checks"]):
            std.sys.exit(1)
    except (libkms.KmsError, libca.CaError, libconjur.ConjurError, libvcf.VcfError, RuntimeError) as e:
        liblog.print_logs("Module 12 stopped: "+str(e))
        std.sys.exit(1)
    finally:
        print("=========================================================")
        print("Module 12 runtime is completed.")
        print("=========================================================")
        print("")

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