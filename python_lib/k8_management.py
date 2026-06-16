# Description: Contains all necessary functions to run and manage kubernetes services
# Author: Brendan O'Connor
# Version: 1.0
# Date: June 2026

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std
from python_lib import logs_and_headers as liblog
from python_lib import os_management as libos
from python_lib import vmware as libvmw

def apply_from_yaml(local_kube_config_path, yaml_file_path):
    std.config.load_kube_config(config_file=local_kube_config_path)
    #v1 = std.client.CoreV1Api()
    v1 = std.client.ApiClient()
    std.utils.create_from_yaml(v1, yaml_file_path, verbose=True)

def deploy_technitium(lab_spec):
    liblog.print_logs("Instantiating deploy_technitium() function.")
    liblog.print_logs("(Step 1) Deploy metallb.")
    libos.download_script_from_github("https://raw.githubusercontent.com/boconnor2017/hesiod-theogony/refs/heads/main/scripts_lib/k8_deploy_metallb_yaml.script", lab_spec["kubernetes"]["metallb_deploy_yaml_name"], lab_spec["authentication"][0])
    liblog.print_logs(f"    {lab_spec["kubernetes"]["metallb_deploy_yaml_name"]} created.")
    libvmw.search_and_replace_in_file("ID:DNS-001", lab_spec["domain"]["server_ips"][0], lab_spec["kubernetes"]["metallb_deploy_yaml_name"])
    liblog.print_logs(f"    ID:DNS-001 replaced with {lab_spec["domain"]["server_ips"][0]}.")
    apply_from_yaml(lab_spec["kubernetes"]["kube_config_path"], lab_spec["kubernetes"]["metallb_deploy_yaml_name"])
    liblog.print_logs(f"    Metallb pod deployed.")

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