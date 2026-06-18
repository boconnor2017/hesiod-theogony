# Description: Contains all necessary functions to run and manage kubernetes services
# Author: Brendan O'Connor
# Version: 1.0
# Date: June 2026

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std
from python_lib import logs_and_headers as liblog
from python_lib import os_management as libos
from python_lib import vmware as libvmw

def apply_from_yaml_old(local_kube_config_path, yaml_file_path, namespace):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CustomObjectsApi()
    liblog.print_logs(f"Applying {yaml_file_path} to the cluster.")
    with open(yaml_file_path, 'r') as file:
        resources = std.yaml.safe_load_all(file)
        for resource in resources:
            if not resource:
                continue
            api_version_split = resource["apiVersion"].split("/")
            group = api_version_split[0]
            version = api_version_split[1]
            plural = resource["kind"].lower() + "s"
            namespace = resource["metadata"].get("namespace", namespace)
            name = resource["metadata"]["name"]
            try:
                v1.create_namespaced_custom_object(
                    group=group,
                    version=version,
                    namespace=namespace,
                    plural=plural,
                    body=resource
                )
                liblog.print_logs(f"Successfully created resource.")
            except std.ApiException as e:
                if e.status == 409:
                    liblog.print_logs(f"Resource {resource['kind']} '{name}' already exists. Skipping.")
                else:
                    liblog.print_logs(f"Failed to create {resource['kind']} '{name}': {e}")

def apply_from_yaml(local_kube_config_path, yaml_file_path, default_namespace="default"):
    # 1. Load configuration and create the DYNAMIC client
    std.config.load_kube_config(config_file=local_kube_config_path)
    k8s_client = std.client.ApiClient()
    dynamic_client = std.dynamic.DynamicClient(k8s_client)
    
    liblog.print_logs(f"Applying {yaml_file_path} to the cluster.")
    
    with open(yaml_file_path, 'r') as file:
        resources = std.yaml.safe_load_all(file)
        
        for resource in resources:
            if not resource or "kind" not in resource:
                continue
                
            name = resource["metadata"].get("name")
            kind = resource["kind"]
            api_version = resource["apiVersion"]
            namespace = resource["metadata"].get("namespace", default_namespace)
            
            try:
                api_resource = dynamic_client.resources.get(
                    api_version=api_version, 
                    kind=kind
                )
                
                if api_resource.namespaced:
                    api_resource.create(body=resource, namespace=namespace)
                else:
                    api_resource.create(body=resource)
                    
                liblog.print_logs(f"Successfully created {kind} '{name}'.")
                
            except std.ApiException as e:
                if e.status == 409:
                    liblog.print_logs(f"Resource {kind} '{name}' already exists. Skipping.")
                else:
                    liblog.print_logs(f"Failed to create {kind} '{name}': {e}")
            except std.ResourceNotFoundError:
                liblog.print_logs(f"CRD for API {api_version} / Kind {kind} not registered on cluster.")

def create_namespace(local_kube_config_path, namespace):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    meta = std.client.V1ObjectMeta(name=namespace)
    body = std.client.V1Namespace(metadata=meta)
    try:
        v1.create_namespace(body=body)
        liblog.print_logs(f"Namespace {namespace} created successfully.")
    except std.ApiException as e:
        if e.status == 409:
            liblog.print_logs(f"Namespace {namespace} already exists.")
        else:
            liblog.print_logs(f"Exception when creating namespace: {e}")


def deploy_technitium(lab_spec):
    liblog.print_logs("Instantiating deploy_technitium() function.")
    # Step 1: Edit config map, change ipvs > strictARP from false to true
    # sudo kubectl --kubeconfig=/root/.kube/config edit configmap -n kube-system kube-proxy
    liblog.print_logs("(Step 1) Editing config map.")
    #edit_kube_proxy_configmap_for_metallb(lab_spec["kubernetes"]["kube_config_path"])
    enable_strict_arp_for_metallb(lab_spec["kubernetes"]["kube_config_path"])
    
    # Step 2: Create metallb namespace
    # sudo kubectl --kubeconfig=/root/.kube/config create namespace metallb-system
    liblog.print_logs("(Step 2) Creating namespaces.")
    create_namespace(lab_spec["kubernetes"]["kube_config_path"], "metallb-system")
    create_namespace(lab_spec["kubernetes"]["kube_config_path"], "technitium")

    # Step 3: Install core Metallb
    liblog.print_logs("(Step 3) Install core metallb.")
    install_core_metallb(lab_spec["kubernetes"]["kube_config_path"])
    
    # Step 4: Monitor pods, pause until they are all "Running" state
    # sudo kubectl --kubeconfig=/root/.kube/config get pods -n metallb-system
    liblog.print_logs("(Step 4) Monitoring metallb pods until they are running.")
    pause_for_pods_until_running(lab_spec["kubernetes"]["kube_config_path"], "metallb-system", 300)
    
    # Step 5: Replace in script file: k8_deploy_metallb_yaml.script
    liblog.print_logs("(Step 5) Generate deploy_metallb.yaml file.")
    set_metallb_yaml_script_name = "deploy_metallb.yaml"
    set_metallb_yaml_script_raw = libvmw.populate_var_from_file("scripts_lib/k8_deploy_metallb_yaml.script")
    set_metallb_yaml_script = set_metallb_yaml_script_raw.splitlines()
    libvmw.write_script_to_script_file(set_metallb_yaml_script, set_metallb_yaml_script_name)
    liblog.print_logs(f"{set_metallb_yaml_script_name} created.")
    i=0 # Hardcoded: will only pull from first group of fqdns in lab_spec.json. Expand this later.
    ip_range = libvmw.get_ip_range(lab_spec["network"][lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_network"]]["default_gateway"], lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_range_start"], lab_spec["domain"]["fqdns"][i]["assign_ip_from_this_range_end"])
    libvmw.search_and_replace_in_file("ID:DNS-001", ip_range[0], set_metallb_yaml_script_name)
    libvmw.search_and_replace_in_file("ID:DNS-002", ip_range[len(ip_range)-1], set_metallb_yaml_script_name)

    # Step 6: Replace in script file: k8_deploy_technitium_dns_yaml.script
    liblog.print_logs("(Step 6) Generate deploy_technitium_dns.yaml file.")
    set_technitium_yaml_script_name = "deploy_technitium_dns.yaml"
    set_technitium_yaml_script_raw = libvmw.populate_var_from_file("scripts_lib/k8_deploy_technitium_dns_yaml.script")
    set_technitium_yaml_script = set_technitium_yaml_script_raw.splitlines()
    libvmw.write_script_to_script_file(set_technitium_yaml_script, set_technitium_yaml_script_name)
    liblog.print_logs(f"{set_technitium_yaml_script_name} created.")
    i=0 # Hardcoded: will only create one DNS server from the dns range, and it will be the first on the list.
    libvmw.search_and_replace_in_file("ID:DNS-001", lab_spec["domain"]["server_ips"][i], set_technitium_yaml_script_name)
    
    # Step 7: Deploy metallb
    # sudo kubectl --kubeconfig=/root/.kube/config apply -f deploy-metallb.yaml
    liblog.print_logs("(Step 7) Deploy metallb.")
    apply_from_yaml(lab_spec["kubernetes"]["kube_config_path"], set_metallb_yaml_script_name, "metallb-system")
    pause_for_pods_until_running(lab_spec["kubernetes"]["kube_config_path"], "metallb-system", 300)
    
    # Step 8: Deploy technitium
    # sudo kubectl --kubeconfig=/root/.kube/config apply -f deploy-technitium-dns.yaml
    liblog.print_logs("(Step 8) Deploy technitium.")
    apply_from_yaml(lab_spec["kubernetes"]["kube_config_path"], set_technitium_yaml_script_name, "technitium")
    pause_for_pods_until_running(lab_spec["kubernetes"]["kube_config_path"], "technitium", 300)
    
    # Step 9: Create zone and populate dns entries for VCF
    liblog.print_logs("(Step 9) Create DNS zone and populate DNS entries for VCF.")

def edit_kube_proxy_configmap_for_metallb(local_kube_config_path):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    try:
        # Hardcode name and namespace as this is a specific function for metallb
        configmap = v1.read_namespaced_config_map(name="kube-proxy", namespace="kube-system")
        if configmap.data is None:
            configmap.data = {}
        # Hardcode key value pair as this is a specific function for metallb
        configmap.data["strictARP"] = "true"
        updated_configmap = v1.replace_namespaced_config_map(
            name="kube-proxy",
            namespace="kube-system",
            body=configmap
        )
        liblog.print_logs(f"ConfigMap kube-proxy updated successfully.")
        return updated_configmap
    except std.ApiException as e:
        liblog.print_logs(f"Exception when updating configmap: {e}")

def enable_strict_arp_for_metallb(local_kube_config_path):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    try:
        # Hardcode name and namespace as this is a specific function for metallb
        # Fetch ConfigMap
        configmap = v1.read_namespaced_config_map(name="kube-proxy", namespace="kube-system")
        # Extract the nested configuration string
        config_conf_str = configmap.data.get("config.conf")
        if not config_conf_str:
            liblog.print_logs(f"Could not find 'config.conf' inside the kube-proxy ConfigMap.")
            return False
        # Parse nested YAML into Python dictionary
        proxy_config = std.yaml.safe_load(config_conf_str)
        # Navigate to ipvs > strictARP and update it
        if "ipvs" not in proxy_config:
            proxy_config["ipvs"] = {}
        proxy_config["ipvs"]["strictARP"] = True
        # Serialize the dictionary back into a YAML string
        configmap.data["config.conf"] = std.yaml.dump(proxy_config, default_flow_style=False)
        # Push the update back to the cluster
        v1.replace_namespaced_config_map(name="kube-proxy", namespace="kube-system", body=configmap)
        liblog.print_logs(f"Successfully set ipvs.strictARP to true in kube-proxy ConfigMap.")
        return True
    except std.ApiException as e:
        liblog.print_logs(f"Kubernetes API Exception: {e}")
    except std.yaml.YAMLError as e:
        liblog.print_logs(f"Error parsing the internal kube-proxy YAML configuration: {e}")


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

def install_core_metallb(local_kube_config_path):
    std.config.load_kube_config(config_file=local_kube_config_path)
    k8s_client = std.client.ApiClient()
    
    # Official MetalLB native installation manifest URL
    # (Adjust the version v0.14.5 to match your environment if needed)
    metallb_manifest_url = "https://raw.githubusercontent.com/metallb/metallb/v0.14.5/config/manifests/metallb-native.yaml"
    
    liblog.print_logs("Installing core MetalLB manifests and CRDs.")
    try:
        # utils.create_from_yaml can accept a live URL string!
        with std.urllib.request.urlopen(metallb_manifest_url) as response:
            yaml_content = response.read()

        with std.tempfile.NamedTemporaryFile(suffix=".yaml", delete=True) as temp_file:
            temp_file.write(yaml_content)
            temp_file.flush()
            std.utils.create_from_yaml(k8s_client, temp_file.name)

        liblog.print_logs("Core MetalLB manifests applied successfully.")
        return True
    
    except std.utils.FailToCreateError as e:
        liblog.print_logs("Manifests applied with some conflicts/already existing resources, continuing.")
        return True

    except Exception as e:
        liblog.print_logs(f"Failed to install core MetalLB: {e}")
        return False

def pause_for_pods_until_running(local_kube_config_path, pod_namespace, timeout_seconds):
    std.config.load_kube_config(config_file=local_kube_config_path)
    v1 = std.client.CoreV1Api()
    w = std.watch.Watch()
    liblog.print_logs(f"Waiting for pods in namespace '{pod_namespace}' to be Running...")
    start_time = std.time.time()
    for event in w.stream(v1.list_namespaced_pod, namespace=pod_namespace, timeout_seconds=timeout_seconds):
        pod = event['object']
        status = pod.status.phase
        pods = v1.list_namespaced_pod(namespace=pod_namespace)
        if not pods.items:
            continue
        all_running = all(p.status.phase == "Running" for p in pods.items)
        if all_running:
            liblog.print_logs(f"All pods are now successfully Running!")
            w.stop()
            return True 
        if std.time.time() - start_time > timeout_seconds:
            liblog.print_logs(f"Timed out waiting for pods to be ready.")
            w.stop()
            return False 
    liblog.print_logs(f"Watch stream ended or timed out.")
    return False
