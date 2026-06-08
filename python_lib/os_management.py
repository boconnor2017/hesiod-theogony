# Description: Contains all necessary functions to install software on Ubuntu
# Author: Brendan O'Connor
# Version: 1.0
# Date: June 2026

# Import Hesiod Libraries (Standard Imports)
from python_lib import standard_imports as std
from python_lib import logs_and_headers as liblog
from python_lib import vmware as libvmw

def helloworld():
    print("Works!")

def install_kubernetes(ssh_username, ssh_password, control_plane_ip, worker_ips, k8_version):
    master_conn = std.Connection(host=control_plane_ip, user=ssh_username, connect_kwargs={"password": ssh_password})
    workers = std.Group(*worker_ips, user=ssh_username, connect_kwargs={"password": ssh_password})
    liblog.print_logs("Starting Kubernetes Cluster deployment.")

    # Step 1: Run common setup everywhere
    setup_common(master_conn, ssh_password, k8_version)
    for worker in workers:
        setup_common(worker, ssh_password, k8_version)
    liblog.print_logs("Step 1: common setup completed.")

    # Step 2: Initialize Control Plane
    init_result = run_sudo(master_conn, f"kubeadm init --apiserver-advertise-address={control_plane_ip} --pod-network-cidr=10.244.0.0/16", ssh_password)
    run_sudo(master_conn, "mkdir -p $HOME/.kube", ssh_password)
    run_sudo(master_conn, "cp -i /etc/kubernetes/admin.conf $HOME/.kube/config", ssh_password)
    run_sudo(master_conn, f"chown {ssh_username}:{ssh_username} $HOME/.kube/config", ssh_password)
    liblog.print_logs("Step 2: initialize control plane completed.")

    # Step 3: Install Pod Network (Flannel CNI)
    master_conn.run("kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml")
    liblog.print_logs("Step 3: pod network (Flannel) installation completed.")

    # Step 4: Extract the Join Command
    token_result = run_sudo(master_conn, "kubeadm token create --print-join-command", ssh_password)
    join_command = token_result.stdout.strip().split('\n')[-1]
    liblog.print_logs("Step 4: join command extract completed.")

    # Step 5: Join Worker Nodes to Cluster
    for worker in workers:
        run_sudo(worker, join_command, ssh_password)
    liblog.print_logs("Step 5: join worker nodes to cluster completed.")

    liblog.print_logs("Kubernetes cluster deployment is completed. You can now login to the Master at "+control_plane_ip+" and run 'kubectl get nodes' to verify.")
    

def install_package(package_name):
    std.subprocess.check_call(["apt", "-y", "install", "python3-"+package_name])

def pause_python_for_duration(seconds):
    std.time.sleep(seconds)

def run_sudo(conn, cmd, ssh_password):
    sudopass = std.Responder(
        pattern=r'\[sudo\] password for .*:',
        response=f"{ssh_password}\n"
    )
    return conn.run(f"echo '{ssh_password}' | sudo -S {cmd}", hide=True)

def setup_common(conn, ssh_password, k8_version):
    liblog.print_logs("Configuring Kubernetes Prerequisites on connection host.")
    
    # 1. Disable Swap (Kubernetes requirement)
    liblog.print_logs("(Prereq 1) Disabling swap.")
    run_sudo(conn, "swapoff -a", ssh_password)
    run_sudo(conn, "sed -i '/swap/d' /etc/fstab", ssh_password)
    
    # 2. Load kernel modules for bridging
    liblog.print_logs("(Prereq 2) Loading kernel modules for bridging.")
    run_sudo(conn, "modprobe overlay", ssh_password)
    run_sudo(conn, "modprobe br_netfilter", ssh_password)
    
    # Configure sysctl params
    sysctl_cmd = (
        'bash -c '
        '\'echo -e "net.bridge.bridge-nf-call-iptables = 1\\n'
        'net.bridge.bridge-nf-call-ip6tables = 1\\n'
        'net.ipv4.ip_forward = 1" > /etc/sysctl.d/k8s.conf\''
    )

    run_sudo(conn, sysctl_cmd, ssh_password)
    run_sudo(conn, "sysctl --system", ssh_password)
    
    # 3. Install containerd runtime
    liblog.print_logs("(Prereq 3) Installing containerd runtime.")
    run_sudo(conn, "apt-get update", ssh_password)
    run_sudo(conn, "apt-get install -y containerd apt-transport-https ca-certificates curl gpg", ssh_password)

    # Configure containerd to use systemd cgroup 
    run_sudo(conn, "mkdir -p /etc/containerd", ssh_password)
    
    # We execute the config generation and redirection inside a single root bash session
    containerd_cmd = "bash -c 'containerd config default > /etc/containerd/config.toml'"
    run_sudo(conn, containerd_cmd, ssh_password)
    
    # Update the file to set SystemdCgroup to true
    run_sudo(conn, "sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml", ssh_password)
    run_sudo(conn, "systemctl restart containerd", ssh_password)

    # 4. Install kubelet, kubeadm, kubectl (Fixed URLs & formatting)
    run_sudo(conn, "mkdir -p -m 755 /etc/apt/keyrings", ssh_password)
    
    # Note the colons (:) in the core:/stable:/ structural path
    curl_cmd = f"curl -fsSL https://pkgs.k8s.io/core:/stable:/{k8_version}/deb/Release.key -o /tmp/Release.key"
    run_sudo(conn, curl_cmd, ssh_password)
    
    # Dearmor natively 
    gpg_cmd = "gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg --yes /tmp/Release.key"
    run_sudo(conn, gpg_cmd, ssh_password)
    
    # Add the repository using correct URL format matching the key
    repo_cmd = (
        f"bash -c 'echo \"deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] "
        f"https://pkgs.k8s.io/core:/stable:/{k8_version}/deb/ /\" > "
        f"/etc/apt/sources.list.d/kubernetes.list'"
    )
    run_sudo(conn, repo_cmd, ssh_password)
    
    # Install
    run_sudo(conn, "apt-get update", ssh_password)
    run_sudo(conn, "apt-get install -y kubelet kubeadm kubectl", ssh_password)
    run_sudo(conn, "apt-mark hold kubelet kubeadm kubectl", ssh_password)

def setup_hesiod_k8_nodes(lab_spec):
    i=0
    while i < len(lab_spec["ubuntu_servers"]):
        liblog.print_logs("Setting up Ubuntu servers of type: "+lab_spec["ubuntu_servers"][i]["ubuntu_type"])
        ip_range = libvmw.get_ip_range(lab_spec["network"][lab_spec["ubuntu_servers"][i]["assign_ip_from_this_network"]]["default_gateway"], lab_spec["ubuntu_servers"][i]["assign_ip_from_this_range_start"], lab_spec["ubuntu_servers"][i]["assign_ip_from_this_range_end"])
        worker_ips = []
        w = 0
        while w < len(ip_range):
            if w == 0:
                control_plane_ip = ip_range[0]
            else:
                worker_ips.append(ip_range[w])
            w=w+1
        install_kubernetes(lab_spec["authentication"][lab_spec["ubuntu_servers"][i]["use_these_credentials"]]["username"], lab_spec["authentication"][lab_spec["ubuntu_servers"][i]["use_these_credentials"]]["password"], control_plane_ip, worker_ips, lab_spec["ubuntu_servers"][i]["kubernetes_version"])
        i=i+1

def setup_os_for_technitium(lab_spec, dns_spec):  
    # Loop through each node
    i=0
    while i < len(lab_spec["ubuntu_servers"]):
        liblog.print_logs("Getting Ubuntu details by servers type: "+lab_spec["ubuntu_servers"][i]["ubuntu_type"])
        ip_range = libvmw.get_ip_range(lab_spec["network"][lab_spec["ubuntu_servers"][i]["assign_ip_from_this_network"]]["default_gateway"], lab_spec["ubuntu_servers"][i]["assign_ip_from_this_range_start"], lab_spec["ubuntu_servers"][i]["assign_ip_from_this_range_end"])
        w = 0
        while w < len(ip_range):
            liblog.print_logs("Prepping node "+str(w)+": "+lab_spec["ubuntu_servers"][i]["naming_convention"]+"00"+str(w+2)+" ["+ip_range[w]+"] for DNS.")
            node_conn = std.Connection(host=ip_range[w], user=lab_spec["authentication"][lab_spec["ubuntu_servers"][i]["use_these_credentials"]]["username"], connect_kwargs={"password": lab_spec["authentication"][lab_spec["ubuntu_servers"][i]["use_these_credentials"]]["password"]})
            # Step 1: replace default /etc/systemd/resolved.conf with scripts_lib/k8_technitium_resolved_conf.script
            liblog.print_logs("(Step 1) Replace resolved.conf.")
            replace_resolved_conf(node_conn, lab_spec["authentication"][lab_spec["ubuntu_servers"][i]["use_these_credentials"]]["password"])
            # Step 2: create a symbolic link for /run/systemd/resolv/resolv.conf with /etc/resolv.conf as the destination
            liblog.print_logs("(Step 2) Create Symbolic Link")
            cmd = "ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf"
            run_sudo(node_conn, cmd, lab_spec["authentication"][lab_spec["ubuntu_servers"][i]["use_these_credentials"]]["password"])
            # Step 3: reboot
            liblog.print_logs("(Step 3) Reboot")
            cmd = "reboot"
            run_sudo(node_conn, cmd, lab_spec["authentication"][lab_spec["ubuntu_servers"][i]["use_these_credentials"]]["password"])
            # Step 4: pause to allow reboot to take effect
            pause_python_for_duration(120)
            # Step 5: reset ip address (changes after reboot: long term fix needed)
            libvmw.pcli_change_vm_ip_address(lab_spec["physical_esxi_servers"][lab_spec["ubuntu_servers"][i]["deploy_to_this_physical_host"]]["ip_address"], lab_spec["authentication"][lab_spec["physical_esxi_servers"][lab_spec["ubuntu_servers"][i]["deploy_to_this_physical_host"]]["use_these_credentials"]]["username"], lab_spec["authentication"][lab_spec["physical_esxi_servers"][lab_spec["ubuntu_servers"][i]["deploy_to_this_physical_host"]]["use_these_credentials"]]["password"], lab_spec["ubuntu_servers"][i]["naming_convention"]+"00"+str(w+2), "ens192", ip_range[w], lab_spec["network"][lab_spec["ubuntu_servers"][i]["assign_ip_from_this_network"]]["subnet_mask"], lab_spec["network"][lab_spec["ubuntu_servers"][i]["assign_ip_from_this_network"]]["default_gateway"], lab_spec["authentication"][lab_spec["ubuntu_servers"][i]["use_these_credentials"]]["username"], lab_spec["authentication"][lab_spec["ubuntu_servers"][i]["use_these_credentials"]]["password"])
            w=w+1
        i=i+1

def replace_resolved_conf(node_conn, ssh_password):
    liblog.print_logs("Replacing resolved.conf.")
    cmd = "curl https://raw.githubusercontent.com/boconnor2017/hesiod-theogony/refs/heads/main/scripts_lib/k8_technitium_resolved_conf.script >> k8_technitium_resolved_conf.script"
    run_sudo(node_conn, cmd, ssh_password)
    cmd = "rm /etc/systemd/resolved.conf"
    run_sudo(node_conn, cmd, ssh_password)
    cmd = "cp $PWD/k8_technitium_resolved_conf.script /etc/systemd/resolved.conf"
    run_sudo(node_conn, cmd, ssh_password)
    return
