import sys
from fabric import Connection, Group

# --- CONFIGURATION ---
# Replace with your actual vSphere Ubuntu VM IPs and SSH credentials
SSH_USER = "ubuntu"
SSH_PASS = "YourSecurePassword"  # Or use connect_kwargs={"key_filename": "/path/to/key"}

CONTROL_PLANE_IP = "192.168.1.10"
WORKER_IPS = ["192.168.1.11", "192.168.1.12"]

# Kubernetes Version
K8S_VERSION = "v1.30" 
# ---------------------

def run_sudo(conn, cmd):
    """Helper to run commands with sudo password handling"""
    print(f"[{conn.host}] Running: {cmd}")
    return conn.run(f"echo '{SSH_PASS}' | sudo -S {cmd}", hide=True)

def setup_common(conn):
    """Steps required on BOTH Master and Worker nodes"""
    print(f"\n--- Configuring Prerequisites on {conn.host} ---")
    
    # 1. Disable Swap (Kubernetes requirement)
    run_sudo(conn, "swapoff -a")
    run_sudo(conn, "sed -i '/swap/d' /etc/fstab")
    
    # 2. Load kernel modules for bridging
    run_sudo(conn, "modprobe overlay")
    run_sudo(conn, "modprobe br_netfilter")
    
    # Configure sysctl params
    sysctl_config = """
cat <<EOF | sudo tee /etc/sysctl.d/k8s.conf
net.bridge.bridge-nf-call-iptables  = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward                 = 1
EOF
"""
    run_sudo(conn, sysctl_config)
    run_sudo(conn, "sysctl --system")
    
    # 3. Install containerd runtime
    run_sudo(conn, "apt-get update")
    run_sudo(conn, "apt-get install -y containerd apt-transport-https ca-certificates curl gpg")
    
    # Configure containerd to use systemd cgroup
    run_sudo(conn, "mkdir -p /etc/containerd")
    run_sudo(conn, "containerd config default | sudo tee /etc/containerd/config.toml")
    run_sudo(conn, "sed -i 's/SystemdCgroup = false/SystemdCgroup = true/g' /etc/containerd/config.toml")
    run_sudo(conn, "systemctl restart containerd")
    
    # 4. Install kubelet, kubeadm, kubectl
    run_sudo(conn, f"mkdir -p -m 755 /etc/apt/keyrings")
    run_sudo(conn, f"curl -fsSL https://pkgs.k8s.io/core:/stable:/{K8S_VERSION}/deb/Release.key | sudo gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg --yes")
    
    repo_cmd = f"echo 'deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:/stable:/{K8S_VERSION}/deb/ /' | sudo tee /etc/apt/sources.list.d/kubernetes.list"
    run_sudo(conn, repo_cmd)
    
    run_sudo(conn, "apt-get update")
    run_sudo(conn, "apt-get install -y kubelet kubeadm kubectl")
    run_sudo(conn, "apt-mark hold kubelet kubeadm kubectl")

def main():
    # Connect to Master
    master_conn = Connection(host=CONTROL_PLANE_IP, user=SSH_USER, connect_kwargs={"password": SSH_PASS})
    
    # Connect to Workers
    workers = Group(*WORKER_IPS, user=SSH_USER, connect_kwargs={"password": SSH_PASS})
    
    print("Starting Kubernetes Cluster Deployment...")
    
    # Step 1: Run common setup everywhere
    setup_common(master_conn)
    for worker in workers:
        setup_common(worker)
        
    # Step 2: Initialize Control Plane
    print("\n--- Initializing Control Plane (Master) ---")
    init_result = run_sudo(master_conn, f"kubeadm init --apiserver-advertise-address={CONTROL_PLANE_IP} --pod-network-cidr=10.244.0.0/16")
    
    # Setup local kubectl config on master so you can use it right away
    run_sudo(master_conn, "mkdir -p $HOME/.kube")
    run_sudo(master_conn, "cp -i /etc/kubernetes/admin.conf $HOME/.kube/config")
    run_sudo(master_conn, f"chown {SSH_USER}:{SSH_USER} $HOME/.kube/config")
    
    # Step 3: Install Pod Network (Flannel CNI)
    print("\n--- Installing Flannel CNI Pod Network ---")
    master_conn.run("kubectl apply -f https://github.com/flannel-io/flannel/releases/latest/download/kube-flannel.yml")
    
    # Step 4: Extract the Join Command
    print("\n--- Generating Join Token for Workers ---")
    token_result = run_sudo(master_conn, "kubeadm token create --print-join-command")
    join_command = token_result.stdout.strip().split('\n')[-1] # Grabs the actual command string
    
    # Step 5: Join Worker Nodes to Cluster
    print("\n--- Joining Worker Nodes to Cluster ---")
    for worker in workers:
        print(f"Joining {worker.host}...")
        run_sudo(worker, join_command)
        
    print("\nKubernetes cluster deployment completed successfully!")
    print(f"Log into Master ({CONTROL_PLANE_IP}) and run 'kubectl get nodes' to verify.")

if __name__ == "__main__":
    main()