import time
from pyVim.connect import SmartConnectNoSSL, Disconnect
from pyVmomi import vim

# --- CONFIGURATION ---
VCENTER_IP = "192.168.1.5"
USER = "administrator@vsphere.local"
PASSWORD = "YourVcenterPassword"

VM_NAME = "Ubuntu-K8s-Node"
DATASTORE_NAME = "datastore1"
CLUSTER_NAME = "Cluster-01"  # Or Resource Pool
ISO_PATH = f"[{DATASTORE_NAME}] ISOs/ubuntu-24.04-live-server-amd64.iso"

# VM Specs
CPU_COUNT = 2
RAM_GB = 4
DISK_GB = 40
NETWORK_NAME = "VM Network"
# ---------------------

def get_obj(content, vimtype, name):
    """Returns a vSphere object by name"""
    container = content.viewManager.CreateContainerView(content.rootFolder, vimtype, True)
    for obj in container.view:
        if obj.name == name:
            return obj
    return None

def create_vm():
    # 1. Connect to vCenter
    si = SmartConnectNoSSL(host=VCENTER_IP, user=USER, pwd=PASSWORD)
    content = si.RetrieveContent()
    
    # 2. Gather environment resources
    datacenter = content.rootFolder.childEntity[0]
    vm_folder = datacenter.vmFolder
    datastore = get_obj(content, [vim.Datastore], DATASTORE_NAME)
    cluster = get_obj(content, [vim.ClusterComputeResource], CLUSTER_NAME)
    resource_pool = cluster.resourcePool
    network = get_obj(content, [vim.Network], NETWORK_NAME)
    
    if not datastore or not cluster or not network:
        print("Error: Could not find Datastore, Cluster, or Network. Check configs.")
        return

    print(f"Creating VM '{VM_NAME}' configuration spec...")

    # 3. Build VM Configuration Spec
    vmx_file = vim.vm.FileInfo(logDirectory=None, snapshotDirectory=None, 
                               suspendDirectory=None, vmPathName=f"[{DATASTORE_NAME}]")
    
    config_spec = vim.vm.ConfigSpec(
        name=VM_NAME,
        memoryMB=RAM_GB * 1024,
        numCPUs=CPU_COUNT,
        files=vmx_file,
        guestId="ubuntu64Guest",
        deviceChange=[]
    )

    # Add SCSI Controller
    scsi_ctrl = vim.vm.device.VirtualDeviceSpec()
    scsi_ctrl.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    scsi_ctrl.device = vim.vm.device.VirtualLsiLogicController()
    scsi_ctrl.device.key = 1
    scsi_ctrl.device.busNumber = 0
    scsi_ctrl.device.sharedBus = vim.vm.device.VirtualSCSIController.Sharing.noSharing
    config_spec.deviceChange.append(scsi_ctrl)

    # Add Hard Disk
    disk_spec = vim.vm.device.VirtualDeviceSpec()
    disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.create
    disk_spec.device = vim.vm.device.VirtualDisk()
    disk_spec.device.capacityInKB = DISK_GB * 1024 * 1024
    disk_spec.device.backing = vim.vm.device.VirtualDisk.FlatVer2BackingInfo()
    disk_spec.device.backing.diskMode = "persistent"
    disk_spec.device.backing.thinProvisioned = True
    disk_spec.device.controllerKey = 1
    disk_spec.device.unitNumber = 0
    config_spec.deviceChange.append(disk_spec)

    # Add Network Interface (VMXNET3)
    nic_spec = vim.vm.device.VirtualDeviceSpec()
    nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    nic_spec.device = vim.vm.device.VirtualVmxnet3()
    nic_spec.device.backing = vim.vm.device.VirtualEthernetCard.NetworkBackingInfo()
    nic_spec.device.backing.network = network
    nic_spec.device.backing.deviceName = NETWORK_NAME
    nic_spec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
    nic_spec.device.connectable.startConnected = True
    nic_spec.device.connectable.allowGuestControl = True
    nic_spec.device.connectable.connected = True
    config_spec.deviceChange.append(nic_spec)

    # Add CD-ROM Drive with Ubuntu ISO attached
    cd_spec = vim.vm.device.VirtualDeviceSpec()
    cd_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.add
    cd_spec.device = vim.vm.device.VirtualCdrom()
    cd_spec.device.backing = vim.vm.device.VirtualCdrom.IsoBackingInfo()
    cd_spec.device.backing.fileName = ISO_PATH
    cd_spec.device.connectable = vim.vm.device.VirtualDevice.ConnectInfo()
    cd_spec.device.connectable.startConnected = True
    cd_spec.device.connectable.allowGuestControl = True
    cd_spec.device.connectable.connected = True
    config_spec.deviceChange.append(cd_spec)

    # Optional: Inject Autoinstall user-data via vApp properties (GuestInfo)
    # This prevents needing a second CD-ROM for configuration data.
    # Note: Requires an Ubuntu ISO customized to read guestinfo or passing boot_arguments.
    
    # 4. Provision the VM
    print(f"Deploying VM to vSphere...")
    task = vm_folder.CreateVM_Task(config=config_spec, pool=resource_pool)
    
    # Wait for creation task to complete
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
        time.sleep(2)
        
    if task.info.state == vim.TaskInfo.State.error:
        print(f"Failed to create VM: {task.info.error.msg}")
        return

    vm = task.info.result
    print(f"VM created successfully. Powering on...")
    
    # 5. Power On the VM
    power_task = vm.PowerOnVM_Task()
    
    while power_task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
        time.sleep(2)
        
    print("VM is powered on and booting into Ubuntu Installer!")
    Disconnect(si)

if __name__ == "__main__":
    create_vm()