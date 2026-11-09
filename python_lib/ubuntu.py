# Hesiod Ubuntu Server Management
# Description: Builds Ubuntu Server VMs on ESXi from the stock Ubuntu cloud image OVA. Each VM is
#              configured on first boot by cloud-init, which reads its settings from VMware guestinfo.
#              No ISO, no ISO customization, no keystrokes. Replaces scripts_lib/pcli_create_ubuntu_server_from_iso.script.
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.1 (build-time DNS probing, degraded cloud-init = warning, apt retries)
#
# Public functions
#   create_ubuntu_servers(lab_spec, replace_existing=False)  Build every VM in lab_spec["ubuntu_servers"]. Returns a list of results.
#   delete_ubuntu_servers(lab_spec)                          Power off and delete every VM in lab_spec["ubuntu_servers"].
#   get_ubuntu_server_specs(lab_spec)                        Resolve lab_spec into one flat dict per VM (names, IPs, sizes, credentials).
#   create_ubuntu_server(vm_spec, replace_existing=False)    Build one VM from a flat dict.
#   render_cloud_init(vm_spec, mac=None)                     Return (metadata, userdata) YAML strings without touching vSphere.
#   wait_for_cloud_init(ip, username, password, timeout_s)   SSH in and block until cloud-init finishes. Raises on error;
#                                                            exit 2 (degraded, recoverable errors only) is logged as a warning.
#
# Every failure raises UbuntuBuildError(stage, message), so the calling module can stop cleanly.
# Dry run from the repo root (renders cloud-init, no vSphere calls):  python3 -m python_lib.ubuntu conf/lab_spec.json

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import vmware as libvmw

import base64
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time

import paramiko
import requests
import urllib3
import xml.etree.ElementTree as ET
import yaml
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

# Timeouts (seconds)
TASK_TIMEOUT = 900
IP_TIMEOUT = 600
SSH_TIMEOUT = 600
CLOUD_INIT_TIMEOUT = 1800


class UbuntuBuildError(Exception):
    def __init__(self, stage, message):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.message = message


# --------------------------------------------------------------------------------------------
# lab_spec -> per-VM specs
# --------------------------------------------------------------------------------------------
def _auth_index(lab_spec, system):
    for idx, auth in enumerate(lab_spec["authentication"]):
        if auth.get("system") == system:
            return idx
    raise UbuntuBuildError("lab_spec", f"no authentication entry with system '{system}'")


def get_ubuntu_server_specs(lab_spec):
    specs = []
    for group in lab_spec["ubuntu_servers"]:
        try:
            host = lab_spec["physical_esxi_servers"][group["deploy_to_this_physical_host"]]
            esxi_auth = lab_spec["authentication"][host["use_these_credentials"]]
            os_auth = lab_spec["authentication"][group.get("use_these_credentials", _auth_index(lab_spec, "ubuntu"))]
            net = lab_spec["network"][group["assign_ip_from_this_network"]]
            ip_range = libvmw.get_ip_range(net["default_gateway"], group["assign_ip_from_this_range_start"],
                                           group["assign_ip_from_this_range_end"])
            count = int(group["deploy_this_many"])
            prefix = int(net["cidr"])
            if ipaddress.ip_network(f"0.0.0.0/{net['subnet_mask']}").prefixlen != prefix:
                raise UbuntuBuildError("lab_spec", f"network '{net['name']}': subnet_mask and cidr disagree")
            if len(ip_range) < count:
                raise UbuntuBuildError("lab_spec", f"'{group['ubuntu_type']}': deploy_this_many={count} "
                                                   f"but the IP range only has {len(ip_range)} addresses")
            if not group.get("OVA_path"):
                raise UbuntuBuildError("lab_spec", f"'{group['ubuntu_type']}': OVA_path is missing")
            domain = lab_spec.get("domain", {})
            dns = group.get("build_dns") or _usable_dns([s for s in domain.get("server_ips", []) if _is_ip(s)])
            for u in range(count):
                name = group["naming_convention"] + "00" + str(u + 2)  # same naming as os_management.py
                specs.append({
                    "ubuntu_type": group["ubuntu_type"],
                    "name": name,
                    "hostname": name,
                    "esxi_host": host["ip_address"],
                    "esxi_username": esxi_auth["username"],
                    "esxi_password": esxi_auth["password"],
                    "datastore": host["deploy_vms_to_these_datastores"][group["deploy_to_this_datastore"]],
                    "network": host["deploy_vms_to_these_networks"][group["deploy_to_this_network"]],
                    "ova_path": group["OVA_path"],
                    "ova_url": group.get("OVA_url"),
                    "cpu": int(group["numCPU"]),
                    "memory_gb": int(group["memoryGB"]),
                    "disks_gb": [int(d["storage_GB"]) for d in group["harddisks"]],
                    "nested_hv": str(group.get("expose_hw_virt_to_guest", "no")).lower() in ("yes", "true"),
                    "ip": ip_range[u],
                    "prefix": prefix,
                    "gateway": net["default_gateway"],
                    "dns": dns,
                    "search_domain": domain.get("name"),
                    "ntp": domain.get("ntp"),
                    "username": os_auth["username"],
                    "password": os_auth["password"],
                })
        except (KeyError, IndexError, ValueError) as e:
            raise UbuntuBuildError("lab_spec", f"ubuntu_servers entry '{group.get('ubuntu_type', '?')}': {e!r}")
    return specs


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _dns_answers(server, name="ubuntu.com", timeout=2):
    """True if `server` answers a DNS query on UDP 53 (stdlib only, no dnspython)."""
    qname = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + qname + b"\x00\x01\x00\x01"
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(query, (server, 53))
            return sock.recvfrom(512)[0][:2] == b"\x12\x34"
        except OSError:
            return False


def _usable_dns(servers):
    """Drop DNS servers that don't answer yet (e.g. Technitium, which Module 3 deploys on these nodes)."""
    live = [s for s in servers if _dns_answers(s)]
    for s in servers:
        if s not in live:
            liblog.print_logs(f"DNS {s} is not answering; leaving it out of the build-time DNS list.")
    if not live:
        liblog.print_logs(f"WARNING: none of {servers} answer DNS; using them anyway.")
        return servers
    return live


# --------------------------------------------------------------------------------------------
# cloud-init
# --------------------------------------------------------------------------------------------
def _hash_password(password):
    result = subprocess.run(["openssl", "passwd", "-6", "-stdin"], input=password, text=True, capture_output=True)
    if result.returncode != 0:
        raise UbuntuBuildError("cloud_init", f"openssl passwd failed: {result.stderr.strip()}")
    return result.stdout.strip()


def render_cloud_init(vm_spec, mac=None):
    eth = {
        "match": {"macaddress": mac} if mac else {"name": "en*"},
        "dhcp4": False,
        "addresses": [f"{vm_spec['ip']}/{vm_spec['prefix']}"],
        "routes": [{"to": "default", "via": vm_spec["gateway"]}],
    }
    if vm_spec["dns"]:
        eth["nameservers"] = {"addresses": vm_spec["dns"]}
        if vm_spec["search_domain"]:
            eth["nameservers"]["search"] = [vm_spec["search_domain"]]
    metadata = {
        "instance-id": f"{vm_spec['name']}-{int(time.time())}",
        "local-hostname": vm_spec["hostname"],
        "network": {"version": 2, "ethernets": {"primary": eth}},
    }
    userdata = {
        "hostname": vm_spec["hostname"],
        "manage_etc_hosts": False,  # os_management.py manages /etc/hosts for the K8 nodes
        "users": [{
            "name": vm_spec["username"],
            "groups": ["sudo"],
            "shell": "/bin/bash",
            "lock_passwd": False,
            "passwd": _hash_password(vm_spec["password"]),
        }],
        "ssh_pwauth": True,
        "growpart": {"mode": "auto", "devices": ["/"]},
        "resize_rootfs": True,
        "package_update": True,
        "packages": ["net-tools"],
        "apt": {"conf": 'Acquire::Retries "5";\n'},
    }
    if vm_spec["ntp"]:
        userdata["ntp"] = {"enabled": True, "servers": [vm_spec["ntp"]]}
    return (yaml.safe_dump(metadata, sort_keys=False),
            "#cloud-config\n" + yaml.safe_dump(userdata, sort_keys=False))


def wait_for_cloud_init(ip, username, password, timeout_s=CLOUD_INIT_TIMEOUT):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # brand-new VM, key unknown
    deadline = time.time() + SSH_TIMEOUT
    while True:
        try:
            ssh.connect(ip, username=username, password=password, timeout=10, banner_timeout=10,
                        auth_timeout=10, look_for_keys=False, allow_agent=False)
            break
        except (paramiko.SSHException, socket.error) as e:
            if time.time() > deadline:
                raise UbuntuBuildError("wait_ssh", f"cannot SSH to {ip} after {SSH_TIMEOUT}s: {e}")
            time.sleep(10)
    try:
        _, stdout, _ = ssh.exec_command("cloud-init status --wait --long", timeout=timeout_s)
        output = stdout.read().decode(errors="replace").strip()
        rc = stdout.channel.recv_exit_status()
    except socket.timeout:
        raise UbuntuBuildError("cloud_init", f"{ip}: cloud-init still running after {timeout_s}s")
    finally:
        ssh.close()
    if rc == 2:  # degraded: finished, with recoverable errors only (e.g. a package mirror hiccup)
        liblog.print_logs(f"WARNING: {ip}: cloud-init finished degraded (recoverable errors):\n{output}")
    elif rc != 0:
        raise UbuntuBuildError("cloud_init", f"{ip}: cloud-init exit {rc}\n{output}")
    return output


# --------------------------------------------------------------------------------------------
# vSphere helpers
# --------------------------------------------------------------------------------------------
def _connect(vm_spec):
    try:
        return SmartConnect(host=vm_spec["esxi_host"], user=vm_spec["esxi_username"],
                            pwd=vm_spec["esxi_password"], sslContext=ssl._create_unverified_context())
    except Exception as e:
        raise UbuntuBuildError("connect", f"cannot log in to {vm_spec['esxi_host']}: {e}")


def _wait_task(task, stage, timeout_s=TASK_TIMEOUT):
    deadline = time.time() + timeout_s
    while task.info.state in (vim.TaskInfo.State.queued, vim.TaskInfo.State.running):
        if time.time() > deadline:
            raise UbuntuBuildError(stage, f"task timed out after {timeout_s}s")
        time.sleep(2)
    if task.info.state != vim.TaskInfo.State.success:
        raise UbuntuBuildError(stage, getattr(task.info.error, "msg", None) or str(task.info.error))
    return task.info.result


def _find(content, vimtype, name=None):
    view = content.viewManager.CreateContainerView(content.rootFolder, [vimtype], True)
    try:
        objs = list(view.view)
    finally:
        view.Destroy()
    return objs if name is None else next((o for o in objs if o.name == name), None)


def _locate(si, vm_spec):
    content = si.RetrieveContent()
    dc = next(iter(_find(content, vim.Datacenter)), None)
    cr = next(iter(_find(content, vim.ComputeResource)), None)
    if not dc or not cr:
        raise UbuntuBuildError("locate", f"no datacenter/host found on {vm_spec['esxi_host']}")
    ds = _find(content, vim.Datastore, vm_spec["datastore"])
    if not ds:
        raise UbuntuBuildError("locate", f"datastore '{vm_spec['datastore']}' not found "
                                         f"({[d.name for d in _find(content, vim.Datastore)]})")
    net = _find(content, vim.Network, vm_spec["network"])
    if not net:
        raise UbuntuBuildError("locate", f"network '{vm_spec['network']}' not found "
                                         f"({[n.name for n in _find(content, vim.Network)]})")
    return {"content": content, "dc": dc, "pool": cr.resourcePool, "host": cr.host[0], "ds": ds, "net": net}


def _destroy_vm(vm):
    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        _wait_task(vm.PowerOffVM_Task(), "destroy")
    _wait_task(vm.Destroy_Task(), "destroy")


def _ensure_ova(vm_spec):
    path = vm_spec["ova_path"]
    if os.path.isfile(path):
        return
    if not vm_spec["ova_url"]:
        raise UbuntuBuildError("ova", f"{path} not found and no OVA_url to download it from")
    liblog.print_logs(f"Downloading {vm_spec['ova_url']} to {path}.")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    try:
        with requests.get(vm_spec["ova_url"], stream=True, timeout=(30, 300)) as r:
            r.raise_for_status()
            with open(path + ".part", "wb") as f:
                for chunk in r.iter_content(chunk_size=8 * 1024 * 1024):
                    f.write(chunk)
        os.replace(path + ".part", path)
    except Exception as e:
        raise UbuntuBuildError("ova", f"download failed: {e}")


class _CountingReader:
    def __init__(self, fileobj, size):
        self.f, self.size, self.done = fileobj, size, 0

    def read(self, n=-1):
        chunk = self.f.read(n if n and n > 0 else 1024 * 1024)
        self.done += len(chunk)
        return chunk

    def __len__(self):
        return self.size


def _import_ova(si, loc, vm_spec):
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    with tarfile.open(vm_spec["ova_path"]) as tar:
        ovf = next((m for m in tar.getmembers() if m.name.endswith(".ovf")), None)
        if not ovf:
            raise UbuntuBuildError("import_ova", "no .ovf descriptor inside the OVA")
        descriptor = tar.extractfile(ovf).read().decode("utf-8")
        ovf_ns = "{http://schemas.dmtf.org/ovf/envelope/1}"
        ovf_networks = [n.get(ovf_ns + "name") for n in ET.fromstring(descriptor).iter(ovf_ns + "Network")]
        om = loc["content"].ovfManager
        params = vim.OvfManager.CreateImportSpecParams(
            entityName=vm_spec["name"], diskProvisioning="thin",
            networkMapping=[vim.OvfManager.NetworkMapping(name=n, network=loc["net"]) for n in ovf_networks])
        spec = om.CreateImportSpec(descriptor, loc["pool"], loc["ds"], params)
        if spec.error:
            raise UbuntuBuildError("import_ova", "; ".join(e.msg for e in spec.error))

        lease = loc["pool"].ImportVApp(spec.importSpec, loc["dc"].vmFolder, loc["host"])
        deadline = time.time() + TASK_TIMEOUT
        while lease.state == vim.HttpNfcLease.State.initializing:
            if time.time() > deadline:
                raise UbuntuBuildError("import_ova", "NFC lease never became ready")
            time.sleep(1)
        if lease.state == vim.HttpNfcLease.State.error:
            raise UbuntuBuildError("import_ova", lease.error.msg)
        lease_info = lease.info  # read now: the lease object goes away once it is completed

        cookie = si._stub.cookie.split(";")[0].strip()
        total = sum(f.size or 0 for f in spec.fileItem) or 1
        readers, stop = [], threading.Event()

        def keep_lease_alive():
            while not stop.wait(15):
                try:
                    lease.HttpNfcLeaseProgress(min(99, int(100 * sum(r.done for r in readers) / total)))
                except Exception:
                    return

        threading.Thread(target=keep_lease_alive, daemon=True).start()
        try:
            for du in lease_info.deviceUrl:
                item = next((f for f in spec.fileItem if f.deviceId == du.importKey), None)
                if not item:
                    continue
                member = tar.getmember(item.path)
                reader = _CountingReader(tar.extractfile(member), member.size)
                readers.append(reader)
                liblog.print_logs(f"Uploading {item.path} ({member.size // 1000000} MB) to {vm_spec['esxi_host']}.")
                r = requests.request("PUT" if item.create else "POST", du.url.replace("*", vm_spec["esxi_host"]),
                                     data=reader, verify=False, timeout=(30, 600),
                                     headers={"Content-Type": "application/x-vnd.vmware-streamVmdk",
                                              "Content-Length": str(member.size), "Cookie": cookie})
                if r.status_code >= 300:
                    raise UbuntuBuildError("import_ova", f"upload of {item.path} failed: HTTP {r.status_code}")
            lease.HttpNfcLeaseProgress(100)
            lease.HttpNfcLeaseComplete()
        except Exception as e:
            try:
                lease.HttpNfcLeaseAbort()
            except Exception:
                pass
            raise e if isinstance(e, UbuntuBuildError) else UbuntuBuildError("import_ova", repr(e))
        finally:
            stop.set()
    return lease_info.entity


def _reconfigure(vm, vm_spec, metadata, userdata):
    b64 = lambda s: base64.b64encode(s.encode()).decode()
    spec = vim.vm.ConfigSpec(numCPUs=vm_spec["cpu"], memoryMB=vm_spec["memory_gb"] * 1024,
                             nestedHVEnabled=vm_spec["nested_hv"])
    spec.vAppConfigRemoved = True  # cloud-init must use the VMware (guestinfo) datasource, not OVF
    spec.extraConfig = [
        vim.option.OptionValue(key="guestinfo.metadata", value=b64(metadata)),
        vim.option.OptionValue(key="guestinfo.metadata.encoding", value="base64"),
        vim.option.OptionValue(key="guestinfo.userdata", value=b64(userdata)),
        vim.option.OptionValue(key="guestinfo.userdata.encoding", value="base64"),
    ]
    devices = vm.config.hardware.device
    disks = [d for d in devices if isinstance(d, vim.vm.device.VirtualDisk)]
    if not disks:
        raise UbuntuBuildError("reconfigure", "imported VM has no disk")
    changes = []
    # harddisks[0] = OS disk: grow the OVA disk (the root filesystem expands on first boot)
    os_disk_kb = vm_spec["disks_gb"][0] * 1024 * 1024
    if disks[0].capacityInKB < os_disk_kb:
        disks[0].capacityInKB = os_disk_kb
        changes.append(vim.vm.device.VirtualDeviceSpec(operation="edit", device=disks[0]))
    # harddisks[1:] = extra data disks on the same controller
    controller = next(d for d in devices if d.key == disks[0].controllerKey)
    if len(vm_spec["disks_gb"]) > 1 and not isinstance(controller, vim.vm.device.VirtualSCSIController):
        raise UbuntuBuildError("reconfigure", "extra disks need a SCSI controller; the OVA disk is not on one")
    used = {d.unitNumber for d in devices if getattr(d, "controllerKey", None) == controller.key}
    unit = 0
    for n, size_gb in enumerate(vm_spec["disks_gb"][1:], start=1):
        while unit in used or unit == 7:
            unit += 1
        used.add(unit)
        disk = vim.vm.device.VirtualDisk(
            key=-n, controllerKey=controller.key, unitNumber=unit, capacityInKB=size_gb * 1024 * 1024,
            backing=vim.vm.device.VirtualDisk.FlatVer2BackingInfo(diskMode="persistent", thinProvisioned=True))
        changes.append(vim.vm.device.VirtualDeviceSpec(operation="add", fileOperation="create", device=disk))
    spec.deviceChange = changes
    _wait_task(vm.ReconfigVM_Task(spec), "reconfigure")


def _vm_mac(vm):
    nic = next((d for d in vm.config.hardware.device if isinstance(d, vim.vm.device.VirtualEthernetCard)), None)
    return nic.macAddress if nic else None


def _wait_for_ip(vm, ip):
    deadline = time.time() + IP_TIMEOUT
    while time.time() < deadline:
        ips = {a for n in (vm.guest.net or []) for a in (n.ipAddress or [])} | {vm.guest.ipAddress}
        if ip in ips:
            return
        time.sleep(5)
    raise UbuntuBuildError("wait_ip", f"VMware Tools never reported {ip} after {IP_TIMEOUT}s (check the VM console)")


# --------------------------------------------------------------------------------------------
# Public build / delete
# --------------------------------------------------------------------------------------------
def create_ubuntu_server(vm_spec, replace_existing=False):
    t0 = time.time()
    liblog.print_logs(f"Building Ubuntu Server {vm_spec['name']} ({vm_spec['ip']}) on {vm_spec['esxi_host']}.")
    _ensure_ova(vm_spec)
    si = _connect(vm_spec)
    try:
        loc = _locate(si, vm_spec)
        existing = _find(loc["content"], vim.VirtualMachine, vm_spec["name"])
        if existing:
            if not replace_existing:
                raise UbuntuBuildError("precheck", f"VM {vm_spec['name']} already exists (use replace_existing=True)")
            liblog.print_logs(f"Deleting existing VM {vm_spec['name']}.")
            _destroy_vm(existing)

        vm = _import_ova(si, loc, vm_spec)
        metadata, userdata = render_cloud_init(vm_spec, _vm_mac(vm))
        _reconfigure(vm, vm_spec, metadata, userdata)
        liblog.print_logs(f"{vm_spec['name']}: deployed and sized. Powering on.")
        _wait_task(vm.PowerOnVM_Task(), "power_on")

        _wait_for_ip(vm, vm_spec["ip"])
        liblog.print_logs(f"{vm_spec['name']}: network is up. Waiting for cloud-init to finish.")
        wait_for_cloud_init(vm_spec["ip"], vm_spec["username"], vm_spec["password"])

        # Remove the password hash from the VM's advanced settings now that it has been applied
        _wait_task(vm.ReconfigVM_Task(vim.vm.ConfigSpec(extraConfig=[
            vim.option.OptionValue(key="guestinfo.userdata", value=""),
            vim.option.OptionValue(key="guestinfo.userdata.encoding", value="")])), "scrub_userdata")

        elapsed = round(time.time() - t0)
        liblog.print_logs(f"{vm_spec['name']}: ready in {elapsed}s.")
        return {"name": vm_spec["name"], "ip": vm_spec["ip"], "status": "success", "elapsed_s": elapsed}
    except UbuntuBuildError:
        raise
    except Exception as e:  # pyVmomi faults, network errors: always surface as UbuntuBuildError
        raise UbuntuBuildError("vsphere", getattr(e, "msg", None) or repr(e))
    finally:
        Disconnect(si)


def create_ubuntu_servers(lab_spec, replace_existing=False):
    liblog.print_logs("Initiating create_ubuntu_servers(lab_spec) function.")
    results = []
    for vm_spec in get_ubuntu_server_specs(lab_spec):
        try:
            results.append(create_ubuntu_server(vm_spec, replace_existing))
        except UbuntuBuildError as e:
            liblog.print_logs(f"FAILED: {vm_spec['name']} at stage '{e.stage}': {e.message}")
            raise
    liblog.print_logs(f"All {len(results)} Ubuntu Servers built.")
    return results


def delete_ubuntu_servers(lab_spec):
    for vm_spec in get_ubuntu_server_specs(lab_spec):
        si = _connect(vm_spec)
        try:
            vm = _find(si.RetrieveContent(), vim.VirtualMachine, vm_spec["name"])
            if vm:
                liblog.print_logs(f"Deleting {vm_spec['name']}.")
                _destroy_vm(vm)
        finally:
            Disconnect(si)


# Dry run: python3 -m python_lib.ubuntu conf/lab_spec.json
if __name__ == "__main__":
    with open(sys.argv[1] if len(sys.argv) > 1 else "conf/lab_spec.json") as f:
        spec_py = json.load(f)
    for s in get_ubuntu_server_specs(spec_py):
        md, ud = render_cloud_init(s, "00:50:56:xx:xx:xx")
        print(f"===== {s['name']} -> {s['ip']}/{s['prefix']} on {s['esxi_host']} [{s['datastore']} / {s['network']}]")
        print(md)
        print(ud)