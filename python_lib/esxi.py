# Hesiod Nested ESXi Management
# Description: Builds nested ESXi hosts from the ESXi installer ISO with a kickstart file. No keystrokes.
#              1. Remasters the stock ESXi ISO ONCE into a kickstart ISO (stock ISO left untouched):
#                 adds scripts_lib/esxi_kickstart.script as /KS.CFG and "ks=cdrom:/KS.CFG" to the boot line.
#              2. Creates each VM through the vSphere API with its per-host values (FQDN, IP, VLAN, DNS, NTP,
#                 password) in guestinfo.hesiod.* advanced settings. The kickstart is identical for every host.
#              3. The unattended install runs; %firstboot reads guestinfo and configures the host, regenerates
#                 its certificate for the FQDN, and reboots.
#              4. Done = the host serves a certificate whose CN is its FQDN and accepts the real root password.
#              Replaces hesiod-vcf9 module 4 (pcli_create_vm_from_iso + Set-VMKeystrokes + pcli_prep_esxi_hosts_for_VCF).
# Author: Brendan O'Connor
# Date: November 2026
# Version: 1.7 (DNS/NTP: clock corrected before ntpd starts, config saved to the boot bank via auto-backup.sh; check_dns_ntp())
#
# Public functions
#   create_nested_esxi_hosts(lab_spec, types=None, replace_existing=False)  Build every host (optionally only "MGT"/"VI").
#   delete_nested_esxi_hosts(lab_spec, types=None)                          Power off and delete them.
#   get_nested_esxi_specs(lab_spec, types=None)                             One flat dict per host (names, IPs, sizes).
#   build_kickstart_iso(lab_spec, types=None, rebuild=False)                Build/upload the kickstart ISO only.
#   remaster_iso(stock_iso, out_iso, ks_text, legacy_cpu=False)             Local ISO remaster (xorriso), no vSphere.
#   configure_dns_ntp(lab_spec, types=None)                                 (Re)apply DNS + NTP to running hosts, no reinstall.
#
# Every failure raises EsxiBuildError(stage, message).
# Dry run from the repo root (prints host plan + kickstart, no vSphere calls):  python3 -m python_lib.esxi conf/lab_spec.json

# Import Hesiod Libraries
from python_lib import logs_and_headers as liblog
from python_lib import vmware as libvmw
from python_lib import ubuntu as libubuntu  # shared vSphere helpers (_connect, _wait_task, _find, _locate, _usable_dns)

import hashlib
import ipaddress
import json
import os
import posixpath
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor

import requests
import urllib3
from cryptography import x509
from cryptography.x509.oid import NameOID
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim

KICKSTART_TEMPLATE = "scripts_lib/esxi_kickstart.script"
ISO_CACHE_DIR = "iso"               # local cache for the stock ISO and the remastered ISO (relative to the repo)
INSTALL_TIMEOUT = 2700              # power-on -> configured host (install + firstboot + reboot), seconds
LEGACY_CPU_POST = """%post --interpreter=busybox --ignorefailure=true
# Carry allowLegacyCPU=true into the INSTALLED system's boot line (the installer only has it on the ISO's).
# Never fatal: a missing path must not fail the install.
for f in $(find /vmfs/volumes /bootbank /altbootbank -maxdepth 2 -name boot.cfg 2>/dev/null); do
  if grep -q "^kernelopt=" "$f" && ! grep -q "allowLegacyCPU" "$f"; then
    sed -i '/^kernelopt=/ s/$/ allowLegacyCPU=true/' "$f" && echo "hesiod: allowLegacyCPU added to $f"
  fi
done
exit 0
"""

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class EsxiBuildError(Exception):
    def __init__(self, stage, message):
        super().__init__(f"[{stage}] {message}")
        self.stage = stage
        self.message = message


# --------------------------------------------------------------------------------------------
# lab_spec -> per-host specs
# --------------------------------------------------------------------------------------------
def _dns_name_for_ip(lab_spec, ip):
    """Return the short name Module 4 (dns_management.py) registers for this IP, so forward/reverse DNS match."""
    for f in lab_spec.get("domain", {}).get("fqdns", []):
        gw = lab_spec["network"][f["assign_ip_from_this_network"]]["default_gateway"]
        ip_range = libvmw.get_ip_range(gw, f["assign_ip_from_this_range_start"], f["assign_ip_from_this_range_end"])
        if ip in ip_range:
            i = ip_range.index(ip)
            if i == 0:
                return None  # reserved for the DNS server
            return f"{f['naming_convention']}-0{i}" if i < 10 else f"{f['naming_convention']}-{i}"
    return None


def get_nested_esxi_specs(lab_spec, types=None):
    specs = []
    domain = lab_spec.get("domain", {})
    dns = [s for s in domain.get("server_ips", []) if libubuntu._is_ip(s)]  # every server, in lab_spec order
    for group in lab_spec["nested_esxi_servers"]:
        gtype = str(group.get("nested_esxi_type", "")).upper()
        if types and gtype not in [t.upper() for t in types]:
            continue
        try:
            host = lab_spec["physical_esxi_servers"][group["deploy_to_this_physical_host"]]
            phys_auth = lab_spec["authentication"][host["use_these_credentials"]]
            nested_auth = lab_spec["authentication"][group.get("use_these_credentials", libubuntu._auth_index(lab_spec, "esxi_nested"))]
            net = lab_spec["network"][group["assign_ip_from_this_network"]]
            ip_range = libvmw.get_ip_range(net["default_gateway"], group["assign_ip_from_this_range_start"],
                                           group["assign_ip_from_this_range_end"])
            count = int(group["deploy_this_many"])
            if len(ip_range) < count:
                raise EsxiBuildError("lab_spec", f"'{gtype}': deploy_this_many={count} but the IP range has {len(ip_range)}")
            # Candidate datastores: "deploy_to_these_datastores" (list of indices) or the single legacy index
            ds_indices = group.get("deploy_to_these_datastores")
            if ds_indices is None:
                ds_indices = [group.get("deploy_to_this_datastore", group.get("deploy_to__this_datastore", 0))]
            ds_names = [host["deploy_vms_to_these_datastores"][i] for i in ds_indices]
            disks = [int(d["storage_GB"]) for d in group["harddisks"]]
            if disks[0] < 32:
                raise EsxiBuildError("lab_spec", f"'{gtype}': harddisks[0] is the boot disk and must be >= 32 GB (is {disks[0]})")
            for n in range(count):
                ip = ip_range[n]                                     # static IPs from this group's range, in order
                dns_short = _dns_name_for_ip(lab_spec, ip)           # hostname = the FQDN Module 4 created for this IP
                if not dns_short or not domain.get("name"):
                    raise EsxiBuildError("lab_spec", f"'{gtype}': {ip} has no FQDN from Module 4 (domain.fqdns range "
                                                     f"must cover nested_esxi_servers IPs)")
                specs.append({
                    "type": gtype,
                    "name": f"{group['naming_convention']}{n + 1:02d}",  # VM name, e.g. hesmpc-esx01
                    "fqdn": f"{dns_short}.{domain['name']}",
                    "ip": ip,
                    "netmask": net["subnet_mask"],
                    "gateway": net["default_gateway"],
                    "vlan": str(group.get("management_vlan_id", "0")),
                    "mtu": str(group.get("mtu", "9000")),
                    "dns": dns,
                    "domain": domain.get("name", ""),
                    "ntp": domain.get("ntp", ""),
                    "password": nested_auth["password"],
                    "esxi_host": host["ip_address"],
                    "esxi_username": phys_auth["username"],
                    "esxi_password": phys_auth["password"],
                    "datastore": ds_names[0],          # replaced by the placement step at build time
                    "datastores": ds_names,
                    "network": host["deploy_vms_to_these_networks"][group["deploy_to_this_network"]],
                    "stock_iso": group["CD_path"],
                    "legacy_cpu": str(group.get("allow_legacy_cpu", "no")).lower() in ("yes", "true"),
                    "guest_id": group.get("guest_id", "vmkernel9Guest"),
                    "cpu": int(group["numCPU"]),
                    "memory_gb": int(group["memoryGB"]),
                    "disks_gb": disks,
                    "nics": int(group.get("numNIC", 2)),
                })
        except (KeyError, IndexError, ValueError) as e:
            raise EsxiBuildError("lab_spec", f"nested_esxi_servers entry '{gtype or '?'}': {e!r}")
    return specs


# --------------------------------------------------------------------------------------------
# Kickstart ISO
# --------------------------------------------------------------------------------------------
def render_kickstart(legacy_cpu=False):
    with open(KICKSTART_TEMPLATE) as f:
        ks = f.read()
    marker = next((l for l in ks.splitlines() if l.startswith("#HESIOD_LEGACY_CPU_POST")), None)
    if marker:
        ks = ks.replace(marker, LEGACY_CPU_POST if legacy_cpu else "")
    if legacy_cpu:
        # Kickstart turns the CPU_SUPPORT_OVERRIDE warning into a hard stop unless the install line allows it
        ks = "\n".join(l + " --forceunsupportedinstall" if l.startswith("install ") and "--forceunsupportedinstall" not in l
                       else l for l in ks.splitlines()) + "\n"
    return ks


def _patch_boot_cfg(text, extra_opts):
    lines, done = text.splitlines(), False
    for i, line in enumerate(lines):
        if line.startswith("kernelopt="):
            opts = line[len("kernelopt="):].split()
            opts += [o for o in extra_opts if o not in opts]
            lines[i], done = "kernelopt=" + " ".join(opts), True
    if not done:
        lines.append("kernelopt=" + " ".join(extra_opts))
    return "\n".join(lines) + "\n"


def remaster_iso(stock_iso, out_iso, ks_text, legacy_cpu=False):
    """Copy the stock ISO to out_iso with /KS.CFG added and ks=cdrom:/KS.CFG on both boot lines (BIOS + UEFI).
    Boot records are replayed from the stock ISO, so the result boots exactly like the original."""
    if not shutil.which("xorriso"):
        raise EsxiBuildError("iso", "xorriso is not installed (sudo apt -y install xorriso)")
    opts = ["ks=cdrom:/KS.CFG"] + (["allowLegacyCPU=true"] if legacy_cpu else [])
    work = tempfile.mkdtemp(prefix="hesiod-ks-")
    try:
        maps = []
        for iso_path, local in (("/BOOT.CFG", "BOOT.CFG"), ("/EFI/BOOT/BOOT.CFG", "EFIBOOT.CFG")):
            local = os.path.join(work, local)
            r = subprocess.run(["xorriso", "-osirrox", "on", "-indev", stock_iso, "-extract", iso_path, local],
                               capture_output=True, text=True)
            if r.returncode != 0 or not os.path.isfile(local):
                if iso_path == "/BOOT.CFG":
                    raise EsxiBuildError("iso", f"{stock_iso} has no /BOOT.CFG; is it an ESXi installer ISO?")
                continue  # BIOS-only ISO
            os.chmod(local, 0o644)
            with open(local) as f:
                patched = _patch_boot_cfg(f.read(), opts)
            with open(local, "w") as f:
                f.write(patched)
            maps += ["-map", local, iso_path]
        ks_local = os.path.join(work, "KS.CFG")
        with open(ks_local, "w") as f:
            f.write(ks_text)
        if os.path.exists(out_iso):
            os.remove(out_iso)
        cmd = ["xorriso", "-indev", stock_iso, "-outdev", out_iso, "-boot_image", "any", "replay",
               "-map", ks_local, "/KS.CFG"] + maps
        r = subprocess.run(cmd, capture_output=True, text=True)
        if r.returncode != 0:
            raise EsxiBuildError("iso", f"xorriso failed: {r.stderr.strip()[-500:]}")
    finally:
        shutil.rmtree(work, ignore_errors=True)
    return out_iso


def _parse_ds_path(ds_path):
    # "[datastore1] ISO/VMware-ESXi-9.1.iso" -> ("datastore1", "ISO/VMware-ESXi-9.1.iso")
    if not ds_path.startswith("[") or "]" not in ds_path:
        raise EsxiBuildError("lab_spec", f"CD_path must look like '[datastore] folder/file.iso', got '{ds_path}'")
    ds, rel = ds_path[1:].split("]", 1)
    return ds.strip(), rel.strip()


def _ds_url(spec, dc_name, ds_name, rel):
    return (f"https://{spec['esxi_host']}/folder/{urllib.parse.quote(rel)}"
            f"?dcPath={urllib.parse.quote(dc_name)}&dsName={urllib.parse.quote(ds_name)}")


def _ensure_kickstart_iso(si, loc, spec, rebuild=False):
    ds_name, rel = _parse_ds_path(spec["stock_iso"])
    # The name carries a hash of the kickstart, so any change to the template or flags builds a fresh ISO
    ks_text = render_kickstart(spec["legacy_cpu"])
    ks_hash = hashlib.sha256((ks_text + str(spec["legacy_cpu"])).encode()).hexdigest()[:8]
    ks_rel = posixpath.join(posixpath.dirname(rel), f"hesiod-ks-{ks_hash}-" + posixpath.basename(rel))
    ks_ds_path = f"[{ds_name}] {ks_rel}"
    cookie = {"Cookie": si._stub.cookie.split(";")[0].strip()}
    dc = loc["dc"].name

    if not rebuild and requests.head(_ds_url(spec, dc, ds_name, ks_rel), headers=cookie, verify=False, timeout=30).status_code == 200:
        liblog.print_logs(f"Kickstart ISO already on the datastore: {ks_ds_path}")
        return ks_ds_path

    os.makedirs(ISO_CACHE_DIR, exist_ok=True)
    stock_local = os.path.join(ISO_CACHE_DIR, posixpath.basename(rel))
    if not os.path.isfile(stock_local):
        liblog.print_logs(f"Downloading {spec['stock_iso']} from {spec['esxi_host']} (one time).")
        with requests.get(_ds_url(spec, dc, ds_name, rel), headers=cookie, verify=False, stream=True, timeout=(30, 300)) as r:
            if r.status_code != 200:
                raise EsxiBuildError("iso", f"cannot download {spec['stock_iso']}: HTTP {r.status_code}")
            with open(stock_local + ".part", "wb") as f:
                for chunk in r.iter_content(8 * 1024 * 1024):
                    f.write(chunk)
        os.replace(stock_local + ".part", stock_local)

    ks_local = os.path.join(ISO_CACHE_DIR, posixpath.basename(ks_rel))
    liblog.print_logs(f"Building kickstart ISO {ks_local}.")
    remaster_iso(stock_local, ks_local, ks_text, spec["legacy_cpu"])

    liblog.print_logs(f"Uploading {ks_ds_path} ({os.path.getsize(ks_local) // 1000000} MB).")
    with open(ks_local, "rb") as f:
        r = requests.put(_ds_url(spec, dc, ds_name, ks_rel), data=f, verify=False, timeout=(30, 1800),
                         headers={**cookie, "Content-Type": "application/octet-stream",
                                  "Content-Length": str(os.path.getsize(ks_local))})
    if r.status_code not in (200, 201):
        raise EsxiBuildError("iso", f"upload of {ks_ds_path} failed: HTTP {r.status_code}")
    return ks_ds_path


def build_kickstart_iso(lab_spec, types=None, rebuild=False):
    done = {}
    for spec in get_nested_esxi_specs(lab_spec, types):
        key = (spec["esxi_host"], spec["stock_iso"], spec["legacy_cpu"])
        if key in done:
            continue
        si = libubuntu._connect(spec)
        try:
            done[key] = _ensure_kickstart_iso(si, libubuntu._locate(si, spec), spec, rebuild)
        finally:
            Disconnect(si)
    return list(done.values())


# --------------------------------------------------------------------------------------------
# VM build
# --------------------------------------------------------------------------------------------
def _guestinfo(spec, include_password=True):
    values = {"fqdn": spec["fqdn"], "ip": spec["ip"], "netmask": spec["netmask"], "gateway": spec["gateway"],
              "vlan": spec["vlan"], "dns": ",".join(spec["dns"]), "domain": spec["domain"], "ntp": spec["ntp"],
              "mtu": spec["mtu"], "password": spec["password"] if include_password else ""}
    return [vim.option.OptionValue(key=f"guestinfo.hesiod.{k}", value=v) for k, v in values.items()]


GIB = 1024 ** 3


def _footprint_gb(spec):
    """(committed, worst_case) GB on the datastore. Committed = what exists at power-on: the swap file
    (= memory, no reservation) + the boot disk + ~1 GB of VM files. Worst case adds fully grown thin vSAN disks."""
    committed = spec["memory_gb"] + spec["disks_gb"][0] + 1
    return committed, committed + sum(spec["disks_gb"][1:])


def _place(content, spec, planned):
    """Pick the candidate datastore with the most room left after what this run has already placed there.
    Ranking uses worst-case sizes (so hosts spread out); the fit check uses power-on sizes (so a datastore can still
    take a second host when there are fewer datastores than hosts). `planned` = {name: [committed_gb, worst_gb]}."""
    committed, worst = _footprint_gb(spec)
    options = []
    for name in spec["datastores"]:
        ds = libubuntu._find(content, vim.Datastore, name)
        if not ds:
            raise EsxiBuildError("placement", f"datastore '{name}' not found on {spec['esxi_host']}")
        try:
            ds.RefreshDatastore()
        except Exception:
            pass
        if not ds.summary.accessible:
            liblog.print_logs(f"  datastore {name} is not accessible; skipping")
            continue
        free = ds.summary.freeSpace / GIB
        p_committed, p_worst = planned.get(name, [0, 0])
        options.append((free - p_worst, free, name, ds, free - p_committed))
    fits = [o for o in options if o[4] >= committed]
    if not fits:
        best = max(options, key=lambda o: o[4], default=(0, 0, "none", None, 0))
        raise EsxiBuildError("placement", f"{spec['name']} needs {committed:.0f} GB at power-on (swap {spec['memory_gb']} GB + "
                                          f"boot {spec['disks_gb'][0]} GB); best candidate '{best[2]}' has {best[4]:.0f} GB left")
    score, free, name, ds, left = max(fits, key=lambda o: (o[0], o[4]))
    planned[name] = [planned.get(name, [0, 0])[0] + committed, planned.get(name, [0, 0])[1] + worst]
    liblog.print_logs(f"  placing {spec['name']} on {name} ({left:.0f} GB left of {free:.0f} GB free; needs {committed:.0f} GB now, "
                      f"up to {worst:.0f} GB if its thin disks fill)")
    if worst > score:  # score = free space minus worst cases already placed here this run
        liblog.print_logs(f"  WARNING: {name} could run out of space if {spec['name']}'s thin disks fill "
                          f"({worst:.0f} GB worst case vs {score:.0f} GB available)")
    return ds


def _portgroup_vlan(host, name):
    for pg in (host.configManager.networkSystem.networkInfo.portgroup or []):  # live view of the host's port groups
        if pg.spec.name == name:
            return pg.spec.vlanId
    return None  # distributed port group or not found: not checked


def _check_portgroup(loc, spec):
    """Nested hosts tag their own VLANs, so a VLAN-tagged (VST) port group would drop their frames."""
    vlan = _portgroup_vlan(loc["host"], spec["network"])
    if spec["vlan"] not in ("", "0") and vlan is not None and vlan != 4095:
        raise EsxiBuildError("precheck", f"port group '{spec['network']}' is VLAN {vlan}, but nested hosts tag VLAN "
                                         f"{spec['vlan']} themselves; use a VLAN 4095 (trunk) port group such as mpc-nested-trunk")
    if spec["vlan"] in ("", "0") and vlan == 4095:
        raise EsxiBuildError("precheck", f"port group '{spec['network']}' is a VLAN 4095 trunk but management_vlan_id is 0; "
                                         f"set management_vlan_id (e.g. 1610)")


def _create_vm(loc, spec, iso_ds_path):
    add, create = vim.vm.device.VirtualDeviceSpec.Operation.add, vim.vm.device.VirtualDeviceSpec.FileOperation.create
    thin = lambda: vim.vm.device.VirtualDisk.FlatVer2BackingInfo(diskMode="persistent", thinProvisioned=True)
    dev = [
        vim.vm.device.VirtualDeviceSpec(operation=add, device=vim.vm.device.ParaVirtualSCSIController(
            key=-100, busNumber=0, sharedBus="noSharing")),
        vim.vm.device.VirtualDeviceSpec(operation=add, device=vim.vm.device.VirtualNVMEController(key=-200, busNumber=0)),
        vim.vm.device.VirtualDeviceSpec(operation=add, device=vim.vm.device.VirtualAHCIController(key=-300, busNumber=0)),
        # harddisks[0] = boot disk on pvscsi (kickstart installs to the first pvscsi disk)
        vim.vm.device.VirtualDeviceSpec(operation=add, fileOperation=create, device=vim.vm.device.VirtualDisk(
            key=-1, controllerKey=-100, unitNumber=0, capacityInKB=spec["disks_gb"][0] * 1024 * 1024, backing=thin())),
        vim.vm.device.VirtualDeviceSpec(operation=add, device=vim.vm.device.VirtualCdrom(
            key=-400, controllerKey=-300, unitNumber=0,
            backing=vim.vm.device.VirtualCdrom.IsoBackingInfo(fileName=iso_ds_path),
            connectable=vim.vm.device.VirtualDevice.ConnectInfo(startConnected=True, connected=True, allowGuestControl=True))),
    ]
    # harddisks[1:] = vSAN disks on NVMe (required for vSAN ESA, fine for OSA)
    for n, gb in enumerate(spec["disks_gb"][1:]):
        dev.append(vim.vm.device.VirtualDeviceSpec(operation=add, fileOperation=create, device=vim.vm.device.VirtualDisk(
            key=-2 - n, controllerKey=-200, unitNumber=n, capacityInKB=gb * 1024 * 1024, backing=thin())))
    for n in range(spec["nics"]):
        dev.append(vim.vm.device.VirtualDeviceSpec(operation=add, device=vim.vm.device.VirtualVmxnet3(
            key=-500 - n, addressType="generated",
            backing=vim.vm.device.VirtualEthernetCard.NetworkBackingInfo(deviceName=spec["network"], network=loc["net"]),
            connectable=vim.vm.device.VirtualDevice.ConnectInfo(startConnected=True, connected=True, allowGuestControl=True))))

    config = vim.vm.ConfigSpec(
        name=spec["name"], guestId=spec["guest_id"], numCPUs=spec["cpu"], numCoresPerSocket=spec["cpu"],
        memoryMB=spec["memory_gb"] * 1024, firmware="efi", nestedHVEnabled=True,
        bootOptions=vim.vm.BootOptions(efiSecureBootEnabled=False),  # %firstboot does not run under Secure Boot
        files=vim.vm.FileInfo(vmPathName=f"[{loc['ds'].name}]"), deviceChange=dev,
        extraConfig=_guestinfo(spec) + [vim.option.OptionValue(key="disk.EnableUUID", value="TRUE")])
    vm = libubuntu._wait_task(loc["dc"].vmFolder.CreateVM_Task(config=config, pool=loc["pool"], host=loc["host"]), "create_vm")

    # Boot order: boot disk first (empty until installed, so EFI falls through to the CD), then CD.
    # After the install the disk boots, so the ISO never reinstalls the host.
    boot_disk = next(d for d in vm.config.hardware.device if isinstance(d, vim.vm.device.VirtualDisk)
                     and d.controllerKey == next(c.key for c in vm.config.hardware.device
                                                 if isinstance(c, vim.vm.device.ParaVirtualSCSIController)))
    libubuntu._wait_task(vm.ReconfigVM_Task(vim.vm.ConfigSpec(bootOptions=vim.vm.BootOptions(bootOrder=[
        vim.vm.BootOptions.BootableDiskDevice(deviceKey=boot_disk.key),
        vim.vm.BootOptions.BootableCdromDevice()]))), "boot_order")
    return vm


def _served_cert(ip):
    pem = ssl.get_server_certificate((ip, 443), timeout=10)
    cert = x509.load_pem_x509_certificate(pem.encode())
    cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    der = ssl.PEM_cert_to_DER_cert(pem)
    thumb = ":".join(f"{b:02X}" for b in hashlib.sha256(der).digest())
    return (cn[0].value if cn else ""), thumb


def _wait_until_ready(spec, timeout_s=INSTALL_TIMEOUT):
    """Ready = served cert CN equals the FQDN (only true after %firstboot regenerated it and rebooted)
    AND the real root password works."""
    deadline, last = time.time() + timeout_s, "no response yet"
    while time.time() < deadline:
        try:
            cn, thumb = _served_cert(spec["ip"])
            if cn.lower() == spec["fqdn"].lower():
                si = SmartConnect(host=spec["ip"], user="root", pwd=spec["password"],
                                  sslContext=ssl._create_unverified_context())
                Disconnect(si)
                return thumb
            last = f"certificate CN is '{cn}' (firstboot not finished)"
        except vim.fault.InvalidLogin:
            last = "root password not set yet"
        except Exception as e:
            last = type(e).__name__
        time.sleep(20)
    raise EsxiBuildError("wait_ready", f"{spec['name']} ({spec['ip']}) not ready after {timeout_s}s: {last}. "
                                       f"Check the VM console and /var/log/hesiod-firstboot.log")


MAX_DRIFT_S = 60


def _dns_ntp_problems(cm, spec):
    """Read-only comparison of a host's DNS/NTP/clock with lab_spec. Returns a list of problems (empty = good)."""
    problems = []
    got_dns = list(cm.networkSystem.dnsConfig.address or [])
    if got_dns != spec["dns"]:
        problems.append(f"DNS servers {got_dns}, expected {spec['dns']}")
    ntp = [x.strip() for x in str(spec["ntp"]).split(",") if x.strip()]
    if ntp:
        got_ntp = list(cm.dateTimeSystem.dateTimeInfo.ntpConfig.server or [])
        if got_ntp != ntp:
            problems.append(f"NTP servers {got_ntp}, expected {ntp}")
        svc = next((x for x in cm.serviceSystem.serviceInfo.service if x.key == "ntpd"), None)
        if not svc or not svc.running:
            problems.append("ntpd not running")
        if svc and svc.policy != "on":
            problems.append(f"ntpd policy '{svc.policy if svc else None}', expected 'on' (start and stop with host)")
    drift = (cm.dateTimeSystem.QueryDateTime() - datetime.now(timezone.utc)).total_seconds()
    if abs(drift) > MAX_DRIFT_S:
        problems.append(f"clock {drift:+.0f}s off Hesiod Main")
    return problems


def _save_config(spec):
    """Persist the running config to the boot bank now. ESXi otherwise saves only hourly or on a clean shutdown,
    so a reset before then silently loses API changes. (No vSphere API call does this; /sbin/auto-backup.sh does.)"""
    import paramiko
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(spec["ip"], username="root", password=spec["password"], timeout=15,
                    look_for_keys=False, allow_agent=False)  # paramiko falls back to keyboard-interactive (ESXi)
        _, out, err = ssh.exec_command("/sbin/auto-backup.sh", timeout=120)
        rc = out.channel.recv_exit_status()
        if rc != 0:
            raise EsxiBuildError("dns_ntp", f"{spec['name']}: auto-backup.sh exit {rc}: {err.read().decode(errors='replace')[-300:]}")
    except EsxiBuildError:
        raise
    except Exception as e:
        raise EsxiBuildError("dns_ntp", f"{spec['name']}: cannot save config over SSH ({type(e).__name__}: {e}); "
                                        f"settings are applied but not yet persisted")
    finally:
        ssh.close()


def check_dns_ntp(spec):
    """Read-only DNS/NTP/clock check for one running host (used by -m8 preflight)."""
    si = SmartConnect(host=spec["ip"], user="root", pwd=spec["password"], sslContext=ssl._create_unverified_context())
    try:
        host = next(iter(libubuntu._find(si.RetrieveContent(), vim.HostSystem)))
        return _dns_ntp_problems(host.configManager, spec)
    finally:
        Disconnect(si)


def _configure_dns_ntp(spec):
    """Set DNS (all domain.server_ips, search domain) and NTP (domain.ntp) on a running host through the vSphere API,
    then read both back. Authoritative: does not depend on what %firstboot managed to do."""
    try:
        si = SmartConnect(host=spec["ip"], user="root", pwd=spec["password"], sslContext=ssl._create_unverified_context())
    except Exception as e:
        raise EsxiBuildError("dns_ntp", f"{spec['name']}: cannot log in to {spec['ip']}: {getattr(e, 'msg', None) or e}")
    try:
        host = next(iter(libubuntu._find(si.RetrieveContent(), vim.HostSystem)))
        cm = host.configManager
        short, _, dom = spec["fqdn"].partition(".")
        cm.networkSystem.UpdateDnsConfig(config=vim.host.DnsConfig(
            dhcp=False, hostName=short, domainName=dom, address=spec["dns"], searchDomain=[dom] if dom else []))

        ntp = [x.strip() for x in str(spec["ntp"]).split(",") if x.strip()]
        if ntp:
            cfg = vim.host.DateTimeConfig(ntpConfig=vim.host.NtpConfig(server=ntp))
            try:
                cfg.protocol = "ntp"  # vSphere 7.0U3+: makes NTP (not manual) the time source
            except Exception:
                pass
            cm.dateTimeSystem.UpdateDateTimeConfig(config=cfg)
            try:
                cm.firewallSystem.EnableRuleset(id="ntpClient")
            except Exception:
                pass
            # ntpd will not step a large offset; a new nested VM starts with the physical host's clock.
            drift = (cm.dateTimeSystem.QueryDateTime() - datetime.now(timezone.utc)).total_seconds()
            if abs(drift) > MAX_DRIFT_S:
                cm.dateTimeSystem.UpdateDateTime(dateTime=datetime.now(timezone.utc))
                liblog.print_logs(f"{spec['fqdn']}: clock was {drift:+.0f}s off; set to Hesiod Main's UTC time before starting ntpd.")
            cm.serviceSystem.UpdateServicePolicy(id="ntpd", policy="on")
            running = any(svc.key == "ntpd" and svc.running for svc in cm.serviceSystem.serviceInfo.service)
            (cm.serviceSystem.RestartService if running else cm.serviceSystem.StartService)(id="ntpd")

        problems = _dns_ntp_problems(cm, spec)
        if problems:
            raise EsxiBuildError("dns_ntp", f"{spec['name']}: read-back mismatch: {'; '.join(problems)}")
        _save_config(spec)
        liblog.print_logs(f"{spec['fqdn']}: DNS {spec['dns']}, search {dom}, NTP {ntp} (ntpd running, start with host, saved).")
        return {"dns": spec["dns"], "ntp": ntp}
    except EsxiBuildError:
        raise
    except Exception as e:
        raise EsxiBuildError("dns_ntp", f"{spec['name']}: {getattr(e, 'msg', None) or repr(e)}")
    finally:
        Disconnect(si)


def configure_dns_ntp(lab_spec, types=None):
    """Apply DNS, NTP and clock from lab_spec to hosts that are already built (no reinstall), and save to the boot bank."""
    return [{"name": s["name"], **_configure_dns_ntp(s)} for s in get_nested_esxi_specs(lab_spec, types)]


def _finish(spec):
    """Wait for one host, set DNS + NTP through the API, then scrub the password from guestinfo and disconnect the CD."""
    t0 = time.time()
    thumb = _wait_until_ready(spec)
    _configure_dns_ntp(spec)
    si = libubuntu._connect(spec)
    try:
        vm = libubuntu._find(si.RetrieveContent(), vim.VirtualMachine, spec["name"])
        cd = next(d for d in vm.config.hardware.device if isinstance(d, vim.vm.device.VirtualCdrom))
        cd.connectable.connected, cd.connectable.startConnected = False, False
        libubuntu._wait_task(vm.ReconfigVM_Task(vim.vm.ConfigSpec(
            extraConfig=_guestinfo(spec, include_password=False),
            deviceChange=[vim.vm.device.VirtualDeviceSpec(operation="edit", device=cd)])), "cleanup")
    finally:
        Disconnect(si)
    liblog.print_logs(f"{spec['fqdn']} ({spec['ip']}) ready. SHA-256 thumbprint {thumb}")
    return {"name": spec["name"], "fqdn": spec["fqdn"], "ip": spec["ip"], "status": "success",
            "ssl_thumbprint": thumb, "wait_s": round(time.time() - t0)}


def create_nested_esxi_hosts(lab_spec, types=None, replace_existing=False):
    liblog.print_logs(f"Initiating create_nested_esxi_hosts(lab_spec, types={types}) function.")
    specs = get_nested_esxi_specs(lab_spec, types)
    if not specs:
        raise EsxiBuildError("lab_spec", f"no nested_esxi_servers match types={types}")
    isos, planned = {}, {}

    # Phase 1 (sequential, a few seconds per host): ISO once, place, create VM, power on
    for spec in specs:
        liblog.print_logs(f"Creating {spec['name']} ({spec['fqdn']}, {spec['ip']}, VLAN {spec['vlan']}) on {spec['esxi_host']}.")
        si = libubuntu._connect(spec)
        try:
            loc = libubuntu._locate(si, spec)
            _check_portgroup(loc, spec)
            existing = libubuntu._find(loc["content"], vim.VirtualMachine, spec["name"])
            if existing:
                if not replace_existing:
                    raise EsxiBuildError("precheck", f"VM {spec['name']} already exists (use replace_existing=True)")
                liblog.print_logs(f"Deleting existing VM {spec['name']}.")
                libubuntu._destroy_vm(existing)
            key = (spec["esxi_host"], spec["stock_iso"], spec["legacy_cpu"])
            if key not in isos:
                isos[key] = _ensure_kickstart_iso(si, loc, spec)
            loc["ds"] = _place(loc["content"], spec, planned.setdefault(spec["esxi_host"], {}))
            spec["datastore"] = loc["ds"].name
            vm = _create_vm(loc, spec, isos[key])
            libubuntu._wait_task(vm.PowerOnVM_Task(), "power_on")
        except (EsxiBuildError, libubuntu.UbuntuBuildError):
            raise
        except Exception as e:
            raise EsxiBuildError("vsphere", f"{spec['name']}: {getattr(e, 'msg', None) or repr(e)}")
        finally:
            Disconnect(si)

    # Phase 2 (parallel): all hosts install at the same time
    liblog.print_logs(f"{len(specs)} host(s) installing unattended. Waiting for each to finish (typically 10-20 min).")
    results, errors = [], []
    with ThreadPoolExecutor(max_workers=len(specs)) as pool:
        for spec, fut in [(s, pool.submit(_finish, s)) for s in specs]:
            try:
                results.append(fut.result())
            except Exception as e:
                liblog.print_logs(f"FAILED: {spec['name']}: {e}")
                errors.append(f"{spec['name']}: {e}")
    if errors:
        raise EsxiBuildError("install", f"{len(errors)} of {len(specs)} host(s) failed: " + "; ".join(errors))
    liblog.print_logs(f"All {len(results)} nested ESXi hosts built.")
    return results


def delete_nested_esxi_hosts(lab_spec, types=None):
    for spec in get_nested_esxi_specs(lab_spec, types):
        si = libubuntu._connect(spec)
        try:
            vm = libubuntu._find(si.RetrieveContent(), vim.VirtualMachine, spec["name"])
            if vm:
                liblog.print_logs(f"Deleting {spec['name']}.")
                libubuntu._destroy_vm(vm)
        finally:
            Disconnect(si)


# Dry run: python3 -m python_lib.esxi conf/lab_spec.json
if __name__ == "__main__":
    with open(sys.argv[1] if len(sys.argv) > 1 else "conf/lab_spec.json") as f:
        spec_py = json.load(f)
    for s in get_nested_esxi_specs(spec_py):
        print(f"{s['type']:4} {s['name']:16} {s['fqdn']:32} {s['ip']:15} vlan={s['vlan']:5} "
              f"{s['cpu']}vCPU {s['memory_gb']}GB disks={s['disks_gb']} nics={s['nics']} "
              f"-> {s['esxi_host']} [{'|'.join(s['datastores'])} / {s['network']}] legacy_cpu={s['legacy_cpu']} "
              f"(datastore need: {_footprint_gb(s)[0]} GB at power-on, {_footprint_gb(s)[1]} GB worst case)")
    print("\n----- KS.CFG -----")
    print(render_kickstart(any(s["legacy_cpu"] for s in get_nested_esxi_specs(spec_py))))