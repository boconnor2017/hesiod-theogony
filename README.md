# Hesiod Theogony
![img01](img_lib/theogony.png)   
This is a branch from Project Hesiod: https://github.com/boconnor2017/hesiod. **Theogony** is an ancient Greek poem by Hesiod that details the origins of the gods, the creation of the universe, and serves as a foundational text for Greek Mythology. As such the contents of this repository represent the foundational codebase for a VMware based home lab. 

# Prerequisites
* At least one physical server running ESXi 9
* A router (virtual or physical) where you can create subnets
* Appropriate access and entitlements to Broadcom software
* Ubuntu 64-bit Server ISO
* ESXi 9.1 ISO
* SDDC Manager (VCF Installer) 9.1 OVA

# Resource Requirements
| Component                | vCPU | vMemory (GB) | vStorage (GB) |
|--------------------------|------|--------------|---------------|
| Hesiod Main Appliance    | 4    | 16           | 100           |
| Hesiod K8 Cluster Master | 4    | 16           | 100           |
| Hesiod K8 Cluster Node 1 | 4    | 16           | 100           |
| VCF Installer            | 4    | 16           | 914           |
| Nested ESXi Host 1       | 40   | 320          | 1080          |
| Nested ESXi Host 2       | 40   | 320          | 1080          |
| Nested ESXi Host 3       | 40   | 320          | 1080          |
| Nested ESXi Host 4       | 40   | 320          | 1080          |
| Nested ESXi Host 5       | 40   | 320          | 1080          |
| TOTAL:                   | 40   | 1664         | 6614          |

# Architecture Summary
![img02](img_lib/architecture_summary.png)

# Quick Start: Deploy Hesiod Main Appliance
Step 1: Deploy Ubuntu 64-bit Server with OpenSSH enabled. Login to the OS with SSH using defined username and password.   

Step 2: Download the `prep-ubuntu` bash script. 
```
sudo curl https://raw.githubusercontent.com/boconnor2017/hesiod-theogony/refs/heads/main/ubuntu/prep-ubuntu.sh >> prep-ubuntu.sh
```

Step 3: Run the `prep-ubuntu` bash script.
```
sudo sh prep-ubuntu.sh
```

Step 4: Navigate to `/usr/local/hesiod-theogony` working directory.
```
cd /usr/local/hesiod-theogony
```

Step 5: Run `hesiod-theogony` python script using the `-init` parameter. This will initialize the Theogony modules below with necessary python packages.
```
sudo python3 hesiod-theogony.py -init
```   

You have now deployed the **Hesiod Main Appliance**. Run `sudo python3 hesiod-theogony.py --help` for details.

# Modules: Deploy a VMware Lab Environment
Using the **Hesiod Main Appliance**, select from the list of modules below and pass parameters accordingly.

## Module 1: Create Lab Spec JSON files (Coming Soon...)
The `lab_spec.json` file contains the specs for your home lab. Specs include physical network configurations, physical host configurations, storage configurations, credentials, etc. Blank json templates are stored in the `/json_lib` folder. This script will generate a copy and will prompt you for inputs. Configurations are stored in the `/conf` folder. If you prefer to generate your own json file, copy `/json_lib/lab_spec.json`, paste into `/conf/lab_spec.json` and edit directly using vi editor. Alternatively, if you've created one already, simply upload it to `/conf/lab_spec.json`.    

The `dns_spec.json` file contains the dns specs for a brand new DNS server that you can deploy as part of Module 3. Blank json templates are stored in the `/json_lib` folder. This script will generate a copy and will prompt you for inputs. Configurations are stored in the `/conf` folder. If you prefer to generate your own json file, copy `/json_lib/dns_spec.json`, paste into `/conf/dns_spec.json` and edit directly using vi editor. Alternatively, if you've created one already, simply upload it to `/conf/dns_spec.json`.    

**WARNING: Do not edit or remove any of the files in /json_lib. Copy only.**
```
sudo python3 hesiod-theogony.py -m1
```  

## Module 2: Deploy Hesiod Kubernetes Services (HKS)
The Hesiod Kubernetes Services are used to host external services needed to run your nested VCF environment. External services include: DNS, LDAPS, offline depots, etc. The Hesiod Main Appliance will interact with your physical ESXi host(s) using details from **Module 1** to build virtual machines running Ubuntu Servers with Kubernetes. 
```
sudo python3 hesiod-theogony.py -m2
```  

## Module 3: Deploy Technitium DNS Server
A DNS server is required for your VMware environment. This script uses the configuration from `lab_spec.json` in Module 1 to deploy a Technitium Server pod on the HKS cluster from Module 2. Specifically:
```
"domain" : {
        "name" : "<sample: hesiod.local>",
        "server_ips" : ["<sample: 10.0.1.9", "8.8.8.8"],
        "ntp" : "pool.ntp.org",
        "fqdns" : [{
            "naming_convention" : "<sample: hesvcf>",
            "assign_ip_from_this_network" : 1, 
            "assign_ip_from_this_range_start" : "9",
            "assign_ip_from_this_range_end" : "60"
        }]
    }
```
The first IP address in `assign_ip_from_this_range_start` is reserved for the Technitium DNS server. This IP address is used by MetalLb to expose the `server_ips`[0] IP address that differs from the Kubernetes node.  
```
sudo python3 hesiod-theogony.py -m3
```    
You can connect to your Technitium DNS server at http://<DNS Server IP Address>:5380

## Module 4: Create DNS Zone and FQDNs for VCF
This script uses the configuration from `lab_spec.json` in Module 1 to create a DNS zone on the Technitium server deployed in Module 3. Specifically:
```
"domain" : {
        "name" : "<sample: hesiod.local>",
        "server_ips" : ["<sample: 10.0.1.9", "8.8.8.8"],
        "ntp" : "pool.ntp.org",
        "fqdns" : [{
            "naming_convention" : "<sample: hesvcf>",
            "assign_ip_from_this_network" : 1, 
            "assign_ip_from_this_range_start" : "9",
            "assign_ip_from_this_range_end" : "60"
        }]
    }
```
The first IP address in `assign_ip_from_this_range_start` is reserved for the Technitium DNS server. This IP address is used by MetalLb to expose the `server_ips`[0] IP address that differs from the Kubernetes node. The remaining addresses in the range will be used for the FQDNs. The FQDN is generated automatically using the naming convention and appending a counter with the zone name. For example, in the example above the first FQDN would be `hesvcf01.hesiod.local`, the second `hesvcf02.hesiod.local` and so on until the last IP address from `assign_ip_from_this_range_end` has been assigned.    

You can run this script as many times as you like. Each time the zone and the previous FQDNs will be overwritten. 
```
sudo python3 hesiod-theogony.py -m4
```   