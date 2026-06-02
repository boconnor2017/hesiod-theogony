# hesiod-theogony
End to end Hesiod lab automation on Ubuntu and Kubernetes.

# Quick Start: Deploy Hesiod Main appliance
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

Step 5: Run `hesiod-theogony` python script.
```
python3 hesiod-theogony.py
```