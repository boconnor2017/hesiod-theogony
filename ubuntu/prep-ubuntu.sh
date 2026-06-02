#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

echo "=========================================================================="
echo " Starting Hesiod Ubuntu Development Environment Bootstrap"
echo "=========================================================================="

# 1. Update system packages
echo "--> Updating package lists and upgrading system..."
export DEBIAN_FRONTEND=noninteractive
apt-get update && apt-get upgrade -y

# 2. Install Core Development & Network Tools
echo "--> Installing Build Essentials, Git, Vim, and SFTP/SSH tools..."
apt-get install -y \
    build-essential \
    curl \
    wget \
    git \
    vim \
    openssh-client \
    openssh-server \
    ca-certificates \
    gnupg \
    lsb-release

# 3. Configure Python Environment
echo "--> Installing Python3 and development tools..."
apt-get install -y python3 python3-pip python3-venv python3-full

# 4. Install PowerShell for Linux
echo "--> Installing Microsoft PowerShell..."
# Download the Microsoft repository GPG keys
wget -q "https://packages.microsoft.com/config/ubuntu/$(lsb_release -rs)/packages-microsoft-prod.deb" -O packages-microsoft-prod.deb
dpkg -i packages-microsoft-prod.deb
rm packages-microsoft-prod.deb

# Update package lists and install PowerShell
apt-get update
apt-get install -y powershell

# 5. Securely Configure /usr/local for Development
echo "--> Configuring secure permissions for /usr/local..."
# Create a developer group if it doesn't exist
if ! getent group developer > /dev/null; then
    groupadd developer
fi

# Add the current user (who called sudo) to the developer group
TARGET_USER=${SUDO_USER:-$USER}
usermod -aG developer "$TARGET_USER"

# Change ownership of /usr/local to root:developer
chown -R root:developer /usr/local

# Standard secure permissions: 
# Directories: rwxrwxr-x (2775 - with setgid)
# Files: rw-rw-r-- (664)
find /usr/local -type d -exec chmod 2775 {} +
find /usr/local -type f -exec chmod 664 {} +

# 6. Optimize Vim for Pasting from Visual Studio
echo "--> Optimizing Vim configuration for clipboard pasting..."
USER_HOME=$(eval echo "~$TARGET_USER")
VIMRC="$USER_HOME/.vimrc"

# Prevent Vim from messing up indentation when pasting code chunks
if [ ! -f "$VIMRC" ] || ! grep -q "pastetoggle" "$VIMRC"; then
    echo "set pastetoggle=<F2>" >> "$VIMRC"
    echo "syntax on" >> "$VIMRC"
    chown "$TARGET_USER":"$TARGET_USER" "$VIMRC"
fi

# 7. Install VMware Tools (Optimizes Ubuntu for VMware)
echo "--> Installing Open VM Tools for VMware optimization..."
apt-get install -y open-vm-tools

echo "=========================================================================="
echo " Bootstrap Complete!"
echo " IMPORTANT: Please log out and log back in for group changes to take effect."
echo " Press [F2] in Vim to toggle 'Paste Mode' before pasting from VS Code."
echo "=========================================================================="