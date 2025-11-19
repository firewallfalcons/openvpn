#!/bin/bash

# ------------------------------------------------------------
# OpenVPN Manager Installer
# ------------------------------------------------------------
# Replace the URL below with the RAW URL of the 'openvpn-manager.sh' 
# file from your GitHub repository or Gist.
# ------------------------------------------------------------
MANAGER_URL="https://raw.githubusercontent.com/firewallfalcons/openvpn/main/openvpn-manager.sh"
# ------------------------------------------------------------

INSTALL_PATH="/usr/local/bin/ovpn"

echo "Installing OVPN Manager..."

# Check for root
if [[ "$EUID" -ne 0 ]]; then
	echo "Error: This script must be run as root."
	exit 1
fi

# Download the script
echo "Downloading manager script from $MANAGER_URL..."
curl -s -L "$MANAGER_URL" -o "$INSTALL_PATH"

if [[ $? -ne 0 ]]; then
    echo "Error: Failed to download the script. Please check the URL."
    exit 1
fi

# Make executable
chmod +x "$INSTALL_PATH"

echo ""
echo "Success! OVPN Manager has been installed."
echo "Type 'ovpn' to start the installer or manage clients."
echo ""

# Automatically run it for the first time
read -p "Do you want to run the installer now? [y/N]: " RUN_NOW
if [[ "$RUN_NOW" =~ ^[yY]$ ]]; then
    "$INSTALL_PATH"
fi
