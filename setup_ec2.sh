#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
# Print commands and their arguments as they are executed.
# Treat unset variables as an error.
# Prevent errors in a pipeline from being masked.
set -euxo pipefail

# Log file for setup script output
LOG_FILE="/var/log/setup_ec2.log"
exec > >(tee -a ${LOG_FILE}) 2>&1

echo "Starting EC2 Setup Script..."

# Update package lists and upgrade installed packages
echo "Updating system packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get upgrade -y -o Dpkg::Options::="--force-confold"
echo "System packages updated."

# Install essential build tools, Python, pip, git, and fpylll dependencies
echo "Installing dependencies (python, build-essential, gmp, mpfr, mpc, git)..."
apt-get install -y python3-pip python3-dev build-essential libgmp-dev libmpfr-dev libmpc-dev pkg-config git
echo "Dependencies installed."

# Install required Python packages
echo "Installing Python libraries (numpy, fpylll)..."
pip3 install --no-cache-dir numpy fpylll
echo "Python libraries installed."

# Clean up apt cache
apt-get clean
rm -rf /var/lib/apt/lists/*

echo "EC2 Setup Script Finished Successfully."
