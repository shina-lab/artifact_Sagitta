#!/bin/bash

artifact_dir=$(cd $(dirname $0)/artifact; pwd)
set -eux

sudo apt update -y
sudo apt install -y snapd

sudo apt install -y python3 python3-pip

# ### Install Apache Airflow
# pip3 install apache-airflow==2.7.0

### Install Docker
if ! snap list | grep -q '^docker '; then
    sudo snap install docker
fi
if ! getent group docker > /dev/null; then
    sudo addgroup --system docker
fi
if ! id -nG "$USER" | grep -qw "docker"; then
    sudo usermod -aG docker "$USER"
fi

### Install Scala CLI
curl -fL https://github.com/Virtuslab/scala-cli/releases/latest/download/scala-cli-x86_64-pc-linux.gz | gzip -d > scala-cli
chmod +x scala-cli
sudo mv scala-cli /usr/local/bin/scala-cli

### Install PolyTracker
cd ${artifact_dir}/polytracker
pip3 install -e . --break-system-packages

### Install docker container helpers
cd ${artifact_dir}/work-desk
export PATH=$PATH:${HOME}/.local/bin/
./setup.sc polytracker
./setup.sc polytracker.slim


echo "[*] Installation completed."