#!/bin/bash

artifact_dir=$(cd $(dirname $0)/artifact; pwd)
set -eux

sudo apt update -y
sudo apt install -y snapd
export PATH=$PATH:$HOME/.local/bin

sudo apt install -y python3 python3-pip

# ### Install Apache Airflow
# pip3 install apache-airflow==2.7.0

### Install Docker
if ! command docker &> /dev/null; then
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo \
"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
$(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable docker
sudo systemctl start docker
fi

if ! getent group docker > /dev/null; then
    sudo addgroup --system docker
fi
if ! id -nG "$USER" | grep -qw "docker"; then
    sudo usermod -aG docker $USER
fi

# ### Activate proper Python environment for Ubuntu 24.04 (Not works)
# sudo apt install software-properties-common -y
# sudo add-apt-repository ppa:deadsnakes/ppa -y
# sudo apt update
# sudo apt install python3.10 python3.10-venv python3.10-dev python3.10-distutils -y
# curl -sSL https://install.python-poetry.org | python3 -
# cd ${artifact_dir}
# poetry env use python3.10
# poetry env activate

### Install Scala CLI
if ! command -v scala-cli &> /dev/null; then
    curl -fL https://github.com/Virtuslab/scala-cli/releases/latest/download/scala-cli-x86_64-pc-linux.gz | gzip -d > scala-cli
    chmod +x scala-cli
    sudo mv scala-cli /usr/local/bin/scala-cli
fi

### Install PolyTracker
cd ${artifact_dir}/polytracker
git submodule update --init --recursive
pip3 install -e . 

### Build docker image for PolyTracker
cd ${artifact_dir}/work-desk
sg docker -c "scala-cli run ./setup.sc -v -- polytracker"
sg docker -c "scala-cli run ./setup.sc -v -- polytracker.slim"


echo "[*] Installation completed."