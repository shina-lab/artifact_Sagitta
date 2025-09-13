#!/bin/bash

artifact_dir=$(cd $(dirname $0)/artifact; pwd)

sudo apt update -y
sudo apt install -y snapd

sudo apt install -y python3 python3-pip

# ### Install Apache Airflow
# pip3 install apache-airflow==2.7.0

### Install Docker
sudo snap install docker

### Install Scala CLI
curl -sSLf https://scala-cli.virtuslab.org/get | sh

### Install PolyTracker
cd ${artifact_dir}/polytracker
pip install .

### Install docker container helpers
cd ${artifact_dir}/work-desk
./setup.sc polytracker
./setup.sc polytracker.slim


echo "[*] Installation completed."