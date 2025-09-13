#!/bin/bash

artifact_dir=$(cd $(dirname $0)/artifact; pwd)

# sudo apt update
sudo apt install -y python3 python3-pip

# ### Install Apache Airflow
# pip3 install apache-airflow==2.7.0

### Install Docker

### Install Scala CLI
# TODO: 

### Install PolyTracker
cd ${artifact_dir}/polytracker
# TODO: 


cd ${artifact_dir}/work-desk
./setup.sc polytracker
./setup.sc polytracker.slim


echo "[*] Installation completed."