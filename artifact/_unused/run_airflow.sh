#!/bin/sh
set -eux
script_dir=$(cd $(dirname $0); pwd)

# cd ${script_dir}
# echo "UID=$(id -u)" > .env
# docker-compose up -d

airflow standalone