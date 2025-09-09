#!/bin/sh
set -eux

script_dir=$(cd $(dirname $0); pwd)

AIRFLOW_HOME=${script_dir}/artifact/airflow \
    airflow standalone &
python3 ${script_dir}/artifact/pipeline.py