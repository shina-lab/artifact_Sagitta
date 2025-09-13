#!/bin/sh

script_dir=$(cd $(dirname $0); pwd)
artifact_dir=$(cd ${script_dir}/../../artifact; pwd)
set -eux

export PATH=$PATH:$HOME/.local/bin
export PATH=$PATH:$HOME/go/bin

### Remove generated results
rm -f ${script_dir}/*.svg

### Perform phase 3, 4
python3 ${artifact_dir}/pipeline.py
