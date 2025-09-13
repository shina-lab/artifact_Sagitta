#!/bin/env python3
import glob
import argparse
import re
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description='Find suitable crash input for TIF014')
parser.add_argument("BASE_DIR")
parser.add_argument("tiffcp")
parser.add_argument("--debug", action="store_true")
parser.add_argument("--output", action="store_true")
parser.add_argument("--poc", action="store_true", help="Find in poc reported by Magma")
args = parser.parse_args()

assert(Path(args.BASE_DIR).is_dir())
assert(Path(args.tiffcp).is_file())

for file in sorted(glob.glob(args.BASE_DIR + "/**/*")):
    file = Path(file)
    if args.poc:
        if not "AAH022" in file.name and not "TIF014" in file.name:
            continue
        if "honggfuzz" in file.name:
            continue
        if not "tiffcp" in file.name:
            continue
    if file.is_dir():
        continue
    if args.debug:
        print(f"[*] {file.name}")
    
    result = subprocess.run([args.tiffcp, "-M", file, "/dev/null"], capture_output=True)
    if b"Canary triggered by TIF014" in result.stderr:
        print(file)
    else:
        if args.debug:
            print(f"[-] {file.name}: Does not trigger canary")
    if args.output:
        print(result.stdout.decode())
        print(result.stderr.decode())