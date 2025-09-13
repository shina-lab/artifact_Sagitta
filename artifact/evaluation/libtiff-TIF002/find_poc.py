#!/bin/env python3
import glob
import argparse
import re
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description='Find suitable crash input for TIF002')
parser.add_argument("BASE_DIR")
parser.add_argument("tiff_read_rgba_fuzzer")
parser.add_argument("--debug", action="store_true")
parser.add_argument("--output", action="store_true")
parser.add_argument("--poc", action="store_true", help="Find in poc reported by Magma")
args = parser.parse_args()

assert(Path(args.BASE_DIR).is_dir())
assert(Path(args.tiff_read_rgba_fuzzer).is_file())

for file in sorted(glob.glob(args.BASE_DIR + "**/*", recursive=True)):
    file = Path(file)
    if args.poc:
        if not "AAH010" in file.name:
            continue
        if "honggfuzz" in file.name:
            continue
    if file.is_dir():
        continue
    if args.debug:
        print(f"[*] {file.name}")
    
    result = subprocess.run([args.tiff_read_rgba_fuzzer, file], capture_output=True)
    if b"TIF002" in result.stderr:
        print(file)
        if args.output:
            print(result.stderr.decode())
    else:
        if args.debug:
            print(f"[-] {file.name}: Does not trigger canary")