#!/bin/env python3
import glob
import argparse
import re
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description='Find suitable crash input for PDF011')
parser.add_argument("BASE_DIR")
parser.add_argument("pdfimages")
parser.add_argument("pdftoppm")
parser.add_argument("--debug", action="store_true")
parser.add_argument("--output", action="store_true")
parser.add_argument("--poc", action="store_true", help="Find in poc reported by Magma")
args = parser.parse_args()

assert(Path(args.BASE_DIR).is_dir())
assert(Path(args.pdfimages).is_file())

for file in sorted(glob.glob(args.BASE_DIR + "/**/*")):
    file = Path(file)
    if args.poc:
        if not "JCH201" in file.name and not "PDF011" in file.name:
            continue
        if "honggfuzz" in file.name:
            continue
    if file.is_dir():
        continue
    if args.debug:
        print(f"[*] {file.name}")

    if "pdfimages" in file.name:
        result = subprocess.run([args.pdfimages, file, "/dev/null"], capture_output=True)
    elif "pdftoppm" in file.name:
        result = subprocess.run([args.pdftoppm, "-mono", "-cropbox", file], capture_output=True)
    if b"Canary triggered by PDF011" in result.stderr:
        print(file)
        if args.output:
            print(result.stderr.decode())
    else:
        if args.debug:
            print(f"[-] {file.name}: Does not trigger canary")