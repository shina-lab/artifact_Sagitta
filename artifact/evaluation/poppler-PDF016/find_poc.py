#!/bin/env python3
import glob
import argparse
import re
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description='Find suitable crash input for PDF016')
parser.add_argument("BASE_DIR")
parser.add_argument("pdfimages")
parser.add_argument("--debug", action="store_true")
parser.add_argument("--output", action="store_true")
parser.add_argument("--poc", action="store_true", help="Find in poc reported by Magma")
parser.add_argument("--check", action="store_true", help="Check if invalid indirect object exists")
args = parser.parse_args()

"""
20 0 obj
<</Type/Font/Subtype/TrueType/BaseFont/BAAAAA+LiberationSerif/FirstChar 0/LastChar 9/Widths[365 722 610 610 722 250 500 500 500 250 ]/FontDescriptor -45027 0 R/ToUnicode 19 0 R>>
endobj
"""

assert(Path(args.BASE_DIR).is_dir())
assert(Path(args.pdfimages).is_file())

for file in sorted(glob.glob(args.BASE_DIR + "/**/*")):
    file = Path(file)
    if args.poc:
        ### NOTE: 脆弱性の実際はPDF011
        if not "JCH201" in file.name and not "PDF011" in file.name:
            continue
        if "honggfuzz" in file.name:
            continue
    if file.is_dir():
        continue
    if args.debug:
        print(f"[*] {file.name}")
    if args.check:
        with open(file, 'rb') as f:
            data = f.read()
            m = re.search(b'(-?\d+)\s+(-?\d+)\s+R', data)
            if m and len(m.group(1)) < 4300 and len(m.group(2)) < 4300:
                num = int(m.group(1))
                gen = int(m.group(2))
                # if num < 0: ### NOTE: Close to crafted.pdf (http://packetstormsecurity.com/files/148661/PDFunite-0.62.0-Buffer-Overflow.html)
                if num < 0: ### NOTE: Close to patch file for this CVE
                    if args.debug:
                        print(f"[*] {file.name}: num={num} gen={gen}")
                    result = subprocess.run([args.pdfimages, file, "/dev/null"], capture_output=True)
                    # if b"PDF016-actual" in result.stderr:
                    if b"Canary triggered" in result.stderr:
                        print(f"{file}: num={num} gen={gen}")
                        line_pattern = f'^(.*{num}\s+{gen}\s+R.*)$'.encode('utf-8')
                        line = re.search(line_pattern, data, re.MULTILINE)
                        if line:
                            print(f"\t{line.group(1)}")
                        if args.output:
                            print(result.stderr.decode())
                    else:
                        if args.debug:
                            print(f"[-] {file.name}: Does not trigger canary")
    else:
        result = subprocess.run([args.pdfimages, file, "/dev/null"], capture_output=True)
        if b"Canary triggered by PDF016" in result.stderr:
            print(file)
            if args.output:
                print(result.stderr.decode())
        else:
            if args.debug:
                print(f"[-] {file.name}: Does not trigger canary")