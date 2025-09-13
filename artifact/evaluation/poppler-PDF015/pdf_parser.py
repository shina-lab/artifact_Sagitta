
import re
import zlib
import hexdump

hex = lambda x: int(x, 16)

import argparse
parser = argparse.ArgumentParser(description='About this program')
parser.add_argument("pdf_file")
parser.add_argument("--offset", default=0, type=hex)
parser.add_argument("--debug", action="store_true")
args = parser.parse_args()

pdf = open(args.pdf_file, "rb").read()[args.offset:]
stream = re.compile(b'(\d+) \d+ obj.*?FlateDecode.*?stream(.*?)endstream', re.S)

for m in re.findall(stream, pdf):
    print("== {} obj".format(m[0]))
    s = m[1].strip(b'\r\n')
    if args.debug:
        hexdump.hexdump(s)
    try:
        deflated = zlib.decompress(s)
        if b'\xff' in deflated:
            print("{}".format(repr(deflated)))
        else:
            print(deflated.decode('UTF-8'))
    except Exception as e:
        print("--", e)
        if deflated:
            # hexdump.hexdump(deflated)
            print("{}".format(repr(deflated)))
        pass