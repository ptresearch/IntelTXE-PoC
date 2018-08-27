#!/usr/bin/env python
# Unlock Token generator by Mark Ermolov (@_markel___)
#                           Maxim Goryachy (@h0t_max)
#
# Details:  https://github.com/ptresearch/IntelME-JTAG
#           https://github.com/ptresearch/IntelTXE-POC

import argparse
import struct

UTFLOFFSET = 0x1fe0
 
def parse_arguments():
    parser = argparse.ArgumentParser(description='Unlock Tocken generator')
    parser.add_argument('-f', help='path', type=str, default="utok.bin")
    return parser.parse_args().f;

def genereate_utok():
    data = struct.pack("<B", 0xff) * UTFLOFFSET
    data += struct.pack("<L", 0x4c465455)
    data += struct.pack("<B", 0xff) * 8
    data += struct.pack("<L", 0x1)
    data += struct.pack("<B", 0xff) * 16
    return data

def main():
    path = parse_arguments()
    with open(path, "wb") as f:
        f.write(genereate_utok())

if __name__ == "__main__":
    main()
