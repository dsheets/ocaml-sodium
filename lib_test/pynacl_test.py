#!/usr/bin/env python

import getopt, sys

import nacl
import binascii

opts, args = getopt.getopt(sys.argv[1:], "f:")

r = binascii.a2b_hex
args = [r(a) for a in args]
def w(s):
    sys.stdout.write(binascii.b2a_hex(s))
if len(opts) < 1:
    o = "fail"
else:
    o,a = opts[0]
if o == "-f" and a == "box":
    w(nacl.crypto_box(args[0],args[1],args[2],args[3]))
elif o == "-f" and a == "box_open":
    w(nacl.crypto_box_open(args[0],args[1],args[2],args[3]))
elif o == "-f" and a == "box_beforenm":
    w(nacl.crypto_box_beforenm(args[0],args[1]))
elif o == "-f" and a == "box_afternm":
    w(nacl.crypto_box_afternm(args[0],args[1],args[2]))
elif o == "-f" and a == "box_open_afternm":
    w(nacl.crypto_box_open_afternm(args[0],args[1],args[2]))
else:
    raise Exception("use -f [box|box_open|box_beforenm|box_afternm|box_open_afternm]")
