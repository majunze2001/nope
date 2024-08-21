# python3 script to extract the constant from a bind private key 

import sys
import os
import re
import base64
import struct
# ecc imports
from ecpy.curves import Curve, Point
from ecpy.keys import ECPublicKey

def usage():
  print("Usage: " + sys.argv[0] + " <keyfile>")
  print("Ex. " + sys.argv[0] + " Kexample.com.+013+00000.private")
  print("Output is is raw bytes, placed in tmp.dat")
  sys.exit(1)

# extract PrivateKey from keyfile
# decode base64 strings so everything is an integer
def parse_bind_keyfile(keyfile):
  with open(keyfile, 'r') as f:
    for line in f:
      if line.startswith("PrivateKey:"):
        return base64.b64decode(line.split()[1])
  # error if we didn't find the private key
  print("Error: private key not found in " + keyfile)
  sys.exit(1)

def extract(keyfile):
  key = parse_bind_keyfile(keyfile)
  # debug print private key as big integer
  k = int.from_bytes(key, byteorder='big')
  print(k, len(key))
  # debug print kG (NIST P-256), for checking that public key matches
  #print(Curve.get_curve_names())
  curve = Curve.get_curve('NIST-P256')
  #print(curve)
  generator = curve.generator
  kG = k * generator
  print(kG.x)
  print(kG.y)

  # first 32 bytes
  with open("tmp.dat", 'wb') as f:
    # write key
    f.write(bytearray(32 - len(key)))
    f.write(key)


if __name__ == "__main__":
  if len(sys.argv) != 2:
    usage()
  keyfile = sys.argv[1]
  extract(keyfile)