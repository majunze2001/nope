# python3 script to extract the factors from a bind private key

import sys
import os
import re
import base64
import struct

def usage():
  print("Usage: " + sys.argv[0] + " <keyfile>")
  print("Ex. " + sys.argv[0] + " Kexample.com.+013+00000.private")
  print("Output is is raw bytes, placed in tmp.dat")
  sys.exit(1)

# extract modulus, public exponent, private exponent, prime1, prime2, exponent1, etc. from keyfile
# decode base64 strings so everything is an integer
def parse_bind_keyfile(keyfile):
  key = {}
  with open(keyfile, 'r') as f:
    for line in f:
      if line.startswith("Modulus:"):
        key['modulus'] = base64.b64decode(line.split()[1])
      elif line.startswith("Prime1:"):
        key['prime1'] = base64.b64decode(line.split()[1])
      elif line.startswith("Prime2:"):
        key['prime2'] = base64.b64decode(line.split()[1])
  return key

def extract(keyfile):
  key = parse_bind_keyfile(keyfile)
  # debug print primes and modulus as big integers
  p = int.from_bytes(key['prime1'], byteorder='big')
  q = int.from_bytes(key['prime2'], byteorder='big')
  m = int.from_bytes(key['modulus'], byteorder='big')
  print(p * q - m, len(key['prime1']), len(key['prime2']), len(key['modulus']))
  # first 128 bytes are the first prime and the next 128 bytes are the second prime
  # primes are padded with 0x00 bytes to reach this length
  with open("tmp.dat", 'wb') as f:
    # pad first prime
    f.write(bytearray(128 - len(key['prime1'])))
    f.write(key['prime1'])
    # pad second prime
    f.write(bytearray(128 - len(key['prime2'])))
    f.write(key['prime2'])


if __name__ == "__main__":
  if len(sys.argv) != 2:
    usage()
  keyfile = sys.argv[1]
  extract(keyfile)