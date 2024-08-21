
# script to compress a Groth16 proof
# usage: python compress.py <proof_file> <circuit_type> <domain_name>

# circuit_type: [TLD uses ECDSA] | [SLD uses ECDSA] | [is mangaged]

import sys
import os
import time
import json

top = 2 ** 256 - 1
p = 21888242871839275222246405745257275088696311157297823662689037894645226208583
# (p + 1)//4
p_e_sqrt = 5472060717959818805561601436314318772174077789324455915672259473661306552146

# from https://github.com/recmo/evm-groth16/blob/main/src/Verifier.sol
constant_1_2 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4
constant_27_82 = 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5
constant_3_82 = 0x2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775

def Fsqrt(x):
  return pow(x, (p + 1) // 4, p)

def F2sqrt(a0, a1, h):
  d = Fsqrt(pow(a0, 2, p) + pow(a1, 2, p))
  if h:
    d = p - d
  x0 = Fsqrt(((a0 + d) * constant_1_2) % p)
  x1 = (a1 * pow(2 * x0, -1, p)) % p
  return x0, x1

def L1(x, y):
  ty = Fsqrt(pow(x, 3, p) + 3)
  if y == ty:
    return x
  elif y == p - ty:
    return top - x
  else:
    print("Error: Error compressing G1 point")
    exit(1)

# based on https://github.com/recmo/evm-groth16/blob/main/src/Verifier.sol
def L2(x0, x1, y0, y1):
  n3ab = (-3 * x0 * x1) % p
  a3 = pow(x0, 3, p)
  b3 = pow(x1, 3, p)
  tx0 = (constant_27_82 + a3 + n3ab * x1) % p
  tx1 = p - ((constant_3_82 + b3 + n3ab * x0) % p)
  ty0, ty1 = F2sqrt(tx0, tx1, False)
  ny0, ny1 = F2sqrt(tx0, tx1, True)
  if y0 == ty0:
    return x0, x1
  elif y0 == p - ty0:
    return top - x0, x1
  elif y0 == ny0:
    return x0, top - x1
  elif y0 == p - ny0:
    return top - x0, top - x1
  else:
    print("Error: Error compressing G2 point")
    exit(1)  

# convert 128 byte integer to URI safe string
def bits1024_to_URI(x):
  alphabet = "0123456789abcdefghijklmnopqrstuvwxyz-"
  alen = len(alphabet)
  result = ["", "", "", ""]
  checksum = 0
  for i in range(197):
    tmp = x % alen
    result[(i + 2) // 50] += alphabet[tmp]
    checksum = (checksum + tmp) % alen
    x = x // alen
  # append checksum
  result[3] += alphabet[checksum]
  return result

# if domain name doesn't start with a dot then add it
def fmt_domain(domain_name):
  if domain_name[0] != ".":
    return "." + domain_name
  return domain_name

def compress_proof(proof_file, circuit_type, domain_name):
  with open(proof_file, 'r') as f:
    proof = json.load(f)
  pi_a = L1(int(proof['pi_a'][0]), int(proof['pi_a'][1]))
  pi_b0, pi_b1 = L2(int(proof['pi_b'][0][0]), int(proof['pi_b'][0][1]),
                    int(proof['pi_b'][1][0]), int(proof['pi_b'][1][1]))
  pi_c = L1(int(proof['pi_c'][0]), int(proof['pi_c'][1]))
  # convert compressed_proof to URI safe string
  compressed_proof = bits1024_to_URI(pi_a + (pi_b0 << 256) + (pi_b1 << 512) + (pi_c << 768))
  domain = fmt_domain(domain_name)
  # if the length of the domain name is <= 29, format as single domain
  if len(domain) <= 29:
    print("n0pe." + "0" + str(circuit_type) + compressed_proof[0] + "." + compressed_proof[1] + "." + compressed_proof[2] + "." + compressed_proof[3] + domain)
  else:
    print("n0pe." + "0" + str(circuit_type) + compressed_proof[0] + "." + compressed_proof[1] + domain)
    print("n1pe." + compressed_proof[2] + "." + compressed_proof[3] + domain)
  #print(compressed_proof_URI)

if __name__ == '__main__':
  if len(sys.argv) != 4:
    print("Usage: python compress.py <proof_file> <circuit_type> <domain_name>")
    print("circuit_type is a 3 bit number representing the circuit type")
    sys.exit(1)
  proof_file = sys.argv[1]
  circuit_type = int(sys.argv[2])
  domain_name = sys.argv[3]
  if not os.path.exists(proof_file):
    print("Error: Proof file does not exist")
    sys.exit(1)
  if circuit_type < 0 or circuit_type > 7:
    print("Error: Circuit type must be a 3 bit number")
    sys.exit(1)
  compress_proof(proof_file, circuit_type, domain_name)
