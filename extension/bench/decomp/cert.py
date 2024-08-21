
# takes in a certificate chain and prints it as JSON
# usage: python3 cert.py ../cert/nope.pem ../cert/dv.pem ../cert/r11.pem

import sys
import json
import re
import subprocess
import os

# convert asn1parse line to tuple
# e.g. '  0:d=0  hl=4 l= 290 cons: SEQUENCE' -> (0, 0, 4, 290, 'SEQUENCE')
def parseline(line):
  name = line.split(":")[-1].strip()
  vals = re.findall(r"\d+", line)
  return {"name":name,
          "offset:": int(vals[0]),
          "depth": int(vals[1]),
          "header_length": int(vals[2]),
          "length": int(vals[3]),
          "tl": int(vals[2]) + int(vals[3])}

def scanFor(arr, name, i):
  while i < len(arr) and arr[i]["name"] != name:
    i += 1
  return i

# get parsed certificate
def callasn1parse(filename):
  # check if file exists
  try:
    open(filename)
  except FileNotFoundError:
    print('File not found:', filename)
    sys.exit(1)
  # build command
  cmd = 'openssl asn1parse -in ' + filename
  # run command
  result = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
  # split on newline
  lines = result.stdout.decode().split('\n')
  # remove empty lines
  lines = list(filter(None, lines))
  # parse output with lambda
  parsed = list(map(lambda x: parseline(x), lines))
  # return parsed
  return parsed

def printLtxLine(tblname, dictname, indent, results, bold = False):
  tmp = ""
  if indent == 1:
    tmp = "\\quad"
  elif indent == 2:
    tmp = "\\qquad"
  elif indent == 3:
    tmp = "\\qquad\\quad"
  elif indent == 4:
    tmp = "\\qquad\\qquad"
  if bold:
    print(tmp, "\\textbf{" + tblname + "} & \\textbf{" + str(results[dictname]) + "} & $\\mathbf{" + '{0:.1f}'.format(100 * results[dictname] / results["CertificateChain"]) + "%}$\\\\")
  else:
    print(tmp, tblname, "&", results[dictname], "&$", '{0:.1f}'.format(100 * results[dictname] / results["CertificateChain"]), "%$\\\\")

# print latex table
def printLatexTable(results):
  printLtxLine("Certificate Chain", "CertificateChain", 0, results)
  printLtxLine("Intermediate Certificate", "IntermediateCert", 1, results)
  printLtxLine("Subscriber Certificate", "SubscriberCert", 1, results)
  printLtxLine("Certificate metadata", "Metadata", 2, results)
  printLtxLine("Subject name", "SubjectName", 2, results)
  printLtxLine("Subject public key", "SubjectKey", 2, results)
  printLtxLine("Extensions", "Extensions", 2, results)
  printLtxLine("OCSP", "AuthorityInfoAccess", 3, results)
  printLtxLine("SCT", "SCTs", 3, results)
  printLtxLine("Other", "Other", 3, results)
  printLtxLine("Signature", "Signature", 2, results)
  print("\\midrule")
  printLtxLine("raw \\sys proof", "NOPERAW", 0, results, True) # 4
  printLtxLine("encoded \\sys proof", "NOPESAN", 0, results, True) # 4
  print("\\midrule")
  results["DNSSEC"] += results["SubjectKey"]
  print("DNSSEC-chain &", results["DNSSEC"], "&$", '{0:.1f}'.format(100 * results["DNSSEC"] / results["CertificateChain"]), "%$\\\\")

# get the number of bytes in a folder
def get_folder_size(folder):
    total = 0
    for root, dirs, files in os.walk(folder):
        for file in files:
            total += os.path.getsize(os.path.join(root, file))
    return total

if __name__ == '__main__':
  # check args
  if len(sys.argv) < 4:
    print('Usage: python cert.py <nope.pem> <dv.pem> <intermediate.pem> [dnssec chain data folder path (optional)]')
    sys.exit(1)
  # list of results for benchmark
  results = {}
  # if dnssec chain data folder path is provided, get size
  if len(sys.argv) == 5:
    results["DNSSEC"] = get_folder_size(sys.argv[4])
  else:
    # else call dns-fetch.sh to get DNSSEC-chain size
    cmd = 'bash dns-fetch.sh'
    res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE).stdout.decode()
    results["DNSSEC"] = int(re.findall(r"\d+", res)[0]) # extract number
  # get parsed certificates
  wproof = callasn1parse(sys.argv[1])
  client = callasn1parse(sys.argv[2])
  intermediate = callasn1parse(sys.argv[3])
  # results from certificates
  results["CertificateChain"] = client[0]["tl"] + intermediate[0]["tl"]
  results["IntermediateCert"] = intermediate[0]["tl"]
  results["SubscriberCert"] = client[0]["tl"]
  # scan for...
  i = scanFor(client, "commonName", 0)
  results["SubjectName"] = client[i - 2]["tl"]
  i = scanFor(client, "rsaEncryption", i)
  results["SubjectKey"] = client[i - 2]["tl"]
  i = scanFor(client, "cont [ 3 ]", i)
  results["Extensions"] = client[i]["tl"]
  i = scanFor(client, "Authority Information Access", i)
  results["AuthorityInfoAccess"] = client[i - 1]["tl"]
  i = scanFor(client, "X509v3 Subject Alternative Name", i)
  results["SubjectAltName"] = client[i - 1]["tl"]
  ti = scanFor(client, "X509v3 Subject Alternative Name", 0)
  results["NOPESAN"] = wproof[ti + 1]["tl"]
  results["NOPERAW"] = 128
  i = scanFor(client, "CT Precertificate SCTs", i)
  results["SCTs"] = client[i - 1]["tl"]
  i = scanFor(client, "sha256WithRSAEncryption", i)
  results["Signature"] = client[i - 2]["tl"]
  # get other fields
  results["Other"] = results["Extensions"] - results["AuthorityInfoAccess"] - results["SCTs"]
  results["Metadata"] = results["SubscriberCert"] - results["SubjectName"] - results["SubjectKey"] - results["Extensions"] - results["Signature"]
  # print results (absolute size and size relative to NOPESAN as latex table)
  printLatexTable(results)

