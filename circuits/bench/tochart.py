
# ./count.sh | tee tmp.log

import re
import json
import math

# benchmark naming convention is:
# category/bench-(sld/tld)-(domain algo)-(parent algo).circom

# ex. log
# Compliling zsk/rsa-from-rsa-high.circom to circuit...
# template instances: 117
# non-linear constraints: 676240
# linear constraints: 0
# public inputs: 0
# public outputs: 0
# private inputs: 2384
# private outputs: 0
# wires: 673020
# labels: 4262051
# Written successfully: bin/zsk/rsa-from-rsa-high.r1cs
# Everything went okay, circom safe

def extract_info(log):
  circuits = re.split(r'Compliling\s', log)[1:]
  result = {}
  for cir in circuits:
    name = cir.split('.circom to circuit...')[0]
    tmp = re.findall(r'non-linear constraints: (\d+)', cir)
    num_constraints = int(tmp[0])
    result[name] = num_constraints
  return result

# cost estimation
# extracting a buffer of length m from a string of length n
# and masking and checking equality
def parse(m, n):
  return 10 * m * n

# cost estimation
# performing an 2048 bit modexp
# from xJsnark
def modexp():
  return 89000

# estimated from circom-ecdsa
def kopk_ecdsa():
  return 95000

def hash(n):
  # if n mod 64 > 55, then we need to add a padding chunk
  tmp = math.ceil((n + 1) / 64)
  if n % 64 > 55:
    tmp += 1
  return 28000 * tmp

def rsasig(n):
  return hash(n) + modexp()

def rsa_suffix_sig(n):
  return hash(64 * (n - 1) + 1) + modexp()

# return the cost of verifying an ECDSA signature
# from circom-ecdsa
def ecdsaverif():
  # old point add is 2515 constraints!
  # ours is 1054 constraints
  return 1509000

def ecdsafasterverif():
  return kopk_ecdsa() + ((1509000 - kopk_ecdsa()) / (2515 / 1054))

def ecdsasig(n):
  return hash(n) + ecdsaverif()

def ecdsasig_faster(n):
  return hash(n) + ecdsafasterverif()

def ecdsa_suffix_sig(n):
  return hash(64 * (n - 1) + 1) + ecdsaverif()

def ecdsa_suffix_sig_faster(n):
  return hash(64 * (n - 1) + 1) + ecdsafasterverif()

# name constants
sld_name_len = 63 + 24 + 3
tld_name_len = 24 + 2
root_name_len = 1
# record constants
sld_ds_rec_len = 2 * (69 + 2 * sld_name_len + tld_name_len)
tld_ds_rec_len = 2 * (69 + 2 * tld_name_len + root_name_len)
sld_dnskey_rsa_rec_len = 836
sld_dnskey_ecdsa_rec_len = 444
tld_dnskey_rsa_rec_len = 644
tld_dnskey_ecdsa_rec_len = 252
# not TXT, swapped to DNSSEC-chain-extension, now TLSA
txt_rec_len = 2 * (69 + 2 * sld_name_len + tld_name_len) # https://labs.ripe.net/author/pgl/the-joy-of-txt/

def estimate_unoptimized():
  # accumulate results
  bas = {}
  # KSK stuff
  bas["ksk/kopk-rsa"] = 5 * 2048 # TO DO, check this
  bas["ksk/kopk-ecdsa"] = kopk_ecdsa()
  bas["ksk/hash-tld-rsa"] = hash(tld_name_len + 4 + 256)
  bas["ksk/hash-tld-ecdsa"] = hash(tld_name_len + 4 + 64)
  bas["ksk/hash-sld-rsa"] = hash(sld_name_len + 4 + 256)
  bas["ksk/hash-sld-ecdsa"] = hash(sld_name_len + 4 + 64)
  # DS Stuff
  bas["ds/parse-tld"] = parse(root_name_len, tld_ds_rec_len) + parse(root_name_len, tld_ds_rec_len) + parse(34, tld_ds_rec_len) + 100 * tld_ds_rec_len
  bas["ds/parse-sld"] = parse(sld_name_len, sld_ds_rec_len) + parse(tld_name_len, sld_ds_rec_len) + parse(34, sld_ds_rec_len) + 100 * sld_ds_rec_len
  bas["ds/sig-tld-rsa"] = rsasig(tld_ds_rec_len)
  bas["ds/sig-tld-ecdsa"] = ecdsasig(tld_ds_rec_len)
  bas["ds/sig-sld-rsa"] = rsasig(sld_ds_rec_len)
  bas["ds/sig-sld-ecdsa"] = ecdsasig(sld_ds_rec_len)
  bas["ds/kos-rsa-rsa"] = bas["ds/parse-sld"] + bas["ds/sig-sld-rsa"] + bas["ksk/hash-sld-rsa"] + bas["ksk/kopk-rsa"]
  bas["ds/kos-rsa-ecdsa"] = bas["ds/parse-sld"] + bas["ds/sig-sld-ecdsa"] + bas["ksk/hash-sld-rsa"] + bas["ksk/kopk-rsa"]
  bas["ds/kos-ecdsa-rsa"] = bas["ds/parse-sld"] + bas["ds/sig-sld-rsa"] + bas["ksk/hash-sld-ecdsa"] + bas["ksk/kopk-ecdsa"]
  bas["ds/kos-ecdsa-ecdsa"] = bas["ds/parse-sld"] + bas["ds/sig-sld-ecdsa"] + bas["ksk/hash-sld-ecdsa"] + bas["ksk/kopk-ecdsa"]
  # DNSKEY Stuff
  bas["dnskey/parse-tld-rsa"] = parse(tld_name_len + 4 + 256, tld_dnskey_rsa_rec_len) + 1000 * tld_dnskey_rsa_rec_len
  bas["dnskey/parse-tld-ecdsa"] = parse(tld_name_len + 4 + 64, tld_dnskey_ecdsa_rec_len) + 1000 * tld_dnskey_ecdsa_rec_len
  bas["dnskey/parse-sld-rsa"] = parse(sld_name_len + 4 + 256, sld_dnskey_rsa_rec_len) + 1000 * sld_dnskey_rsa_rec_len
  bas["dnskey/parse-sld-ecdsa"] = parse(sld_name_len + 4 + 64, sld_dnskey_ecdsa_rec_len) + 1000 * sld_dnskey_ecdsa_rec_len
  bas["dnskey/sig-tld-rsa"] = rsasig(tld_dnskey_rsa_rec_len)
  bas["dnskey/sig-tld-ecdsa"] = ecdsasig(tld_dnskey_ecdsa_rec_len)
  bas["dnskey/sig-sld-rsa"] = rsasig(sld_dnskey_rsa_rec_len)
  bas["dnskey/sig-sld-ecdsa"] = ecdsasig(sld_dnskey_ecdsa_rec_len)
  # ZSK to ZSK, fix this
  bas["zsk/to-tld-rsa-rsa"] = bas["dnskey/parse-tld-rsa"] + bas["dnskey/sig-tld-rsa"] + bas["ksk/hash-tld-rsa"] + bas["ds/parse-tld"] + bas["ds/sig-tld-rsa"]
  bas["zsk/to-tld-rsa-ecdsa"] = bas["dnskey/parse-tld-rsa"] + bas["dnskey/sig-tld-rsa"] + bas["ksk/hash-tld-rsa"] + bas["ds/parse-tld"] + bas["ds/sig-tld-ecdsa"]
  bas["zsk/to-tld-ecdsa-rsa"] = bas["dnskey/parse-tld-ecdsa"] + bas["dnskey/sig-tld-ecdsa"] + bas["ksk/hash-tld-ecdsa"] + bas["ds/parse-tld"] + bas["ds/sig-tld-rsa"]
  bas["zsk/to-tld-ecdsa-ecdsa"] = bas["dnskey/parse-tld-ecdsa"] + bas["dnskey/sig-tld-ecdsa"] + bas["ksk/hash-tld-ecdsa"] + bas["ds/parse-tld"] + bas["ds/sig-tld-ecdsa"]
  bas["zsk/to-sld-rsa-rsa"] = bas["dnskey/parse-sld-rsa"] + bas["dnskey/sig-sld-rsa"] + bas["ksk/hash-sld-rsa"] + bas["ds/parse-sld"] + bas["ds/sig-sld-rsa"]
  bas["zsk/to-sld-rsa-ecdsa"] = bas["dnskey/parse-sld-rsa"] + bas["dnskey/sig-sld-rsa"] + bas["ksk/hash-sld-rsa"] + bas["ds/parse-sld"] + bas["ds/sig-sld-ecdsa"]
  bas["zsk/to-sld-ecdsa-rsa"] = bas["dnskey/parse-sld-ecdsa"] + bas["dnskey/sig-sld-ecdsa"] + bas["ksk/hash-sld-ecdsa"] + bas["ds/parse-sld"] + bas["ds/sig-sld-rsa"]
  bas["zsk/to-sld-ecdsa-ecdsa"] = bas["dnskey/parse-sld-ecdsa"] + bas["dnskey/sig-sld-ecdsa"] + bas["ksk/hash-sld-ecdsa"] + bas["ds/parse-sld"] + bas["ds/sig-sld-ecdsa"]  
  # TXT Stuff
  bas["txt/parse"] = parse(50, txt_rec_len)
  bas["txt/sig-rsa"] = rsasig(txt_rec_len)
  bas["txt/sig-ecdsa"] = ecdsasig(txt_rec_len)
  # full circuit stuff
  bas["app/rsa-rsa"] = bas["ds/kos-rsa-rsa"] + bas["zsk/to-tld-rsa-rsa"]
  bas["app/rsa-ecdsa"] = bas["ds/kos-rsa-ecdsa"] + bas["zsk/to-tld-ecdsa-rsa"]
  bas["app/ecdsa-rsa"] = bas["ds/kos-ecdsa-rsa"] + bas["zsk/to-tld-rsa-rsa"]
  bas["app/ecdsa-ecdsa"] = bas["ds/kos-ecdsa-ecdsa"] + bas["zsk/to-tld-ecdsa-rsa"]
  bas["app/man-rsa-rsa"] = bas["txt/parse"] + bas["txt/sig-rsa"] + bas["zsk/to-sld-rsa-rsa"] + bas["zsk/to-tld-rsa-rsa"]
  bas["app/man-rsa-ecdsa"] = bas["txt/parse"] + bas["txt/sig-rsa"] + bas["zsk/to-sld-rsa-ecdsa"] + bas["zsk/to-tld-ecdsa-rsa"]
  bas["app/man-ecdsa-rsa"] = bas["txt/parse"] + bas["txt/sig-ecdsa"] + bas["zsk/to-sld-ecdsa-rsa"] + bas["zsk/to-tld-rsa-rsa"]
  bas["app/man-ecdsa-ecdsa"] = bas["txt/parse"] + bas["txt/sig-ecdsa"] + bas["zsk/to-sld-ecdsa-ecdsa"] + bas["zsk/to-tld-ecdsa-rsa"]
  # return
  return bas

def print_row(statement, lvl, dalgo, palgo, key, res, bas):
  bcons = bas[key]
  ocons = res[key]
  tmp = statement + " & " + lvl + " & " + dalgo + " & " + palgo + " & "
  if bcons == -1:
    tmp += "- & "
  else:
    tmp += str(bcons) + " & "
  tmp += str(ocons) + " & "
  if ocons == 0:
    tmp += "$\\infty$\\\\"
  else:
    tmp += '{0:.2f}'.format(bcons / ocons) + "$\\times$\\\\"

# given a common name
# key name
# list of lvls (tld/sld)
# list of domain algorithms (rsa/ecdsa)
# list of parent algorithms (rsa/ecdsa)
# result dict
# baseline dict
# print a set of ltx formatted rows showing off the optimizations
def print_row_set(cname, key, lvls, das, pas, res, bas, override = -1):
  # get total number of rows in set
  # set to 1 after printed
  top = len(lvls) * len(das) * len(pas)
  if override != -1:
    top = override
  for lvl in lvls:
    # get total number of rows in subset
    # set to 1 after printed
    flvl = len(das) * len(pas)
    for da in das:
      # get total number of rows in subsubset
      # set to 1 after printed
      fda = len(pas)
      for pa in pas:
        # build key
        rkey = key
        if len(lvl) != 0:
          rkey += "-" + lvl
        if len(da) != 0:
          rkey += "-" + da
        if len(pa) != 0:
          rkey += "-" + pa
        # build line w/
        # name
        line = ""
        if top > 1:
          line += "\\multirow{" + str(top) + "}{*}{" + cname + "}"
          top = 0
        elif top == 1:
          line += cname
        line += " & "
        # level
        if flvl > 1:
          line += "\\multirow{" + str(flvl) + "}{*}{" + lvl.upper() + "}"
          flvl = 0
        elif flvl == 1:
          line += lvl.upper()
        line += " & "
        # domain algo
        if fda > 1:
          line += "\\multirow{" + str(fda) + "}{*}{" + da.upper() + "}"
          fda = 0
        elif fda == 1:
          line += da.upper()
        line += " & "
        # parent algo
        line += pa.upper() + " & "
        # constraints
        line += "\\textit{" + str(bas[rkey]) + "} & " + str(res[rkey]) + " & "
        # relative factor
        if res[rkey] == 0:
          line += "$\\infty$\\\\"
        else:
          line += '{0:.2f}'.format(bas[rkey] / res[rkey]) + "$\\times$\\\\"
        # output
        print(line)

def write_tbl(res, bas):
  # KSK stuff
  print_row_set("\\kskknowprivlong", "ksk/kopk", [""], ["rsa", "ecdsa"], [""], res, bas)
  print_row_set("\\kskhashlong", "ksk/hash", ["sld", "tld"], ["rsa", "ecdsa"], [""], res, bas)
  print("\\midrule")
  # DS stuff
  print_row_set("\\dsparselong", "ds/parse", ["sld", "tld"], [""], [""], res, bas)
  print_row_set("\\dssiglong", "ds/sig", ["sld", "tld"], [""], ["rsa", "ecdsa"], res, bas)
  print_row_set("\\dsknowprivlong", "ds/kos", [""], ["rsa", "ecdsa"], ["rsa", "ecdsa"], res, bas)
  print("\\midrule")
  # DNSKEY stuff
  print_row_set("\\dnskeyparselong", "dnskey/parse", ["sld", "tld"], ["rsa", "ecdsa"], [""], res, bas)
  print_row_set("\\dnskeysiglong", "dnskey/sig", ["sld", "tld"], ["rsa", "ecdsa"], [""], res, bas)
  print("\\midrule")
  # ZSK to ZSK
  print_row_set("\\zskverifylong", "zsk/to", ["sld"], ["rsa", "ecdsa"], ["rsa", "ecdsa"], res, bas, 6)
  print_row_set("\\zskverifylong", "zsk/to", ["tld"], ["rsa", "ecdsa"], ["rsa"], res, bas, 0)
  print("\\midrule")
  # TXT 
  res["txt/parse"] = 0 # :)
  print_row_set("\\txtparselong", "txt/parse", [""], [""], [""], res, bas)
  print_row_set("\\txtsiglong", "txt/sig", [""], ["rsa", "ecdsa"], [""], res, bas)
  print("\\midrule")
  # APP
  print_row_set("\\sys", "app/nope", [""], ["rsa", "ecdsa"], ["rsa", "ecdsa"], res, bas)
  print_row_set("\\sysman", "app/nope-man", [""], ["rsa", "ecdsa"], ["rsa", "ecdsa"], res, bas)

def estimate_ram(ccount):
  # estimated RAM usage
  # from the number of constraints
  # via linear regression
  return (2 / 1.72) * (1.50813459476 * ccount + 4637.34371901) / 1000000

def estimate_cpu(ccount):
  # estimated CPU usage
  # from the number of constraints
  # via linear regression
  return 60 * (0.000100592552928 * ccount + 0.422283831001) / 126

def cond_it(s, italics):
  if italics:
    return "\\textit{" + s + "}"
  else:
    return s

def to_mil(x):
  return x / 1000000

def print_tiny_row(opt, ccount, is_estimate=True):
  # if an estimate then round
  line = opt + " & " + cond_it(f'{to_mil(ccount):.2f}', is_estimate) + " & "
  line += cond_it(f'{estimate_cpu(ccount):.0f}', is_estimate) + " s & "
  line += cond_it(f'{estimate_ram(ccount):.2f}', is_estimate) + " GB\\\\"
  print(line)

# table with estimates for optimizations
def write_tiny(res, bas):
  print_tiny_row("Baseline",
    bas["app/man-ecdsa-ecdsa"])
  print_tiny_row("+ design (\\S\\ref{s:design})",
    bas["app/ecdsa-ecdsa"])
  if False:
    print_tiny_row("+ (\\S\\rrr{4.?})~avoiding parsing",
    parse(34, sld_ds_rec_len) +  # parse sld
    ecdsa_suffix_sig(2) + # sig sld
    bas["ksk/hash-sld-ecdsa"] +
    bas["ksk/kopk-ecdsa"] +
    bas["dnskey/parse-tld-ecdsa"] +
    bas["dnskey/sig-tld-ecdsa"] +
    parse(34, tld_ds_rec_len) +  # parse tld
    bas["ksk/hash-tld-ecdsa"] +
    rsa_suffix_sig(2))
  print_tiny_row("+ parsing (\\S\\ref{s:parsingdns})",
    res["ds/parse-sld"] + 
    ecdsa_suffix_sig(2) + 
    bas["ksk/hash-sld-ecdsa"] +
    bas["ksk/kopk-ecdsa"] +
    res["dnskey/parse-tld-ecdsa"] +
    bas["dnskey/sig-tld-ecdsa"] +
    res["ds/parse-tld"] + 
    bas["ksk/hash-tld-ecdsa"] +
    rsa_suffix_sig(2))
  if False:
    print_tiny_row("+ (\\S\\rrr{5.?})~faster point operations",
    res["ds/parse-sld"] + 
    ecdsa_suffix_sig_faster(2) +
    bas["ksk/hash-sld-ecdsa"] +
    bas["ksk/kopk-ecdsa"] +
    res["dnskey/parse-tld-ecdsa"] +
    ecdsasig_faster(tld_dnskey_ecdsa_rec_len) +
    res["ds/parse-tld"] + 
    bas["ksk/hash-tld-ecdsa"] +
    rsa_suffix_sig(2))
  print_tiny_row("+ crypto (\\S\\ref{s:crypto})",
    res["ds/sig-sld-ecdsa"] +
    res["ksk/hash-sld-ecdsa"] +
    bas["ksk/kopk-ecdsa"] +
    res["dnskey/parse-tld-ecdsa"] +
    res["dnskey/sig-tld-ecdsa"] +
    res["ksk/hash-tld-ecdsa"] +
    res["ds/sig-tld-rsa"])
  print_tiny_row("+ misc.", res["app/ecdsa-ecdsa"], False)

# main function, takes the log file as input
if __name__ == '__main__':
  with open('tmp.log', 'r') as log_file:
    log_data = log_file.read()
  # Extract information
  res = extract_info(log_data)
  bas = estimate_unoptimized()
  # write tiny table
  write_tiny(res, bas)
