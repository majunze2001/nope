import sys
import os
import dns.query
import dns.dnssec
import json

# format a domain name from a string to a wire format
def wire_fmt(domain):
  if domain.endswith('.'):
    domain = domain[:-1]
  labels = domain.split('.')
  return b''.join(bytes([len(label)]) + label.encode('ascii') for label in labels) + b'\x00'

# get the key with the given tag from the rrset
def get_keyrr(rrset, tag):
  # find key with tag and print
  for rr in rrset:
    if tag == dns.dnssec.key_id(rr):
      return rr
  # otherwise error out
  print("Could not find key with tag", tag)
  exit(1)

dnssec_algs = {}
# get the key signing key and format it for verification
def get_ksk_and_fmt(rrset, tag, domain, is_sld=False):
  rr = get_keyrr(rrset, tag)
  if is_sld:
      dnssec_algs['sld'] = int(rr.algorithm)
  else:
      dnssec_algs['tld'] = int(rr.algorithm)
  return wire_fmt(domain) + \
         rr.flags.to_bytes(2, byteorder="big") + \
         rr.protocol.to_bytes(1, byteorder="big") + \
         rr.algorithm.to_bytes(1, byteorder="big") + \
         rr.key

# make a DNS query for a domain and record type
# return the rrset + rrsig
def make_request(domain, record_type):
  # get properly formatted domain name and make DNS query
  name = dns.name.from_text(domain)
  request = dns.message.make_query(name, record_type, want_dnssec=True)
  response = dns.query.udp(request, "8.8.8.8")
  # ensure correct number/format of answers
  if len(response.answer) < 2 or (response.answer[1].rdtype != dns.rdatatype.RRSIG):
    print(domain, record_type, "does not have an RRSIG record")
    exit(1)
  elif len(response.answer[1]) > 2:
    print(domain, record_type, "has too many RRSIG records")
    exit(1)
  # return the rrset + rrsig
  return {"rrset": response.answer[0], "rrsig": response.answer[1][0]}

# bit of a hack, works for us with a linear domain sig structure
def get_par_domain(domain):
  count = domain.count(".");
  if count == 1:
    return "."
  elif count > 1:
    return domain[domain.find(".") + 1:]
  else:
    print("Invalid domain name", domain)
    exit(1)

# write binary data to file in data/
# based on domain, rrtype, and modifier
def to_file(domain, rrtype, modifier, data):
  filename = "data/" + domain + "-" + rrtype + "-" + modifier + ".dat"
  print("Writing", filename)
  with open(filename, "wb") as f:
    f.write(data)

def gather_info(domain, is_leaf = False):
  print("Gathering info for", domain)
  # always request DNSKEY rrset and rrsig
  dnskey = make_request(domain, "DNSKEY")
  if domain == ".":
    to_file(domain, "DNSKEY", "KEY", get_keyrr(dnskey["rrset"], dnskey["rrsig"].key_tag).key)
  else:
    to_file(domain, "DNSKEY", "KSK", get_ksk_and_fmt(dnskey["rrset"], dnskey["rrsig"].key_tag, domain, is_leaf))
    to_file(domain, "DNSKEY", "SIG", dnskey["rrsig"].signature)
    to_file(domain, "DNSKEY", "REC", dns.dnssec._make_rrsig_signature_data(dnskey["rrset"], dnskey["rrsig"]))
  # if leaf, request TXT rrset and rrsig
  if is_leaf:
    txt = make_request(domain, "TXT")
    to_file(domain, "TXT", "KEY", get_keyrr(dnskey["rrset"], txt["rrsig"].key_tag).key)
    to_file(domain, "TXT", "SIG", txt["rrsig"].signature)
    to_file(domain, "TXT", "REC", dns.dnssec._make_rrsig_signature_data(txt["rrset"], txt["rrsig"]))
  # if not root, request DS rrset and rrsig and recurse
  if domain != ".":
    ds = make_request(domain, "DS")
    par_domain = get_par_domain(domain)
    par_dnskey = gather_info(par_domain)
    to_file(domain, "DS", "KEY", get_keyrr(par_dnskey["rrset"], ds["rrsig"].key_tag).key)
    to_file(domain, "DS", "SIG", ds["rrsig"].signature)
    to_file(domain, "DS", "REC", dns.dnssec._make_rrsig_signature_data(ds["rrset"], ds["rrsig"]))
  # return the DNSKEY rrset for DS verification one level down
  return dnskey

if __name__ == '__main__':
  # if no arg provided print usage
  if len(sys.argv) != 2:
    print("Usage:", sys.argv[0] ,"<domain>")
    print("Ex:", sys.argv[0] ,"proton.me")
    sys.exit(1)
  # otherwise get domain and record type from args
  domain = sys.argv[1]
  # if domain doesn't end in a period, add it
  if domain[-1] != ".":
    domain += "."
  # if data folder doesn't exist, create it
  if not os.path.exists("data"):
    os.makedirs("data")
  # and iteratively fetch DNS info for proving domain ownership
  gather_info(domain, True)
  with open(f'data/{domain}-algs.json', "w") as f:
      json.dump(dnssec_algs, f)

