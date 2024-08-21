import sys
import os
import dns.query
import dns.dnssec

# Analyze how much padding we need for a TXT record

def domain_to_wire(domain):
  """Convert a domain name to DNS wire format."""
  # dns.name.Name.to_wire() for RFC compliant 
  # https://dnspython.readthedocs.io/en/latest/_modules/dns/name.html#Name.to_wire

  # if just a dot, return null byte
  if domain == '.':
    return b'\x00'

  # Remove the trailing dot if it's present
  if domain.endswith('.'):
    domain = domain[:-1]
  
  # Split the domain into labels and prepend each label with its length
  labels = domain.split('.')
  wire_format = b''.join(
    bytes([len(label)]) + label.encode('ascii') for label in labels
  )
  
  # Append a null byte to indicate the end of the domain name
  wire_format += b'\x00'
  # print(wire_format) 
  return wire_format

# make a DNS query for a domain and record type
# return the rrset + rrsig
def make_request(domain, record_type):
  # get properly formatted domain name and make DNS query
  name = dns.name.from_text(domain)
  request = dns.message.make_query(name, record_type, want_dnssec=True)
  response = dns.query.udp(request, "8.8.8.8")
  # ensure correct number/format of answers
  if len(response.answer) == 0:
      # no existing txt record
      return None
  if len(response.answer) < 2 or (response.answer[1].rdtype != dns.rdatatype.RRSIG):
    print(domain, "does not have an RRSIG record")
    exit(1)
  elif len(response.answer[1]) > 2:
    print(domain, "has too many RRSIG records")
    exit(1)
  # return the rrset + rrsig
  return {"rrset": response.answer[0], "rrsig": response.answer[1][0]}

def analyze_txt(domain):
  txt = make_request(domain, "TXT")
  if not txt:
      #print('no existing TXT records')
    print('=' * (64 - calc_header(domain) % 64), end='')
    return
  rrset_dat = dns.dnssec._make_rrsig_signature_data(txt["rrset"], txt["rrsig"])
  #print('existing TXT records rrset', len(rrset_dat))
  print('=' * (64 - len(rrset_dat) % 64), end='')

# hard coded, see fetch.py
def calc_header(name):
  return 29 + 2 * len(domain_to_wire(name))

# we get the byte length of current txt rrset len
if __name__ == '__main__':
  # if no arg provided print usage
  if len(sys.argv) == 1 or len(sys.argv) > 3:
    print("Usage:", sys.argv[0] ,"<domain>")
    print("Ex:", sys.argv[0] ,"proton.me")
    sys.exit(1)
  # otherwise get domain and record type from args
  domain = sys.argv[1]
  # if domain doesn't end in a period, add it
  if domain[-1] != ".":
    domain += "."
  analyze_txt(domain)

# dove=[43 char]
# 48
