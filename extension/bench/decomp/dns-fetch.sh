#!/bin/sh
# fetch chain
echo "" > tmp.dat
dig nope-tools.org TXT +dnssec +short +tcp >> tmp.dat
dig nope-tools.org DNSKEY +dnssec +short +tcp >> tmp.dat
dig nope-tools.org DS +dnssec +short +tcp >> tmp.dat
dig org DNSKEY +dnssec +short +tcp >> tmp.dat
dig org DS +dnssec +short +tcp >> tmp.dat
dig . DNSKEY +dnssec +short +tcp >> tmp.dat
# get size of file
wc -c tmp.dat
# remove file
rm tmp.dat