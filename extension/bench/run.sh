#!/bin/bash
# call with taskset -c 1 to isolate to one core

# Benchmark DV
cd dv
node client.js ../cert/dv.pem ../cert/r11.pem ../cert/root.pem | tee dv-dv.txt
node client.js ../cert/nope.pem ../cert/r11.pem ../cert/root.pem | tee nope-dv.txt
cd ../

# Benchmark NOPE
cd nope
node client.js ../cert/dv.pem ../cert/r11.pem ../cert/root.pem | tee dv-nope.txt
node client.js ../cert/nope.pem ../cert/r11.pem ../cert/root.pem | tee nope-nope.txt
cd ../

# benchmark DNSSEC-chain
cd dnssec-chain
# data is provided for the sake of benchmarking
# the following commented out code can be used to fetch for the latest data
#python3 fetch_tlsa.py _443._tcp.nope-tools.org
node client.js | tee dnssec.txt
cd ../
