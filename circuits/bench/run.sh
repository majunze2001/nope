#!/bin/bash

# create bin and tmp directories if they don't exist
mkdir -p bin
mkdir -p tmp

# compile app/ecdsa-ecdsa.circom to circuit
echo "Compliling app/ecdsa-ecdsa.circom for benchmarking..."
circom stubs/app/ecdsa-ecdsa.circom --r1cs --c --wasm -o bin/app
# make -C bin/app/ecdsa-ecdsa\_cpp

# creating proving key
echo "Generating proving key for ecdsa-ecdsa"
zkutil setup -c bin/app/ecdsa-ecdsa.r1cs -p tmp/ecdsa-ecdsa.params

# input generation
echo "Generating input for app/ecdsa-ecdsa from test vectors..."
node process_input.js > tmp/input.json
node bin/app/ecdsa-ecdsa\_js/generate_witness.js bin/app/ecdsa-ecdsa\_js/ecdsa-ecdsa.wasm tmp/input.json tmp/wit.wtns

# proof generation (timed)
echo "Proof generation for app/ecdsa-ecdsa"
taskset -c 1 /usr/bin/time -l zkutil prove -c bin/app/ecdsa-ecdsa.r1cs -p tmp/ecdsa-ecdsa.params -r tmp/zk.proof -o tmp/public.json -w tmp/wit.wtns

# remove the tmp directory
rm -rf tmp

