#!/bin/bash

# create bin directory if it doesn't exist
mkdir -p bin

# prepare files for benchmarking
# if args then use args as list of targets, otherwise get all from app
if [ $# -eq 0 ]; then
  # get all benchmarks
  files=$(ls src/app)
else
  files=$@
fi

# for all benchmarks, compile to circuit
for file in $files; do
  # strip file extension
  name=$(echo "${file%.*}")
  # compile circuit
  echo "Compliling $name.circom to circuit..."
  circom src/app/$name.circom --r1cs --wasm --c -o bin/
  make -C bin/$name\_cpp
done
