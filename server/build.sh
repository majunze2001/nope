#!/bin/bash

SRC_PATH="../circuits"

# create bin directory if it doesn't exist
mkdir -p bin

# if args then use args as list of targets, otherwise get all from app
if [ $# -eq 0 ]; then
  # get all benchmarks
  files=$(ls $SRC_PATH/src/app)
else
  files=$@
fi

# for all circuits, compile
for file in $files; do
  # strip file extension
  name=$(echo "${file%.*}")
  # compile circuit
  echo "Compliling $name.circom to circuit..."
  circom $SRC_PATH/src/app/$name.circom --r1cs --O2 --c -o bin/
  make -j$(nproc) -C bin/$name\_cpp
done
