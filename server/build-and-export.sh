#!/usr/bin/env bash

SRC_PATH="../circuits"
BIN_DIR="bin"

# create bin directory if it doesn't exist
mkdir -p bin

# if args then use args as list of targets, otherwise get all from app
if [ $# -eq 0 ]; then
  files=$(ls $SRC_PATH/src/app)
else
  files=$@
fi

for file in $files; do
  # strip file extension
  name=$(echo "${file%.*}")
  # compile circuit
  echo "Compliling $name.circom to circuit..."
  circom $SRC_PATH/src/app/$name.circom --r1cs --O2 --c -o bin/
  make -j4 -C bin/$name\_cpp
  zkutil setup -c bin/$name.r1cs -p bin/$name.params
  zkutil export-keys -c bin/$name.r1cs -p bin/$name.params -r bin/$name-pk.json -v bin/$name-vk.json
done
