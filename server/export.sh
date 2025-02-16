#!/bin/bash

SRC_PATH="../circuits"

# if args then use args as list of targets, otherwise get all from app
if [ $# -eq 0 ]; then
  # get all benchmarks
  files=$(ls $SRC_PATH/src/app)
else
  files=$@
fi

# for all circuts, export keys
for file in $files; do
  # strip file extension
  name=$(echo "${file%.*}")
  echo "Exporting keys for $name..."
  zkutil setup -c bin/$name.r1cs -p bin/$name.params
  zkutil export-keys -c bin/$name.r1cs -p bin/$name.params -r bin/$name-pk.json -v bin/$name-vk.json
done
