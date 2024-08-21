#!/bin/bash

# create bin directory if it doesn't exist
mkdir -p bin

# prepare files for benchmarking
# if args then use args as list of targets, otherwise get all from stubs
if [ $# -eq 0 ]; then
  # get all benchmarks
  files=$(ls stubs)
else
  files=$@
fi

# for all benchmarks, compile to circuit if they haven't been compiled
# if they have then just print the number of constraints
for file in $files; do
  # if directory, call self with contents of directory (prepended by name of directory)
  # ex. if stubs/foo contains bar.circom, call self with foo/bar
  if [ -d "stubs/$file" ]; then
    # if bin/foo doesn't exist, create it
    mkdir -p bin/$file
    ./count.sh $(ls stubs/$file | sed "s/^/$file\//")
    continue
  fi
  # strip file extension
  name=$(echo "${file%.*}")
  # get path to file (just directories), to mirror in bin
  path=$(dirname $file)
  # compile circuit
  echo "Compliling $name.circom to circuit..."
  circom stubs/$name.circom --r1cs -o bin/$path
done
