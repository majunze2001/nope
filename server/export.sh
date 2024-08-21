#!/bin/bash

# export vk&pk keys
# iterate through all subfolders to build witness calculator
NAMES=("rsa-rsa" "rsa-ecdsa" "ecdsa-ecdsa" "ecdsa-rsa")

# set the path to this directory
DIR="$( cd "$( dirname "${bash_source[0]}" )" && pwd )"
BIN_DIR="$DIR/bin"

# this produces a proof using zkutil and verifies it using snarkjs
test_proof () {
  MODE=$1
  echo "Test Proving $MODE"
  TLDALG=8
  SLDALG=8
  if [[ $MODE == *-man ]]; then
    MAN=1
  else 
    MAN=0
  fi

  if [[ $MODE == rsa-rsa* ]]; then
    TLDALG=8
    SLDALG=8
  elif [[ $MODE == rsa-ecdsa* ]]; then
    TLDALG=8
    SLDALG=13
  elif [[ $MODE == ecdsa-ecdsa* ]]; then
    TLDALG=13
    SLDALG=13
  elif [[ $MODE == ecdsa-rsa* ]]; then
    TLDALG=13
    SLDALG=8
  fi

  if [ $TLDALG = 8 ]; then
    DOMAIN="dove-tools.me"
  else 
    DOMAIN="dove-tools.com"
  fi

  # test proof, using dummy values
  PUB_DIGEST="0000000000000000000000000000000000000000000"
  # input
  node "$DIR/js/make_input.js" -d $DOMAIN -t $TLDALG -s $SLDALG -m $MAN -g $PUB_DIGEST
  # witness
  "$BIN_DIR/${MODE}_cpp/$MODE" "$BIN_DIR/${MODE}_input.json" "$BIN_DIR/${MODE}.wtns" 
  # prove
  zkutil prove -c "$BIN_DIR/${MODE}.r1cs" -p "$BIN_DIR/$MODE.params" -r "$BIN_DIR/${MODE}_proof.json" -o "$BIN_DIR/${MODE}_public.json" -w "$BIN_DIR/${MODE}.wtns" # verify
  snarkjs g16v "$BIN_DIR/${MODE}-vk.json" "$BIN_DIR/${MODE}_public.json" "$BIN_DIR/${MODE}_proof.json"
}

setup_and_export () {
  MODE=$1
  echo $MODE
  cd "$BIN_DIR/${MODE}_cpp"
  # build witness geneartor
  make

  # params and export keys
  cd "$BIN_DIR"
  zkutil setup -c $MODE.r1cs -p $MODE.params
  # note: $MODE-pk.json is not used and cannot be converted to pk.bin for snarkjs direct use due to node string length limit
  zkutil export-keys -c $MODE.r1cs -p $MODE.params -r $MODE-pk.json -v $MODE-vk.json
}

TEST_ONLY=0
if [ "$TEST_ONLY" -eq "1" ];then
  for NAME in ${NAMES[@]}; do
    test_proof $NAME
    NAME+="-man"
    test_proof $NAME
    exit 0
  done
  exit 0
fi

for NAME in ${NAMES[@]}; do
  setup_and_export $NAME
  NAME+="-man"
  setup_and_export $NAME
done

# if push.sh exists, we push the key files to cloud
if [ ! -f "push.sh" ]; then
  ./push.sh
fi

