#!/bin/bash
# Should be run with `taskset` 

# Bench iterations
ITER=100

# files to be checked
NAMES=("rsa-rsa" "rsa-ecdsa" "ecdsa-ecdsa" "ecdsa-rsa")
FILEEXTS=(".r1cs" ".params" "-vk.json")

SRC_PATH="../bin"
SCRIPT_PATH="../scripts"

# create dat directory if it doesn't exist
mkdir -p dat

check_files () {
  for NAME in ${NAMES[@]}; do
    echo "Checking $NAME files ..."
    for EXT in ${FILEEXTS[@]}; do
      if [ ! -f "$SRC_PATH/${NAME}${EXT}" ] || [ ! -f "$SRC_PATH/${NAME}_cpp/${NAME}.o" ]; then
        echo "Please make sure to build and export"
        exit 1
      fi
    done
    NAME+="-man"
    for EXT in ${FILEEXTS[@]}; do
      if [ ! -f "$SRC_PATH/${NAME}${EXT}" ] || [ ! -f "$SRC_PATH/${NAME}_cpp/${NAME}.o" ]; then
        echo "Please make sure to build and export"
        exit 1
      fi
    done
  done
}

# One iteration
# with test data
prove () {
    MODE=$1
    DOMAIN=$2
    TLDALG=$3
    SLDALG=$4
    MAN=$5

    if [ "$TLDALG" -eq 8 ]; then
      FIRST_PART="rsa"
    else
      FIRST_PART="ecdsa"
    fi

    if [ "$SLDALG" -eq 8 ]; then
      SECOND_PART="rsa"
    else
      SECOND_PART="ecdsa"
    fi

    SUBFOLDER="${FIRST_PART}-${SECOND_PART}"
    
    # {time ls;} > >(tee -a tlog) 2> >(tee -a tlog)
    openssl rsa -in $SRC_PATH/domain.key -pubout -out $SRC_PATH/${DOMAIN}.pub 2>/dev/null
    # TODO: update hash
    PUB_DIGEST=$(python3 $SCRIPT_PATH/hash_pub.py $SRC_PATH/${DOMAIN}.pub)
    node $SCRIPT_PATH/make_input.js -d $DOMAIN -t $TLDALG -s $SLDALG -m $MAN -g $PUB_DIGEST -p sdata/$SUBFOLDER
    $SRC_PATH/${MODE}_cpp/$MODE $SRC_PATH/${MODE}_input.json $SRC_PATH/$MODE.wtns
    zkutil prove -c $SRC_PATH/$MODE.r1cs -p $SRC_PATH/$MODE.params -r $SRC_PATH/${MODE}_proof.json -o $SRC_PATH/${MODE}_public.json -w $SRC_PATH/$MODE.wtns 
    # calcualte circuite type
    TYPE=$(( ($TLDALG == 13 ? 1 : 0) * 4 + ($SLDALG == 13 ? 1 : 0) * 2 + ($MAN == 1 ? 1 : 0) ))
    # we know there is only one SAN for test data
    SAN=$(python3 $SCRIPT_PATH/compress.py $SRC_PATH/${MODE}_proof.json $TYPE $DOMAIN)
    openssl req -new -nodes -out "$SRC_PATH/$DOMAIN.csr" -key "$SRC_PATH/domain.key" -subj "/CN=$DOMAIN" -addext "subjectAltName = DNS:$DOMAIN, DNS:$SAN" 
}

# Assumes the prover has already fetched inputs
# **and** compiled the witness generator
# Running on test data
benchmark () {
  if [ ! -f "$SRC_PATH/domain.key" ]; then
    echo "Key Generation"
    openssl genrsa -out $SRC_PATH/domain.key 2048 
  fi
  if [ $? -ne 0 ]; then
    echo "Error generating domain key"
    exit 1
  fi
  MODE=$1
  echo "Benchmarking $MODE"

  # parse cli paramerters from MODE
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
    DOMAIN="nope-tools.me"
  else 
    DOMAIN="nope-tools.com"
  fi

  LOGFILE="dat/$MODE.log"
  > $LOGFILE

  for k in $(seq 1 $ITER); do
    echo "iteration $k out of $ITER"
    { time prove $MODE $DOMAIN $TLDALG $SLDALG $MAN; } 2> >(tee -a $LOGFILE)
  done

  echo "Log saved to $MODE.log"
}

check_files

export NODE_OPTIONS=--max-old-space-size=8192
for NAME in ${NAMES[@]}; do
  benchmark $NAME
  NAME+="-man"
  benchmark $NAME
done
