#!/bin/bash

set -exo pipefail

SRC_PATH="./bin"
SCRIPT_PATH="./scripts"
FILEEXTS=(".r1cs" ".params" "-vk.json")

# To run this script, DNSSEC data must be fetched using 
# sscripts/fetchmin.py (this goes to a data folder by default).
# Also, the corresponding bind KSK must be parsed and placed under the same folder.
# Parse ECDSA keys with scripts/eccextract.py and rename the output to domain.-DNSKEY-KSK-dlog.dat
# Parse RSA keys with extract.py and rename the output to domain.-DNSKEY-KSK-factors.dat
# The corresponding circuits and keys also need to be compiled and exported. (To make sure of this, run `./build.sh` then `./export.sh`) 

# Usage function
usage() {
    echo "Usage: $0 DOMAIN TLDALG SLDALG MAN [KEY]"
    echo "  DOMAIN  : The domain name"
    echo "  TLDALG  : Top-level domain algorithm (must be 8 or 13)"
    echo "  SLDALG  : Second-level domain algorithm (must be 8 or 13)"
    echo "  MAN     : Manager flag (must be 0 or 1)"
    echo "  DATA_PATH : Path to the data file (must exist)"
    echo "  EMAIL   : Domain admin's email"
    echo "  KEY     : Optional TLS key file path (must exist if provided)"
    exit 1
}

# Check if at least six arguments are provided
if [ $# -lt 6 ]; then
    echo "Error: Not enough arguments provided."
    usage
fi

# Assign positional arguments to variables
DOMAIN=$1
TLDALG=$2
SLDALG=$3
MAN=$4
DATA_PATH=$5
EMAIL=$6
KEY=$7

# Validate TLDALG
if [[ "$TLDALG" != "8" && "$TLDALG" != "13" ]]; then
    echo "Error: Unsupported TLDALG. Must be 8 or 13."
    exit 1
fi

# Validate SLDALG
if [[ "$SLDALG" != "8" && "$SLDALG" != "13" ]]; then
    echo "Error: Unsupported SLDALG. Must be 8 or 13."
    exit 1
fi

# Validate MAN
if [[ "$MAN" != "0" && "$MAN" != "1" ]]; then
    echo "Error: Unsupported MAN. Must be 0 or 1."
    exit 1
fi

# Check if DATA_PATH is an existing directory
if [ ! -d "$DATA_PATH" ]; then
    echo "Error: The directory path provided in DATA_PATH does not exist."
    exit 1
fi

# If KEY is provided, check if the file exists
if [ -n "$KEY" ]; then
    if [ ! -f "$KEY" ]; then
        echo "Error: The file path provided in KEY does not exist."
        exit 1
    fi
else
    KEY="$SRC_PATH/$DOMAIN.key"
    # reuse previous key if exists
    if [ ! -f "$KEY" ]; then
        echo "Generate new TLS key to $KEY"
        openssl genrsa -out $KEY 2048 
    fi
fi

# MODE construction
TLD_ALGORITHM=$([ "$TLDALG" == "8" ] && echo "rsa" || echo "ecdsa")
SLD_ALGORITHM=$([ "$SLDALG" == "8" ] && echo "rsa" || echo "ecdsa")

MODE="${TLD_ALGORITHM}-${SLD_ALGORITHM}"
if [ "$MAN" == "1" ]; then
    MODE="${MODE}-man"
fi

check_files () {
  NAME=$1
  for EXT in ${FILEEXTS[@]}; do
    if [ ! -f "$SRC_PATH/${NAME}${EXT}" ] || [ ! -f "$SRC_PATH/${NAME}_cpp/${NAME}.o" ]; then
      echo "Please make sure to build and export"
      exit 1
    fi
  done
}

prove () {
    echo "Get public key digest"
    openssl rsa -in $KEY -pubout -out $SRC_PATH/${DOMAIN}.pub 
    PUB_DIGEST=$(python3 $SCRIPT_PATH/hash_pub.py $SRC_PATH/${DOMAIN}.pub)

    echo "Build prover input"
    node $SCRIPT_PATH/make_input.js -d $DOMAIN -t $TLDALG -s $SLDALG -m $MAN -g $PUB_DIGEST -p $DATA_PATH
    echo "Generate witness"
    $SRC_PATH/${MODE}_cpp/$MODE $SRC_PATH/${MODE}_input.json $SRC_PATH/$MODE.wtns
    # zkutil prove
    zkutil prove -c $SRC_PATH/$MODE.r1cs -p $SRC_PATH/$MODE.params -r $SRC_PATH/${MODE}_proof.json -o $SRC_PATH/${MODE}_public.json -w $SRC_PATH/$MODE.wtns 
    # Verifying
    echo "Create CSR"
    # calcualte circuite type
    TYPE=$(( ($TLDALG == 13 ? 1 : 0) * 4 + ($SLDALG == 13 ? 1 : 0) * 2 + ($MAN == 1 ? 1 : 0) ))
    # assume there is only one SAN
    SAN=$(python3 $SCRIPT_PATH/compress.py $SRC_PATH/${MODE}_proof.json $TYPE $DOMAIN)
    openssl req -new -nodes -out "$SRC_PATH/$DOMAIN.csr" -key "$KEY" -subj "/CN=$DOMAIN" -addext "subjectAltName = DNS:$DOMAIN, DNS:$SAN" 

    # now we run the acme server
    python3 src/app.py -e $EMAIL -d $DOMAIN --csr $SRC_PATH/$DOMAIN.csr --domain_key $KEY
}

check_files $MODE

export NODE_OPTIONS=--max-old-space-size=8192
prove
