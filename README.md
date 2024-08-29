# NOPE: Strengthening domain authentication with zero-knowledge

_Note to artifact evaluators: DOVE is the anonymized name of the project.
Its real name is NOPE. We use that latter term below. However, this
README is with reference to the submitted version of the paper, as
opposed to the camera ready (we will update the README after the camera
ready is finalized)._

_Note to everyone else: this is a README for a code artifact that
accompanies a research paper. The research paper itself is under
preparation and will be available by the end of September; for a
preliminary version, please write to the authors.  Along those lines,
please note the following Warning._

**Warning!** *NOPE is a research project.*
*This code has not been audited and the zero-knowledge proof system uses a dummy trusted setup.*
*Do not use NOPE in production environments or anywhere else that security is necessary.*

There are three core pieces of NOPE, each of which is in a separate directory:

1. `circuits/`: circom code for generating proofs of domain ownership, tests, and circuit specific benchmarks
2. `server/`: server-side automation for generating proofs and certificates for a given domain, serving them locally, and benchmarking system performance
3. `extension/`: a browser extension for NOPE certificate validation and scripts for client benchmarking

The NOPE artifact is these three items, together with a Dockerfile, for
portability.

To connect these items to the proof system in NOPE: specifically,
`circuits/` contains the underlying proof system specifications, the
prover is `server/`, the verifier is `extension/`. 

This repository includes instructions for reproducing the results in the
paper, figure by figure, and then more general instructions for using
each of the components.

## Getting started

The easiest ways to interact with the artifact are to use one of two platforms: (1) a running, NOPE-aware DNS
server and (2) a Docker container, for portability. The running DNS
server is preferred for artifact evaluation because some of the
benchmarks require the ability to update DNS records. 

### A running DNS server

The reviewer account for the DNS server for [nope-tools.org](nope-tools.org)
is accessible via ssh at `reviewer@34.30.228.2`
via the password supplied in the hotcrp artifact submission.

### Docker container

The Docker container is specified in `Dockerfile`. The following scripts
are relevant:

1. `./build-docker.sh`: this builds the docker image
2. `./run-docker.sh`: this runs the docker image, mounts the current directory, and opens an interactive shell inside the container

These are provided to make deploying NOPE on your own DNS server easier.

## Reproducing paper results

The following instructions will reproduce the results in the paper,
figure by figure, on either the DNS server or the Docker container.

Note that the description for reproducing each figure is self-contained,
and thus the figures can be reproduced in any order.

### Figure 3 (1-2 minutes to run to completion)

To reproduce Figure 3, navigate to the `extension/bench/` directory and run the following commands:

```
npm install
taskset -c 1 ./run.sh
python3 tochart.py
```

Note that this does not reproduce the final "time (native)" column in Figure 3.
That column is estimated, and we will explain the estimation process in
the next version of the paper.

### Figure 4 (several hours to run, but the bulk can be skipped)

Reproducing Figure 4 is a several step process.
We indicate which steps apply to which bars in the figure inline.

First, navigate to the `server/` directory and run the following two commands to build the circuits and export (*insecure*) proving keys.

```
./build.sh
./export.sh
```

_These commands take several hours to run to completion; however, in
the running DNS server, we have pre-executed them to save time in
evaluation, so it is safe to skip them if desired (if you are using the Docker
container, they will need to be executed). They correspond to a one-time cost for a server owner._

Second, navigate to the `server/bench/` directory and run the following two commands.

```
taskset -c 1 ./bench.sh
python3 parse.py
```

In the figure, this corresponds to "proof generation" and handles the generation of Certificate Signing Request with NOPE proof embedded.

_These commands take 40-50 minutes to run to completion._

Third, navigate to the `server/src/` directory and run the following command to begin the ACME protocol with Let's Encrypt.

```
python3 app.py --time_it -e admin@nope-tools.org -d nope-tools.org 
```

Note that this part involves updating DNS records and is subject to ACME
rate limiting, so, for the sake of benchmarking, we require manual input.
That is, the script will pause halfway and prompt a manual DNS update, for example:

```
Please create a DNS TXT record in your zone:
_acme-challenge.nope-tools.org. IN      TXT     "-3MFg8LCoTFR-gVQuJaUGsLy8agudB7UcL9I6lGcrM8"
```

The time from ACME start to this prompt is "ACME Initiation" in the figure.

To manually edit the DNS record, run `sudo vim /var/cache/bind/nope-tools.org` to open the zone file and make the following two edits.

1. Increment the serial number.
2. Replace the line prefixed by `_acme-challenge.nope-tools.org.` with the line provided by the script.

After saving the new zone file, run `sudo systemctl reload bind9` to publish the new records.

After waiting 10-30 seconds, return to the script and press `Enter` to continue with the ACME process.

The time from pressing `Enter` to the end of the script is "ACME Verification" in the figure.

_This portion of the benchmark takes 1-2 minutes to run to completion._

The results of this benchmark are stored in the `server/src/dat/` directory with files having a `.dat` suffix.

To summarize the results, run

```
python3 ../scripts/summarize.py dat
```

### Figure 5 (40-50 minutes)

To reproduce the results in Figure 5, navigate to the `circuits/bench/` directory and run the following two commands:

```
./count.sh | tee tmp.log
python3 tochart.py
```

The `tochart.py` script uses these results to estimate the effect of NOPE's optimizations on constraint count, prover time, and memory usage (consistent with macrobenchmarks).

_These commands take 40-50 minutes to run to completion, with `count.sh` taking the bulk of the time._

We have also included a `./run.sh` script which compiles and runs the full pipeline for the most expensive circuit to demonstrate the full process with dummy data.
Note that the `run.sh` script requires `npm install` to be run in the `circuits/` directory first.

### Figure 6 (~0 seconds)

To replicate the results in Figure 6, navigate to the `extension/bench/decomp/` directory and run the following command.

```
python3 cert.py ../cert/nope.pem ../cert/dv.pem ../cert/r11.pem ../dnssec-chain/data
```

This Python script handles the slicing and dicing of the raw certificate data and DNSSEC chain data to produce the results in Figure 6.

The arguments above are static paths to test certificates and DNSSEC chain data, but it is easy to replace them with other data if desired.

_Exact byte counts will vary slightly from the paper due to inherent variability in certificate issuance and DNSSEC record lengths._

## Circuits general instructions

The circuits are a collection of circom files specifying constraints and witness generation code for DNSSEC verification.

### Building the circuits (several minutes)

To build all circuits, navigate to the `circuits/` directory and run `make`.

### Circuit tests

All of our circuits are equipped with tests of completeness on sample data.
To the run the tests, first run `npm install`.
Then run `npm test` to run all tests or `mocha [testname]` in the `circuits/test/` directory to run a specific test (add option `--max-old-space-size=4000` if you see Out Of Memory). 

We have provided sample test data from [nope-tools.com](nope-tools.com) and [nope-tools.me](nope-tools.me) in the `circuits/test/sdata/` directory and the tests are configured to use this data by default.

To use custom test data, run `python3 fetchmin.py [your url]` which fetches sample DNS data for tests from the specified URL and places it in the `circuits/test/data/` directory.
Then modify the appropriate test to use the new data.

## Server general instructions

`server.sh` is a complete tool for generating a NOPE proof and obtaining a NOPE cert.

*Note that this script assumes all the data and binary files are prepared as follows.*

1. The domain's DNSSEC data must be fetched using sscripts/fetchmin.py (this goes to a data folder by default). 
2. The corresponding bind Key Signing Key (KSK) should be parsed as follows (based on key type). 
    - If the KSK is an ECDSA key then `scripts/eccextract.py` should be run and the output renamed to `[domain].-DNSKEY-KSK-dlog.dat`
    - If the KSK is an RSA key then `extract.py` should be run and the output renamed to `[domain].-DNSKEY-KSK-factors.dat`
3. The corresponding circuits and keys also need to be compiled and exported. (To make sure of this, run `./build.sh` then `./export.sh`) 
4. For NOPE-managed, run `analyze.py` to get the amount of padding required for the current TXT recordset configuration.

The arguments and one example usage of `server.sh` are as follows:

```
./server.sh <domain> <TLD algorithm = 8/13> <SLD algorithm = 8/13> <managed=0/1> <data path> <email>
./server.sh nope-tools.org 8 13 0 data nope-admin@nope-tools.org
```

`./server.sh` generates a NOPE proof, encodes it into a Certificate Signing Request, and initiates the ACME protocol with Let's Encrypt using the Request.

### Auxiliary server scripts

`server/scripts` includes additional helper scripts for `server.sh`

- `compress.py` compresses a NOPE proof to a SAN
- `hash_pub.py` hashes a TLS public key and encodes it with base64
- `make_input.js` creates prover input for the witness generator

These are used internally by `server.sh`, but they can be used independently for debugging and testing.

## Extension general instructions

**NOTE:** *Due to browser security policies, this extension only works in Firefox.*

### Building the extension

To build the extension, navigate to the `extension` directory and run the following commands:
- `npm install`
- `npm run build`

### Loading the extension

To load the extension into Firefox, do the following:

1. Navigate to `about:debugging#/runtime/this-firefox`
2. Click `Load Temporary Add-on...` and select `/addon/manifest.json`

### Using the extension

When visiting a website, for example [nope-tools.org](nope-tools.org), the extension will check if the server is 
using a NOPE certificate and try extract and verify the proof if found.

If no proof is detected, the NOPE icon will be unchanged.
If a NOPE proof is detected and verifies, a green checkmark will appear.
However, if a NOPE proof is detected and verification fails, then a red X will appear indicating that the proof is invalid.

## References

This project contains modified code from the following sources with the following licenses

- [snarkjs](https://github.com/iden3/snarkjs) which is licensed under GPL-3.0, 
- [Bluecrypt ASN.1 Parser](https://git.coolaj86.com/coolaj86/asn1-parser.js) which is licensed under MPL-2.0, and
- [ffjavascript](https://github.com/iden3/ffjavascript) which is licensed under GPL-3.0
