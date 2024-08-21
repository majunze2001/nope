const path = require('path');
const {ArgumentParser} = require('argparse');
const {makeDigest, writeInput} = require('../../sscripts/master_input_maker');

const parser = new ArgumentParser({
  description: 'NOPE Input Maker Arguments',
});

parser.add_argument('-d', '--domain', {help: 'doman name', required: true});
parser.add_argument('-g', '--pub_key_digest', {
  help: 'Public Key Digest -- base 64 encoded string of 43 characters',
  required: true,
});
parser.add_argument('-t', '--tld_alg', {help: 'TLD Algorithm', required: true});
parser.add_argument('-s', '--sld_alg', {help: 'SLD Algorithm', required: true});
parser.add_argument('-c', '--ca_org', {help: 'CA'});
parser.add_argument('-p', '--data_path', {
  help: 'path to the subfolder with all DNSSEC records and so on',
});
parser.add_argument('-o', '--output_folder', {help: 'output_folder'});
parser.add_argument('-m', '--managed', {help: 'enable managed'});

const args = parser.parse_args();

// base64 encode the digest
const encodeDigest = function(sha256Array){
    let binaryString = '';
    for (let i = 0; i < sha256Array.length; i++) {
        binaryString += String.fromCharCode(sha256Array[i]);
    }

    let base64String = btoa(binaryString);

    let intArray = [];
    for (let i = 0; i < base64String.length; i++) {
        if (base64String[i] !== '=') {
            intArray.push(base64String.charCodeAt(i));
        }
    }

    return intArray.slice(0, 43);
}

const createInput = function(
  domain,
  pub_key_digest,
  tld_alg,
  sld_alg,
  data_path,
  managed = false,
  ca_org = `Let's Encrypt`
) {
  if (pub_key_digest.length != 43) {
    console.log('Error: pub_key_digest should have length 43');
    process.exit(1);
  }

  let output_path;
  if (args.output_folder) {
    const outname = domain + (managed ? '-man' : '');
    output_path = path.join(args.output_folder, outname + '_input.json');
  } else {
    const subfolder =
      (tld_alg === 8 ? 'rsa' : 'ecdsa') +
      '-' +
      (sld_alg === 8 ? 'rsa' : 'ecdsa');
    const outname = subfolder + (managed ? '-man' : '');
    output_path = path.join(__dirname, '..', 'bin', outname + '_input.json');
  }

  if (!data_path) {
    const subfolder =
      (tld_alg === 8 ? 'rsa' : 'ecdsa') +
      '-' +
      (sld_alg === 8 ? 'rsa' : 'ecdsa');
    data_path = path.join(__dirname, '..', 'test', 'sdata', subfolder);
  }

  const digest = makeDigest(pub_key_digest, ca_org)

  const encoded_digest = encodeDigest(digest);
  writeInput(
    data_path,
    output_path,
    domain,
    encoded_digest,
    tld_alg,
    sld_alg,
    managed,
  );
};

createInput(
  args.domain,
  args.pub_key_digest,
  parseInt(args.tld_alg),
  parseInt(args.sld_alg),
  args.data_path,
  args.managed && parseInt(args.managed) ? true : false,
);
