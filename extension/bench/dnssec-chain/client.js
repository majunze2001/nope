const DEBUG = 0;

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const {Timer, N, DOMAIN} = require('../lib/bench-utils.js');

function debug_log(...args) {
  if (DEBUG) {
    console.log(...args);
  }
}

function parseRRSETData(data) {
  const baseSize = 18; // Size of the packed data in bytes
  const typeCovered = data.readUInt16BE(0);
  const algorithm = data.readUInt8(2);
  const labels = data.readUInt8(3);
  const originalTtl = data.readUInt32BE(4);
  const expiration = data.readUInt32BE(8);
  const inception = data.readUInt32BE(12);
  const keyTag = data.readUInt16BE(16);
  let index = baseSize;

  // Parsing the signer domain (based on previous code)
  const signer = wireToDomain(data.slice(index));
  debug_log(signer);
  index += signer.size;

  // Parsing the RRNAME
  const rrname = wireToDomain(data.slice(index));
  debug_log(rrname);
  index += rrname.size;

  const rdata = data.slice(index);

  return {
    typeCovered,
    algorithm,
    labels,
    originalTtl,
    expiration,
    inception,
    keyTag,
    signer: signer.domain,
    rrname: rrname.domain,
    data: rdata,
  };
}

function parseTLSA(data) {
  let index = 10;
  const usage = data.readUInt8(index);
  const selector = data.readUInt8(index + 1);
  const matchingType = data.readUInt8(index + 2);
  const certData = data.slice(index + 3);

  return {usage, selector, matchingType, certData};
}

function wireToDomain(data) {
  let index = 0;
  const domainParts = [];
  while (index < data.length) {
    const length = data[index];
    index += 1;
    if (length === 0) {
      if (domainParts.length === 0) {
        return {domain: '.', size: index};
      }
      break;
    }
    if (index + length > data.length) {
      debug_log(length);
      throw new Error('Data is out of bounds.');
    }
    const label = data.slice(index, index + length).toString('ascii');
    domainParts.push(label);
    index += length;
  }
  const domain = domainParts.length ? domainParts.join('.') + '.' : '';
  return {domain, size: index};
}

function parseDNSKEY(data) {
  const {domain, size} = wireToDomain(data);
  let index = size;
  if (domain == "."){
    index += 1; // ??
  }
  if (index + 4 > data.length) {
    console.log('Error: Not enough data for DNSKEY record fields.');
    return null;
  }
  const flags = data.readUInt16BE(index);
  const protocol = data.readUInt8(index + 2);
  const algorithm = data.readUInt8(index + 3);
  const key = data.slice(index + 4);

  return {domain, flags, protocol, algorithm, key};
}

function verifySignature(signedData, signature, key, alg) {
  if (alg === 8) {
    // RSA-SHA256

    const exponent = key.slice(1, 4);
    const modulus = key.slice(4);

    // Convert to URL-safe base64
    function toUrlSafeBase64(buffer) {
      return buffer
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    }

    // Convert to base64
    const exponentBase64 = toUrlSafeBase64(exponent);
    const modulusBase64 = toUrlSafeBase64(modulus);

    // Create the public key using JWK format
    const publicKey = crypto.createPublicKey({
      key: {
        kty: 'RSA',
        n: modulusBase64,
        e: exponentBase64,
      },
      format: 'jwk',
    });

    // Create and initialize verifier
    const verify = crypto.createVerify('RSA-SHA256');
    verify.update(signedData);
    verify.end();
    try {
      if (verify.verify(publicKey, signature)) {
        debug_log('RSA-SHA256 signature verified');
      } else {
        console.log('RSA-SHA256 signature verification failed');
        process.exit(1);
      }
    } catch (error) {
      console.log('RSA-SHA256 signature verification failed', error);
      process.exit(1);
    }
  } else if (alg === 13) {
    // ECDSA-SHA256
    if (key.length !== 64) {
      console.log('Invalid key length for ECDSA P-256.');
      process.exit(1);
    }

    // Convert x and y coordinates to URL-safe Base64 without padding
    const x_coord = key
      .slice(0, 32)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
    const y_coord = key
      .slice(32)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');

    // Create the public key using JWK
    const publicKey = crypto.createPublicKey({
      key: {
        kty: 'EC',
        crv: 'P-256',
        x: x_coord,
        y: y_coord,
      },
      format: 'jwk',
    });

    // Check signature length
    if (signature.length !== 64) {
      console.log('Invalid signature length for ECDSA raw format.');
      process.exit(1);
    }

    // Extract r and s values from the signature
    const r = signature.slice(0, 32);
    const s = signature.slice(32);

    // Helper function to ensure ASN.1 DER integers are correctly formatted
    function asn1IntBuffer(integerBuffer) {
      if (integerBuffer[0] & 0x80) {
        return Buffer.concat([Buffer.from('00', 'hex'), integerBuffer]);
      }
      return integerBuffer;
    }

    const rDer = asn1IntBuffer(r);
    const sDer = asn1IntBuffer(s);
    const derSignature = Buffer.concat([
      Buffer.from('30', 'hex'), // ASN.1 Sequence
      Buffer.from([rDer.length + sDer.length + 4], 'hex'), // Total length
      Buffer.from('02', 'hex'), // ASN.1 Integer
      Buffer.from([rDer.length], 'hex'), // Length of r
      rDer, // r value
      Buffer.from('02', 'hex'), // ASN.1 Integer
      Buffer.from([sDer.length], 'hex'), // Length of s
      sDer, // s value
    ]);

    // Verify the signature
    const verifier = crypto.createVerify('SHA256');
    verifier.update(signedData);
    try {
      const isValid = verifier.verify(publicKey, derSignature);
      if (isValid) {
        debug_log('ECDSA-SHA256 signature verified');
      } else {
        console.log('ECDSA-SHA256 signature verification failed');
        process.exit(1);
      }
    } catch (err) {
      console.log('ECDSA-SHA256 signature verification failed:', err);
      process.exit(1);
    }
  } else {
    console.log('Error: unsupported algorithm');
    process.exit(1);
  }
}

let subfolder = 'fmdata/';

function fromFile(domain, rrtype, modifier) {
  const filename = path.join(subfolder, `${domain}-${rrtype}-${modifier}.dat`);
  debug_log('Reading', filename);
  return fs.readFileSync(filename);
}

function getParDomain(domain) {
  const count = (domain.match(/\./g) || []).length;
  if (count === 1) {
    return '.';
  } else if (count > 1) {
    return domain.substring(domain.indexOf('.') + 1);
  } else {
    console.log('Invalid domain name', domain);
    process.exit(1);
  }
}

function gatherInfo(domain, isLeaf = false) {
  debug_log('Gathering info for', domain);
  if (isLeaf) {
    const tlsaRec = fromFile(domain, 'TLSA', 'REC');
    const tlsaKey = fromFile(domain, 'TLSA', 'KEY');
    const tlsaSig = fromFile(domain, 'TLSA', 'SIG');
    const tlsaRrsetInfo = parseRRSETData(tlsaRec);
    verifySignature(tlsaRec, tlsaSig, tlsaKey, tlsaRrsetInfo.algorithm);
    const tlsaRecInfo = parseTLSA(tlsaRrsetInfo.data);
    debug_log(tlsaRecInfo.certData.toString('base64'));
    debug_log(domain, 'tlsa', tlsaRrsetInfo.signer);
    domain = tlsaRrsetInfo.signer;
  }
  const dnskeyRec = fromFile(domain, 'DNSKEY', 'REC');
  const dnskeyKey = fromFile(domain, 'DNSKEY', 'KSK');
  const dnskeyInfo = parseDNSKEY(dnskeyKey);
  const dnskeySig = fromFile(domain, 'DNSKEY', 'SIG');
  const dnskeySigInfo = parseRRSETData(dnskeyRec);
  debug_log(
    dnskeyRec.length,
    dnskeySig.length,
    dnskeyInfo.key.length,
    dnskeySigInfo.algorithm,
  );
  verifySignature(
    dnskeyRec,
    dnskeySig,
    dnskeyInfo.key,
    dnskeySigInfo.algorithm,
  );
  debug_log(domain, 'dnskey', dnskeyInfo.domain);

  const hash = crypto.createHash('sha256');
  hash.update(dnskeyKey);

  if (domain !== '.') {
    const dsRec = fromFile(domain, 'DS', 'REC');
    const dsKey = fromFile(domain, 'DS', 'KEY');
    const dsSig = fromFile(domain, 'DS', 'SIG');
    const dsSigInfo = parseRRSETData(dsRec);
    debug_log(domain, 'ds', dsSigInfo.signer);
    if (!dsRec.includes(hash.digest())) {
      console.log(`DS record content not verified`);
      process.exit(1);
    }
    verifySignature(dsRec, dsSig, dsKey, dsSigInfo.algorithm);
    const parDomain = getParDomain(domain);
    gatherInfo(parDomain);
  }
}

function bench(domain) {
  const record_dnssec = new Timer('full');
  for (let i = 0; i < N; i++) {
    record_dnssec.set(1);
    gatherInfo(domain, true);
    record_dnssec.set(0);
  }
  record_dnssec.display();
}

let domain = '_443._tcp.' + DOMAIN;

if (!domain.endsWith('.')) {
  domain += '.';
}

subfolder = `data`;
if (!fs.existsSync(subfolder)) {
  console.log('Error: data directory does not exist');
  process.exit(1);
}

bench(domain);
