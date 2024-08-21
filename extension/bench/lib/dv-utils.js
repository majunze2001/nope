const crypto = require('crypto');
const forge = require('node-forge');
const pki = forge.pki;
const asn1 = forge.asn1;

const DEBUG = 0;
function debug_log(...args) {
  if (DEBUG) {
    console.log(...args);
  }
}

// internal vars for parsing
let targets;
var tbsCert;
var headerBytes;
var fullSubPKInfo;
var prefixes;

const endTargets = ['061', '07061', '2'];
const interTargets = ['061', '2'];
const rootTargets = ['061'];
const allPrefixes = [endTargets, interTargets, rootTargets].map(t =>
  generatePrefixes(t),
);

// parse different field based on different depth in chain
function parseCert(certPem, type) {
  const certDer = parseDer(certPem);
  const bytes = forge.util.createBuffer(certDer);

  switch (type) {
    case 0: // end
      prefixes = allPrefixes[0];
      break;
    case 1: // inter
      prefixes = allPrefixes[1];
      break;
    case 2: // root
      prefixes = allPrefixes[2];
      break;
  }

  const myDer = _fromDer(bytes, bytes.length(), 0, {
    strict: false,
    parseAllBytes: false,
    decodeBitStrings: false,
  });

  let res = {};
  if (type === 0) {
    // we prepare data for hashing the pubkey
    res = {fullSubPKInfo};
  }
  switch (type) {
    case 0: // end
      const sans = parseAsn1Expanded(myDer[0][7][0][6][1])[0].content.map(
        c => c.content,
      );
      res = {...res, sans};
    case 1: // inter
      const sig = myDer[2].slice(1);
      res = {...res, sig};
    case 2: // root
      const subPubKeyInfo = parseAsn1Expanded(
        myDer[0][6][1].slice(1),
      )[0].content.map(c => c.content);
      res = {...res, subPubKeyInfo};
  }
  if (type != 2) {
    res = {...res, tbsCert};
  }
  return res;
}

// crypto API
function rsaVerify(modulus, exponent, signedData, signature) {
  // Convert BigInt to Buffer
  function bigIntToBuffer(bigint) {
    let hex = bigint.toString(16);
    if (hex.length % 2 !== 0) {
      hex = '0' + hex; // Padding to ensure even length
    }
    return Buffer.from(hex, 'hex');
  }

  // Convert to URL-safe base64
  function toUrlSafeBase64(buffer) {
    return buffer
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  // Convert BigInts to Buffer and then to base64
  const modulusBase64 = toUrlSafeBase64(bigIntToBuffer(modulus));
  const exponentBase64 = toUrlSafeBase64(bigIntToBuffer(exponent));

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
}

// pem to Der
function parseDer(chain) {
  // if it is a LE chain, we extract the first cert
  const lines = chain.split('\n');
  const cert = lines
    .slice(1, lines.indexOf('-----END CERTIFICATE-----'))
    .join('\n');

  return forge.util.decode64(cert);
}

// copied from node-forge
function _getValueLength(bytes, remaining) {
  // TODO: move this function and related DER/BER functions to a der.js
  // file; better abstract ASN.1 away from der/ber.
  // fromDer already checked that this byte exists
  var b2 = bytes.getByte();
  headerBytes.push(b2);
  remaining--;
  if (b2 === 0x80) {
    return undefined;
  }

  // see if the length is "short form" or "long form" (bit 8 set)
  var length;
  var longForm = b2 & 0x80;
  if (!longForm) {
    // length is just the first byte
    length = b2;
  } else {
    // the number of bytes the length is specified in bits 7 through 1
    // and each length byte is in big-endian base-256
    var longFormBytes = b2 & 0x7f;
    _checkBufferLength(bytes, remaining, longFormBytes);
    for (let i = bytes.read; i < bytes.read + longFormBytes; i++) {
      headerBytes.push(bytes.data.charCodeAt(i));
    }
    length = bytes.getInt(longFormBytes << 3);
  }
  // FIXME: this will only happen for 32 bit getInt with high bit set
  if (length < 0) {
    throw new Error('Negative length: ' + length);
  }
  return length;
}

// internal helpers
function generatePrefixes(targets) {
  const prefixes = new Set(); // Use a Set to avoid duplicates
  prefixes.add('');

  targets.forEach(target => {
    // For each target, generate all possible prefixes
    for (let i = 1; i <= target.length; i++) {
      prefixes.add(target.substring(0, i));
    }
  });

  return prefixes;
}

// modified from node-forge
function _fromDer(bytes, remaining, depth, options, cid = '') {
  // temporary storage for consumption calculations
  headerBytes = [];

  var start;

  // get the first byte
  var b1 = bytes.getByte();
  headerBytes.push(b1);

  // consumed one byte
  remaining--;

  // get the tag class
  var tagClass = b1 & 0xc0;

  // get the type (bits 1-5)
  var type = b1 & 0x1f;

  // get the variable value length and adjust remaining bytes
  start = bytes.length();
  var length = _getValueLength(bytes, remaining);
  remaining -= start - bytes.length();

  if (depth === 1 && cid == '0') {
    tbsCert = bytes.data.slice(4, length + 4 + 4);
  }
  if (cid == '06') {
    // save the full subPubKeyInfo for hashing
    fullSubPKInfo =
      String.fromCharCode(...headerBytes) +
      bytes.data.slice(bytes.read, bytes.read + length);
  }

  // value storage
  var value;
  // possible BIT STRING contents storage
  var bitStringContents;

  let id = 0;
  debug_log('--'.repeat(depth) + depth, length, remaining, cid, type);
  debug_log(typeof prefixes, prefixes);
  // where magic happens, we skip this node bc it's not on path to target nodes
  if (!prefixes.has(cid)) {
    debug_log('--'.repeat(depth) + 'skipped', length, remaining, cid, type);
    remaining -= length;
    return [bytes.getBytes(length)];
  }

  // constructed flag is bit 6 (32 = 0x20) of the first byte
  var constructed = (b1 & 0x20) === 0x20;
  if (constructed) {
    debug_log('nested');
    // parse child asn1 objects from the value
    value = [];
    if (length === undefined) {
      // asn1 object of indefinite length, read until end tag
      process.exit(1);
    } else {
      // parsing asn1 object of definite length
      while (length > 0) {
        start = bytes.length();
        value.push(_fromDer(bytes, length, depth + 1, options, cid + id));
        remaining -= start - bytes.length();
        length -= start - bytes.length();
        id += 1;
      }
    }
  }

  // if a BIT STRING, save the contents including padding
  if (
    value === undefined &&
    tagClass === asn1.Class.UNIVERSAL &&
    type === asn1.Type.BITSTRING
  ) {
    debug_log('BIT string');
    bitStringContents = bytes.bytes(length);
  }

  if (value === undefined) {
    debug_log('raw value');
    // asn1 not constructed or composed, get raw value
    // TODO: do DER to OID conversion and vice-versa in .toDer?

    debug_log('undefined value');
    //process.exit(1);
    if (length === undefined) {
      if (options.strict) {
        throw new Error('Non-constructed ASN.1 object of indefinite length.');
      }
      // be lenient and use remaining state bytes
      length = remaining;
    }

    if (type === asn1.Type.BMPSTRING) {
      value = '';
      for (; length > 0; length -= 2) {
        _checkBufferLength(bytes, remaining, 2);
        value += String.fromCharCode(bytes.getInt16());
        remaining -= 2;
      }
    } else {
      value = bytes.getBytes(length);
      remaining -= length;
    }
  }

  // add BIT STRING contents if available
  var asn1Options =
    bitStringContents === undefined
      ? null
      : {
          bitStringContents: bitStringContents,
        };

  return value;
}

// copied from node-forge, parsing helper
function _checkBufferLength(bytes, remaining, n) {
  if (n > remaining) {
    var error = new Error('Too few bytes to parse DER.');
    error.available = bytes.length();
    error.remaining = remaining;
    error.requested = n;
    throw error;
  }
}

// asn1 parsers
function parseAsn1Content(content, typeByte) {
  switch (typeByte) {
    case 0x02: // INTEGER
      return BigInt('0x' + content.toString('hex'));
    case 0x04: // OCTET STRING
      return content.toString('hex');
    case 0x13: // PrintableString
    case 0x82:
      return content.toString('ascii');
    case 0x30: // SEQUENCE
    case 0x31: // SET
      return parseAsn1Expanded(content); // Recursively parse contents
    default:
      return content.toString('hex'); // Default to hex string
  }
}

function parseAsn1Expanded(binaryString, indent = 0) {
  let index = 0;
  const buffer = Buffer.from(binaryString, 'binary');
  const result = [];

  while (index < buffer.length) {
    // Get the type
    const typeByte = buffer[index];
    index += 1;
    const constructed = (typeByte & 0x20) >> 5 === 1;
    const typeClass = (typeByte & 0xc0) >> 6;
    const tagNumber = typeByte & 0x1f;

    // Get the length
    let lengthByte = buffer[index];
    index += 1;
    let lengthInt = lengthByte;

    if (lengthByte & 0x80) {
      const lengthOfLength = lengthByte & 0x7f;
      lengthInt = 0;
      for (let i = 0; i < lengthOfLength; i++) {
        lengthInt = (lengthInt << 8) | buffer[index];
        index += 1;
      }
    }

    // Get the content
    const content = buffer.slice(index, index + lengthInt);
    index += lengthInt;

    // Parse content based on the type
    const parsedContent = parseAsn1Content(content, typeByte);

    // Construct the element object
    const element = {
      type: typeByte.toString(16).padStart(2, '0'),
      class: typeClass,
      constructed: constructed,
      tagNumber: tagNumber,
      length: lengthInt,
      content: parsedContent,
    };

    // If it's a constructed type and not a known grouping type, recurse
    if (constructed && ![0x30, 0x31].includes(typeByte)) {
      element.children = parseAsn1Expanded(content, indent + 4);
    }

    // Add the current element to the result array
    result.push(element);
  }

  return result;
}

module.exports = {
  parseCert,
  rsaVerify,
};
