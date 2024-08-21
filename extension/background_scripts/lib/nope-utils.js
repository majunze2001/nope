const {ECurve} = require('./ecurve.js');
const decompress = require('./decompress.js');
const ASN1 = require('./asn1-parser.js');
const decompressNope = decompress.decompressNope;

const MAX_KEY_BYTES = 260;
// TLD is max 24 bytes
// 63 bytes per label beyond that
const MAX_NAME_BYTES = [
  1,
  24 + 2,
  63 + 24 + 3,
  2 * 63 + 24 + 4,
  3 * 63 + 24 + 5,
  255,
];
const PUBLIC_INPUT_BYTES = 13;
const DEPTH = 2;
const apiUrl = 'https://dns.google/resolve?name=.&type=DNSKEY&do=true';

const types = [
  'rsa-rsa',
  'rsa-ecdsa',
  'ecdsa-ecdsa',
  'ecdsa-rsa',
  'rsa-rsa-man',
  'rsa-ecdsa-man',
  'ecdsa-ecdsa-man',
  'ecdsa-rsa-man',
];

function base64ToBytes(base64) {
  const binString = atob(base64);
  return Array.from(binString, m => m.codePointAt(0));
}

function stringToBytes(s) {
  return Array.from(s, c => c.charCodeAt(0));
}

function timeToTruncatedBytes(t) {
  // given a timestamp as a number, convert it to 8 bytes
  // then just get the first 5 bytes
  var bytes = [];
  for (var i = 0; i < 8; i++) {
    bytes.push(t & 0xff);
    t = Math.floor(t / 256);
  }
  // reverse bytes
  bytes.reverse();
  return bytes.slice(0, 5);
}

function mergeNested(arr) {
  let len = 0;
  for (let i = 0; i < arr.length; i++) {
    len += arr[i].length;
  }
  let merged = new Array(len);
  let offset = 0;
  for (let i = 0; i < arr.length; i++) {
    for (let j = 0; j < arr[i].length; j++) {
      merged[offset + j] = arr[i][j];
    }
    offset += arr[i].length;
  }
  return merged;
}

function rightPadArrayTo(arr, len, padValue = 0) {
  let a = new Array(len).fill(padValue);
  // right pad
  for (let i = 0; i < arr.length && i < len; i++) {
    a[i] = arr[i];
  }
  return a;
}

function strToWire(str) {
  // strip trailing dot if present
  if (str[str.length - 1] == '.') {
    str = str.slice(0, -1);
  }
  // split string into labels
  let labels = str.split('.');
  // create array of bytes [len, label, len, label, ...]
  let bytes = [];
  for (let i = 0; i < labels.length; i++) {
    bytes.push(labels[i].length);
    for (let j = 0; j < labels[i].length; j++) {
      bytes.push(labels[i].charCodeAt(j));
    }
  }
  // append 0 byte and return
  bytes.push(0);
  return bytes;
}

function packInputsForField(fields) {
  // unfold
  let unfolded = [];
  for (let i = 0; i < fields.length; i++) {
    for (let j = 0; j < fields[i].length; j++) {
      unfolded.push(fields[i][j]);
    }
  }
  const packed = new Array(Math.ceil(unfolded.length / 31)).fill(BigInt(0));
  for (let i = 0; i < packed.length; i++) {
    for (let j = 0; j < 31; j++) {
      if (i * 31 + j < unfolded.length) {
        packed[i] += BigInt(unfolded[i * 31 + j]) << BigInt(8 * j);
      }
    }
  }
  return packed;
}

async function buildPublicSignals(
  domain,
  publicKeyDigest,
  issuerOrgName,
  validityStart,
  root_zsk,
) {
  // format and merge into digest
  const digest = mergeNested([
    stringToBytes(publicKeyDigest),
    stringToBytes(issuerOrgName),
    timeToTruncatedBytes(validityStart),
  ]);
  // compute sha256 hash of digest
  const hash = await crypto.subtle
    .digest('SHA-256', new Uint8Array(digest))
    .then(h => Array.from(new Uint8Array(h)));
  // convert hash to base64 string
  const b64 = btoa(String.fromCharCode(...hash));
  // pack inputs
  return packInputsForField([
    rightPadArrayTo(strToWire(domain), MAX_NAME_BYTES[DEPTH]),
    rightPadArrayTo(root_zsk, MAX_KEY_BYTES),
    [root_zsk.length % 256, root_zsk.length >> 8],
    stringToBytes(b64).slice(0, 43),
  ]);
}

function fetchRootZSK() {
  return fetch(apiUrl)
    .then(response => response.json())
    .then(data => {
      if (data.Answer && data.Answer.length > 0) {
        const response = data.Answer;
        const root_zsk_string = response
          .find(c => c.data.startsWith(256))
          .data.split(' ')
          .pop();
        return base64ToBytes(root_zsk_string);
      } else {
        console.error('No DNSKEY record found for root domain.');
        throw new Error('No DNSKEY record found for root domain.');
      }
    });
}

async function setupCurves(vks) {
  const allECurves = {};

  for (const type of types) {
    allECurves[type] = new ECurve();
    await allECurves[type].setup(vks[type], PUBLIC_INPUT_BYTES);
  }

  return allECurves;
}

async function fetchVKs() {
  const vks = {};
  for (const type of types) {
    const vk = await fetch(`src/${type}-vk.json`).then(res => res.json());
    vks[type] = vk;
  }
  return vks;
}

function extractIssuerAndValidity(json){
  const decoder = new TextDecoder('utf-8');

  const issuer = json.children[0].children[3];
  const ca_obj = issuer.children[1].children[0].children[1];
  const ca_bytes = ASN1.decode(ca_obj).VAL;
  const issuerOrgName = decoder.decode(ca_bytes);

  const validity_obj = json.children[0].children[4];
  const validityStart_bytes = validity_obj.children[0].value;

  const dateString = new TextDecoder().decode(validityStart_bytes);

  const year = parseInt(dateString.slice(0, 2), 10) + 2000;
  const month = parseInt(dateString.slice(2, 4), 10) - 1;
  const day = parseInt(dateString.slice(4, 6), 10);
  const hours = parseInt(dateString.slice(6, 8), 10);
  const minutes = parseInt(dateString.slice(8, 10), 10);
  const seconds = parseInt(dateString.slice(10, 12), 10);

  let date = new Date(Date.UTC(year, month, day, hours, minutes, seconds));
  let validityStart = date.getTime();
  return {issuerOrgName, validityStart};
}

function extractNope(rawDER, bench = false) {
  // DER to json
  const json = ASN1.parse(rawDER);
  // assume static path for subject alternative name extension
  const extensions = json.children[0].children[7].children[0].children;
  const parsedSans = ASN1.decode(extensions[6].children[1].children[0]);
  if (
    Array.isArray(parsedSans) &&
    typeof parsedSans[0] === 'string' &&
    parsedSans.length > 1
  ) {
  } else {
    return undefined;
  }
  // extract nope proof
  const nope = decompressNope(parsedSans);
  // if bench, also call extractIssuerAndValidity
  if (bench) {
    const res = extractIssuerAndValidity(json);
    return {nope, ...res};
  } else {
    // and return
    return nope;
  }
}

module.exports = {
  extractNope,
  extractIssuerAndValidity,
  decompressNope,
  setupCurves,
  fetchRootZSK,
  buildPublicSignals,
  fetchVKs,
};
