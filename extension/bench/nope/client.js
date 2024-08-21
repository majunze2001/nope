const fs = require('fs');
const ffjavascript = require('ffjavascript');
const path = require('path');
const crypto = require('crypto');
const {
  fetchRootZSK,
  extractNope,
  extractIssuerAndValidity,
  buildPublicSignals
} = require('../../background_scripts/lib/nope-utils.js');
const {
  ECurve
} = require('../../background_scripts/lib/ecurve.js');
const {
  Timer,
  N,
  DOMAIN,
} = require('../lib/bench-utils.js');
const {
  parseCert,
  rsaVerify
} = require('../lib/dv-utils.js');
const {
  parseDer
} = require('../lib/parse-utils.js');

const PUBLIC_INPUT_BYTES = 13;
const circuits = [
  'rsa-rsa',
  'rsa-ecdsa',
  'ecdsa-ecdsa',
  'ecdsa-rsa',
  'rsa-rsa-man',
  'rsa-ecdsa-man',
  'ecdsa-ecdsa-man',
  'ecdsa-rsa-man',
];

const root_zsk = [3,1,0,1,212,162,203,171,44,149,138,220,101,33,156,184,193,10,224,59,68,240,54,89,99,80,52,242,64,44,190,32,3,227,219,104,113,131,185,155,126,192,188,131,178,205,232,138,5,107,143,184,158,38,246,238,71,162,112,140,254,123,113,146,86,74,96,92,140,126,219,252,94,132,112,110,37,221,165,40,223,118,147,71,136,198,19,77,93,168,13,67,76,141,210,197,156,94,135,97,38,56,243,26,207,109,235,208,57,134,192,20,97,233,198,167,23,1,4,244,248,22,129,136,12,119,46,206,165,92,20,55,254,20,149,58,154,239,13,98,66,66,34,54,57,63,189,250,198,138,45,215,82,33,126,131,193,53,114,209,46,83,225,134,56,16,104,57,71,119,63,120,165,27,219,255,23,128,165,148,206,83,136,102,197,64,101,149,18,76,165,180,181,126,120,113,192,0,44,238,198,174,251,49,252,213,186,218,55,53,198,254,176,88,5,232,112,225,21,128,30,254,224,188,219,238,175,105,230,141,244,250,198,40,26,147,172,42,1,111,49,44,184,160,38,83,64,196,49,217,40,221,252,209,182,108,195,48,234,115]

async function bench() {
  // for benchmarking we use a fixed root zsk, but in production and in the extension it is fetched
  // code to refresh it is included here for reference
  /*const root_zsk = await fetchRootZSK();
  console.log(root_zsk);
  let str = root_zsk.join(',');
  console.log("[" + str + "]");*/

  // set up curves from vks
  const allECurves = {};
  for (const type of circuits) {
    allECurves[type] = new ECurve();
    const vk = ffjavascript.utils.unstringifyBigInts(
      JSON.parse(
        fs.readFileSync(
          path.join(__dirname, '..', '..', 'addon', 'src', type + '-vk.json'),
        ),
      ),
    );
    await allECurves[type].setup(vk, PUBLIC_INPUT_BYTES);
  }

  const records = [];

  const record_fulltime = new Timer('full');
  records.push(record_fulltime);
  const record_dvtime = new Timer('dv');
  records.push(record_dvtime);
  const record_nopetime = new Timer('nope');
  records.push(record_nopetime);

  const certPaths = process.argv.slice(2);
  const certPems = certPaths.map(p => fs.readFileSync(p, 'utf8'));

  for (let i = 0; i < N; i++) {
    // start full timer
    record_fulltime.set(1);
    // run lightweight DV checks
    record_dvtime.set(1);
    const certs = certPems.map((p,i) => parseCert(p,i));
    if (!certs[0].sans.includes(DOMAIN)) {
      throw new Error('domain does not match');
    }
    // verify signatures
    // use custom RSA implementation to avoid slowdowns
    rsaVerify(
      certs[1].subPubKeyInfo[0],
      certs[1].subPubKeyInfo[1],
      Buffer.from(certs[0].tbsCert, 'binary'),
      Buffer.from(certs[0].sig, 'binary'),
    );
    rsaVerify(
      certs[2].subPubKeyInfo[0],
      certs[2].subPubKeyInfo[1],
      Buffer.from(certs[1].tbsCert, 'binary'),
      Buffer.from(certs[1].sig, 'binary'),
    );
    record_dvtime.set(0);
    // attempt to extract NOPE proof and verify
    record_nopetime.set(1);
    if (certs[0].sans.length > 1) {
      const {nope, issuerOrgName, validityStart} = extractNope(parseDer(certPems[0]), true);
      // NOPE verification if proof found
      if (nope) {
        const {proof, type, domain} = nope;
        const hash = crypto.createHash("sha256");
        hash.update(Buffer.from(certs[0].fullSubPKInfo, 'binary'));
        const pubKeyDigest = hash.digest().toString('base64').slice(0, 43);
        // build the public signals
        const publicSignals = await buildPublicSignals(
          "nope-tools.org",
          pubKeyDigest,
          issuerOrgName,
          validityStart,
          root_zsk,
        );
        // and verify using the appropriate curve
        const res = await allECurves[type].verify(proof, publicSignals);
        if (!res) {
          console.log('Error', type);
          process.exit(1);
        }
      }
    }
    record_nopetime.set(0);
    record_fulltime.set(0);
  }

  for (const record of records) {
    record.display();
  }
}

// bench then exit process
if (process.argv.length != 5) {
  console.log('Usage: node client.js <end_cert_path> <mid_cert_path> <root_cert_path>');
  process.exit(1);
}
bench().then(() => process.exit(0));

