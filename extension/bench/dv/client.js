const fs = require('fs');
const {
  Timer,
  N,
  DOMAIN,
} = require('../lib/bench-utils.js');
const {
  parseCert,
  rsaVerify
} = require('../lib/dv-utils.js');

async function bench() {
  // set up timers
  const records = [];
  const record_fulltime = new Timer('full');
  records.push(record_fulltime);
  const record_parsetime = new Timer('parse');
  records.push(record_parsetime);
  const record_verifytime = new Timer('verify');
  records.push(record_verifytime);
  // load in certs
  const certPaths = process.argv.slice(2);
  const certPems = certPaths.map(p => fs.readFileSync(p, 'utf8'));
  // repeat N times
  for (let i = 0; i < N; i++) {
    // parse
    record_fulltime.set(1);
    record_parsetime.set(1);
    const certs = certPems.map((p,i) => parseCert(p,i));
    if (!certs[0].sans.includes(DOMAIN)) {
      throw new Error('domain does not match');
    }
    record_parsetime.set(0);
    // verify signatures
    // use custom RSA implementation to avoid slowdowns
    record_verifytime.set(1);
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
    record_verifytime.set(0);
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
