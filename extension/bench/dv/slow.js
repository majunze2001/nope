const fs = require('fs');
const {
  Timer,
  N,
  DOMAIN,
} = require('../lib/bench-utils.js');
const forge = require('node-forge');

// benchmark script with forge instead of custom RSA implementation
// slower than dv/client.js but here for comparison
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
  // repeat N / 10 times (scaled down to avoid timeout)
  for (let i = 0; i < N / 10; i++) {
    // parse
    record_fulltime.set(1);
    record_parsetime.set(1);
    const certs = certPems.map((p,i) => forge.pki.certificateFromPem(p));
    // ensure that first certificate is for the domain
    if (!certs[0].subject.getField('CN').value.includes(DOMAIN)) {
      throw new Error('domain does not match');
    }
    record_parsetime.set(0);
    // verify signatures
    record_verifytime.set(1);
    for (let j = 0; j < certs.length - 1; j++) {
      const issuer = certs[j + 1];
      const subject = certs[j];
      if (!issuer.verify(subject)) {
        throw new Error(`Error: certificate ${j} is not signed by certificate ${j + 1}`);
      }
    }
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
