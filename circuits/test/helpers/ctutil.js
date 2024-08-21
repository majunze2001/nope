const https = require('https');
const { flattenEccSigAux } = require('./util.js');
const { buildSigWitness } = require('./eccutil.js');

// function to make http request
// boilerplate 
function getJSON(url) {
  return new Promise((resolve, reject) => {
    https.get(url, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        resolve(JSON.parse(data));
      });
    }).on('error', (err) => {
      reject(err);
    });
  });
}

async function getSCTHead() {
  // build return map
  var ret = {};
  // get head of CT log
  const head = await getJSON("https://ct.googleapis.com/logs/us1/argon2024/ct/v1/get-sth");
  ret['timestamp'] = [...Buffer.from(head.timestamp.toString(16).padStart(16, '0'), 'hex')];
  ret['treesize'] = [...Buffer.from(head.tree_size.toString(16).padStart(16, '0'), 'hex')];
  ret['roothash'] = [...Buffer.from(head.sha256_root_hash, 'base64')];
  // get sig
  const tmp = Buffer.from(head.tree_head_signature, 'base64');
  const rLen = tmp[7];
  const sLen = tmp[8 + rLen + 1];
  const r = tmp.slice(8, 8 + rLen);
  const s = tmp.slice(8 + rLen + 2, 8 + rLen + 2 + sLen);
  const sig = Buffer.concat([r.slice(-32), s.slice(-32)]);
  // get key
  const logList = await getJSON("https://www.gstatic.com/ct/log_list/v3/log_list.json");
  ret['key'] = [...Buffer.from(logList.operators[0].logs[0].key, 'base64').slice(-64)];
  ret['sig'] = flattenEccSigAux(
    buildSigWitness(
      Buffer.concat([
        Buffer.from([0]),
        Buffer.from([1]),
        Buffer.from(head.timestamp.toString(16).padStart(16, '0'), 'hex'),
        Buffer.from(head.tree_size.toString(16).padStart(16, '0'), 'hex'),
        Buffer.from(head.sha256_root_hash, 'base64')
      ]),
      sig,
      ret['key']
    )
  );
  return ret;
}

module.exports = {
  getSCTHead
};