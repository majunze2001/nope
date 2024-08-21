const asn1Parser = require('./asn1-parser.js');
const ASN1 = asn1Parser.ASN1;
const PEM = asn1Parser.PEM;

// parseDer
function parseDer(chain) {
  // if it is a LE chain, we extract the first cert
  const lines = chain.split('\n');
  const cert = lines
    .slice(0, lines.indexOf('-----END CERTIFICATE-----') + 1)
    .join('\n');
  const der = PEM.parseBlock(cert).der;
  return der;
}

function extractSANs(json) {
  const extensions = json.children[0].children[7].children[0].children;
  // SAN extension
  const filter_object = {type: 6, value: [85, 29, 17]};
  const SAN = extensions.find(
    e =>
      e.children[0]?.type === filter_object.type &&
      filter_object.value.every(
        (val, index) => val === e.children[0]?.value[index],
      ),
  )?.children[1];
  // utf-8 SANs
  const sans = SAN.children[0].children.map(e =>
    String.fromCharCode(...e.value),
  );
  return sans;
}


module.exports = {
  extractSANs,
  parseDer,
  ASN1,
  PEM,
};
