pragma circom 2.0.0;

include "../../../src/dns/DS.circom";
include "../../../src/dns/DNSKEY.circom";

template Main() {
  // standard constants
  var MAX_SLD_NAME_LEN = 63 + 24 + 3;
  var MAX_TLD_NAME_LEN = 24 + 2;
  var MAX_RSA_SIG_LEN = 256;
  var MAX_RSA_KEY_LEN = MAX_RSA_SIG_LEN + 4;
  var ECDSA_SIG_LEN = 6254; // includes aux data
  var ECDSA_KEY_LEN = 64;

  signal input sld_name_len;
  // SLD KSK and factors
  signal input sld_ksk[MAX_SLD_NAME_LEN + 4 + MAX_RSA_KEY_LEN];
  signal input sld_ksk_len;
  signal input sld_ksk_factors[2][MAX_RSA_SIG_LEN / 2];

  // verify SLD KSK factors
  component SLDKSKExtract = ExtractKSK(MAX_SLD_NAME_LEN, MAX_RSA_KEY_LEN, 8);
  SLDKSKExtract.ksk <== sld_ksk;
  SLDKSKExtract.real_ksk_byte_len <== sld_ksk_len;
  SLDKSKExtract.real_name_byte_len <== sld_name_len;
  component RSAPrivateKeyVerify = RSAPrivKeyVerify(MAX_RSA_KEY_LEN, MAX_RSA_SIG_LEN / 2);
  RSAPrivateKeyVerify.key <== SLDKSKExtract.key;
  RSAPrivateKeyVerify.real_key_byte_len <== SLDKSKExtract.real_key_byte_len;
  RSAPrivateKeyVerify.factors <== sld_ksk_factors;
}

component main = Main();
