pragma circom 2.0.0;

include "../../../src/crypto/sha256.circom";

template Main() {
  // standard constants
  var MAX_SLD_NAME_LEN = 63 + 24 + 3;
  var MAX_TLD_NAME_LEN = 24 + 2;
  var MAX_RSA_SIG_LEN = 256;
  var MAX_RSA_KEY_LEN = MAX_RSA_SIG_LEN + 4;
  var ECDSA_SIG_LEN = 6254; // includes aux data
  var ECDSA_KEY_LEN = 64;

  signal input sld_ksk[MAX_SLD_NAME_LEN + 4 + ECDSA_KEY_LEN];
  signal input sld_ksk_len;

  component HashKSK = SHA256(MAX_SLD_NAME_LEN + 4 + ECDSA_KEY_LEN);
  HashKSK.msg <== sld_ksk;
  HashKSK.real_byte_len <== sld_ksk_len;
}

component main = Main();
