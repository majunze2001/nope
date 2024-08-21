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
  // 18 + 26 + 2 * (26 + 10 + 4 + 260)
  var MAX_TLD_DNSKEY_REC_LEN = 644;
  // 18 + 90 + 2 * (90 + 10 + 4 + 260)
  var MAX_SLD_DNSKEY_REC_LEN = 836;
  // inputs
  signal input rec[MAX_TLD_DNSKEY_REC_LEN];
  signal input sig[MAX_RSA_SIG_LEN];
  signal input ksk[MAX_RSA_KEY_LEN];
  signal input sname[MAX_TLD_NAME_LEN];
  signal input real_rec_byte_len;
  signal input real_sig_byte_len;
  signal input real_ksk_byte_len;
  signal input real_name_byte_len;
  // signature verification
  component VerifyRRSIG = VerifyRRSIGRSA(MAX_TLD_DNSKEY_REC_LEN, MAX_RSA_SIG_LEN, MAX_RSA_KEY_LEN, MAX_TLD_NAME_LEN, 48);
  VerifyRRSIG.rec <== rec;
  VerifyRRSIG.sig <== sig;
  VerifyRRSIG.key <== ksk;
  VerifyRRSIG.sname <== sname;
  VerifyRRSIG.real_rec_byte_len <== real_rec_byte_len;
  VerifyRRSIG.real_sig_byte_len <== real_sig_byte_len;
  VerifyRRSIG.real_key_byte_len <== real_ksk_byte_len;
  VerifyRRSIG.real_sname_byte_len <== real_name_byte_len;
}

component main = Main();
