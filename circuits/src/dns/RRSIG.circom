pragma circom 2.0.0;

include "../crypto/RSA.circom";
include "../crypto/ECDSA.circom";
include "../util/buffer.circom";

template VerifyRRSIGRSA(MAX_REC_BYTES, MAX_SIG_BYTES, MAX_KEY_BYTES, MAX_SNAME_BYTES, EXPECTED_TYPE_COVERED) {
  /* inputs */
  signal input rec[MAX_REC_BYTES];
  signal input sig[MAX_SIG_BYTES];
  signal input key[MAX_KEY_BYTES];
  signal input sname[MAX_SNAME_BYTES];
	signal input real_rec_byte_len;
  signal input real_sig_byte_len;
  signal input real_key_byte_len;
  signal input real_sname_byte_len;

  // check record type
  EXPECTED_TYPE_COVERED === 256 * rec[0] + rec[1];

  // slice rec to get rec[18:]
  component Slice = Slice(MAX_REC_BYTES, 18, 18 + MAX_SNAME_BYTES);
  Slice.a <== rec;
  // check that rec[18] onwards matches the signer
  component PrefixMatch = AssertPrefixMatch(MAX_SNAME_BYTES, 0);
  PrefixMatch.a <== Slice.b;
  PrefixMatch.b <== sname;
  PrefixMatch.real_len <== real_sname_byte_len;

  // check that real_key_byte_len === 4 + real_sig_byte_len
  real_key_byte_len === real_sig_byte_len + 4;

  // check exponent = 65537 ([1:4]) and 
  // extract and pad modulus
  component Extract = RSAKeyExtract(MAX_KEY_BYTES, MAX_SIG_BYTES);
  Extract.key <== key;
  Extract.real_key_byte_len <== real_key_byte_len;
  // check RSA sig
  component VerifySig = RSASHA256Verify(MAX_REC_BYTES, MAX_SIG_BYTES);
  VerifySig.msg <== rec;
  VerifySig.mod <== Extract.mod;
  VerifySig.sig <== sig;
  VerifySig.real_msg_byte_len <== real_rec_byte_len;
  VerifySig.real_mod_byte_len <== real_key_byte_len - 4;
}

template VerifyRRSIGECDSA(MAX_REC_BYTES, MAX_SNAME_BYTES, EXPECTED_TYPE_COVERED) {
  /* inputs */
  signal input rec[MAX_REC_BYTES];
  signal input sig[6254];
  signal input key[64];
  signal input sname[MAX_SNAME_BYTES];
	signal input real_rec_byte_len;
  signal input real_sname_byte_len;

  // check record type
  EXPECTED_TYPE_COVERED === 256 * rec[0] + rec[1];

  // slice rec to get rec[18:]
  component Slice = Slice(MAX_REC_BYTES, 18, 18 + MAX_SNAME_BYTES);
  Slice.a <== rec;
  // check that rec[18] onwards matches the signer
  component PrefixMatch = AssertPrefixMatch(MAX_SNAME_BYTES, 0);
  PrefixMatch.a <== Slice.b;
  PrefixMatch.b <== sname;
  PrefixMatch.real_len <== real_sname_byte_len;

  // unpack sig
  component UnpackSig = ECDSAP256SHA256SigUnpack();
  UnpackSig.sig <== sig;
  // check ECDSA sig
  component VerifySig = ECDSAP256SHA256Verify(MAX_REC_BYTES);
  VerifySig.msg <== rec;
  VerifySig.real_msg_byte_len <== real_rec_byte_len;
  VerifySig.key <== key;
  VerifySig.sig_s_inv <== UnpackSig.sig_s_inv;
  VerifySig.sig_rx <== UnpackSig.sig_rx;
  VerifySig.sig_ry <== UnpackSig.sig_ry;
  VerifySig.u <== UnpackSig.u;
  VerifySig.u2sign <== UnpackSig.u2sign;
  VerifySig.AUX <== UnpackSig.AUX;
  VerifySig.addres_x <== UnpackSig.addres_x;
  VerifySig.addres_y <== UnpackSig.addres_y;
  VerifySig.addadva <== UnpackSig.addadva;
  VerifySig.addadvb <== UnpackSig.addadvb;
}

// for TXT and DS records
template VerifyRRSIGSuffixRSA(MAX_SIG_BYTES, MAX_KEY_BYTES, SUFFIX_BLOCKS) {
  /* inputs */
  signal input suffix[SUFFIX_BLOCKS][64];
  signal input prev_hash_bits[8][32];
  signal input sig[MAX_SIG_BYTES];
  signal input key[MAX_KEY_BYTES];
  signal input real_sig_byte_len;
  signal input real_key_byte_len;
  // check exponent = 65537 ([1:4]) and 
  // extract and pad modulus
  component Extract = RSAKeyExtract(MAX_KEY_BYTES, MAX_SIG_BYTES);
  Extract.key <== key;
  Extract.real_key_byte_len <== real_key_byte_len;
  // check RSA sig
  component VerifySig = RSASHA256SuffixVerify(MAX_SIG_BYTES, SUFFIX_BLOCKS);
  VerifySig.suffix <== suffix;
  VerifySig.prev_hash_bits <== prev_hash_bits;
  VerifySig.mod <== Extract.mod;
  VerifySig.sig <== sig;
  VerifySig.real_mod_byte_len <== real_key_byte_len - 4;
}

// for TXT and DS records
template VerifyRRSIGSuffixECDSA(SUFFIX_BLOCKS) {
  /* inputs */
  signal input suffix[SUFFIX_BLOCKS][64];
  signal input prev_hash_bits[8][32];
  signal input sig[6254];
  signal input key[64];
  // unpack sig
  component UnpackSig = ECDSAP256SHA256SigUnpack();
  UnpackSig.sig <== sig;
  // check ECDSA sig
  component VerifySig = ECDSAP256SHA256SuffixVerify(SUFFIX_BLOCKS);
  VerifySig.suffix <== suffix;
  VerifySig.prev_hash_bits <== prev_hash_bits;
  VerifySig.key <== key;
  VerifySig.sig_s_inv <== UnpackSig.sig_s_inv;
  VerifySig.sig_rx <== UnpackSig.sig_rx;
  VerifySig.sig_ry <== UnpackSig.sig_ry;
  VerifySig.u <== UnpackSig.u;
  VerifySig.u2sign <== UnpackSig.u2sign;
  VerifySig.AUX <== UnpackSig.AUX;
  VerifySig.addres_x <== UnpackSig.addres_x;
  VerifySig.addres_y <== UnpackSig.addres_y;
  VerifySig.addadva <== UnpackSig.addadva;
  VerifySig.addadvb <== UnpackSig.addadvb;
}