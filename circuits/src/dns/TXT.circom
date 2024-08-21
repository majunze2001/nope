pragma circom 2.0.0;

include "./RRSIG.circom";
include "../util/buffer.circom";

// verify TXT record given suffix
template VerifyTXTSuffixRSA(MAX_SIG_BYTES, MAX_KEY_BYTES) {
	/* inputs */
  // suffix contains hash of preimage, checked elsewhere
  signal input suffix[64];
  signal input prev_hash_bits[8][32];
	signal input sig[MAX_SIG_BYTES];
	signal input key[MAX_KEY_BYTES];
  signal input real_sig_byte_len;
  signal input real_key_byte_len;

  // verify signature 
  signal blockedsuffix[1][64];
  for (var i = 0; i < 64; i++) {
    blockedsuffix[0][i] <== suffix[i];
  }
  component RRSIG = VerifyRRSIGSuffixRSA(MAX_SIG_BYTES, MAX_KEY_BYTES, 1);
  RRSIG.suffix <== blockedsuffix;
  RRSIG.prev_hash_bits <== prev_hash_bits;
  RRSIG.sig <== sig;
  RRSIG.key <== key;
  RRSIG.real_sig_byte_len <== real_sig_byte_len;
  RRSIG.real_key_byte_len <== real_key_byte_len;
}

// verify TXT record given suffix
template VerifyTXTSuffixECDSA() {
	/* inputs */
  // suffix contains hash of preimage, checked elsewhere
  signal input suffix[64];
  signal input prev_hash_bits[8][32];
	signal input sig[6254];
	signal input key[64];

  // verify signature 
  signal blockedsuffix[1][64];
  for (var i = 0; i < 64; i++) {
    blockedsuffix[0][i] <== suffix[i];
  }
  component RRSIG = VerifyRRSIGSuffixECDSA(1);
  RRSIG.suffix <== blockedsuffix;
  RRSIG.prev_hash_bits <== prev_hash_bits;
  RRSIG.sig <== sig;
  RRSIG.key <== key;
}
