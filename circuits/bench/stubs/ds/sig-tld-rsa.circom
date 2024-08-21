pragma circom 2.0.0;

include "../../../src/dns/DS.circom";

template Main() {
  var MAX_SIG_BYTES = 256;
  var MAX_KEY_BYTES = 260;
  signal input suffix[128];
  signal input offset; // where the algorithm starts in the suffix
  signal input prev_hash_bits[8][32];
	signal input sig[MAX_SIG_BYTES];
	signal input key[MAX_KEY_BYTES];
  // KSK hash here is hash(domain || flags || protocol || algo || key)
  signal input ksk_hash[32];
  // real lengths of each input
  signal input real_sig_byte_len;
  signal input real_key_byte_len;
  // verify signature on suffix
  signal blockedsuffix[2][64];
  for (var i = 0; i < 2; i++) {
    for (var j = 0; j < 64; j++) {
      blockedsuffix[i][j] <== suffix[i * 64 + j];
    }
  }
  component RRSIG = VerifyRRSIGSuffixRSA(MAX_SIG_BYTES, MAX_KEY_BYTES, 2);
  RRSIG.suffix <== blockedsuffix;
  RRSIG.prev_hash_bits <== prev_hash_bits;
  RRSIG.sig <== sig;
  RRSIG.key <== key;
  RRSIG.real_sig_byte_len <== real_sig_byte_len;
  RRSIG.real_key_byte_len <== real_key_byte_len;
}

component main = Main();