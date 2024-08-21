pragma circom 2.0.0;

include "../../../src/dns/DS.circom";

template Main() {
  signal input suffix[128];
  signal input offset; // where the algorithm starts in the suffix
  signal input prev_hash_bits[8][32];
	signal input sig[6254];
	signal input key[64];
  // KSK hash here is hash(domain || flags || protocol || algo || key)
  signal input ksk_hash[32];

  // verify signature on suffix
  signal blockedsuffix[2][64];
  for (var i = 0; i < 2; i++) {
    for (var j = 0; j < 64; j++) {
      blockedsuffix[i][j] <== suffix[i * 64 + j];
    }
  }
  component RRSIG = VerifyRRSIGSuffixECDSA(2);
  RRSIG.suffix <== blockedsuffix;
  RRSIG.prev_hash_bits <== prev_hash_bits;
  RRSIG.sig <== sig;
  RRSIG.key <== key;
}

component main = Main();