pragma circom 2.0.0;

include "../crypto/sha256.circom";
include "../util/buffer.circom";
include "RRSIG.circom";

template DSSuffixParse(ALGO) {
  signal input suffix[128];
  signal input offset;
  signal input ksk_hash[32];
  // verify that suffix is 8 || 2 || hash of ksk
  // to verify hash is contained in suffix, we need to shift the suffix
  component Shift = SigBarrelShift(128, 128 - 32 - 2 - 8);
  Shift.a <== suffix;
  Shift.dist <== offset;
  // check algorithm
  Shift.b[0] === ALGO;
  // check digest type
  Shift.b[1] === 2;
  // check that hash matches suffix
  for (var i = 0; i < 32; i++) {
    Shift.b[i + 2] === ksk_hash[i];
  }
}

template VerifyDSSuffixFromHashRSA(MAX_SIG_BYTES, MAX_KEY_BYTES, ALGO) {
    /* inputs */
  // suffix requires looking at last 2 * 64 bytes in case threshold is crossed
  // we assume the DS RRset is at least 56 bytes long here so that the suffix can be this long
  // this is a safe assumption because of the fixed length headers on the RRset and on each RR.
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

  // verify that suffix is ALGO || 2 || hash of ksk
  // to verify hash is contained in suffix, we need to shift the suffix
  component DSSuffix = DSSuffixParse(ALGO);
  DSSuffix.suffix <== suffix;
  DSSuffix.offset <== offset;
  DSSuffix.ksk_hash <== ksk_hash;
}

template VerifyDSSuffixFromHashECDSA(ALGO) {
  /* inputs */
  // suffix requires looking at last 2 * 64 bytes in case threshold is crossed
  // we assume the DS RRset is at least 56 bytes long here so that the suffix can be this long
  // this is a safe assumption because of the fixed length headers on the RRset and on each RR.
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

  // verify that suffix is ALGO || 2 || hash of ksk
  // to verify hash is contained in suffix, we need to shift the suffix
  component DSSuffix = DSSuffixParse(ALGO);
  DSSuffix.suffix <== suffix;
  DSSuffix.offset <== offset;
  DSSuffix.ksk_hash <== ksk_hash;
}
