pragma circom 2.0.0;

include "sha256.circom";
include "../bigint/arith.circom";
include "../util/buffer.circom";

// verify exp is 65537
// format modulus correctly
template RSAKeyExtract(MAX_KEY_BYTES, MAX_MOD_BYTES) {
  //assert(MAX_KEY_BYTES == MAX_MOD_BYTES + 4);
  /* Inputs */
  signal input key[MAX_KEY_BYTES];
  signal input real_key_byte_len;
  /* Outputs */
  signal output mod[MAX_MOD_BYTES];
  // assert exp is 65537
  key[1] === 1;
  key[2] === 0;
  key[3] === 1;
  // build modulus with proper padding
  signal rev_unshifted_mod[MAX_MOD_BYTES];
  for (var i = 0; i < MAX_MOD_BYTES; i++) {
    rev_unshifted_mod[i] <== key[MAX_KEY_BYTES - i - 1];
  }
  // shift modulus
  // TO DO, tighten second parameter here
  signal rev_mod[MAX_MOD_BYTES];
  component Shift = SigBarrelShift(MAX_MOD_BYTES, MAX_MOD_BYTES);
  Shift.a <== rev_unshifted_mod;
  Shift.dist <== MAX_KEY_BYTES - real_key_byte_len;
  rev_mod <== Shift.b;
  // reverse modulus
  for (var i = 0; i < MAX_MOD_BYTES; i++) {
    mod[i] <== rev_mod[MAX_MOD_BYTES - i - 1];
  }
}

template RSAExpAndVerify(MAX_MOD_BYTES) {
  /* Inputs */
  signal input hash[32]; // bytes
  signal input mod[MAX_MOD_BYTES];
  signal input sig[MAX_MOD_BYTES];
  signal input real_mod_byte_len;
  /* No Outputs, validity checked */
  // modexp
  component ModExp = BigModExp(MAX_MOD_BYTES / 4, 32, 65537);
  for (var i = 0; i < MAX_MOD_BYTES / 4; i++) {
    var sa = 0;
    var sm = 0;
    for (var j = 0; j < 4; j++) {
      sa = 256 * sa + sig[i * 4 + j];
      sm = 256 * sm + mod[i * 4 + j];
    }
    ModExp.A[(MAX_MOD_BYTES / 4) - i - 1] <== sa;
    ModExp.M[(MAX_MOD_BYTES / 4) - i - 1] <== sm;
  }
  // combine ModExp.C into 8 byte blocks for convenience
  // ModExp.C is 32 bytes, so 4 blocks, so this just involves doubling up
  // no constraints, but this makes the next step cleaner
  signal C[MAX_MOD_BYTES / 8];
  for (var i = 0; i < MAX_MOD_BYTES / 8; i++) {
    C[i] <== ModExp.C[2 * i + 1] * (2 ** 32) + ModExp.C[2 * i];
  }
  // check that 8 byte blocks of digest match first 4 of modexp output
  for (var i = 0; i < 4; i++) {
    var s = 0;
    for (var j = 0; j < 8; j++) {
      s = 256 * s + hash[i * 8 + j];
    }
    C[3 - i] === s;
  }
  // check that next blocks match pkcs1.5 padding
  C[4] === 217300885422736416;
  C[5] === 938447882527703397;
  C[6] === 18446744069417742640;
  // for all remaining blocks there are 3 cases,
  // 1. if they are prior to the final block: 18446744073709551615
  // 2. final block: 562949953421311
  // 3. beyond final block: 0
  // we will handle this by checking that ModExp.C[i] = 18446744073709551615 * (1 - NotPrior[i]) + 562949953421311 * (final[i])
  component Last = SigBoolSelect((MAX_MOD_BYTES / 8) - 7);
  // implicitly assumes that real_mod_byte_len is a multiple of 8
  // TO DO, ensure this is checked in the circuit when parsing the key
  Last.index <== (real_mod_byte_len / 8) - 8;
  // technically after and final
  component NotPrior = PrefixSum((MAX_MOD_BYTES / 8) - 7);
  NotPrior.arr <== Last.flag;
  // use them to enforce checks
  for (var i = 7; i < (MAX_MOD_BYTES / 8); i++) {
    C[i] === 18446744073709551615 * (1 - NotPrior.psum[i - 7]) + 562949953421311 * Last.flag[i - 7];
  }
}

template RSASHA256SuffixVerify(MAX_MOD_BYTES, SUFFIX_BLOCKS) {
  /* Inputs */
  signal input suffix[SUFFIX_BLOCKS][64];
  signal input prev_hash_bits[8][32];
  signal input mod[MAX_MOD_BYTES];
  signal input sig[MAX_MOD_BYTES];
  signal input real_mod_byte_len;
  /* No Outputs, validity checked */
  /* Components */
  // get hash of suffix
  component Hash[SUFFIX_BLOCKS];
  for (var i = 0; i < SUFFIX_BLOCKS; i++) {
    Hash[i] = SHAChunk();
    Hash[i].chunk_bytes <== suffix[i];
    if (i == 0) {
      Hash[i].prev_hash_bits <== prev_hash_bits;
    } else {
      Hash[i].prev_hash_bits <== Hash[i - 1].hash_bits;
    }
  }
  // exp and verify
  component ExpAndVerify = RSAExpAndVerify(MAX_MOD_BYTES);
  ExpAndVerify.hash <== Hash[SUFFIX_BLOCKS - 1].hash_bytes;
  ExpAndVerify.mod <== mod;
  ExpAndVerify.sig <== sig;
  real_mod_byte_len ==> ExpAndVerify.real_mod_byte_len;
}

// assume highest order byte first in all arrays
// assume arrays are padded with 0s as necessary for smaller keys
// modulus is of the form [0s, ..., highest order byte, ..., lowest order byte]
// this is consistent with the format of the modulus in the DNSKEY records
// also assume signature is formatted this way as well
// also assume exponent is 65537 (checked before this function)
template RSASHA256Verify(MAX_MSG_BYTES, MAX_MOD_BYTES) {
  /* Inputs */
  signal input msg[MAX_MSG_BYTES];
  signal input mod[MAX_MOD_BYTES];
  signal input sig[MAX_MOD_BYTES];
  signal input real_msg_byte_len;
  signal input real_mod_byte_len;
  /* No Outputs, validity checked */
  /* Components */
  // get hash of message
  component Hash = SHA256(MAX_MSG_BYTES);
  msg ==> Hash.msg;
  real_msg_byte_len ==> Hash.real_byte_len;
  // exp and verify
  component ExpAndVerify = RSAExpAndVerify(MAX_MOD_BYTES);
  ExpAndVerify.hash <== Hash.hash;
  ExpAndVerify.mod <== mod;
  ExpAndVerify.sig <== sig;
  real_mod_byte_len ==> ExpAndVerify.real_mod_byte_len;
}

template RSAPrivKeyVerify(MAX_KEY_BYTES, MAX_FACTOR_BYTES) {
  signal input key[MAX_KEY_BYTES];
  signal input real_key_byte_len;
  signal input factors[2][MAX_FACTOR_BYTES];
  // extract modulus
  component Extract = RSAKeyExtract(MAX_KEY_BYTES, MAX_KEY_BYTES - 4);
  Extract.key <== key;
  Extract.real_key_byte_len <== real_key_byte_len;
  // check that p and q are nontrivial factors of modulus
  component Fact = NonTrivialFact((MAX_KEY_BYTES - 4) / 4, MAX_FACTOR_BYTES / 4, 32);
  // format modulus
  for (var i = 0; i < (MAX_KEY_BYTES - 4) / 4; i++) {
    var sa = 0;
    for (var j = 0; j < 4; j++) {
      sa = 256 * sa + Extract.mod[i * 4 + j];
    }
    Fact.A[(MAX_KEY_BYTES - 4) / 4 - i - 1] <== sa;
  }
  // format factors
  for (var i = 0; i < MAX_FACTOR_BYTES / 4; i++) {
    var sp = 0;
    var sq = 0;
    for (var j = 0; j < 4; j++) {
      sp = 256 * sp + factors[0][MAX_FACTOR_BYTES - (i * 4 + 3 - j) - 1];
      sq = 256 * sq + factors[1][MAX_FACTOR_BYTES - (i * 4 + 3 - j) - 1];
    }
    Fact.P[i] <== sp;
    Fact.Q[i] <== sq;
  }
}
