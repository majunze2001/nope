pragma circom 2.0.0;

include "../crypto/sha256.circom";
include "../crypto/ECDSA.circom";

template VerifyTreeHead() {
  // inputs
  signal input timestamp[8];
  signal input treesize[8];
  signal input roothash[32];
  //signal input head[1 + 1 + 8 + 8 + 32];
  signal input key[64];
  signal input sig[6254]; // ECDSA signature
  // timestamp validated externally
  // tree size doesn't need to be validated
  // root hash doesn't need to be validated
  // compute hash and check sig
  // initial hash values
  var H[8] = [
    0x6a09e667, 0xbb67ae85,
    0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
  ];
  component Hash = SHAChunk();
  // block bytes
  Hash.chunk_bytes[0] <== 0;
  Hash.chunk_bytes[1] <== 1;
  for (var i = 0; i < 8; i++) {
    Hash.chunk_bytes[i + 2] <== timestamp[i];
    Hash.chunk_bytes[i + 10] <== treesize[i];
  }
  for (var i = 0; i < 32; i++) {
    Hash.chunk_bytes[i + 18] <== roothash[i];
  }
  Hash.chunk_bytes[50] <== 128;
  for (var i = 51; i < 62; i++) {
    Hash.chunk_bytes[i] <== 0;
  }
  Hash.chunk_bytes[62] <== 1;
  Hash.chunk_bytes[63] <== 144;
  // prev bits from H
  for (var j = 0; j < 8; j++) {
    for (var k = 0; k < 32; k++) {
      Hash.prev_hash_bits[j][k] <== (H[j] >> (31 - k)) & 1;
    }
  }
  // unpack sig
  component UnpackSig = ECDSAP256SHA256SigUnpack();
  UnpackSig.sig <== sig;
  // check ECDSA sig
  component VerifySig = ECDSAP256ValidateHash();
  VerifySig.hash <== Hash.hash_bytes;
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
