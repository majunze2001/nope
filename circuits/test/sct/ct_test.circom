pragma circom 2.0.0;

include "../../src/sct/CT.circom";

template Main() {
  signal input timestamp[8];
  signal input treesize[8];
  signal input roothash[32];
  signal input key[64];
  signal input sig[6254]; // ECDSA signature
  component CT = VerifyTreeHead();
  CT.timestamp <== timestamp;
  CT.treesize <== treesize;
  CT.roothash <== roothash;
  CT.key <== key;
  CT.sig <== sig;
}

component main = Main();