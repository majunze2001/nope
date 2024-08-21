pragma circom 2.0.0;

include "../../../src/dns/TXT.circom";

template Main() {
  signal input suffix[64];
  signal input prev_hash_bits[8][32];
	signal input sig[6254];
	signal input key[64];

  component TXT = VerifyTXTSuffixECDSA();
  TXT.suffix <== suffix;
  TXT.prev_hash_bits <== prev_hash_bits;
  TXT.sig <== sig;
  TXT.key <== key;
}

component main = Main();
