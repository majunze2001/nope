pragma circom 2.0.0;

include "../../../src/dns/TXT.circom";

template Main(MAX_SIG_BYTES, MAX_KEY_BYTES) {
  signal input suffix[64];
  signal input prev_hash_bits[8][32];
	signal input sig[MAX_SIG_BYTES];
	signal input key[MAX_KEY_BYTES];
  signal input real_sig_byte_len;
  signal input real_key_byte_len;

  component TXT = VerifyTXTSuffixRSA(MAX_SIG_BYTES, MAX_KEY_BYTES);
  TXT.suffix <== suffix;
  TXT.prev_hash_bits <== prev_hash_bits;
  TXT.sig <== sig;
  TXT.key <== key;
  TXT.real_sig_byte_len <== real_sig_byte_len;
  TXT.real_key_byte_len <== real_key_byte_len;
}

component main = Main(256, 260);
