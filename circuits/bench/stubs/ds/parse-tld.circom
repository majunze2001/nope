pragma circom 2.0.0;

include "../../../src/dns/DS.circom";

template Main() {
  signal input suffix[128];
  signal input offset;
  signal input ksk_hash[32];
  component DSSuffixParse = DSSuffixParse(13); // algo doesn't actually matter here
  DSSuffixParse.suffix <== suffix;
  DSSuffixParse.offset <== offset;
  DSSuffixParse.ksk_hash <== ksk_hash;
}

component main = Main();