pragma circom 2.0.0;

include "../dns/DS.circom";
include "../dns/DNSKEY.circom";
include "../dns/TXT.circom";
include "../sct/CT.circom";

// standard nope system circuit
// used when the TLD is using ECDSA keys
// and when the SLD has an RSA KSK
template NopeECDSARSAManaged() {
  // standard constants
  var MAX_SLD_NAME_LEN = 63 + 24 + 3;
  var MAX_TLD_NAME_LEN = 24 + 2;
  var MAX_RSA_SIG_LEN = 256;
  var MAX_RSA_KEY_LEN = MAX_RSA_SIG_LEN + 4;
  var ECDSA_SIG_LEN = 6254; // includes aux data
  var ECDSA_KEY_LEN = 64;
  // 18 + 26 + 2 * (26 + 10 + 4 + 64)
  var MAX_TLD_DNSKEY_REC_LEN = 252;
  // 18 + 90 + 2 * (90 + 10 + 4 + 260)
  var MAX_SLD_DNSKEY_REC_LEN = 836;

  /* TRUE PUBLIC INPUTS */
  // pack public input bytes into field elements to reduce verifier complexity
  var N_PUB_BYTES = MAX_SLD_NAME_LEN + MAX_RSA_KEY_LEN + 2 + 43;
  var N_PUB_FIELDS = 1 + (N_PUB_BYTES - 1) \ 31;
  signal input packed_pub_inputs[N_PUB_FIELDS];

  /* FAUX PUBLIC INPUTS */
  signal input sld_name[MAX_SLD_NAME_LEN];
  signal input root_zsk[MAX_RSA_KEY_LEN];
  signal input root_zsk_len_bytes[2];
  signal root_zsk_len <== root_zsk_len_bytes[0] + 256 * root_zsk_len_bytes[1];
  signal input pub_digest[43];

  /* PRIVATE INPUTS */
  // DS record suffix for the TLD
  signal input tld_ds_rec_suffix[128];
  signal input tld_ds_hash_offset;
  signal input tld_ds_prev_hash_bits[8][32];
  signal input tld_ds_sig[MAX_RSA_SIG_LEN];
  signal input tld_ds_sig_len;
  // DNSKEY record for the TLD
  signal input tld_dnskey_rec[MAX_TLD_DNSKEY_REC_LEN];
  signal input tld_dnskey_rec_len;
  signal input tld_dnskey_sig[ECDSA_SIG_LEN];
  signal input tld_ksk[MAX_TLD_NAME_LEN + 4 + ECDSA_KEY_LEN];
  signal input tld_ksk_len;
  // DS record suffix for the SLD
  signal input sld_ds_rec_suffix[128];
  signal input sld_ds_hash_offset;
  signal input sld_ds_prev_hash_bits[8][32];
  signal input sld_ds_sig[ECDSA_SIG_LEN];
  signal input sld_ds_key[ECDSA_KEY_LEN];
  // DNSKEY record for the SLD
  signal input sld_dnskey_rec[MAX_SLD_DNSKEY_REC_LEN];
  signal input sld_dnskey_rec_len;
  signal input sld_dnskey_sig[MAX_RSA_SIG_LEN];
  signal input sld_dnskey_sig_len;
  signal input sld_ksk[MAX_SLD_NAME_LEN + 4 + MAX_RSA_KEY_LEN];
  signal input sld_ksk_len;
  // TXT record for the SLD
  signal input sld_txt_rec_suffix[64];
  signal input sld_txt_prev_hash_bits[8][32];
  signal input sld_txt_sig[MAX_RSA_SIG_LEN];
  signal input sld_txt_sig_len;
  signal input sld_txt_key[MAX_RSA_KEY_LEN];
  signal input sld_txt_key_len;

  /* Components */
  // verify public input packing
  component PubDecompress = AssertPubDecompress(N_PUB_BYTES);
  var tmp = 0;
  for (var i = 0; i < MAX_SLD_NAME_LEN; i++) {
    PubDecompress.bytes[tmp] <== sld_name[i]; tmp += 1;
  }
  for (var i = 0; i < MAX_RSA_KEY_LEN; i++) {
    PubDecompress.bytes[tmp] <== root_zsk[i]; tmp += 1;
  }
  PubDecompress.bytes[tmp] <== root_zsk_len_bytes[0]; tmp += 1;
  PubDecompress.bytes[tmp] <== root_zsk_len_bytes[1]; tmp += 1;
  for (var i = 0; i < 43; i++) {
    PubDecompress.bytes[tmp] <== pub_digest[i]; tmp += 1;
  }
  PubDecompress.packs <== packed_pub_inputs;

  // ensure well-formedness of SLD name and extract tld_name
  signal tld_name[MAX_TLD_NAME_LEN];
  component NameShift = SigBarrelShift(MAX_SLD_NAME_LEN, 63);
  NameShift.a <== sld_name;
  NameShift.dist <== sld_name[0] + 1;
  for (var i = 0; i < MAX_TLD_NAME_LEN; i++) {
    tld_name[i] <== NameShift.b[i];
  }
  signal tld_name_len <== tld_name[0] + 2;
  signal sld_name_len <== sld_name[0] + 1 + tld_name_len;

  // match SLD name to start of SLD KSK
  component KSKPrefixMatch = AssertPrefixMatch(MAX_SLD_NAME_LEN, 0);
  for (var i = 0; i < MAX_SLD_NAME_LEN; i++) {
    KSKPrefixMatch.a[i] <== sld_ksk[i];
    KSKPrefixMatch.b[i] <== sld_name[i];
  }
  KSKPrefixMatch.real_len <== sld_name_len;

  // verify TLD DS record
  component HashTLDKSK = SHA256(MAX_TLD_NAME_LEN + 4 + ECDSA_KEY_LEN);
  HashTLDKSK.msg <== tld_ksk;
  HashTLDKSK.real_byte_len <== tld_ksk_len;
  component TLDDSVerify = VerifyDSSuffixFromHashRSA(MAX_RSA_SIG_LEN, MAX_RSA_KEY_LEN, 13);
  TLDDSVerify.suffix <== tld_ds_rec_suffix;
  TLDDSVerify.offset <== tld_ds_hash_offset;
  TLDDSVerify.prev_hash_bits <== tld_ds_prev_hash_bits;
  TLDDSVerify.sig <== tld_ds_sig;
  TLDDSVerify.key <== root_zsk;
  TLDDSVerify.ksk_hash <== HashTLDKSK.hash;
  TLDDSVerify.real_sig_byte_len <== tld_ds_sig_len;
  TLDDSVerify.real_key_byte_len <== root_zsk_len;

  // verify TLD DNSKEY record
  component TLDKSKExtract = ExtractKSK(MAX_TLD_NAME_LEN, 64, 13);
  TLDKSKExtract.ksk <== tld_ksk;
  TLDKSKExtract.real_ksk_byte_len <== tld_ksk_len;
  TLDKSKExtract.real_name_byte_len <== tld_name_len;
  component TLDDNSKEYVerify = VerifyDNSKEYECDSA(MAX_TLD_DNSKEY_REC_LEN, MAX_TLD_NAME_LEN);
  TLDDNSKEYVerify.rec <== tld_dnskey_rec;
  TLDDNSKEYVerify.real_rec_byte_len <== tld_dnskey_rec_len;
  TLDDNSKEYVerify.sig <== tld_dnskey_sig;
  TLDDNSKEYVerify.ksk <== TLDKSKExtract.key;
  TLDDNSKEYVerify.zsk <== sld_ds_key;
  TLDDNSKEYVerify.sname <== tld_name;
  TLDDNSKEYVerify.real_name_byte_len <== tld_name_len;

  // verify SLD DS record
  component HashSLDKSK = SHA256(MAX_SLD_NAME_LEN + 4 + MAX_RSA_KEY_LEN);
  HashSLDKSK.msg <== sld_ksk;
  HashSLDKSK.real_byte_len <== sld_ksk_len;
  component SLDDSVerify = VerifyDSSuffixFromHashECDSA(8);
  SLDDSVerify.suffix <== sld_ds_rec_suffix;
  SLDDSVerify.offset <== sld_ds_hash_offset;
  SLDDSVerify.prev_hash_bits <== sld_ds_prev_hash_bits;
  SLDDSVerify.sig <== sld_ds_sig;
  SLDDSVerify.key <== sld_ds_key;
  SLDDSVerify.ksk_hash <== HashSLDKSK.hash;

  // verify SLD DNSKEY record
  component SLDKSKExtract = ExtractKSK(MAX_SLD_NAME_LEN, MAX_RSA_KEY_LEN, 8);
  SLDKSKExtract.ksk <== sld_ksk;
  SLDKSKExtract.real_ksk_byte_len <== sld_ksk_len;
  SLDKSKExtract.real_name_byte_len <== sld_name_len;
  component SLDDNSKEYVerify = VerifyDNSKEYRSA(MAX_SLD_DNSKEY_REC_LEN, MAX_RSA_SIG_LEN, MAX_RSA_KEY_LEN, MAX_SLD_NAME_LEN);
  SLDDNSKEYVerify.rec <== sld_dnskey_rec;
  SLDDNSKEYVerify.real_rec_byte_len <== sld_dnskey_rec_len;
  SLDDNSKEYVerify.sig <== sld_dnskey_sig;
  SLDDNSKEYVerify.real_sig_byte_len <== sld_dnskey_sig_len;
  SLDDNSKEYVerify.ksk <== SLDKSKExtract.key;
  SLDDNSKEYVerify.real_ksk_byte_len <== SLDKSKExtract.real_key_byte_len;
  SLDDNSKEYVerify.zsk <== sld_txt_key;
  SLDDNSKEYVerify.real_zsk_byte_len <== sld_txt_key_len;
  SLDDNSKEYVerify.sname <== sld_name;
  SLDDNSKEYVerify.real_name_byte_len <== sld_name_len;

  // verify SLD TXT record
  component SLDTXTVerify = VerifyTXTSuffixRSA(MAX_RSA_SIG_LEN, MAX_RSA_KEY_LEN);
  SLDTXTVerify.suffix <== sld_txt_rec_suffix;
  SLDTXTVerify.prev_hash_bits <== sld_txt_prev_hash_bits;
  SLDTXTVerify.sig <== sld_txt_sig;
  SLDTXTVerify.key <== sld_txt_key;
  SLDTXTVerify.real_sig_byte_len <== sld_txt_sig_len;
  SLDTXTVerify.real_key_byte_len <== sld_txt_key_len;

  // verify that pub_digest is in sld_txt_rec_suffix
  for (var i = 0; i < 43; i++) {
		pub_digest[i] === sld_txt_rec_suffix[i + 5];
	}
}

component main { public[packed_pub_inputs] } = NopeECDSARSAManaged();
