pragma circom 2.0.0;

include "../../../src/dns/DNSKEY.circom";
include "../../../src/dns/DS.circom";

template Main() {
  // standard constants
  var MAX_SLD_NAME_LEN = 63 + 24 + 3;
  var MAX_TLD_NAME_LEN = 24 + 2;
  var MAX_RSA_SIG_LEN = 256;
  var MAX_RSA_KEY_LEN = MAX_RSA_SIG_LEN + 4;
  var ECDSA_SIG_LEN = 6254; // includes aux data
  var ECDSA_KEY_LEN = 64;
  // inputs
  signal input sld_name_len;
  // DS record suffix for the SLD
  signal input sld_ds_rec_suffix[128];
  signal input sld_ds_hash_offset;
  signal input sld_ds_prev_hash_bits[8][32];
  signal input sld_ds_sig[MAX_RSA_SIG_LEN];
  signal input sld_ds_sig_len;
  signal input sld_ds_key[MAX_RSA_KEY_LEN];
  signal input sld_ds_key_len;
  // SLD KSK and priv key info
  signal input sld_ksk[MAX_SLD_NAME_LEN + 4 + ECDSA_KEY_LEN];
  signal input sld_ksk_len;
  signal input sld_ksk_priv_k[256];
  signal input sld_ksk_priv_addres_x[21][8];
  signal input sld_ksk_priv_addres_y[21][8];
  signal input sld_ksk_priv_addadva[22][3];
  signal input sld_ksk_priv_addadvb[22][4];
  signal input sld_ksk_priv_Gadv_x[22][8];
  signal input sld_ksk_priv_Gadv_y[22][8];
  // verify SLD DS record
  component HashSLDKSK = SHA256(MAX_SLD_NAME_LEN + 4 + ECDSA_KEY_LEN);
  HashSLDKSK.msg <== sld_ksk;
  HashSLDKSK.real_byte_len <== sld_ksk_len;
  component SLDDSVerify = VerifyDSSuffixFromHashRSA(MAX_RSA_SIG_LEN, MAX_RSA_KEY_LEN, 13);
  SLDDSVerify.suffix <== sld_ds_rec_suffix;
  SLDDSVerify.offset <== sld_ds_hash_offset;
  SLDDSVerify.prev_hash_bits <== sld_ds_prev_hash_bits;
  SLDDSVerify.sig <== sld_ds_sig;
  SLDDSVerify.key <== sld_ds_key;
  SLDDSVerify.ksk_hash <== HashSLDKSK.hash;
  SLDDSVerify.real_sig_byte_len <== sld_ds_sig_len;
  SLDDSVerify.real_key_byte_len <== sld_ds_key_len;
  // verify SLD KSK private key
  component SLDKSKExtract = ExtractKSK(MAX_SLD_NAME_LEN, ECDSA_KEY_LEN, 13);
  SLDKSKExtract.ksk <== sld_ksk;
  SLDKSKExtract.real_ksk_byte_len <== sld_ksk_len;
  SLDKSKExtract.real_name_byte_len <== sld_name_len;
  component ECDSAPrivateKeyVerify = ECDSAPrivKeyVerify();
  ECDSAPrivateKeyVerify.key <== SLDKSKExtract.key;
  ECDSAPrivateKeyVerify.k <== sld_ksk_priv_k;
  ECDSAPrivateKeyVerify.addres_x <== sld_ksk_priv_addres_x;
  ECDSAPrivateKeyVerify.addres_y <== sld_ksk_priv_addres_y;
  ECDSAPrivateKeyVerify.addadva <== sld_ksk_priv_addadva;
  ECDSAPrivateKeyVerify.addadvb <== sld_ksk_priv_addadvb;
  ECDSAPrivateKeyVerify.Gadv_x <== sld_ksk_priv_Gadv_x;
  ECDSAPrivateKeyVerify.Gadv_y <== sld_ksk_priv_Gadv_y;
}

component main = Main();