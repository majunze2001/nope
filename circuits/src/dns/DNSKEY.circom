pragma circom 2.0.0;

include "../crypto/RSA.circom";
include "../util/buffer.circom";
include "RRSIG.circom";

// KSK in the circuit is domain || flags || protocol || algo || key
// this extracts key from the end of the KSK
// take as input the algo and check it (8 vs 13)
template ExtractKSK(MAX_NAME_BYTES, MAX_KEY_BYTES, AGLO) {
  signal input ksk[MAX_NAME_BYTES + 4 + MAX_KEY_BYTES];
  signal input real_ksk_byte_len;
  signal input real_name_byte_len;

  signal output key[MAX_KEY_BYTES];
  signal output real_key_byte_len;

  // variable shift by dname length
  component ShiftKSK = SigBarrelShift(MAX_NAME_BYTES + 4 + MAX_KEY_BYTES, MAX_NAME_BYTES);
  ShiftKSK.a <== ksk;
  ShiftKSK.dist <== real_name_byte_len;
  component SliceKey = Slice(MAX_NAME_BYTES + 4 + MAX_KEY_BYTES, 0, 4 + MAX_KEY_BYTES);
  SliceKey.a <== ShiftKSK.b;
  for (var i = 0; i < MAX_KEY_BYTES; i++) {
    key[i] <== SliceKey.b[i + 4];
  }
  // confirm protocol is 3
  SliceKey.b[2] === 3;
  // confirm algo is ALGO
  SliceKey.b[3] === AGLO;
  // ensure lengths are correct
  real_key_byte_len <== real_ksk_byte_len - real_name_byte_len - 4;
}

template VerifyContainsZSK(MAX_REC_BYTES, MAX_KEY_BYTES, MAX_NAME_BYTES) {
  /* inputs */
  signal input rec[MAX_REC_BYTES];
  signal input zsk[MAX_KEY_BYTES];
  signal input sname[MAX_NAME_BYTES];
  signal input real_rec_byte_len;
  signal input real_zsk_byte_len;
  signal input real_name_byte_len;
  // check that recordset contains a record containing the ZSK
  // this involves parsing the recordset
  // parse past RRSIG
  // each record has the format:
  // name | type | class | ttl | rdlength | rdata
  // where rdata is flags | protocol | algo | key
  // use rdlength as a touchstone with a counter that decreases until it hits it
  // we know the location of the first rdlength, and we can use its value to find the next one, etc.
  // 18 bytes for the fixed length components of the rrsig info
  // 8 bytes for the fixed length components of the rrinfo
  signal cdown[MAX_REC_BYTES - 18 - 8];
  var idx = 0;
  component IsZero[MAX_REC_BYTES - 18 - 8][2];
  // get key_idx based on actual location of key in recordset
  var tmpi = 2 * real_name_byte_len + 8 + 18;
  while(tmpi < real_rec_byte_len) {
    var tmpkeylen = 256 * rec[tmpi] + rec[tmpi + 1];
    var j = 0;
    while ((tmpkeylen - 4) == real_zsk_byte_len &&
            j < tmpkeylen - 4 &&
            rec[tmpi + 6 + j] == zsk[j]) {
      j = j + 1;
    }
    if (j == tmpkeylen - 4) {
      idx = tmpi;
    }
    tmpi += tmpkeylen + real_name_byte_len + 10;
  }
  // we start 2 * real_name_byte_len away from the first rdlength entry
  cdown[0] <== 2 * real_name_byte_len;
  for (var i = 1; i < MAX_REC_BYTES - 18 - 8; i++) {
    var j = i + 18 + 8;
    cdown[i] <-- (cdown[i - 1] == 0) ? 256 * rec[j - 1] + rec[j] + real_name_byte_len + 9 : cdown[i - 1] - 1;
    IsZero[i][0] = IsZero();
    IsZero[i][0].in <== cdown[i - 1];
    cdown[i] - (cdown[i - 1] - 1) === IsZero[i][0].out * (256 * rec[j - 1] + rec[j] + real_name_byte_len + 9 - (cdown[i - 1] - 1));
  }
  signal key_index;
  key_index <-- idx;
  for (var i = 1; i < MAX_REC_BYTES - 18 - 8; i++) {
    var j = i + 18 + 8;
    IsZero[i][1] = IsZero();
    IsZero[i][1].in <== j - key_index;
    0 === IsZero[i][1].out * cdown[i];
  }
  // check that key_index is < real_rec_byte_len!
  // AKA real_rec_byte_len - key_index - 1 >= 0
  // TO DO, maybe clean this up and move it into a function
  var logN = 0;
  var tmp = MAX_REC_BYTES;
  while (tmp > 0) {
    logN++;
    tmp >>= 1;
  }
  component IsNBits = IsNBits(logN);
  IsNBits.val <== real_rec_byte_len - key_index - 1;

  // shift based on key_index and check that key matches
  // TO DO, below is ~6000 constraints but doesn't need to be
  // overall it is a minor cost though, so only refactor if we have time
  component Slice1 = Slice(MAX_REC_BYTES, 18 + 8, MAX_REC_BYTES);
  Slice1.a <== rec;
  component Shift = SigBarrelShift(MAX_REC_BYTES - 18 - 8, MAX_REC_BYTES - 18 - 8);
  Shift.a <== Slice1.b;
  Shift.dist <== key_index - 18 - 8;
  component Slice2 = Slice(MAX_REC_BYTES - 18 - 8, 6, 6 + MAX_KEY_BYTES);
  Slice2.a <== Shift.b;
  component PrefixMatch = AssertPrefixMatch(MAX_KEY_BYTES, 1);
  PrefixMatch.a <== Slice2.b;
  PrefixMatch.b <== zsk;
  PrefixMatch.real_len <== real_zsk_byte_len;

  // confirm real_zsk_byte_len
  256 * Shift.b[0] + Shift.b[1] === real_zsk_byte_len + 4;
}

// This script doesn't check that the KSK is in the DNSKEY recordset, just that the ZSK is in it
// This script is very optimized but also quite verbose and messy
// TO DO, refactor this for clarity
template VerifyDNSKEYRSA(MAX_REC_BYTES, MAX_SIG_BYTES, MAX_KEY_BYTES, MAX_NAME_BYTES) {
	/* inputs */
	signal input rec[MAX_REC_BYTES];
	signal input sig[MAX_SIG_BYTES];
  // KSK here purely the key, not the key + extra info like in DS
  // assume parsing is done before feeding into this component
	signal input ksk[MAX_KEY_BYTES];
  // it is possible that the zsk is the KSK but we need to handle the case where they are different
  // this code technically supports either case
  signal input zsk[MAX_KEY_BYTES];
  signal input sname[MAX_NAME_BYTES];

  /* No Outputs, validity checked */
  signal input real_rec_byte_len;
  signal input real_sig_byte_len;
  signal input real_ksk_byte_len;
  signal input real_zsk_byte_len;
  signal input real_name_byte_len;

  // verify RRSIG
  component VerifyRRSIG = VerifyRRSIGRSA(MAX_REC_BYTES, MAX_SIG_BYTES, MAX_KEY_BYTES, MAX_NAME_BYTES, 48);
  VerifyRRSIG.rec <== rec;
  VerifyRRSIG.sig <== sig;
  VerifyRRSIG.key <== ksk;
  VerifyRRSIG.sname <== sname;

  VerifyRRSIG.real_rec_byte_len <== real_rec_byte_len;
  VerifyRRSIG.real_sig_byte_len <== real_sig_byte_len;
  VerifyRRSIG.real_key_byte_len <== real_ksk_byte_len;
  VerifyRRSIG.real_sname_byte_len <== real_name_byte_len;

  // verify that the recordset contains the ZSK
  component VerifyContainsZSK = VerifyContainsZSK(MAX_REC_BYTES, MAX_KEY_BYTES, MAX_NAME_BYTES);
  VerifyContainsZSK.rec <== rec;
  VerifyContainsZSK.zsk <== zsk;
  VerifyContainsZSK.sname <== sname;
  VerifyContainsZSK.real_rec_byte_len <== real_rec_byte_len;
  VerifyContainsZSK.real_zsk_byte_len <== real_zsk_byte_len;
  VerifyContainsZSK.real_name_byte_len <== real_name_byte_len;

}

template VerifyDNSKEYECDSA(MAX_REC_BYTES, MAX_NAME_BYTES) {
	/* inputs */
	signal input rec[MAX_REC_BYTES];
	signal input sig[6254];
  // KSK here purely the key, not the key + extra info like in DS
  // assume parsing is done before feeding into this component
	signal input ksk[64];
  // it is possible that the zsk is the KSK but we need to handle the case where they are different
  // this code technically supports either case
  signal input zsk[64];
  signal input sname[MAX_NAME_BYTES];

  /* No Outputs, validity checked */
  signal input real_rec_byte_len;
  signal input real_name_byte_len;

  // verify RRSIG
  component VerifyRRSIG = VerifyRRSIGECDSA(MAX_REC_BYTES, MAX_NAME_BYTES, 48);
  VerifyRRSIG.rec <== rec;
  VerifyRRSIG.sig <== sig;
  VerifyRRSIG.key <== ksk;
  VerifyRRSIG.sname <== sname;
  VerifyRRSIG.real_rec_byte_len <== real_rec_byte_len;
  VerifyRRSIG.real_sname_byte_len <== real_name_byte_len;

  // verify that the recordset contains the ZSK
  // TO DO, minor optimization possible here since we know the key length
  component VerifyContainsZSK = VerifyContainsZSK(MAX_REC_BYTES, 64, MAX_NAME_BYTES);
  VerifyContainsZSK.rec <== rec;
  VerifyContainsZSK.zsk <== zsk;
  VerifyContainsZSK.sname <== sname;
  VerifyContainsZSK.real_rec_byte_len <== real_rec_byte_len;
  VerifyContainsZSK.real_zsk_byte_len <== 64;
  VerifyContainsZSK.real_name_byte_len <== real_name_byte_len;
}