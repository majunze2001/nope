const top = 2n ** 256n - 1n;
const p = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
const p_e_sqrt = 5472060717959818805561601436314318772174077789324455915672259473661306552146n;
const constant_1_2 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4n;
const constant_27_82 = 0x2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5n;
const constant_3_82 = 0x2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775n;

function pow(b, e, m = undefined) {
  if (typeof b === "number") b = BigInt(b);
  if (typeof e === "number") e = BigInt(e);
  if (typeof m === "number") m = BigInt(m);

  if (m === undefined) {
    return b ** e;
  }

  if (m === 1n) return 0n;

  let r = 1n;
  b = b % m;
  while (e > 0) {
    if (e % 2n === 1n) r = (r * b) % m;
    e = e >> 1n;
    b = (b * b) % m;
  }

  return r;
}

function Fsqrt(x) {
  const e = (p + 1n) / 4n;
  const res = pow(x, e, p);
  return res;
}

function F2sqrt(a0, a1, h) {
  let d = Fsqrt(pow(a0, 2, p) + pow(a1, 2, p));
  if (h) {
    d = p - d;
  }
  let x0 = Fsqrt(((a0 + d) * constant_1_2) % p);
  let x1 = (a1 * pow(2n * x0, p - 2n, p)) % p;
  return [x0, x1];
}

function L1(x, h) {
  let ty = Fsqrt(pow(x, 3, p) + 3n);
  if (h) ty = p - ty;
  return [x, ty];
}

function L2(x0, x1, h0, h1) {
  let n3ab = ((p - 3n) * x0 * x1) % p;
  let a3 = pow(x0, 3, p);
  let b3 = pow(x1, 3, p);
  let tx0 = (constant_27_82 + a3 + n3ab * x1) % p;
  let tx1 = p - ((constant_3_82 + b3 + n3ab * x0) % p);
  let [ty0, ty1] = F2sqrt(tx0, tx1, h1);
  if (h0) {
    return [
      [x0, x1],
      [p - ty0, p - ty1]
    ];
  } else {
    return [
      [x0, x1],
      [ty0, ty1]
    ];
  }
}

// convert URI safe string to 1024 bit integer
function URI_to_bits1024(s) {
  const alphabet = "0123456789abcdefghijklmnopqrstuvwxyz-";
  const alen = BigInt(alphabet.length);
  let r = 0n;
  if (s.length < 197) {
    console.log('Error: string not long enough');
    return undefined;
  }
  let e = 1n;
  let checksum = 0n;
  for (let i = 0; i < 197; i++) {
    if (!alphabet.includes(s[i])) {
      // check for invalid characters
      console.log('Error: invalid character: ', s[i], ' at index: ', i);
      return undefined;
    } else {
      // convert character to integer and add to result
      let tmp = BigInt(alphabet.indexOf(s[i]));
      r += tmp * e;
      checksum = (checksum + tmp) % alen;
      e *= alen;
    }
  }
  // simple checksum check to reduce false positive rate
  let check = alphabet.indexOf(s[s.length - 1]);
  if (check != checksum) {
    console.log(
      'Error: checksum mismatch. Expected: ',
      checksum,
      ' got: ',
      check,
    );
    return undefined;
  }
  // return 1024 bit integer segmented into 256 bit chunks
  return [
    r % 2n ** 256n,
    (r >> 256n) % 2n ** 256n,
    (r >> 512n) % 2n ** 256n,
    (r >> 768n) % 2n ** 256n
  ];
}

function validate_and_extract(URI, isMultiSAN = false) {
  // check that first 5 characters are "n0pe." or "n1pe." and strip them
  if (URI.substr(0, 5) != "n0pe." && URI.substr(0, 5) != "n1pe.") {
    console.log("Error: invalid NOPE proof");
    process.exit(1);
  }
  URI = URI.slice(5);
  // split on "."
  let arr = URI.split(".");
  // if multiSAN, get first 2 segments, if not, get first 4
  if (isMultiSAN) {
    arr = arr.slice(0, 2);
  } else {
    arr = arr.slice(0, 4);
  }
  // check that each segment is 50 characters long
  for (let i = 0; i < arr.length; i++) {
    if (arr[i].length != 50) {
      console.log("Error: invalid segment length");
      return undefined;
    }
  }
  // return concatenated segments
  return arr.join("");
}

function decompress_proof(arr) {
  let found = [-1, -1];
  for (let i = 0; i < arr.length; i++) {
    if (arr[i].substr(0, 5) == "n0pe.") {
      found[0] = i;
    } else if (arr[i].substr(0, 5) == "n1pe.") {
      found[1] = 1;
    }
  }

  // extract
  let URI;
  let domain;
  if (found[0] === -1) {
    console.log('Error: missing n0pe. proof');
    return undefined;
  } else if (found[1] == -1) {
    // not multiSAN
    URI = validate_and_extract(arr[found[0]]);
    domain = arr[found[0]].split(".").slice(5).join(".");
  } else {
    domain = arr[found[0]].split(".").slice(3).join(".");
    URI = validate_and_extract(arr[found[0]], true);
    URI += validate_and_extract(arr[found[1]], true);
  }
  // read the first two characters to determine version and circuit type (and strip)
  if (!domain.endsWith(".")) domain += ".";
  let version = URI[0];
  if (version != "0") {
    console.log("Error: unknown version");
    return undefined;
  }
  let circuit_type = parseInt(URI[1]);
  if (circuit_type < 0 || circuit_type > 7) {
    console.log("Error: unknown circuit type");
    return undefined;
  }
  URI = URI.substr(2, URI.length);
  // decompress URI safe string
  arr = URI_to_bits1024(URI);
  if (!arr) return undefined;
  // preprocess x coordinates
  for (let i = 0; i < 4; i++) {
    if (arr[i] >= p) arr[i] = [top - arr[i], true];
    else arr[i] = [arr[i], false];
  }
  // decompress proof
  let pi_a = L1(arr[0][0], arr[0][1]);
  let [pi_b0, pi_b1] = L2(arr[1][0], arr[2][0], arr[1][1], arr[2][1]);
  let pi_c = L1(arr[3][0], arr[3][1]);
  const proof = {
    pi_a: [...pi_a, 1],
    pi_b: [[...pi_b0], [...pi_b1], [1, 0]],
    pi_c: [...pi_c, 1],
    protocol: "groth16",
    curve: "bn128"
  };

  const typeCode = Number(circuit_type)
    .toString(2)
    .padStart(3, 0);
  const type =
    (typeCode[0] == "0" ? "rsa-" : "ecdsa-") +
    (typeCode[1] == "0" ? "rsa" : "ecdsa") +
    (typeCode[2] == "0" ? "" : "-man");
  return { proof, type, domain};
}

//export { decompress_proof as decompressNope };
exports.decompressNope = decompress_proof;
