const ffjavascript = require("./ffjavascript.js");

class ECurve {
  constructor() {
    this.CurveData = {
      curve: null,
      IC0: null,
      IC: null,
      vk_gamma_2: null,
      vk_delta_2: null,
      vk_alpha_1: null,
      vk_beta_2: null
    };
    this.vk = null;
  }

  async setup(vk, public_input_bytes) {
    const processedVK = ffjavascript.utils.unstringifyBigInts(vk);
    this.vk = processedVK;
    await this.precompute(public_input_bytes, processedVK);
  }

  async precompute(publen, vk) {
    this.CurveData.curve = await ffjavascript.getCurveFromName("bn128");
    this.CurveData.IC0 = this.CurveData.curve.G1.fromObject(vk.IC[0]);
    this.CurveData.IC = new Uint8Array(
      this.CurveData.curve.G1.F.n8 * 2 * publen
    );
    this.CurveData.w = new Uint8Array(this.CurveData.curve.Fr.n8 * publen);
    this.CurveData.vk_gamma_2 = this.CurveData.curve.G2.fromObject(
      vk.vk_gamma_2
    );
    this.CurveData.vk_delta_2 = this.CurveData.curve.G2.fromObject(
      vk.vk_delta_2
    );
    this.CurveData.vk_alpha_1 = this.CurveData.curve.G1.fromObject(
      vk.vk_alpha_1
    );
    this.CurveData.vk_beta_2 = this.CurveData.curve.G2.fromObject(vk.vk_beta_2);
  }

  async verify(proof, publicInputs) {
    const vk = this.vk;
    if (!publicInputsAreValid(this.CurveData.curve, publicInputs)) {
      return false;
    }

    for (let i = 0; i < publicInputs.length; i++) {
      const buffP = this.CurveData.curve.G1.fromObject(vk.IC[i + 1]);
      this.CurveData.IC.set(buffP, i * this.CurveData.curve.G1.F.n8 * 2);
      ffjavascript.Scalar.toRprLE(
        this.CurveData.w,
        this.CurveData.curve.Fr.n8 * i,
        publicInputs[i],
        this.CurveData.curve.Fr.n8
      );
    }

    let cpub = await this.CurveData.curve.G1.multiExpAffine(
      this.CurveData.IC,
      this.CurveData.w
    );
    cpub = this.CurveData.curve.G1.add(cpub, this.CurveData.IC0);

    const pi_a = this.CurveData.curve.G1.fromObject(proof.pi_a);
    const pi_b = this.CurveData.curve.G2.fromObject(proof.pi_b);
    const pi_c = this.CurveData.curve.G1.fromObject(proof.pi_c);

    if (!isWellConstructed(this.CurveData.curve, { pi_a, pi_b, pi_c })) {
      return false;
    }

    const res = await this.CurveData.curve.pairingEq(
      this.CurveData.curve.G1.neg(pi_a),
      pi_b,
      cpub,
      this.CurveData.vk_gamma_2,
      pi_c,
      this.CurveData.vk_delta_2,
      this.CurveData.vk_alpha_1,
      this.CurveData.vk_beta_2
    );

    if (!res) {
      return false;
    }

    return true;
  }
}

// utils at the bottom
function publicInputsAreValid(curve, publicInputs) {
  for (let i = 0; i < publicInputs.length; i++) {
    if (!ffjavascript.Scalar.lt(publicInputs[i], curve.r)) {
      return false;
    }
  }
  return true;
}

function isWellConstructed(curve, proof) {
  const G1 = curve.G1;
  const G2 = curve.G2;

  return (
    G1.isValid(proof.pi_a) && G2.isValid(proof.pi_b) && G1.isValid(proof.pi_c)
  );
}

// from ffjavascript/src/utils.js
function unstringifyBigInts(o) {
  if (typeof o == "string" && /^[0-9]+$/.test(o)) {
    return BigInt(o);
  } else if (typeof o == "string" && /^0x[0-9a-fA-F]+$/.test(o)) {
    return BigInt(o);
  } else if (Array.isArray(o)) {
    return o.map(unstringifyBigInts);
  } else if (typeof o == "object") {
    if (o === null) return null;
    const res = {};
    const keys = Object.keys(o);
    keys.forEach(k => {
      res[k] = unstringifyBigInts(o[k]);
    });
    return res;
  } else {
    return o;
  }
}

module.exports = {
  ECurve
};
