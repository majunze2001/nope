const path = require("path");
const { makeInput } = require("../test/helpers/master_input_maker.js");

const data_path = path.join("..", "test", "sdata/ecdsa-ecdsa");
const input = makeInput(
  data_path,
  "nope-tools.com.",
  Array(43).fill(0), // dummy values
  13, 13, false
);

// https://github.com/GoogleChromeLabs/jsbi/issues/30
BigInt.prototype.toJSON = function() { return this.toString() }

console.log(JSON.stringify(input));