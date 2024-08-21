const path = require('path');
const wasm_tester = require('circom_tester').wasm;
const { logCircuitStats } = require('./helpers/util');
const { getSCTHead } = require('./helpers/ctutil');

describe('SCT Testing', function() {
  this.timeout(1000000);
  it('CT log test', async () => {
    const input = await getSCTHead();
    const cir = await wasm_tester(path.join(__dirname,'sct', 'ct_test.circom'));
    const w = await cir.calculateWitness(
      input
    );
    const res = await cir.checkConstraints(w);
    logCircuitStats(cir);
  }).timeout(1000000);
});
