const path = require('path');
const wasm_tester = require('circom_tester').wasm;
const cir_path = path.join(__dirname, '..', 'src', 'app');
const {logCircuitStats} = require('./helpers/util');
const {makeInput} = require('./helpers/master_input_maker');

describe('NOPE test suite', function() {
  this.timeout(1000000);
  it('nope-tools.me. rsa-rsa test', async () => {
    const data_path = path.join(__dirname, 'sdata', 'rsa-rsa');
    const cir = await wasm_tester(path.join(cir_path, 'rsa-rsa.circom'));
    const w = await cir.calculateWitness(
      makeInput(
        data_path,
        'nope-tools.me.',
        Array(43).fill(0), // dummy values
        8,
        8,
        false,
      ),
    );
    const res = await cir.checkConstraints(w);
    logCircuitStats(cir);
  }).timeout(1000000);
  it('nope-tools.com. ecdsa-rsa test', async () => {
    const data_path = path.join(__dirname, 'sdata', 'ecdsa-rsa');
    const cir = await wasm_tester(path.join(cir_path, 'ecdsa-rsa.circom'));
    const w = await cir.calculateWitness(
      makeInput(
        data_path,
        'nope-tools.com.',
        Array(43).fill(0), // dummy values
        13,
        8,
        false,
      )
    );
    const res = await cir.checkConstraints(w);
    logCircuitStats(cir);
  }).timeout(1000000);
  it('nope-tools.me. rsa-ecdsa test', async () => {
    const data_path = path.join(__dirname, 'sdata', 'rsa-ecdsa');
    const cir = await wasm_tester(path.join(cir_path, 'rsa-ecdsa.circom'));
    const w = await cir.calculateWitness(
      makeInput(
        data_path,
        'nope-tools.me.',
        Array(43).fill(0), // dummy values
        8,
        13,
        false,
      ),
    );
    const res = await cir.checkConstraints(w);
    logCircuitStats(cir);
  }).timeout(1000000);
  it('nope-tools.com. ecdsa-ecdsa test', async () => {
    const data_path = path.join(__dirname, 'sdata', 'ecdsa-ecdsa');
    const cir = await wasm_tester(
      path.join(cir_path, 'ecdsa-ecdsa.circom'),
    );
    const w = await cir.calculateWitness(
      makeInput(
        data_path,
        'nope-tools.com.',
        Array(43).fill(0), // dummy values
        13,
        13,
        false,
      ),
    );
    const res = await cir.checkConstraints(w);
    logCircuitStats(cir);
  }).timeout(1000000);
  it('nope-tools.me. rsa-rsa-man test', async () => {
    const data_path = path.join(__dirname, 'sdata', 'rsa-rsa');
    const cir = await wasm_tester(
      path.join(cir_path, 'rsa-rsa-man.circom'),
    );
    const w = await cir.calculateWitness(
      makeInput(
        data_path,
        'nope-tools.me.',
        Array(43).fill(0), // dummy values
        8,
        8,
        true,
      ),
    );
    const res = await cir.checkConstraints(w);
    logCircuitStats(cir);
  }).timeout(1000000);
  it('nope-tools.com. ecdsa-rsa-man test', async () => {
    const data_path = path.join(__dirname, 'sdata', 'ecdsa-rsa');
    const cir = await wasm_tester(
      path.join(cir_path, 'ecdsa-rsa-man.circom'),
    );
    const w = await cir.calculateWitness(
      makeInput(
        data_path,
        'nope-tools.com.',
        Array(43).fill(0), // dummy values
        13,
        8,
        true,
      ),
    );
    const res = await cir.checkConstraints(w);
    logCircuitStats(cir);
  }).timeout(1000000);
  it('nope-tools.me. rsa-ecdsa-man test', async () => {
    const data_path = path.join(__dirname, 'sdata', 'rsa-ecdsa');
    const cir = await wasm_tester(
      path.join(cir_path, 'rsa-ecdsa-man.circom'),
    );
    const w = await cir.calculateWitness(
      makeInput(
        data_path,
        'nope-tools.me.',
        Array(43).fill(0), // dummy values
        8,
        13,
        true,
      ),
    );
    const res = await cir.checkConstraints(w);
    logCircuitStats(cir);
  }).timeout(1000000);
  it('nope-tools.com. ecdsa-ecdsa-man test', async () => {
    const data_path = path.join(__dirname, 'sdata', 'ecdsa-ecdsa');
    const cir = await wasm_tester(
      path.join(cir_path, 'ecdsa-ecdsa-man.circom'),
    );
    const w = await cir.calculateWitness(
      makeInput(
        data_path,
        'nope-tools.com.',
        Array(43).fill(0), // dummy values
        13,
        13,
        true,
      ),
    );
    const res = await cir.checkConstraints(w);
    logCircuitStats(cir);
  }).timeout(1000000);
});
