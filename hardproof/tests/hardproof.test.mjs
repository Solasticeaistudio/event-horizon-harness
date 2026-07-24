import test from 'node:test';
import assert from 'node:assert/strict';
import { SimulatorProver } from '../packages/simulator/dist/index.js';
import { Verifier } from '../packages/core/dist/index.js';
import { Client, Server, encodeBundle, decodeBundle } from '../packages/sdk/dist/index.js';

function fixture() {
  const deviceId = 'device-test-1';
  const prover = new SimulatorProver({ deviceId, seed: 'fixed-seed' });
  const verifier = new Verifier({
    minTrustLevel: 'simulated',
    deviceKeys: { [deviceId]: prover.publicKeyPem },
    pcrPolicy: { executor: { type: 'exact', value: prover.measurements.executor } },
  });
  return { deviceId, prover, verifier };
}

test('simulator proof verifies', async () => {
  const { prover, verifier } = fixture();
  const nonce = verifier.nonceStore.issue();
  const proof = await prover.prove({ nonce });
  const result = verifier.verify(proof, { nonce });
  assert.equal(result.valid, true);
  assert.equal(result.valid && result.trustLevel, 'simulated');
});

test('tampered measurement fails signature', async () => {
  const { prover, verifier } = fixture();
  const nonce = verifier.nonceStore.issue();
  const proof = await prover.prove({ nonce });
  proof.measurements.executor = 'tampered';
  const result = verifier.verify(proof, { nonce });
  assert.equal(result.valid, false);
  assert.equal(!result.valid && result.failureCode, 'INVALID_SIGNATURE');
});

test('nonce mismatch fails', async () => {
  const { prover, verifier } = fixture();
  const nonce = verifier.nonceStore.issue();
  const proof = await prover.prove({ nonce });
  const result = verifier.verify(proof, { nonce: 'different-nonce-value-0000' });
  assert.equal(result.valid, false);
  assert.equal(!result.valid && result.failureCode, 'NONCE_MISMATCH');
});

test('proof replay fails', async () => {
  const { prover, verifier } = fixture();
  const nonce = verifier.nonceStore.issue();
  const proof = await prover.prove({ nonce });
  assert.equal(verifier.verify(proof, { nonce }).valid, true);
  const replay = verifier.verify(proof, { nonce });
  assert.equal(replay.valid, false);
  assert.equal(!replay.valid && replay.failureCode, 'PROOF_REPLAY');
});

test('measurement policy mismatch fails', async () => {
  const { deviceId, prover } = fixture();
  const verifier = new Verifier({
    minTrustLevel: 'simulated',
    deviceKeys: { [deviceId]: prover.publicKeyPem },
    pcrPolicy: { executor: { type: 'exact', value: 'not-the-expected-measurement' } },
  });
  const nonce = verifier.nonceStore.issue();
  const result = verifier.verify(await prover.prove({ nonce }), { nonce });
  assert.equal(result.valid, false);
  assert.equal(!result.valid && result.failureCode, 'MEASUREMENT_POLICY_FAILED');
});

test('unknown device fails closed', async () => {
  const { prover } = fixture();
  const verifier = new Verifier({ minTrustLevel: 'simulated' });
  const nonce = verifier.nonceStore.issue();
  const result = verifier.verify(await prover.prove({ nonce }), { nonce });
  assert.equal(result.valid, false);
  assert.equal(!result.valid && result.failureCode, 'UNKNOWN_DEVICE');
});

test('sdk local path and bundle encoding work', async () => {
  process.env.HARDPROOF_ALLOW_SIMULATOR = '1';
  const deviceId = 'sdk-device';
  const seed = 'sdk-seed';
  const rawProver = new SimulatorProver({ deviceId, seed });
  const server = Server.create({ mode: 'local', config: { deviceKeys: { [deviceId]: rawProver.publicKeyPem } } });
  const nonce = await server.nonce.issue();
  const client = await Client.create({ deviceId, method: 'simulator', simulatorSeed: seed });
  const proof = await client.prove({ nonce });
  const decoded = decodeBundle(encodeBundle(proof));
  const result = await server.verify(decoded, { nonce });
  assert.equal(result.valid, true);
});
