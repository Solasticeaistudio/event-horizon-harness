import test from 'node:test';
import assert from 'node:assert/strict';

import { Verifier } from '../packages/core/dist/index.js';
import { SimulatorProver } from '../packages/simulator/dist/index.js';
import { createTpmBundle, createTpmIdentity } from './tpm-fixture.mjs';
import { issueChallenge } from './nonce-context.mjs';

function simulatorFixture(config = {}) {
  const deviceId = 'dispatch-simulator-device';
  const prover = new SimulatorProver({ deviceId, seed: 'dispatch-simulator-seed' });
  const verifier = new Verifier({
    deviceKeys: { [deviceId]: prover.publicKeyPem },
    ...config,
  });
  return { deviceId, prover, verifier };
}

function failureCode(result) {
  assert.equal(result.valid, false);
  return result.failureCode;
}

test('valid simulator attestation derives development trust from simulator verifier', async () => {
  const { deviceId, prover, verifier } = simulatorFixture();
  const { nonce, context } = await issueChallenge(verifier, deviceId);
  const result = await verifier.verify(await prover.prove({ nonce }), { nonce, context });
  assert.equal(result.valid, true);
  assert.equal(result.valid && result.trustLevel, 'simulated');
  assert.equal(result.valid && result.assuranceLevel, 'development');
});

test('signed simulator bundle claiming tpm2 cannot acquire hardware trust', async () => {
  const { deviceId, prover, verifier } = simulatorFixture({ minTrustLevel: 'hardware' });
  const { nonce, context } = await issueChallenge(verifier, deviceId);
  const bundle = await prover.prove({ nonce });
  bundle.method = 'tpm2';
  const result = await verifier.verify(bundle, { nonce, context });
  assert.equal(failureCode(result), 'KEY_ID_MISMATCH');
  assert.equal('trustLevel' in result, false);
});

test('unknown attestation method is rejected before provider dispatch', async () => {
  const { deviceId, prover, verifier } = simulatorFixture();
  const { nonce, context } = await issueChallenge(verifier, deviceId);
  const bundle = await prover.prove({ nonce });
  bundle.method = 'unknown-provider';
  assert.equal(failureCode(await verifier.verify(bundle, { nonce, context })), 'UNSUPPORTED_METHOD');
});

test('known method with no registered verifier fails closed', async () => {
  const { deviceId, prover, verifier } = simulatorFixture({ useDefaultProviderVerifiers: false });
  const { nonce, context } = await issueChallenge(verifier, deviceId);
  const bundle = await prover.prove({ nonce });
  assert.equal(failureCode(await verifier.verify(bundle, { nonce, context })), 'VERIFIER_UNAVAILABLE');
});

test('provider exception fails closed without trust output', async () => {
  const throwingProvider = {
    method: 'simulator',
    verify() { throw new Error('provider unavailable'); },
  };
  const { deviceId, prover, verifier } = simulatorFixture({
    useDefaultProviderVerifiers: false,
    providerVerifiers: [throwingProvider],
  });
  const { nonce, context } = await issueChallenge(verifier, deviceId);
  const result = await verifier.verify(await prover.prove({ nonce }), { nonce, context });
  assert.equal(failureCode(result), 'PROVIDER_ERROR');
  assert.equal('trustLevel' in result, false);
});

test('invalid TPM quote fails before hardware trust is returned', async () => {
  const identity = createTpmIdentity();
  const deviceId = 'invalid-quote-device';
  const now = new Date('2026-01-01T00:00:00.000Z');
  const verifier = new Verifier({
    minTrustLevel: 'hardware',
    now: () => now,
    deviceKeys: { [deviceId]: identity.publicKeyPem },
    tpmAkQualifiedNames: { [deviceId]: identity.qualifiedName },
    tpmPcrSelections: { [deviceId]: ['sha256:0', 'sha256:7'] },
    requireTpmEventLog: true,
  });
  const { nonce, context } = await issueChallenge(verifier, deviceId);
  const bundle = createTpmBundle(identity, { nonce, deviceId, issuedAt: now });
  bundle.evidence.quote = 'AA';
  const result = await verifier.verify(bundle, { nonce, context });
  assert.equal(failureCode(result), 'TPM_QUOTE_MALFORMED');
  assert.equal('trustLevel' in result, false);
});

test('simulator attestation cannot satisfy hardware-only policy', async () => {
  const { deviceId, prover, verifier } = simulatorFixture({ minTrustLevel: 'hardware' });
  const { nonce, context } = await issueChallenge(verifier, deviceId);
  assert.equal(
    failureCode(await verifier.verify(await prover.prove({ nonce }), { nonce, context })),
    'TRUST_LEVEL_TOO_LOW',
  );
});

test('method substitution after signing is rejected', async () => {
  const { deviceId, prover, verifier } = simulatorFixture();
  const { nonce, context } = await issueChallenge(verifier, deviceId);
  const bundle = await prover.prove({ nonce });
  bundle.method = 'secure-enclave';
  assert.equal(failureCode(await verifier.verify(bundle, { nonce, context })), 'VERIFIER_UNAVAILABLE');
});

test('caller-added trust level is rejected as an unknown bundle field', async () => {
  const { deviceId, prover, verifier } = simulatorFixture();
  const { nonce, context } = await issueChallenge(verifier, deviceId);
  const bundle = await prover.prove({ nonce });
  bundle.trustLevel = 'hardware';
  assert.equal(failureCode(await verifier.verify(bundle, { nonce, context })), 'MALFORMED_BUNDLE');
});

test('simulator provider cannot substitute hardware trust in its result', async () => {
  const overstatingProvider = {
    method: 'simulator',
    verify(bundle) {
      return {
        valid: true,
        method: 'simulator',
        trustLevel: 'hardware',
        assuranceLevel: 'hardware-rooted',
        keyId: bundle.keyId,
        measurements: bundle.measurements,
      };
    },
  };
  const { deviceId, prover, verifier } = simulatorFixture({
    useDefaultProviderVerifiers: false,
    providerVerifiers: [overstatingProvider],
  });
  const { nonce, context } = await issueChallenge(verifier, deviceId);
  assert.equal(
    failureCode(await verifier.verify(await prover.prove({ nonce }), { nonce, context })),
    'PROVIDER_RESULT_INVALID',
  );
});
