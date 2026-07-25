import test from 'node:test';
import assert from 'node:assert/strict';

import { Verifier } from '../packages/core/dist/index.js';
import { SimulatorProver } from '../packages/simulator/dist/index.js';
import { nonceContext } from './nonce-context.mjs';

function harness(options = {}) {
  let nowMs = Date.parse('2026-01-01T00:00:00.000Z');
  const now = () => new Date(nowMs);
  const deviceId = options.deviceId ?? 'fresh-device';
  const prover = new SimulatorProver({
    deviceId,
    seed: options.seed ?? 'fresh-seed',
    measurements: options.measurements,
    ttlSeconds: options.proofTtlSeconds ?? 30,
    now,
  });
  const expectedMeasurement = options.expectedMeasurement ?? prover.measurements.executor;
  const verifier = new Verifier({
    deviceKeys: { [deviceId]: options.publicKeyPem ?? prover.publicKeyPem },
    nonceTtlSeconds: options.nonceTtlSeconds ?? 30,
    maxProofAgeSeconds: options.maxProofAgeSeconds ?? 30,
    pcrPolicy: { executor: { type: 'exact', value: expectedMeasurement } },
    now,
  });
  const context = nonceContext(deviceId, {
    executorId: options.executorId ?? 'executor-fresh',
    sessionId: options.sessionId ?? 'session-fresh',
    purpose: 'capability-issuance',
  });
  return {
    context,
    deviceId,
    prover,
    verifier,
    advance(milliseconds) { nowMs += milliseconds; },
    async freshProof(overrides = {}) {
      const proofContext = { ...context, ...overrides };
      const nonce = await verifier.nonceAuthority.issue(proofContext);
      return { context: proofContext, nonce, proof: await prover.prove({ nonce }) };
    },
  };
}

function failureCode(result) {
  assert.equal(result.valid, false);
  return result.failureCode;
}

test('fresh proof acceptance uses a fresh challenge for each verification', async () => {
  const value = harness();
  const first = await value.freshProof();
  value.advance(1);
  const second = await value.freshProof();
  const firstResult = await value.verifier.verify(first.proof, first);
  const secondResult = await value.verifier.verify(second.proof, second);
  assert.equal(firstResult.valid, true);
  assert.equal(secondResult.valid, true);
  assert.notEqual(first.nonce, second.nonce);
  assert.notEqual(firstResult.valid && firstResult.bundleDigest, secondResult.valid && secondResult.bundleDigest);
});

test('cache expiration cannot turn an expired challenge into authorization', async () => {
  const value = harness({ nonceTtlSeconds: 1 });
  const attempt = await value.freshProof();
  value.advance(1_000);
  assert.equal(failureCode(await value.verifier.verify(attempt.proof, attempt)), 'NONCE_EXPIRED');
});

test('measurement change requires fresh evidence satisfying the configured policy', async () => {
  const baseline = harness();
  const accepted = await baseline.freshProof();
  assert.equal((await baseline.verifier.verify(accepted.proof, accepted)).valid, true);
  const changed = new SimulatorProver({
    deviceId: baseline.deviceId,
    seed: 'fresh-seed',
    measurements: { ...baseline.prover.measurements, executor: 'f'.repeat(64) },
    now: () => new Date('2026-01-01T00:00:00.000Z'),
  });
  const context = baseline.context;
  const nonce = await baseline.verifier.nonceAuthority.issue(context);
  const proof = await changed.prove({ nonce });
  assert.equal(
    failureCode(await baseline.verifier.verify(proof, { nonce, context })),
    'MEASUREMENT_POLICY_FAILED',
  );
});

test('policy change reevaluates fresh evidence instead of reusing an old approval', async () => {
  const oldPolicy = harness();
  const accepted = await oldPolicy.freshProof();
  assert.equal((await oldPolicy.verifier.verify(accepted.proof, accepted)).valid, true);

  const newPolicy = harness({ expectedMeasurement: '0'.repeat(64) });
  const attempt = await newPolicy.freshProof();
  assert.equal(
    failureCode(await newPolicy.verifier.verify(attempt.proof, attempt)),
    'MEASUREMENT_POLICY_FAILED',
  );
});

test('session change cannot reuse a challenge or verification result', async () => {
  const value = harness();
  const attempt = await value.freshProof();
  const changed = { ...attempt, context: { ...attempt.context, sessionId: 'other-session' } };
  assert.equal(
    failureCode(await value.verifier.verify(attempt.proof, changed)),
    'NONCE_CONTEXT_MISMATCH',
  );
});

test('key rotation rejects proof signed by the previously enrolled key', async () => {
  const old = harness();
  const rotated = new SimulatorProver({
    deviceId: old.deviceId,
    seed: 'rotated-device-key',
    now: () => new Date('2026-01-01T00:00:00.000Z'),
  });
  old.verifier.registerDevice(old.deviceId, rotated.publicKeyPem);
  const attempt = await old.freshProof();
  assert.equal(failureCode(await old.verifier.verify(attempt.proof, attempt)), 'KEY_ID_MISMATCH');
});

test('executor identifier reuse across sessions does not reuse attestation', async () => {
  const value = harness({ executorId: 'reused-executor', sessionId: 'old-session' });
  const oldAttempt = await value.freshProof();
  const newContext = { ...oldAttempt.context, sessionId: 'new-session' };
  assert.equal(
    failureCode(await value.verifier.verify(oldAttempt.proof, { ...oldAttempt, context: newContext })),
    'NONCE_CONTEXT_MISMATCH',
  );
  const fresh = await value.freshProof({ sessionId: 'new-session' });
  assert.equal((await value.verifier.verify(fresh.proof, fresh)).valid, true);
});

test('stale proof is rejected even when its device and measurement remain enrolled', async () => {
  const value = harness({ proofTtlSeconds: 1, nonceTtlSeconds: 30 });
  const stale = await value.freshProof();
  value.advance(1_001);
  assert.equal(failureCode(await value.verifier.verify(stale.proof, stale)), 'PROOF_EXPIRED');
});
