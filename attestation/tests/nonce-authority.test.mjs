import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';

import { Verifier } from '../packages/core/dist/index.js';
import { SimulatorProver } from '../packages/simulator/dist/index.js';
import { nonceContext } from './nonce-context.mjs';

function fixture(options = {}) {
  let nowMs = Date.parse('2026-01-01T00:00:00.000Z');
  const deviceId = 'nonce-device';
  const now = () => new Date(nowMs);
  const prover = new SimulatorProver({
    deviceId,
    seed: 'nonce-authority-seed',
    now,
    ttlSeconds: 60,
  });
  const verifier = new Verifier({
    deviceKeys: { [deviceId]: prover.publicKeyPem },
    nonceTtlSeconds: options.nonceTtlSeconds ?? 60,
    now,
  });
  const context = nonceContext(deviceId, {
    executorId: 'executor-a',
    sessionId: 'session-a',
    purpose: 'capability-issuance',
  });
  return {
    context,
    deviceId,
    prover,
    verifier,
    advance(milliseconds) { nowMs += milliseconds; },
    issue(overrides = {}) {
      const issuedContext = { ...context, ...overrides };
      return {
        context: issuedContext,
        nonce: verifier.nonceAuthority.issue(issuedContext),
      };
    },
  };
}

function failureCode(result) {
  assert.equal(result.valid, false);
  return result.failureCode;
}

test('unknown nonce fails even when it is signed by the enrolled simulator', async () => {
  const value = fixture();
  const nonce = randomBytes(32).toString('base64url');
  const proof = await value.prover.prove({ nonce });
  assert.equal(
    failureCode(value.verifier.verify(proof, { nonce, context: value.context })),
    'NONCE_UNKNOWN',
  );
});

test('expired nonce transitions to expired and fails closed', async () => {
  const value = fixture({ nonceTtlSeconds: 1 });
  const { nonce, context } = value.issue();
  const proof = await value.prover.prove({ nonce });
  value.advance(1_000);
  assert.equal(failureCode(value.verifier.verify(proof, { nonce, context })), 'NONCE_EXPIRED');
  assert.equal(value.verifier.nonceAuthority.inspect(nonce)?.state, 'expired');
});

test('a consumed nonce cannot validate a second signed bundle', async () => {
  const value = fixture();
  const { nonce, context } = value.issue();
  const first = await value.prover.prove({ nonce });
  value.advance(1);
  const second = await value.prover.prove({ nonce });
  assert.notEqual(first.issuedAt, second.issuedAt);
  assert.equal(value.verifier.verify(first, { nonce, context }).valid, true);
  assert.equal(failureCode(value.verifier.verify(second, { nonce, context })), 'NONCE_REPLAY');
});

test('nonce issued for one executor cannot cross executor context', async () => {
  const value = fixture();
  const { nonce, context } = value.issue();
  const proof = await value.prover.prove({ nonce });
  const wrongContext = { ...context, executorId: 'executor-b' };
  assert.equal(
    failureCode(value.verifier.verify(proof, { nonce, context: wrongContext })),
    'NONCE_CONTEXT_MISMATCH',
  );
  assert.equal(value.verifier.nonceAuthority.inspect(nonce)?.state, 'issued');
});

test('nonce issued for one session cannot cross session context', async () => {
  const value = fixture();
  const { nonce, context } = value.issue();
  const proof = await value.prover.prove({ nonce });
  const wrongContext = { ...context, sessionId: 'session-b' };
  assert.equal(
    failureCode(value.verifier.verify(proof, { nonce, context: wrongContext })),
    'NONCE_CONTEXT_MISMATCH',
  );
  assert.equal(value.verifier.nonceAuthority.inspect(nonce)?.state, 'issued');
});

test('malformed nonce cannot be registered or accepted', async () => {
  const value = fixture();
  const malformed = 'not-a-canonical-32-byte-nonce';
  assert.throws(
    () => value.verifier.nonceAuthority.register(malformed, value.context, Date.now(), Date.now() + 1_000),
    /malformed/,
  );
  const proof = await value.prover.prove({ nonce: malformed });
  assert.equal(
    failureCode(value.verifier.verify(proof, { nonce: malformed, context: value.context })),
    'MALFORMED_NONCE',
  );
});

test('parallel verification attempts consume one nonce at most once', async () => {
  const value = fixture();
  const { nonce, context } = value.issue();
  const proofs = [];
  for (let index = 0; index < 64; index += 1) {
    proofs.push(await value.prover.prove({ nonce }));
    value.advance(1);
  }
  const results = await Promise.all(
    proofs.map(async (proof) => value.verifier.verify(proof, { nonce, context })),
  );
  assert.equal(results.filter((result) => result.valid).length, 1);
  assert.equal(results.filter((result) => !result.valid && result.failureCode === 'NONCE_REPLAY').length, 63);
  assert.equal(value.verifier.nonceAuthority.inspect(nonce)?.state, 'consumed');
});

test('correct context permits exactly one successful verification', async () => {
  const value = fixture();
  const { nonce, context } = value.issue();
  const proof = await value.prover.prove({ nonce });
  const result = value.verifier.verify(proof, { nonce, context });
  assert.equal(result.valid, true);
  assert.deepEqual(result.valid && result.nonceContext, context);
  assert.equal(value.verifier.nonceAuthority.inspect(nonce)?.state, 'consumed');
});
