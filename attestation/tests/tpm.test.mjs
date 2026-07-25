import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { mkdtemp } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { Verifier } from '../packages/core/dist/index.js';
import { LinuxTpm2ToolsProvider, TpmProver } from '../packages/tpm/dist/index.js';
import { createTpmBundle, createTpmIdentity } from './tpm-fixture.mjs';
import { nonceContext } from './nonce-context.mjs';

function fixture(options = {}) {
  let now = options.now ?? new Date('2026-01-01T00:00:00.000Z');
  const identity = options.identity ?? createTpmIdentity();
  const deviceId = options.deviceId ?? 'tpm-device-1';
  const verifier = new Verifier({
    minTrustLevel: 'hardware',
    maxProofAgeSeconds: 30,
    nonceTtlSeconds: options.nonceTtlSeconds ?? 60,
    now: () => now,
    deviceKeys: { [deviceId]: identity.publicKeyPem },
    tpmAkQualifiedNames: { [deviceId]: identity.qualifiedName },
    tpmPcrSelections: { [deviceId]: options.expectedPcrSelection ?? ['sha256:0', 'sha256:7'] },
    requireTpmEventLog: options.requireEventLog ?? true,
  });
  const context = nonceContext(deviceId, { sessionId: 'tpm-test-session' });
  return {
    identity,
    verifier,
    deviceId,
    context,
    issue: () => verifier.nonceAuthority.issue(context),
    bundle: (nonce, bundleOptions = {}) => createTpmBundle(identity, { nonce, deviceId, issuedAt: now, ...bundleOptions }),
    advance: (milliseconds) => { now = new Date(now.valueOf() + milliseconds); },
  };
}

test('valid TPM quote fixture verifies as hardware rooted', async () => {
  const value = fixture();
  const nonce = await value.issue();
  const result = await value.verifier.verify(value.bundle(nonce), { nonce, context: value.context });
  assert.equal(result.valid, true);
  assert.equal(result.valid && result.trustLevel, 'hardware');
  assert.equal(result.valid && result.assuranceLevel, 'hardware-rooted');
  assert.equal(result.valid && result.measurements['sha256:7']?.length, 64);
});

test('tampered PCR values are rejected against the signed composite', async () => {
  const value = fixture();
  const nonce = await value.issue();
  const bundle = value.bundle(nonce);
  bundle.evidence.pcrValues['sha256:0'] = '00'.repeat(32);
  const result = await value.verifier.verify(bundle, { nonce, context: value.context });
  assert.equal(result.valid, false);
  assert.equal(!result.valid && result.failureCode, 'TPM_PCR_DIGEST');
});

test('stale TPM proof timestamps fail before authorization', async () => {
  const value = fixture();
  const nonce = await value.issue();
  const issuedAt = new Date('2025-12-31T23:58:00.000Z');
  const bundle = value.bundle(nonce, { issuedAt, ttlSeconds: 300 });
  const result = await value.verifier.verify(bundle, { nonce, context: value.context });
  assert.equal(result.valid, false);
  assert.equal(!result.valid && result.failureCode, 'PROOF_TOO_OLD');
});

test('accepted TPM proof cannot be replayed', async () => {
  const value = fixture();
  const nonce = await value.issue();
  const bundle = value.bundle(nonce);
  assert.equal((await value.verifier.verify(bundle, { nonce, context: value.context })).valid, true);
  const replay = await value.verifier.verify(bundle, { nonce, context: value.context });
  assert.equal(replay.valid, false);
  assert.equal(!replay.valid && replay.failureCode, 'PROOF_REPLAY');
});

test('quote from the wrong AK is rejected', async () => {
  const registered = createTpmIdentity();
  const attacker = createTpmIdentity();
  const value = fixture({ identity: registered });
  const nonce = await value.issue();
  const bundle = createTpmBundle(attacker, { nonce, deviceId: value.deviceId, issuedAt: new Date('2026-01-01T00:00:00.000Z') });
  bundle.keyId = registered.keyId;
  const result = await value.verifier.verify(bundle, { nonce, context: value.context });
  assert.equal(result.valid, false);
  assert.equal(!result.valid && result.failureCode, 'TPM_AK_MISMATCH');
});

test('signed wrong PCR selection is rejected by verifier policy', async () => {
  const value = fixture();
  const nonce = await value.issue();
  const result = await value.verifier.verify(value.bundle(nonce, { pcrSelection: [0, 8] }), { nonce, context: value.context });
  assert.equal(result.valid, false);
  assert.equal(!result.valid && result.failureCode, 'TPM_PCR_SELECTION');
});

test('tampered or missing required event log is rejected', async () => {
  const tamperedValue = fixture();
  const tamperedNonce = await tamperedValue.issue();
  const tampered = tamperedValue.bundle(tamperedNonce);
  tampered.evidence.eventLog[0].digest = '11'.repeat(32);
  const tamperedResult = await tamperedValue.verifier.verify(tampered, { nonce: tamperedNonce, context: tamperedValue.context });
  assert.equal(tamperedResult.valid, false);
  assert.equal(!tamperedResult.valid && tamperedResult.failureCode, 'TPM_EVENT_LOG');

  const missingValue = fixture();
  const missingNonce = await missingValue.issue();
  const missing = await missingValue.verifier.verify(
    missingValue.bundle(missingNonce, { includeEventLog: false }),
    { nonce: missingNonce, context: missingValue.context },
  );
  assert.equal(missing.valid, false);
  assert.equal(!missing.valid && missing.failureCode, 'TPM_EVENT_LOG');
});

test('unknown and expired verifier nonces are rejected', async () => {
  const unknownValue = fixture();
  const unknownNonce = randomBytes(32).toString('base64url');
  const unknown = await unknownValue.verifier.verify(
    unknownValue.bundle(unknownNonce),
    { nonce: unknownNonce, context: unknownValue.context },
  );
  assert.equal(unknown.valid, false);
  assert.equal(!unknown.valid && unknown.failureCode, 'NONCE_UNKNOWN');

  const expiredValue = fixture({ nonceTtlSeconds: 1 });
  const expiredNonce = await expiredValue.issue();
  const expiredBundle = expiredValue.bundle(expiredNonce);
  expiredValue.advance(2_000);
  const expired = await expiredValue.verifier.verify(
    expiredBundle,
    { nonce: expiredNonce, context: expiredValue.context },
  );
  assert.equal(expired.valid, false);
  assert.equal(!expired.valid && expired.failureCode, 'NONCE_EXPIRED');
});

test('TPM prover never silently falls back without a hardware provider', async () => {
  const prover = new TpmProver({ deviceId: 'no-provider' });
  await assert.rejects(() => prover.prove({ nonce: randomBytes(32).toString('base64url') }), { name: 'PROVER_NOT_IMPLEMENTED' });
});

test('real Linux TPM quote integration', { skip: process.env.EH_ATTESTATION_REAL_TPM !== '1' }, async () => {
  assert.equal(process.platform, 'linux');
  const workDirectory = process.env.EH_ATTESTATION_TPM_WORKDIR ?? await mkdtemp(join(tmpdir(), 'attestation-tpm-'));
  const provider = new LinuxTpm2ToolsProvider({
    workDirectory,
    tcti: process.env.EH_ATTESTATION_TPM_TCTI,
    akContextPath: process.env.EH_ATTESTATION_TPM_AK_CONTEXT,
    akPublicKeyPath: process.env.EH_ATTESTATION_TPM_AK_PUBLIC,
    akQualifiedNamePath: process.env.EH_ATTESTATION_TPM_AK_QUALIFIED_NAME,
    normalizedEventLogPath: process.env.EH_ATTESTATION_TPM_EVENT_LOG_JSON,
  });
  const ak = process.env.EH_ATTESTATION_TPM_PROVISION_AK === '1'
    ? await provider.provisionAk()
    : await provider.loadAk();
  const deviceId = 'real-tpm-device';
  const verifier = new Verifier({
    minTrustLevel: 'hardware',
    deviceKeys: { [deviceId]: ak.publicKeyPem },
    tpmAkQualifiedNames: { [deviceId]: ak.qualifiedName },
    tpmPcrSelections: { [deviceId]: ['sha256:0', 'sha256:7'] },
    requireTpmEventLog: Boolean(process.env.EH_ATTESTATION_TPM_EVENT_LOG_JSON),
  });
  const context = nonceContext(deviceId, { sessionId: 'real-tpm-test-session' });
  const nonce = await verifier.nonceAuthority.issue(context);
  const prover = new TpmProver({ deviceId, pcrSelection: [0, 7], provider });
  const result = await verifier.verify(await prover.prove({ nonce }), { nonce, context });
  assert.equal(result.valid, true, JSON.stringify(result));
});
