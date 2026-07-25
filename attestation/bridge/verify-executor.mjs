#!/usr/bin/env node
import { SimulatorProver } from '../packages/simulator/dist/index.js';
import { SqliteNoncePersistence, Verifier } from '../packages/core/dist/index.js';

const deviceId = process.argv[2];
const seed = process.argv[3];
const sessionId = process.argv[4];
const purpose = process.argv[5];
if (!deviceId || !seed || !sessionId || !purpose) {
  console.error('usage: verify-executor.mjs <device-id> <seed> <session-id> <purpose>');
  process.exit(2);
}

const prover = new SimulatorProver({ deviceId, seed });
const noncePersistence = process.env.EH_ATTESTATION_REPLAY_DB
  ? new SqliteNoncePersistence(
    process.env.EH_ATTESTATION_REPLAY_DB,
    process.env.EH_ATTESTATION_REPLAY_NAMESPACE ?? 'event-horizon',
  )
  : undefined;
const verifier = new Verifier({
  minTrustLevel: 'simulated',
  maxProofAgeSeconds: 30,
  deviceKeys: { [deviceId]: prover.publicKeyPem },
  pcrPolicy: { executor: { type: 'exact', value: prover.measurements.executor } },
  noncePersistence,
});
const context = { deviceId, executorId: deviceId, sessionId, purpose };
const nonce = verifier.nonceAuthority.issue(context);
const bundle = await prover.prove({ nonce });
const result = verifier.verify(bundle, { nonce, context });
console.log(JSON.stringify(result));
noncePersistence?.close();
if (!result.valid) process.exitCode = 1;
