#!/usr/bin/env node
import { SimulatorProver } from '../packages/simulator/dist/index.js';
import { Verifier } from '../packages/core/dist/index.js';

const deviceId = process.argv[2];
const seed = process.argv[3];
if (!deviceId || !seed) {
  console.error('usage: verify-executor.mjs <device-id> <seed>');
  process.exit(2);
}

const prover = new SimulatorProver({ deviceId, seed });
const verifier = new Verifier({
  minTrustLevel: 'simulated',
  maxProofAgeSeconds: 30,
  deviceKeys: { [deviceId]: prover.publicKeyPem },
  pcrPolicy: { executor: { type: 'exact', value: prover.measurements.executor } },
});
const nonce = verifier.nonceStore.issue();
const bundle = await prover.prove({ nonce });
const result = verifier.verify(bundle, { nonce });
console.log(JSON.stringify(result));
if (!result.valid) process.exitCode = 1;
