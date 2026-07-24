#!/usr/bin/env node
import { Client, Server, decodeBundle, encodeBundle } from '@event-horizon/attestation-sdk';
import { SimulatorProver } from '@event-horizon/attestation-simulator';

const deviceId = 'event-horizon-executor-dev';
const seed = 'event-horizon-attestation-cli-fixture';

function developmentServer(simulator: SimulatorProver): Server {
  return Server.create({
    mode: 'local',
    config: {
      minTrustLevel: 'simulated',
      maxProofAgeSeconds: 30,
      deviceKeys: { [deviceId]: simulator.publicKeyPem },
      pcrPolicy: { executor: { type: 'exact', value: simulator.measurements.executor! } },
    },
  });
}

async function createDevelopmentBundle() {
  process.env.EH_ATTESTATION_ALLOW_SIMULATOR = '1';
  const simulator = new SimulatorProver({ deviceId, seed });
  const server = developmentServer(simulator);
  const nonce = await server.nonce.issue();
  const client = await Client.create({ deviceId, method: 'simulator', simulatorSeed: seed });
  const bundle = await client.prove({ nonce });
  return { bundle, nonce, server };
}

async function prove(): Promise<void> {
  const { bundle } = await createDevelopmentBundle();
  console.log(JSON.stringify({
    warning: 'Development simulator output; not hardware-backed attestation.',
    bundle,
    encodedBundle: encodeBundle(bundle),
  }, null, 2));
}

async function verify(): Promise<void> {
  const { bundle, nonce, server } = await createDevelopmentBundle();
  const result = await server.verify(bundle, { nonce });
  console.log(JSON.stringify({
    warning: 'Development simulator verification; not hardware-backed attestation.',
    result,
  }, null, 2));
  if (!result.valid) process.exitCode = 1;
}

async function inspect(encoded = process.argv[3]): Promise<void> {
  const bundle = encoded ? decodeBundle(encoded) : (await createDevelopmentBundle()).bundle;
  console.log(JSON.stringify({
    verified: false,
    warning: 'Inspection parses fields only; it does not verify trust.',
    bundle,
  }, null, 2));
}

function usage(): void {
  console.error('usage: eh-attest <prove|verify|inspect> [encoded-bundle]');
}

const command = process.argv[2];
if (command === 'prove') await prove();
else if (command === 'verify') await verify();
else if (command === 'inspect') await inspect();
else {
  usage();
  process.exitCode = 2;
}
