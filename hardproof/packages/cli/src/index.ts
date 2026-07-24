#!/usr/bin/env node
import { Client, Server } from '@hardproof/sdk';
import { SimulatorProver } from '@hardproof/simulator';

async function demo(): Promise<void> {
  process.env.HARDPROOF_ALLOW_SIMULATOR = '1';
  const deviceId = 'event-horizon-executor-dev';
  const seed = 'event-horizon-hardproof-rebuild';
  const simulator = new SimulatorProver({ deviceId, seed });
  const server = Server.create({
    mode: 'local',
    config: {
      minTrustLevel: 'simulated',
      maxProofAgeSeconds: 30,
      deviceKeys: { [deviceId]: simulator.publicKeyPem },
      pcrPolicy: { executor: { type: 'exact', value: simulator.measurements.executor! } },
    },
  });
  const nonce = await server.nonce.issue();
  const client = await Client.create({ deviceId, method: 'simulator', simulatorSeed: seed });
  const proof = await client.prove({ nonce });
  const verified = await server.verify(proof, { nonce });
  console.log(JSON.stringify({ proof: { deviceId: proof.deviceId, method: proof.method, keyId: proof.keyId }, verified }, null, 2));
}

const command = process.argv[2] ?? 'demo';
if (command === 'demo') await demo();
else {
  console.error(`Unknown command: ${command}`);
  process.exitCode = 2;
}
