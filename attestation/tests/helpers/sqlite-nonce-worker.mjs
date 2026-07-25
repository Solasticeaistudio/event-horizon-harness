#!/usr/bin/env node
import { readFile } from 'node:fs/promises';
import { SqliteNoncePersistence, Verifier } from '../../packages/core/dist/index.js';

const inputPath = process.argv[2];
if (!inputPath) throw new Error('worker input path is required');
const input = JSON.parse(await readFile(inputPath, 'utf8'));
const persistence = new SqliteNoncePersistence(input.databasePath, input.namespace, 10_000);
try {
  const verifier = new Verifier({
    deviceKeys: { [input.bundle.deviceId]: input.publicKeyPem },
    now: () => new Date(input.now),
    noncePersistence: persistence,
  });
  const result = await verifier.verify(input.bundle, {
    nonce: input.nonce,
    context: input.context,
  });
  process.stdout.write(JSON.stringify(result));
} finally {
  persistence.close();
}
