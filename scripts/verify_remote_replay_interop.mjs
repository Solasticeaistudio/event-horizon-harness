#!/usr/bin/env node
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

import {
  NonceAuthority,
  RemoteNoncePersistence,
  SignedReplayClient,
  createHttpReplayTransport,
} from '../attestation/packages/core/dist/index.js';

const configurationPath = process.argv[2];
if (!configurationPath) throw new Error('remote replay interoperability configuration is required');
const configuration = JSON.parse(await readFile(configurationPath, 'utf8'));
const client = new SignedReplayClient({
  serviceId: configuration.serviceId,
  clientPrivateKeyPem: configuration.clientPrivateKeyPem,
  serverPublicKeyPem: configuration.serverPublicKeyPem,
  epoch: configuration.epoch,
  transport: createHttpReplayTransport(configuration.url),
});
const persistence = new RemoteNoncePersistence(client, configuration.partition);
const authority = new NonceAuthority(60, () => Date.now(), persistence);
const context = {
  deviceId: 'interop-device',
  executorId: 'interop-executor',
  sessionId: 'interop-session',
  purpose: 'interop-conformance',
};
const nonce = await authority.issue(context);
const first = await authority.consume(nonce, context);
const replay = await authority.consume(nonce, context);
const record = await authority.inspect(nonce);
assert.equal(first.accepted, true);
assert.equal(first.status, 'consumed-now');
assert.equal(replay.accepted, false);
assert.equal(replay.status, 'consumed');
assert.equal(record?.state, 'consumed');
assert.deepEqual(record?.context, context);
process.stdout.write(JSON.stringify({
  accepted: first.accepted,
  replay: replay.status,
  state: record?.state,
  checkpoint: client.checkpoint,
}));
