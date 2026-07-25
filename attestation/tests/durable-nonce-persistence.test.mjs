import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import Database from 'better-sqlite3';

import {
  NonceAuthority,
  SqliteNoncePersistence,
  Verifier,
} from '../packages/core/dist/index.js';
import { SimulatorProver } from '../packages/simulator/dist/index.js';
import { nonceContext } from './nonce-context.mjs';

const run = promisify(execFile);
const worker = fileURLToPath(new URL('./helpers/sqlite-nonce-worker.mjs', import.meta.url));
const fixedNow = Date.parse('2026-01-01T00:00:00.000Z');

async function temporaryTest(callback) {
  const directory = await mkdtemp(join(tmpdir(), 'eh-nonce-sqlite-'));
  try {
    await callback(directory);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

test('durable nonce state survives verifier restart', async () => {
  await temporaryTest(async (directory) => {
    const databasePath = join(directory, 'replay.sqlite3');
    const context = nonceContext('durable-device');
    const first = new SqliteNoncePersistence(databasePath, 'restart-test');
    const authority = new NonceAuthority(60, () => fixedNow, first);
    const nonce = authority.issue(context);
    first.close();

    const second = new SqliteNoncePersistence(databasePath, 'restart-test');
    const afterRestart = new NonceAuthority(60, () => fixedNow + 1, second);
    assert.equal(afterRestart.inspect(nonce)?.state, 'issued');
    assert.equal(afterRestart.consume(nonce, context).accepted, true);
    second.close();

    const third = new SqliteNoncePersistence(databasePath, 'restart-test');
    const finalAuthority = new NonceAuthority(60, () => fixedNow + 2, third);
    assert.equal(finalAuthority.inspect(nonce)?.state, 'consumed');
    assert.equal(finalAuthority.consume(nonce, context).status, 'consumed');
    third.close();
  });
});

test('concurrent verifier processes accept one nonce exactly once', async () => {
  await temporaryTest(async (directory) => {
    const databasePath = join(directory, 'replay.sqlite3');
    const namespace = 'replica-race';
    const deviceId = 'replica-device';
    const context = nonceContext(deviceId, {
      executorId: 'replica-executor',
      sessionId: 'replica-session',
      purpose: 'replica-concurrency-test',
    });
    const prover = new SimulatorProver({
      deviceId,
      seed: 'durable-nonce-replica-seed',
      now: () => new Date(fixedNow),
    });
    const persistence = new SqliteNoncePersistence(databasePath, namespace, 10_000);
    const authority = new NonceAuthority(60, () => fixedNow, persistence);
    const nonce = authority.issue(context);
    persistence.close();
    const bundle = await prover.prove({ nonce });
    const inputPath = join(directory, 'worker-input.json');
    await writeFile(inputPath, JSON.stringify({
      databasePath,
      namespace,
      bundle,
      publicKeyPem: prover.publicKeyPem,
      nonce,
      context,
      now: new Date(fixedNow + 1).toISOString(),
    }));

    const results = await Promise.all(
      Array.from({ length: 24 }, async () => {
        const completed = await run(process.execPath, [worker, inputPath], {
          windowsHide: true,
          maxBuffer: 1024 * 1024,
        });
        return JSON.parse(completed.stdout);
      }),
    );
    assert.equal(results.filter((result) => result.valid).length, 1);
    assert.equal(
      results.filter((result) => !result.valid && result.failureCode === 'NONCE_REPLAY').length,
      23,
    );
  });
});

test('nonce namespaces isolate independent verifier populations', async () => {
  await temporaryTest(async (directory) => {
    const databasePath = join(directory, 'replay.sqlite3');
    const context = nonceContext('namespace-device');
    const first = new SqliteNoncePersistence(databasePath, 'population-a');
    const nonce = new NonceAuthority(60, () => fixedNow, first).issue(context);
    const second = new SqliteNoncePersistence(databasePath, 'population-b');
    assert.equal(new NonceAuthority(60, () => fixedNow, second).inspect(nonce), undefined);
    first.close();
    second.close();
  });
});

test('closed, corrupt, or incompatible durable nonce storage fails closed', async () => {
  await temporaryTest(async (directory) => {
    const databasePath = join(directory, 'replay.sqlite3');
    const deviceId = 'failure-device';
    const context = nonceContext(deviceId);
    const prover = new SimulatorProver({
      deviceId,
      seed: 'durable-nonce-failure-seed',
      now: () => new Date(fixedNow),
    });
    const persistence = new SqliteNoncePersistence(databasePath, 'failure-test');
    const verifier = new Verifier({
      deviceKeys: { [deviceId]: prover.publicKeyPem },
      now: () => new Date(fixedNow),
      noncePersistence: persistence,
    });
    const nonce = verifier.nonceAuthority.issue(context);
    const bundle = await prover.prove({ nonce });
    persistence.close();
    const result = verifier.verify(bundle, { nonce, context });
    assert.equal(result.valid, false);
    assert.equal(result.failureCode, 'VERIFIER_UNAVAILABLE');

    const corruptPath = join(directory, 'corrupt.sqlite3');
    await writeFile(corruptPath, 'not a sqlite database');
    assert.throws(
      () => new SqliteNoncePersistence(corruptPath, 'failure-test'),
      /database|file is not a database/i,
    );

    const schemaPath = join(directory, 'schema.sqlite3');
    new SqliteNoncePersistence(schemaPath, 'failure-test').close();
    const schemaDatabase = new Database(schemaPath);
    schemaDatabase.prepare(`
      UPDATE event_horizon_replay_schema SET version = 2 WHERE component = 'attestation-nonce'
    `).run();
    schemaDatabase.close();
    assert.throws(
      () => new SqliteNoncePersistence(schemaPath, 'failure-test'),
      /schema version is unsupported/,
    );
  });
});
