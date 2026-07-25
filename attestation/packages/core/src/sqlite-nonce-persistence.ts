import { chmodSync, mkdirSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import Database from 'better-sqlite3';
import { canonicalBytes, sha256 } from '@event-horizon/attestation-crypto';
import type {
  NonceContext,
  NoncePersistence,
  NonceRecord,
  NonceTransitionResult,
} from './nonce-authority.js';

interface NonceRow {
  nonce: string;
  context_json: string;
  context_digest: string;
  issued_at: number;
  expires_at: number;
  state: string;
  consumed_at: number | null;
}

const NAMESPACE = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const DIGEST = /^[0-9a-f]{64}$/;

function contextFromJson(value: string): NonceContext {
  const parsed: unknown = JSON.parse(value);
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new TypeError('persisted nonce context is malformed');
  }
  const context = parsed as Record<string, unknown>;
  const fields = ['deviceId', 'executorId', 'purpose', 'sessionId'];
  if (JSON.stringify(Object.keys(context).sort()) !== JSON.stringify(fields)) {
    throw new TypeError('persisted nonce context fields are malformed');
  }
  for (const field of fields) {
    const item = context[field];
    if (typeof item !== 'string' || !item || item.length > 256) {
      throw new TypeError('persisted nonce context value is malformed');
    }
  }
  return context as unknown as NonceContext;
}

function recordFromRow(row: NonceRow | undefined): NonceRecord | undefined {
  if (!row) return undefined;
  const context = contextFromJson(row.context_json);
  if (
    !NONCE.test(row.nonce)
    || !DIGEST.test(row.context_digest)
    || sha256(canonicalBytes(context)) !== row.context_digest
    || !Number.isSafeInteger(row.issued_at)
    || !Number.isSafeInteger(row.expires_at)
    || row.expires_at <= row.issued_at
    || !['issued', 'consumed', 'expired'].includes(row.state)
    || (row.consumed_at !== null && !Number.isSafeInteger(row.consumed_at))
  ) {
    throw new TypeError('persisted nonce record is malformed');
  }
  if (row.state === 'consumed' && row.consumed_at === null) {
    throw new TypeError('persisted consumed nonce omitted its transition time');
  }
  const record: NonceRecord = {
    nonce: row.nonce,
    context,
    contextDigest: row.context_digest,
    issuedAt: row.issued_at,
    expiresAt: row.expires_at,
    state: row.state as NonceRecord['state'],
  };
  if (row.consumed_at !== null) record.consumedAt = row.consumed_at;
  return record;
}

/**
 * Durable, single-host nonce persistence using SQLite conditional transitions.
 *
 * WAL plus a conditional UPDATE makes issued -> consumed atomic across verifier
 * processes that share one local database file. This does not claim safety on
 * network filesystems or provide multi-host consensus.
 */
export class SqliteNoncePersistence implements NoncePersistence {
  private readonly database: Database.Database;
  private selectRecord!: Database.Statement<[string, string], NonceRow>;
  private insertIssued!: Database.Statement;
  private consumeIssued!: Database.Statement;
  private expireIssued!: Database.Statement;
  private closed = false;

  constructor(
    databasePath: string,
    private readonly namespace = 'default',
    busyTimeoutMs = 5_000,
  ) {
    if (typeof databasePath !== 'string' || !databasePath || databasePath === ':memory:') {
      throw new TypeError('durable nonce database path is invalid');
    }
    if (!NAMESPACE.test(namespace)) throw new TypeError('nonce database namespace is invalid');
    if (!Number.isSafeInteger(busyTimeoutMs) || busyTimeoutMs < 1 || busyTimeoutMs > 60_000) {
      throw new TypeError('nonce database busy timeout is invalid');
    }
    const absolutePath = resolve(databasePath);
    mkdirSync(dirname(absolutePath), { recursive: true });
    this.database = new Database(absolutePath, { timeout: busyTimeoutMs });
    try {
      if (process.platform !== 'win32') chmodSync(absolutePath, 0o600);
      this.database.pragma('journal_mode = WAL');
      this.database.pragma('synchronous = FULL');
      this.database.pragma('foreign_keys = ON');
      this.database.pragma(`busy_timeout = ${busyTimeoutMs}`);
      this.database.exec(`
        CREATE TABLE IF NOT EXISTS event_horizon_replay_schema (
          component TEXT PRIMARY KEY,
          version INTEGER NOT NULL
        ) WITHOUT ROWID;
        INSERT OR IGNORE INTO event_horizon_replay_schema (component, version)
          VALUES ('attestation-nonce', 1);
        CREATE TABLE IF NOT EXISTS attestation_nonces (
          namespace TEXT NOT NULL,
          nonce TEXT NOT NULL,
          context_json TEXT NOT NULL,
          context_digest TEXT NOT NULL,
          issued_at INTEGER NOT NULL,
          expires_at INTEGER NOT NULL,
          state TEXT NOT NULL CHECK (state IN ('issued', 'consumed', 'expired')),
          consumed_at INTEGER,
          PRIMARY KEY (namespace, nonce)
        ) WITHOUT ROWID
      `);
      const schema = this.database.prepare(`
        SELECT version FROM event_horizon_replay_schema WHERE component = 'attestation-nonce'
      `).get() as { version?: unknown } | undefined;
      if (schema?.version !== 1) throw new Error('durable nonce schema version is unsupported');
      this.selectRecord = this.database.prepare(`
        SELECT nonce, context_json, context_digest, issued_at, expires_at, state, consumed_at
        FROM attestation_nonces WHERE namespace = ? AND nonce = ?
      `);
      this.insertIssued = this.database.prepare(`
        INSERT INTO attestation_nonces (
          namespace, nonce, context_json, context_digest, issued_at, expires_at, state, consumed_at
        ) VALUES (?, ?, ?, ?, ?, ?, 'issued', NULL)
        ON CONFLICT(namespace, nonce) DO NOTHING
      `);
      this.consumeIssued = this.database.prepare(`
        UPDATE attestation_nonces SET state = 'consumed', consumed_at = ?
        WHERE namespace = ? AND nonce = ? AND context_digest = ?
          AND state = 'issued' AND expires_at > ?
      `);
      this.expireIssued = this.database.prepare(`
        UPDATE attestation_nonces SET state = 'expired'
        WHERE namespace = ? AND nonce = ? AND state = 'issued' AND expires_at <= ?
      `);
    } catch (error) {
      this.database.close();
      throw error;
    }
  }

  createIssued(record: Readonly<NonceRecord>): boolean {
    this.assertOpen();
    const result = this.insertIssued.run(
      this.namespace,
      record.nonce,
      canonicalBytes(record.context).toString('utf8'),
      record.contextDigest,
      record.issuedAt,
      record.expiresAt,
    );
    return result.changes === 1;
  }

  transitionToConsumed(nonce: string, contextDigest: string, now: number): NonceTransitionResult {
    this.assertOpen();
    const transitioned = this.consumeIssued.run(now, this.namespace, nonce, contextDigest, now);
    if (transitioned.changes === 1) {
      const record = this.read(nonce);
      if (!record || record.state !== 'consumed') {
        throw new Error('durable nonce transition record is unavailable');
      }
      return { accepted: true, status: 'consumed-now', record };
    }
    this.expireIssued.run(this.namespace, nonce, now);
    const record = this.read(nonce);
    if (!record) return { accepted: false, status: 'unknown' };
    if (record.state === 'expired') return { accepted: false, status: 'expired', record };
    if (record.state === 'consumed') return { accepted: false, status: 'consumed', record };
    if (record.contextDigest !== contextDigest) {
      return { accepted: false, status: 'wrong-context', record };
    }
    throw new Error('durable nonce conditional transition failed without a terminal state');
  }

  inspect(nonce: string, now: number): Readonly<NonceRecord> | undefined {
    this.assertOpen();
    this.expireIssued.run(this.namespace, nonce, now);
    return this.read(nonce);
  }

  close(): void {
    if (!this.closed) {
      this.database.close();
      this.closed = true;
    }
  }

  private read(nonce: string): NonceRecord | undefined {
    return recordFromRow(this.selectRecord.get(this.namespace, nonce));
  }

  private assertOpen(): void {
    if (this.closed) throw new Error('durable nonce persistence is closed');
  }
}
