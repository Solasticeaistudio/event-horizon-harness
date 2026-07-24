import { randomBytes } from 'node:crypto';
import { canonicalBytes, sha256 } from '@event-horizon/attestation-crypto';

export interface NonceContext {
  deviceId: string;
  executorId: string;
  sessionId: string;
  purpose: string;
}

export type NonceState = 'issued' | 'consumed' | 'expired';

export interface NonceRecord {
  nonce: string;
  context: NonceContext;
  contextDigest: string;
  issuedAt: number;
  expiresAt: number;
  state: NonceState;
  consumedAt?: number;
}

export type NonceTransitionStatus =
  | 'consumed-now'
  | 'unknown'
  | 'expired'
  | 'consumed'
  | 'wrong-context'
  | 'malformed';

export interface NonceTransitionResult {
  accepted: boolean;
  status: NonceTransitionStatus;
  record?: Readonly<NonceRecord>;
}

/**
 * Persistence boundary for one atomic compare-and-transition operation.
 *
 * A Redis or transactional-database implementation must implement
 * transitionToConsumed as one server-side transaction. This artifact ships
 * only the in-memory implementation and makes no distributed-atomicity claim.
 */
export interface NoncePersistence {
  createIssued(record: Readonly<NonceRecord>): boolean;
  transitionToConsumed(nonce: string, contextDigest: string, now: number): NonceTransitionResult;
  inspect(nonce: string, now: number): Readonly<NonceRecord> | undefined;
}

function cloneRecord(record: Readonly<NonceRecord>): NonceRecord {
  return { ...record, context: { ...record.context } };
}

export class InMemoryNoncePersistence implements NoncePersistence {
  private readonly records = new Map<string, NonceRecord>();

  createIssued(record: Readonly<NonceRecord>): boolean {
    if (this.records.has(record.nonce)) return false;
    this.records.set(record.nonce, cloneRecord(record));
    return true;
  }

  transitionToConsumed(nonce: string, contextDigest: string, now: number): NonceTransitionResult {
    const record = this.records.get(nonce);
    if (!record) return { accepted: false, status: 'unknown' };
    if (record.state === 'consumed') {
      return { accepted: false, status: 'consumed', record: cloneRecord(record) };
    }
    if (record.state === 'expired' || now >= record.expiresAt) {
      record.state = 'expired';
      return { accepted: false, status: 'expired', record: cloneRecord(record) };
    }
    if (record.contextDigest !== contextDigest) {
      return { accepted: false, status: 'wrong-context', record: cloneRecord(record) };
    }
    record.state = 'consumed';
    record.consumedAt = now;
    return { accepted: true, status: 'consumed-now', record: cloneRecord(record) };
  }

  inspect(nonce: string, now: number): Readonly<NonceRecord> | undefined {
    const record = this.records.get(nonce);
    if (!record) return undefined;
    if (record.state === 'issued' && now >= record.expiresAt) record.state = 'expired';
    return cloneRecord(record);
  }
}

function validateContext(context: NonceContext): NonceContext {
  if (!context || typeof context !== 'object' || Array.isArray(context)) {
    throw new TypeError('nonce context must be an object');
  }
  const fields = ['deviceId', 'executorId', 'purpose', 'sessionId'];
  if (JSON.stringify(Object.keys(context).sort()) !== JSON.stringify(fields)) {
    throw new TypeError('nonce context fields are invalid');
  }
  for (const field of fields) {
    const value = context[field as keyof NonceContext];
    if (typeof value !== 'string' || !value || value.length > 256) {
      throw new TypeError(`nonce context ${field} is invalid`);
    }
  }
  return { ...context };
}

function isCanonicalNonce(nonce: string): boolean {
  if (typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)) return false;
  const decoded = Buffer.from(nonce, 'base64url');
  return decoded.length === 32 && decoded.toString('base64url') === nonce;
}

export class NonceAuthority {
  constructor(
    private readonly ttlSeconds = 60,
    private readonly now: () => number = () => Date.now(),
    private readonly persistence: NoncePersistence = new InMemoryNoncePersistence(),
  ) {
    if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0 || ttlSeconds > 3600) {
      throw new TypeError('nonce TTL must be greater than 0 and no more than 3600 seconds');
    }
  }

  issue(context: NonceContext): string {
    const validatedContext = validateContext(context);
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const nonce = randomBytes(32).toString('base64url');
      const issuedAt = this.now();
      const record: NonceRecord = {
        nonce,
        context: validatedContext,
        contextDigest: sha256(canonicalBytes(validatedContext)),
        issuedAt,
        expiresAt: issuedAt + this.ttlSeconds * 1000,
        state: 'issued',
      };
      if (this.persistence.createIssued(record)) return nonce;
    }
    throw new Error('nonce generation collision limit exceeded');
  }

  register(nonce: string, context: NonceContext, issuedAt: number, expiresAt: number): void {
    const validatedContext = validateContext(context);
    if (!isCanonicalNonce(nonce)) throw new TypeError('registered nonce is malformed');
    if (
      !Number.isFinite(issuedAt)
      || !Number.isFinite(expiresAt)
      || issuedAt > this.now()
      || expiresAt <= issuedAt
      || expiresAt - issuedAt > 3600 * 1000
    ) {
      throw new TypeError('registered nonce timestamps are invalid');
    }
    const created = this.persistence.createIssued({
      nonce,
      context: validatedContext,
      contextDigest: sha256(canonicalBytes(validatedContext)),
      issuedAt,
      expiresAt,
      state: 'issued',
    });
    if (!created) throw new Error('nonce is already registered');
  }

  consume(nonce: string, context: NonceContext): NonceTransitionResult {
    if (!isCanonicalNonce(nonce)) return { accepted: false, status: 'malformed' };
    let validatedContext: NonceContext;
    try {
      validatedContext = validateContext(context);
    } catch {
      return { accepted: false, status: 'malformed' };
    }
    return this.persistence.transitionToConsumed(
      nonce,
      sha256(canonicalBytes(validatedContext)),
      this.now(),
    );
  }

  inspect(nonce: string): Readonly<NonceRecord> | undefined {
    if (!isCanonicalNonce(nonce)) return undefined;
    return this.persistence.inspect(nonce, this.now());
  }
}
