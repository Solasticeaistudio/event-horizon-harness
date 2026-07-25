import { randomBytes } from 'node:crypto';
import {
  canonicalBytes,
  canonicalize,
  importPrivateKeyPem,
  importPublicKeyPem,
  keyIdFromPublicKey,
  sha256,
  signDetached,
  verifyDetached,
} from '@event-horizon/attestation-crypto';
import type {
  NonceContext,
  NoncePersistence,
  NonceRecord,
  NonceTransitionResult,
  NonceTransitionStatus,
} from './nonce-authority.js';

const REQUEST_SCHEMA = 'event-horizon.replay-request.v1';
const RESPONSE_SCHEMA = 'event-horizon.replay-response.v1';
const GENESIS_SCHEMA = 'event-horizon.replay-genesis.v1';
const REQUEST_FIELDS = [
  'algorithm',
  'client_key_id',
  'expected_epoch',
  'expires_at',
  'issued_at',
  'minimum_checkpoint',
  'minimum_checkpoint_digest',
  'operation',
  'partition',
  'payload',
  'request_id',
  'schema',
  'service_id',
  'signature',
];
const RESPONSE_FIELDS = [
  'accepted',
  'algorithm',
  'checkpoint',
  'checkpoint_digest',
  'epoch',
  'request_digest',
  'request_id',
  'responded_at',
  'result',
  'schema',
  'server_key_id',
  'service_id',
  'signature',
  'status',
];
const RECORD_FIELDS = ['context', 'contextDigest', 'expiresAt', 'issuedAt', 'nonce', 'state'];
const RECORD_WITH_CONSUMED_FIELDS = [...RECORD_FIELDS, 'consumedAt'].sort();
const CONTEXT_FIELDS = ['deviceId', 'executorId', 'purpose', 'sessionId'];
const SCOPE = /^[a-z0-9][a-z0-9._:-]{0,127}$/;
const DIGEST = /^[0-9a-f]{64}$/;
const KEY_ID = /^ed25519:[0-9a-f]{32}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const TRANSITION_STATUSES = new Set<NonceTransitionStatus>([
  'consumed-now',
  'unknown',
  'expired',
  'consumed',
  'wrong-context',
  'malformed',
]);

type JsonObject = Record<string, unknown>;
export type ReplayOperation = 'nonce-create' | 'nonce-consume' | 'nonce-inspect';
export type ReplayTransport = (request: Readonly<JsonObject>) => Promise<unknown>;

export class RemoteReplayProtocolError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RemoteReplayProtocolError';
  }
}

export class RemoteReplayUnavailableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'RemoteReplayUnavailableError';
  }
}

function isObject(value: unknown): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactFields(value: unknown, fields: string[], label: string): JsonObject {
  if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...fields].sort())) {
    throw new RemoteReplayProtocolError(`${label} fields are invalid`);
  }
  return value;
}

function strictJson(value: unknown, depth = 0): void {
  if (depth > 8) throw new RemoteReplayProtocolError('replay value exceeds nesting limit');
  if (value === null || typeof value === 'boolean') return;
  if (typeof value === 'string') {
    if (value.normalize('NFC') !== value || Buffer.byteLength(value, 'utf8') > 16_384) {
      throw new RemoteReplayProtocolError('replay string is not strict canonical input');
    }
    return;
  }
  if (typeof value === 'number') {
    if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
      throw new RemoteReplayProtocolError('replay numbers must be safe integers other than negative zero');
    }
    return;
  }
  if (Array.isArray(value)) {
    if (value.length > 256) throw new RemoteReplayProtocolError('replay array exceeds item limit');
    value.forEach((item) => strictJson(item, depth + 1));
    return;
  }
  if (isObject(value)) {
    const keys = Object.keys(value);
    if (keys.length > 256) throw new RemoteReplayProtocolError('replay object exceeds item limit');
    for (const key of keys) {
      strictJson(key, depth + 1);
      strictJson(value[key], depth + 1);
    }
    return;
  }
  throw new RemoteReplayProtocolError('replay value is not canonical JSON');
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) <= 0) {
    throw new RemoteReplayProtocolError(`${label} is invalid`);
  }
  return value as number;
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0) {
    throw new RemoteReplayProtocolError(`${label} is invalid`);
  }
  return value as number;
}

function requireDigest(value: unknown, label: string): string {
  if (typeof value !== 'string' || !DIGEST.test(value)) {
    throw new RemoteReplayProtocolError(`${label} is invalid`);
  }
  return value;
}

function canonicalNonce(value: unknown): value is string {
  if (typeof value !== 'string' || !NONCE.test(value)) return false;
  try {
    const bytes = Buffer.from(value, 'base64url');
    return bytes.length === 32 && bytes.toString('base64url') === value;
  } catch {
    return false;
  }
}

function validateContext(value: unknown): value is NonceContext {
  if (!isObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(CONTEXT_FIELDS)) return false;
  return CONTEXT_FIELDS.every((field) => {
    const item = value[field];
    return typeof item === 'string' && item.length > 0 && item.length <= 256 && item.normalize('NFC') === item;
  });
}

function validateRecord(value: unknown): NonceRecord {
  const object = isObject(value) ? value : {};
  const expected = object.consumedAt === undefined ? RECORD_FIELDS : RECORD_WITH_CONSUMED_FIELDS;
  exactFields(object, expected, 'remote nonce record');
  if (
    !canonicalNonce(object.nonce)
    || !validateContext(object.context)
    || typeof object.contextDigest !== 'string'
    || !DIGEST.test(object.contextDigest)
    || object.contextDigest !== sha256(canonicalBytes(object.context))
    || !Number.isSafeInteger(object.issuedAt)
    || !Number.isSafeInteger(object.expiresAt)
    || !['issued', 'consumed', 'expired'].includes(String(object.state))
  ) {
    throw new RemoteReplayProtocolError('remote nonce record is malformed');
  }
  if (object.state === 'consumed' && !Number.isSafeInteger(object.consumedAt)) {
    throw new RemoteReplayProtocolError('remote consumed nonce record omits its transition time');
  }
  if (object.state !== 'consumed' && object.consumedAt !== undefined) {
    throw new RemoteReplayProtocolError('remote nonce record has an invalid transition time');
  }
  return {
    nonce: object.nonce,
    context: { ...object.context },
    contextDigest: object.contextDigest,
    issuedAt: object.issuedAt as number,
    expiresAt: object.expiresAt as number,
    state: object.state as NonceRecord['state'],
    ...(object.consumedAt === undefined ? {} : { consumedAt: object.consumedAt as number }),
  };
}

export function remoteReplayGenesisDigest(serviceId: string, epoch: number): string {
  if (!SCOPE.test(serviceId) || !Number.isSafeInteger(epoch) || epoch <= 0) {
    throw new TypeError('remote replay service identity is invalid');
  }
  return sha256(canonicalBytes({ schema: GENESIS_SCHEMA, service_id: serviceId, epoch }));
}

export interface SignedReplayClientOptions {
  serviceId: string;
  clientPrivateKeyPem: string;
  serverPublicKeyPem: string;
  epoch: number;
  transport: ReplayTransport;
  checkpoint?: number;
  checkpointDigest?: string;
  lifetimeMs?: number;
  now?: () => number;
}

export class SignedReplayClient {
  readonly serviceId: string;
  readonly clientKeyId: string;
  serverKeyId: string;
  private readonly clientPrivateKey: ReturnType<typeof importPrivateKeyPem>;
  private serverPublicKey: ReturnType<typeof importPublicKeyPem>;
  private transport: ReplayTransport;
  private readonly lifetimeMs: number;
  private readonly now: () => number;
  private queue: Promise<void> = Promise.resolve();
  epoch: number;
  checkpoint: number;
  checkpointDigest: string;

  constructor(options: SignedReplayClientOptions) {
    if (!SCOPE.test(options.serviceId)) throw new TypeError('remote replay service ID is invalid');
    this.clientPrivateKey = importPrivateKeyPem(options.clientPrivateKeyPem);
    this.serverPublicKey = importPublicKeyPem(options.serverPublicKeyPem);
    if (
      this.clientPrivateKey.asymmetricKeyType !== 'ed25519'
      || this.serverPublicKey.asymmetricKeyType !== 'ed25519'
    ) {
      throw new TypeError('remote replay keys must be Ed25519');
    }
    this.clientKeyId = keyIdFromPublicKey(options.clientPrivateKeyPem);
    this.serverKeyId = keyIdFromPublicKey(this.serverPublicKey);
    this.serviceId = options.serviceId;
    this.epoch = positiveInteger(options.epoch, 'remote replay epoch');
    this.checkpoint = nonNegativeInteger(options.checkpoint ?? 0, 'remote replay checkpoint');
    this.checkpointDigest = options.checkpointDigest
      ?? remoteReplayGenesisDigest(this.serviceId, this.epoch);
    requireDigest(this.checkpointDigest, 'remote replay checkpoint digest');
    this.transport = options.transport;
    this.lifetimeMs = options.lifetimeMs ?? 5_000;
    if (!Number.isSafeInteger(this.lifetimeMs) || this.lifetimeMs <= 0 || this.lifetimeMs > 30_000) {
      throw new TypeError('remote replay request lifetime is invalid');
    }
    this.now = options.now ?? (() => Date.now());
  }

  async call(operation: ReplayOperation, partition: string, payload: JsonObject): Promise<JsonObject> {
    let release!: () => void;
    const previous = this.queue;
    this.queue = new Promise<void>((resolve) => { release = resolve; });
    await previous;
    try {
      if (!['nonce-create', 'nonce-consume', 'nonce-inspect'].includes(operation)) {
        throw new RemoteReplayProtocolError('remote replay operation is unsupported');
      }
      if (!SCOPE.test(partition)) throw new RemoteReplayProtocolError('remote replay partition is invalid');
      strictJson(payload);
      const issuedAt = this.now();
      if (!Number.isSafeInteger(issuedAt) || issuedAt < 0) {
        throw new RemoteReplayProtocolError('remote replay clock is invalid');
      }
      const unsigned: JsonObject = {
        schema: REQUEST_SCHEMA,
        algorithm: 'Ed25519',
        service_id: this.serviceId,
        client_key_id: this.clientKeyId,
        request_id: randomBytes(32).toString('base64url'),
        issued_at: issuedAt,
        expires_at: issuedAt + this.lifetimeMs,
        expected_epoch: this.epoch,
        minimum_checkpoint: this.checkpoint,
        minimum_checkpoint_digest: this.checkpointDigest,
        operation,
        partition,
        payload,
      };
      const request: JsonObject = {
        ...unsigned,
        signature: signDetached(canonicalBytes(unsigned), this.clientPrivateKey),
      };
      let response: unknown;
      try {
        response = await this.transport(request);
      } catch (error) {
        if (error instanceof RemoteReplayProtocolError) throw error;
        throw new RemoteReplayUnavailableError('remote replay request failed closed', { cause: error });
      }
      const verified = this.verifyResponse(request, response);
      if (verified.status === 'checkpoint-mismatch') {
        throw new RemoteReplayProtocolError('remote replay service cannot prove checkpoint continuity');
      }
      const checkpoint = verified.checkpoint as number;
      if (checkpoint > this.checkpoint) {
        this.checkpoint = checkpoint;
        this.checkpointDigest = verified.checkpoint_digest as string;
      }
      return verified;
    } finally {
      release();
    }
  }

  adoptEpoch(
    epoch: number,
    checkpoint: number,
    checkpointDigest: string,
    serverPublicKeyPem?: string,
    transport?: ReplayTransport,
  ): void {
    positiveInteger(epoch, 'promoted replay epoch');
    nonNegativeInteger(checkpoint, 'promoted replay checkpoint');
    requireDigest(checkpointDigest, 'promoted replay checkpoint digest');
    if (epoch <= this.epoch) throw new RemoteReplayProtocolError('promoted replay epoch must increase');
    if (checkpoint < this.checkpoint) {
      throw new RemoteReplayProtocolError('promoted replay service checkpoint regresses');
    }
    if (checkpoint === this.checkpoint && checkpointDigest !== this.checkpointDigest) {
      throw new RemoteReplayProtocolError('promoted replay service forks known history');
    }
    if (serverPublicKeyPem !== undefined) {
      const promotedKey = importPublicKeyPem(serverPublicKeyPem);
      if (promotedKey.asymmetricKeyType !== 'ed25519') {
        throw new TypeError('promoted remote replay key must be Ed25519');
      }
      this.serverPublicKey = promotedKey;
      this.serverKeyId = keyIdFromPublicKey(this.serverPublicKey);
    }
    if (transport !== undefined) this.transport = transport;
    this.epoch = epoch;
    this.checkpoint = checkpoint;
    this.checkpointDigest = checkpointDigest;
  }

  private verifyResponse(request: JsonObject, response: unknown): JsonObject {
    const value = exactFields(response, RESPONSE_FIELDS, 'remote replay response');
    strictJson(value);
    if (value.schema !== RESPONSE_SCHEMA || value.algorithm !== 'Ed25519') {
      throw new RemoteReplayProtocolError('remote replay response schema or algorithm is invalid');
    }
    if (value.service_id !== this.serviceId || value.server_key_id !== this.serverKeyId) {
      throw new RemoteReplayProtocolError('remote replay response service key is not pinned');
    }
    if (value.request_id !== request.request_id || value.request_digest !== sha256(canonicalBytes(request))) {
      throw new RemoteReplayProtocolError('remote replay response is not bound to the exact request');
    }
    const signature = value.signature;
    if (typeof signature !== 'string' || !SIGNATURE.test(signature)) {
      throw new RemoteReplayProtocolError('remote replay response signature is malformed');
    }
    const unsigned = Object.fromEntries(Object.entries(value).filter(([key]) => key !== 'signature'));
    if (!verifyDetached(canonicalBytes(unsigned), signature, this.serverPublicKey)) {
      throw new RemoteReplayProtocolError('remote replay response signature is invalid');
    }
    if (value.epoch !== this.epoch) {
      throw new RemoteReplayProtocolError('remote replay response came from an unpinned or stale epoch');
    }
    const checkpoint = nonNegativeInteger(value.checkpoint, 'remote replay response checkpoint');
    const checkpointDigest = requireDigest(value.checkpoint_digest, 'remote replay response checkpoint digest');
    if (checkpoint < this.checkpoint) {
      throw new RemoteReplayProtocolError('remote replay service checkpoint regressed');
    }
    if (checkpoint === this.checkpoint && checkpointDigest !== this.checkpointDigest) {
      throw new RemoteReplayProtocolError('remote replay service checkpoint forked known history');
    }
    if (typeof value.accepted !== 'boolean' || typeof value.status !== 'string' || !isObject(value.result)) {
      throw new RemoteReplayProtocolError('remote replay response decision is malformed');
    }
    nonNegativeInteger(value.responded_at, 'remote replay response time');
    return value;
  }
}

export class RemoteNoncePersistence implements NoncePersistence {
  constructor(
    private readonly client: SignedReplayClient,
    private readonly partition = 'attestation.nonces',
  ) {
    if (!SCOPE.test(partition)) throw new TypeError('remote nonce partition is invalid');
  }

  async createIssued(record: Readonly<NonceRecord>): Promise<boolean> {
    const response = await this.client.call('nonce-create', this.partition, {
      nonce: record.nonce,
      context: { ...record.context },
      context_digest: record.contextDigest,
      issued_at: record.issuedAt,
      expires_at: record.expiresAt,
    });
    if (response.status === 'created' && response.accepted === true) return true;
    if (response.status === 'already-exists' && response.accepted === false) return false;
    throw new RemoteReplayProtocolError('remote nonce creation failed closed');
  }

  async transitionToConsumed(
    nonce: string,
    contextDigest: string,
    now: number,
  ): Promise<NonceTransitionResult> {
    const response = await this.client.call('nonce-consume', this.partition, {
      nonce,
      context_digest: contextDigest,
      now,
    });
    if (!TRANSITION_STATUSES.has(response.status as NonceTransitionStatus)) {
      throw new RemoteReplayProtocolError('remote nonce transition status is invalid');
    }
    const result = exactFields(
      response.result,
      response.status === 'unknown' ? [] : ['record'],
      'remote nonce transition result',
    );
    const record = result.record === undefined ? undefined : validateRecord(result.record);
    return {
      accepted: response.accepted as boolean,
      status: response.status as NonceTransitionStatus,
      ...(record === undefined ? {} : { record }),
    };
  }

  async inspect(nonce: string, now: number): Promise<Readonly<NonceRecord> | undefined> {
    const response = await this.client.call('nonce-inspect', this.partition, { nonce, now });
    if (response.status === 'unknown' && response.accepted === false) {
      exactFields(response.result, [], 'remote nonce inspection result');
      return undefined;
    }
    if (response.status !== 'found' || response.accepted !== true) {
      throw new RemoteReplayProtocolError('remote nonce inspection failed closed');
    }
    const result = exactFields(response.result, ['record'], 'remote nonce inspection result');
    return validateRecord(result.record);
  }
}

export function createHttpReplayTransport(url: string, timeoutMs = 2_000): ReplayTransport {
  if (!/^https?:\/\//.test(url)) throw new TypeError('remote replay URL is invalid');
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0 || timeoutMs > 30_000) {
    throw new TypeError('remote replay timeout is invalid');
  }
  return async (request: Readonly<JsonObject>): Promise<JsonObject> => {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: canonicalize(request),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) throw new RemoteReplayUnavailableError('remote replay service returned an error');
    const text = await response.text();
    if (Buffer.byteLength(text, 'utf8') > 65_536) {
      throw new RemoteReplayProtocolError('remote replay response is too large');
    }
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch (error) {
      throw new RemoteReplayProtocolError(`remote replay response JSON is malformed: ${String(error)}`);
    }
    strictJson(value);
    if (canonicalize(value) !== text) {
      throw new RemoteReplayProtocolError('remote replay response JSON is not canonical');
    }
    if (!isObject(value)) throw new RemoteReplayProtocolError('remote replay response is not an object');
    return value;
  };
}
