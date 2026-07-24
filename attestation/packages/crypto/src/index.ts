import {
  KeyObject,
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
} from 'node:crypto';

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue };

function normalize(value: unknown): JsonValue {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return value;
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new TypeError('canonical JSON rejects non-finite numbers');
    return value;
  }
  if (Array.isArray(value)) return value.map(normalize);
  if (typeof value === 'object') {
    const output: Record<string, JsonValue> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      const item = (value as Record<string, unknown>)[key];
      if (item === undefined) throw new TypeError(`canonical JSON rejects undefined at ${key}`);
      output[key] = normalize(item);
    }
    return output;
  }
  throw new TypeError(`unsupported canonical JSON value: ${typeof value}`);
}

export function canonicalize(value: unknown): string {
  return JSON.stringify(normalize(value));
}

export function canonicalBytes(value: unknown): Buffer {
  return Buffer.from(canonicalize(value), 'utf8');
}

export function sha256(data: string | Uint8Array): string {
  return createHash('sha256').update(data).digest('hex');
}

export function base64urlEncode(data: string | Uint8Array): string {
  return Buffer.from(data).toString('base64url');
}

export function base64urlDecode(data: string): Buffer {
  return Buffer.from(data, 'base64url');
}

export interface Ed25519KeyPair {
  privateKey: KeyObject;
  publicKey: KeyObject;
}

export function generateEd25519KeyPair(): Ed25519KeyPair {
  return generateKeyPairSync('ed25519');
}

export function ed25519KeyPairFromSeed(seed: string | Uint8Array): Ed25519KeyPair {
  const seedBytes = createHash('sha256').update(seed).digest();
  const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
  const privateKey = createPrivateKey({ key: Buffer.concat([prefix, seedBytes]), format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey) };
}

export function exportPublicKeyPem(key: KeyObject): string {
  return key.export({ format: 'pem', type: 'spki' }).toString();
}

export function exportPrivateKeyPem(key: KeyObject): string {
  return key.export({ format: 'pem', type: 'pkcs8' }).toString();
}

export function importPublicKeyPem(pem: string): KeyObject {
  return createPublicKey(pem);
}

export function importPrivateKeyPem(pem: string): KeyObject {
  return createPrivateKey(pem);
}

export function keyIdFromPublicKey(key: KeyObject | string): string {
  const publicKey = typeof key === 'string' ? createPublicKey(key) : key;
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return `ed25519:${sha256(der).slice(0, 32)}`;
}

export function signDetached(payload: Uint8Array, privateKey: KeyObject | string): string {
  const key = typeof privateKey === 'string' ? createPrivateKey(privateKey) : privateKey;
  return nodeSign(null, Buffer.from(payload), key).toString('base64url');
}

export function verifyDetached(payload: Uint8Array, signature: string, publicKey: KeyObject | string): boolean {
  try {
    const key = typeof publicKey === 'string' ? createPublicKey(publicKey) : publicKey;
    return nodeVerify(null, Buffer.from(payload), key, Buffer.from(signature, 'base64url'));
  } catch {
    return false;
  }
}
