import {
  createHash,
  generateKeyPairSync,
  sign,
} from 'node:crypto';
import { tpm2KeyIdFromPublicKey } from '../packages/core/dist/index.js';

function hash(value) {
  return createHash('sha256').update(value).digest();
}

function u8(value) {
  const result = Buffer.alloc(1);
  result.writeUInt8(value);
  return result;
}

function u16(value) {
  const result = Buffer.alloc(2);
  result.writeUInt16BE(value);
  return result;
}

function u32(value) {
  const result = Buffer.alloc(4);
  result.writeUInt32BE(value);
  return result;
}

function u64(value) {
  const result = Buffer.alloc(8);
  result.writeBigUInt64BE(BigInt(value));
  return result;
}

function sized(value) {
  return Buffer.concat([u16(value.length), value]);
}

export function createTpmIdentity() {
  const keyPair = generateKeyPairSync('rsa', { modulusLength: 2048, publicExponent: 0x10001 });
  const publicKeyPem = keyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString();
  const publicDer = keyPair.publicKey.export({ format: 'der', type: 'spki' });
  const qualifiedName = Buffer.concat([u16(0x000b), hash(publicDer)]).toString('hex');
  return {
    privateKey: keyPair.privateKey,
    publicKeyPem,
    qualifiedName,
    keyId: tpm2KeyIdFromPublicKey(publicKeyPem),
  };
}

export function createTpmBundle(identity, options) {
  const selection = [...(options.pcrSelection ?? [0, 7])].sort((left, right) => left - right);
  const bitmap = Buffer.alloc(3);
  for (const pcr of selection) bitmap[Math.floor(pcr / 8)] |= 1 << (pcr % 8);
  const pcrValues = {};
  const eventLog = [];
  const pcrBuffers = [];
  for (const pcr of selection) {
    const eventDigest = hash(`fixture-event:${pcr}`);
    const pcrValue = hash(Buffer.concat([Buffer.alloc(32), eventDigest]));
    pcrValues[`sha256:${pcr}`] = pcrValue.toString('hex');
    pcrBuffers.push(pcrValue);
    eventLog.push({ bank: 'sha256', pcr, digest: eventDigest.toString('hex') });
  }
  const pcrDigest = hash(Buffer.concat(pcrBuffers));
  const qualifiedSigner = Buffer.from(identity.qualifiedName, 'hex');
  const nonce = Buffer.from(options.nonce, 'base64url');
  const quote = Buffer.concat([
    u32(0xff544347),
    u16(0x8018),
    sized(qualifiedSigner),
    sized(nonce),
    u64(123456),
    u32(1),
    u32(1),
    u8(1),
    u64(7),
    u32(1),
    u16(0x000b),
    u8(bitmap.length),
    bitmap,
    sized(pcrDigest),
  ]);
  const signature = sign('sha256', quote, identity.privateKey);
  const executor = hash(JSON.stringify(Object.fromEntries(Object.entries(pcrValues).sort()))).toString('hex');
  const issuedAt = options.issuedAt ?? new Date();
  return {
    version: 'hp1',
    method: 'tpm2',
    deviceId: options.deviceId ?? 'tpm-device-1',
    nonce: options.nonce,
    issuedAt: issuedAt.toISOString(),
    expiresAt: new Date(issuedAt.valueOf() + (options.ttlSeconds ?? 30) * 1000).toISOString(),
    keyId: identity.keyId,
    measurements: { ...pcrValues, executor },
    evidence: {
      provider: 'tpm2-fixture',
      quote: quote.toString('base64url'),
      signatureAlgorithm: 'rsassa-sha256',
      hashAlgorithm: 'sha256',
      pcrValues,
      pcrSelection: selection.map((pcr) => `sha256:${pcr}`),
      eventLog: options.includeEventLog === false ? null : eventLog,
      akQualifiedName: identity.qualifiedName,
    },
    signature: signature.toString('base64url'),
  };
}
