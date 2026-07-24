import type { AttestationBundle } from '@event-horizon/attestation-core';

export { Client } from './client.js';
export type { ClientConfig, ClientEvents } from './client.js';
export { Server } from './server.js';
export type { ServerConfig, ServerEvents } from './server.js';
export { Emitter } from './emitter.js';
export { AttestationError, toAttestationError } from './errors.js';
export type { AttestationErrorCode } from './errors.js';
export type * from '@event-horizon/attestation-core';

export function encodeBundle(bundle: AttestationBundle): string {
  return Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64url');
}

export function decodeBundle(encoded: string): AttestationBundle {
  const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as unknown;
  if (!parsed || typeof parsed !== 'object') throw new TypeError('encoded proof bundle is invalid');
  return parsed as AttestationBundle;
}
