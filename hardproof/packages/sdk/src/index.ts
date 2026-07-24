import type { HardproofBundle } from '@hardproof/core';

export { Client } from './client.js';
export type { ClientConfig, ClientEvents } from './client.js';
export { Server } from './server.js';
export type { ServerConfig, ServerEvents } from './server.js';
export { Emitter } from './emitter.js';
export { HardproofError, toHardproofError } from './errors.js';
export type { HardproofErrorCode } from './errors.js';
export type * from '@hardproof/core';

export function encodeBundle(bundle: HardproofBundle): string {
  return Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64url');
}

export function decodeBundle(encoded: string): HardproofBundle {
  const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8')) as unknown;
  if (!parsed || typeof parsed !== 'object') throw new TypeError('encoded proof bundle is invalid');
  return parsed as HardproofBundle;
}
