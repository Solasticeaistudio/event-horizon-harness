import type { HardproofBundle } from '@hardproof/core';
export { Client } from './client.js';
export type { ClientConfig, ClientEvents } from './client.js';
export { Server } from './server.js';
export type { ServerConfig, ServerEvents } from './server.js';
export { Emitter } from './emitter.js';
export { HardproofError, toHardproofError } from './errors.js';
export type { HardproofErrorCode } from './errors.js';
export type * from '@hardproof/core';
export declare function encodeBundle(bundle: HardproofBundle): string;
export declare function decodeBundle(encoded: string): HardproofBundle;
//# sourceMappingURL=index.d.ts.map