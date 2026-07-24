export { Client } from './client.js';
export { Server } from './server.js';
export { Emitter } from './emitter.js';
export { HardproofError, toHardproofError } from './errors.js';
export function encodeBundle(bundle) {
    return Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64url');
}
export function decodeBundle(encoded) {
    const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
    if (!parsed || typeof parsed !== 'object')
        throw new TypeError('encoded proof bundle is invalid');
    return parsed;
}
//# sourceMappingURL=index.js.map