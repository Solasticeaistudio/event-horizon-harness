import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, sign as nodeSign, verify as nodeVerify, } from 'node:crypto';
function normalize(value) {
    if (value === null || typeof value === 'boolean' || typeof value === 'string')
        return value;
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            throw new TypeError('canonical JSON rejects non-finite numbers');
        return value;
    }
    if (Array.isArray(value))
        return value.map(normalize);
    if (typeof value === 'object') {
        const output = {};
        for (const key of Object.keys(value).sort()) {
            const item = value[key];
            if (item === undefined)
                throw new TypeError(`canonical JSON rejects undefined at ${key}`);
            output[key] = normalize(item);
        }
        return output;
    }
    throw new TypeError(`unsupported canonical JSON value: ${typeof value}`);
}
export function canonicalize(value) {
    return JSON.stringify(normalize(value));
}
export function canonicalBytes(value) {
    return Buffer.from(canonicalize(value), 'utf8');
}
export function sha256(data) {
    return createHash('sha256').update(data).digest('hex');
}
export function base64urlEncode(data) {
    return Buffer.from(data).toString('base64url');
}
export function base64urlDecode(data) {
    return Buffer.from(data, 'base64url');
}
export function generateEd25519KeyPair() {
    return generateKeyPairSync('ed25519');
}
export function ed25519KeyPairFromSeed(seed) {
    const seedBytes = createHash('sha256').update(seed).digest();
    const prefix = Buffer.from('302e020100300506032b657004220420', 'hex');
    const privateKey = createPrivateKey({ key: Buffer.concat([prefix, seedBytes]), format: 'der', type: 'pkcs8' });
    return { privateKey, publicKey: createPublicKey(privateKey) };
}
export function exportPublicKeyPem(key) {
    return key.export({ format: 'pem', type: 'spki' }).toString();
}
export function exportPrivateKeyPem(key) {
    return key.export({ format: 'pem', type: 'pkcs8' }).toString();
}
export function importPublicKeyPem(pem) {
    return createPublicKey(pem);
}
export function importPrivateKeyPem(pem) {
    return createPrivateKey(pem);
}
export function keyIdFromPublicKey(key) {
    const publicKey = typeof key === 'string' ? createPublicKey(key) : key;
    const der = publicKey.export({ format: 'der', type: 'spki' });
    return `ed25519:${sha256(der).slice(0, 32)}`;
}
export function signDetached(payload, privateKey) {
    const key = typeof privateKey === 'string' ? createPrivateKey(privateKey) : privateKey;
    return nodeSign(null, Buffer.from(payload), key).toString('base64url');
}
export function verifyDetached(payload, signature, publicKey) {
    try {
        const key = typeof publicKey === 'string' ? createPublicKey(publicKey) : publicKey;
        return nodeVerify(null, Buffer.from(payload), key, Buffer.from(signature, 'base64url'));
    }
    catch {
        return false;
    }
}
//# sourceMappingURL=index.js.map