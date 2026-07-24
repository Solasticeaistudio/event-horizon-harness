import { randomBytes } from 'node:crypto';
export class NonceStore {
    ttlSeconds;
    now;
    issued = new Map();
    consumed = new Set();
    constructor(ttlSeconds = 60, now = () => Date.now()) {
        this.ttlSeconds = ttlSeconds;
        this.now = now;
    }
    issue() {
        const nonce = randomBytes(32).toString('base64url');
        this.issued.set(nonce, this.now() + this.ttlSeconds * 1000);
        return nonce;
    }
    consume(nonce) {
        if (this.status(nonce) !== 'valid')
            return false;
        this.consumed.add(nonce);
        return true;
    }
    status(nonce) {
        if (this.consumed.has(nonce))
            return 'consumed';
        const expiry = this.issued.get(nonce);
        if (expiry === undefined)
            return 'unknown';
        if (expiry < this.now())
            return 'expired';
        return 'valid';
    }
    isConsumed(nonce) {
        return this.consumed.has(nonce);
    }
}
//# sourceMappingURL=nonce-store.js.map