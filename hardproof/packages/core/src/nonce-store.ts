import { randomBytes } from 'node:crypto';

export class NonceStore {
  private readonly issued = new Map<string, number>();
  private readonly consumed = new Set<string>();

  constructor(private readonly ttlSeconds = 60, private readonly now: () => number = () => Date.now()) {}

  issue(): string {
    const nonce = randomBytes(32).toString('base64url');
    this.issued.set(nonce, this.now() + this.ttlSeconds * 1000);
    return nonce;
  }

  consume(nonce: string): boolean {
    const expiry = this.issued.get(nonce);
    if (expiry === undefined || expiry < this.now() || this.consumed.has(nonce)) return false;
    this.consumed.add(nonce);
    return true;
  }

  isConsumed(nonce: string): boolean {
    return this.consumed.has(nonce);
  }
}
