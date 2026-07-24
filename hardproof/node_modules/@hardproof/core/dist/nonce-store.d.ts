export type NonceStatus = 'valid' | 'unknown' | 'expired' | 'consumed';
export declare class NonceStore {
    private readonly ttlSeconds;
    private readonly now;
    private readonly issued;
    private readonly consumed;
    constructor(ttlSeconds?: number, now?: () => number);
    issue(): string;
    consume(nonce: string): boolean;
    status(nonce: string): NonceStatus;
    isConsumed(nonce: string): boolean;
}
//# sourceMappingURL=nonce-store.d.ts.map