export declare class NonceStore {
    private readonly ttlSeconds;
    private readonly now;
    private readonly issued;
    private readonly consumed;
    constructor(ttlSeconds?: number, now?: () => number);
    issue(): string;
    consume(nonce: string): boolean;
    isConsumed(nonce: string): boolean;
}
//# sourceMappingURL=nonce-store.d.ts.map