import type { HardproofBundle } from '@hardproof/core';
export interface SimulatorConfig {
    deviceId: string;
    seed?: string;
    ttlSeconds?: number;
    now?: () => Date;
    measurements?: Record<string, string>;
}
export declare class SimulatorProver {
    readonly method: "simulator";
    readonly deviceId: string;
    readonly publicKeyPem: string;
    readonly keyId: string;
    readonly measurements: Record<string, string>;
    private readonly keyPair;
    private readonly ttlSeconds;
    private readonly now;
    constructor(config: SimulatorConfig);
    prove(options: {
        nonce: string;
    }): Promise<HardproofBundle>;
}
//# sourceMappingURL=index.d.ts.map