import type { HardproofBundle } from '@hardproof/core';
export interface TpmQuoteProvider {
    prove(options: {
        deviceId: string;
        nonce: string;
        pcrSelection: number[];
    }): Promise<HardproofBundle>;
}
export interface TpmProverConfig {
    deviceId: string;
    pcrSelection?: number[];
    provider?: TpmQuoteProvider;
}
export declare class TpmProver {
    private readonly config;
    readonly method: "tpm2";
    private readonly pcrSelection;
    constructor(config: TpmProverConfig);
    static isAvailable(): Promise<boolean>;
    prove(options: {
        nonce: string;
    }): Promise<HardproofBundle>;
}
export * from './linux.js';
//# sourceMappingURL=index.d.ts.map