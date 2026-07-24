import { NonceStore } from './nonce-store.js';
import type { HardproofBundle, VerificationResult, VerifierConfig } from './types.js';
export declare class Verifier {
    private readonly config;
    private readonly deviceKeys;
    private readonly consumedProofs;
    readonly nonceStore: NonceStore;
    constructor(config?: VerifierConfig);
    registerDevice(deviceId: string, publicKeyPem: string): void;
    verify(bundle: HardproofBundle, options: {
        nonce: string;
        publicKeyPem?: string;
    }): VerificationResult;
}
//# sourceMappingURL=verifier.d.ts.map