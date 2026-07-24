import { type HardproofBundle, type VerificationResult, type VerifierConfig } from '@hardproof/core';
import { Emitter } from './emitter.js';
export interface ServerConfig {
    apiKey?: string;
    cloudUrl?: string;
    mode?: 'cloud' | 'local';
    config?: VerifierConfig;
    debug?: boolean;
}
export interface ServerEvents extends Record<string, unknown> {
    'verify.started': {
        deviceId: string;
    };
    'verify.success': {
        deviceId: string;
        trustLevel: string;
    };
    'verify.failed': {
        deviceId?: string;
        reason: string;
    };
    'device.verified': {
        deviceId: string;
        trustLevel: string;
    };
    'nonce.issued': {
        nonce: string;
    };
}
export declare class Server extends Emitter<ServerEvents> {
    private readonly options;
    private readonly verifier?;
    readonly resolvedMode: 'cloud' | 'local';
    private constructor();
    static create(config?: ServerConfig): Server;
    registerDevice(deviceId: string, publicKeyPem: string): void;
    verify(bundle: HardproofBundle, options: {
        nonce: string;
        publicKeyPem?: string;
    }): Promise<VerificationResult>;
    readonly nonce: {
        issue: () => Promise<string>;
    };
    readonly session: {
        verify: (_options: {
            authorizationHeader?: string;
        }) => Promise<null>;
    };
}
//# sourceMappingURL=server.d.ts.map