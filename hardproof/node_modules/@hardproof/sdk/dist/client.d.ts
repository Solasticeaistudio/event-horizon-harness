import type { HardproofBundle, ProofMethod } from '@hardproof/core';
import { Emitter } from './emitter.js';
import { HardproofError } from './errors.js';
export interface ClientConfig {
    apiKey?: string;
    cloudUrl?: string;
    deviceId?: string;
    debug?: boolean;
    eager?: boolean;
    method?: ProofMethod;
    simulatorSeed?: string;
    pcrSelection?: number[];
}
export interface ClientEvents extends Record<string, unknown> {
    'prover.ready': {
        method: ProofMethod;
    };
    'prover.unavailable': {
        reason: string;
    };
    'prove.started': {
        deviceId: string;
        nonce: string;
    };
    'prove.completed': {
        deviceId: string;
        keyId: string;
    };
    'prove.failed': {
        deviceId: string;
        error: HardproofError;
    };
    'device.registered': {
        deviceId: string;
    };
    'session.started': {
        token: string;
        expiresAt: string;
    };
}
export declare class Client extends Emitter<ClientEvents> {
    private readonly config;
    private prover?;
    private constructor();
    static create(config?: ClientConfig): Promise<Client>;
    get method(): ProofMethod | undefined;
    readonly device: {
        register: (_options: {
            token: string;
            label?: string;
        }) => Promise<{
            deviceId: string;
        }>;
    };
    readonly session: {
        start: (_options?: {
            ttlMinutes?: number;
        }) => Promise<void>;
        token: () => Promise<string>;
        stop: () => void;
    };
    prove(options?: {
        nonce?: string;
        deviceId?: string;
    }): Promise<HardproofBundle>;
    private resolveProver;
}
//# sourceMappingURL=client.d.ts.map