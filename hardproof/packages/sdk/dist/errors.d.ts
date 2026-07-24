export type HardproofErrorCode = 'NO_PROVER_AVAILABLE' | 'PROVER_NOT_IMPLEMENTED' | 'VERIFIER_NOT_CONFIGURED' | 'CLOUD_API_ERROR' | 'REGISTRATION_FAILED' | 'DEVICE_ALREADY_REGISTERED' | 'INVALID_CONFIG' | 'NOT_IMPLEMENTED';
export declare class HardproofError extends Error {
    readonly code: HardproofErrorCode;
    readonly suggestion?: string | undefined;
    readonly docsUrl?: string | undefined;
    readonly context?: Record<string, unknown> | undefined;
    constructor(code: HardproofErrorCode, message: string, suggestion?: string | undefined, docsUrl?: string | undefined, context?: Record<string, unknown> | undefined);
}
export declare function toHardproofError(error: unknown): HardproofError;
//# sourceMappingURL=errors.d.ts.map