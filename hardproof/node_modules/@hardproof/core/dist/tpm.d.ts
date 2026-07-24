export interface TpmPcrSelection {
    algorithmId: number;
    algorithm: string;
    selectedPcrs: number[];
}
export interface ParsedTpmQuote {
    magic: number;
    type: number;
    qualifiedSigner: string;
    extraData: Buffer;
    clock: bigint;
    resetCount: number;
    restartCount: number;
    safe: boolean;
    firmwareVersion: bigint;
    pcrSelections: TpmPcrSelection[];
    pcrDigest: Buffer;
}
export declare function parseTpmsAttest(input: Uint8Array): ParsedTpmQuote;
export type TpmQuoteFailureCode = 'TPM_QUOTE_MALFORMED' | 'TPM_NONCE_MISMATCH' | 'TPM_AK_MISMATCH' | 'TPM_QUOTE_SIGNATURE' | 'TPM_PCR_SELECTION' | 'TPM_PCR_DIGEST' | 'TPM_EVENT_LOG';
export interface TpmQuoteSuccess {
    valid: true;
    measurements: Record<string, string>;
    parsed: ParsedTpmQuote;
}
export interface TpmQuoteFailure {
    valid: false;
    code: TpmQuoteFailureCode;
    reason: string;
}
export type TpmQuoteResult = TpmQuoteSuccess | TpmQuoteFailure;
export declare function tpm2KeyIdFromPublicKey(publicKeyPem: string): string;
export declare function verifyTpmQuote(evidence: Record<string, unknown>, signatureValue: unknown, options: {
    nonce: string;
    publicKeyPem: string;
    expectedQualifiedSigner?: string;
    expectedPcrSelection?: string[];
    requireEventLog?: boolean;
}): TpmQuoteResult;
//# sourceMappingURL=tpm.d.ts.map