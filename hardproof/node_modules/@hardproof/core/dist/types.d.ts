export type ProofMethod = 'simulator' | 'tpm2' | 'secure-enclave' | 'android-keystore';
export type TrustLevel = 'simulated' | 'software' | 'hardware';
export type AssuranceLevel = 'development' | 'measured' | 'hardware-rooted';
export interface HardproofBundleUnsigned {
    version: 'hp1';
    method: ProofMethod;
    deviceId: string;
    nonce: string;
    issuedAt: string;
    expiresAt: string;
    keyId: string;
    measurements: Record<string, string>;
    evidence: Record<string, unknown>;
}
export interface HardproofBundle extends HardproofBundleUnsigned {
    signature: string;
}
export interface ExactMeasurementRule {
    type: 'exact';
    value: string;
}
export interface OneOfMeasurementRule {
    type: 'oneOf';
    values: string[];
}
export type MeasurementRule = ExactMeasurementRule | OneOfMeasurementRule;
export interface VerifierConfig {
    minTrustLevel?: TrustLevel;
    maxProofAgeSeconds?: number;
    maxFutureSkewSeconds?: number;
    pcrPolicy?: Record<string, MeasurementRule>;
    deviceKeys?: Record<string, string>;
    allowUnregisteredSimulator?: boolean;
    now?: () => Date;
}
export interface VerificationSuccess {
    valid: true;
    deviceId: string;
    method: ProofMethod;
    trustLevel: TrustLevel;
    assuranceLevel: AssuranceLevel;
    keyId: string;
    measurements: Record<string, string>;
    bundleDigest: string;
    verifiedAt: string;
}
export interface VerificationFailure {
    valid: false;
    failureReason: string;
    failureCode: 'MALFORMED_BUNDLE' | 'NONCE_MISMATCH' | 'NONCE_REPLAY' | 'PROOF_REPLAY' | 'PROOF_EXPIRED' | 'PROOF_FROM_FUTURE' | 'PROOF_TOO_OLD' | 'UNKNOWN_DEVICE' | 'KEY_ID_MISMATCH' | 'INVALID_SIGNATURE' | 'TRUST_LEVEL_TOO_LOW' | 'MEASUREMENT_POLICY_FAILED' | 'UNSUPPORTED_METHOD';
    verifiedAt: string;
}
export type VerificationResult = VerificationSuccess | VerificationFailure;
//# sourceMappingURL=types.d.ts.map