export type AttestationMethod = 'simulator' | 'tpm2' | 'secure-enclave' | 'android-keystore';
export type TrustLevel = 'simulated' | 'software' | 'hardware';
export type AssuranceLevel = 'development' | 'measured' | 'hardware-rooted';

export interface AttestationBundleUnsigned {
  version: 'eh-attestation-1';
  method: AttestationMethod;
  deviceId: string;
  nonce: string;
  issuedAt: string;
  expiresAt: string;
  keyId: string;
  measurements: Record<string, string>;
  evidence: Record<string, unknown>;
}

export interface AttestationBundle extends AttestationBundleUnsigned {
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

export interface ProviderVerificationContext {
  nonce: string;
  nonceContext: import('./nonce-authority.js').NonceContext;
  publicKeyPem: string;
  now: Date;
  maxProofAgeSeconds: number;
  maxFutureSkewSeconds: number;
  measurementPolicy: Record<string, MeasurementRule>;
  expectedTpmQualifiedSigner?: string;
  expectedTpmPcrSelection?: string[];
  requireTpmEventLog: boolean;
}

export interface ProviderVerificationSuccess {
  valid: true;
  method: AttestationMethod;
  trustLevel: TrustLevel;
  assuranceLevel: AssuranceLevel;
  keyId: string;
  measurements: Record<string, string>;
}

export interface ProviderVerificationFailure {
  valid: false;
  failureCode: VerificationFailure['failureCode'];
  failureReason: string;
}

export type ProviderVerificationResult = ProviderVerificationSuccess | ProviderVerificationFailure;

export interface AttestationProviderVerifier {
  readonly method: AttestationMethod;
  verify(bundle: Readonly<AttestationBundle>, context: Readonly<ProviderVerificationContext>): ProviderVerificationResult;
}

export interface VerifierConfig {
  minTrustLevel?: TrustLevel;
  maxProofAgeSeconds?: number;
  maxFutureSkewSeconds?: number;
  pcrPolicy?: Record<string, MeasurementRule>;
  deviceKeys?: Record<string, string>;
  allowUnregisteredSimulator?: boolean;
  nonceTtlSeconds?: number;
  noncePersistence?: import('./nonce-authority.js').NoncePersistence;
  tpmAkQualifiedNames?: Record<string, string>;
  tpmPcrSelections?: Record<string, string[]>;
  requireTpmEventLog?: boolean;
  useDefaultProviderVerifiers?: boolean;
  providerVerifiers?: AttestationProviderVerifier[];
  now?: () => Date;
}

export interface VerificationSuccess {
  valid: true;
  deviceId: string;
  method: AttestationMethod;
  trustLevel: TrustLevel;
  assuranceLevel: AssuranceLevel;
  keyId: string;
  measurements: Record<string, string>;
  bundleDigest: string;
  nonceContext: import('./nonce-authority.js').NonceContext;
  nonceIssuedAt: string;
  nonceExpiresAt: string;
  verifiedAt: string;
}

export interface VerificationFailure {
  valid: false;
  failureReason: string;
  failureCode:
    | 'MALFORMED_BUNDLE'
    | 'NONCE_MISMATCH'
    | 'NONCE_UNKNOWN'
    | 'NONCE_EXPIRED'
    | 'NONCE_REPLAY'
    | 'NONCE_CONTEXT_MISMATCH'
    | 'MALFORMED_NONCE'
    | 'PROOF_REPLAY'
    | 'PROOF_EXPIRED'
    | 'PROOF_FROM_FUTURE'
    | 'PROOF_TOO_OLD'
    | 'UNKNOWN_DEVICE'
    | 'KEY_ID_MISMATCH'
    | 'INVALID_SIGNATURE'
    | 'TRUST_LEVEL_TOO_LOW'
    | 'MEASUREMENT_POLICY_FAILED'
    | 'UNSUPPORTED_METHOD'
    | 'VERIFIER_UNAVAILABLE'
    | 'PROVIDER_ERROR'
    | 'PROVIDER_RESULT_INVALID'
    | 'TPM_QUOTE_MALFORMED'
    | 'TPM_NONCE_MISMATCH'
    | 'TPM_AK_MISMATCH'
    | 'TPM_QUOTE_SIGNATURE'
    | 'TPM_PCR_SELECTION'
    | 'TPM_PCR_DIGEST'
    | 'TPM_EVENT_LOG'
    | 'TPM_BUNDLE_SIGNATURE';
  verifiedAt: string;
}

export type VerificationResult = VerificationSuccess | VerificationFailure;
