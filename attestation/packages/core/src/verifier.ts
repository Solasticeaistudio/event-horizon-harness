import { canonicalBytes, sha256 } from '@event-horizon/attestation-crypto';
import { NonceAuthority, type NonceContext } from './nonce-authority.js';
import { SimulatorAttestationVerifier, Tpm2AttestationVerifier } from './provider-verifiers.js';
import type {
  AttestationBundle,
  AttestationMethod,
  AttestationProviderVerifier,
  ProviderVerificationResult,
  TrustLevel,
  VerificationFailure,
  VerificationResult,
  VerifierConfig,
} from './types.js';

const TRUST_ORDER: Record<TrustLevel, number> = { simulated: 0, software: 1, hardware: 2 };
const KNOWN_METHODS = new Set<AttestationMethod>([
  'simulator',
  'tpm2',
  'secure-enclave',
  'android-keystore',
]);
const BUNDLE_FIELDS = [
  'deviceId',
  'evidence',
  'expiresAt',
  'issuedAt',
  'keyId',
  'measurements',
  'method',
  'nonce',
  'signature',
  'version',
];
const PROVIDER_SUCCESS_FIELDS = [
  'assuranceLevel',
  'keyId',
  'measurements',
  'method',
  'trustLevel',
  'valid',
];
const FAILURE_CODES = new Set<VerificationFailure['failureCode']>([
  'MALFORMED_BUNDLE',
  'NONCE_MISMATCH',
  'NONCE_UNKNOWN',
  'NONCE_EXPIRED',
  'NONCE_REPLAY',
  'NONCE_CONTEXT_MISMATCH',
  'MALFORMED_NONCE',
  'PROOF_REPLAY',
  'PROOF_EXPIRED',
  'PROOF_FROM_FUTURE',
  'PROOF_TOO_OLD',
  'UNKNOWN_DEVICE',
  'KEY_ID_MISMATCH',
  'INVALID_SIGNATURE',
  'TRUST_LEVEL_TOO_LOW',
  'MEASUREMENT_POLICY_FAILED',
  'UNSUPPORTED_METHOD',
  'VERIFIER_UNAVAILABLE',
  'PROVIDER_ERROR',
  'PROVIDER_RESULT_INVALID',
  'TPM_QUOTE_MALFORMED',
  'TPM_NONCE_MISMATCH',
  'TPM_AK_MISMATCH',
  'TPM_QUOTE_SIGNATURE',
  'TPM_PCR_SELECTION',
  'TPM_PCR_DIGEST',
  'TPM_EVENT_LOG',
  'TPM_BUNDLE_SIGNATURE',
]);

function failure(code: VerificationFailure['failureCode'], reason: string, at: Date): VerificationFailure {
  return { valid: false, failureCode: code, failureReason: reason, verifiedAt: at.toISOString() };
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isBundleShape(value: unknown): value is AttestationBundle {
  if (!isPlainObject(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(BUNDLE_FIELDS)) return false;
  return value.version === 'eh-attestation-1'
    && typeof value.method === 'string'
    && typeof value.deviceId === 'string'
    && value.deviceId.length > 0
    && typeof value.nonce === 'string'
    && value.nonce.length > 0
    && typeof value.issuedAt === 'string'
    && typeof value.expiresAt === 'string'
    && typeof value.keyId === 'string'
    && value.keyId.length > 0
    && isPlainObject(value.measurements)
    && Object.values(value.measurements).every((item) => typeof item === 'string')
    && isPlainObject(value.evidence)
    && typeof value.signature === 'string'
    && value.signature.length > 0;
}

function validProviderSuccess(
  result: ProviderVerificationResult,
  selectedMethod: AttestationMethod,
): boolean {
  if (!isPlainObject(result) || result.valid !== true) return false;
  if (JSON.stringify(Object.keys(result).sort()) !== JSON.stringify(PROVIDER_SUCCESS_FIELDS)) return false;
  if (
    result.method !== selectedMethod
    || !['simulated', 'software', 'hardware'].includes(result.trustLevel)
    || !['development', 'measured', 'hardware-rooted'].includes(result.assuranceLevel)
    || typeof result.keyId !== 'string'
    || !isPlainObject(result.measurements)
    || !Object.values(result.measurements).every((item) => typeof item === 'string')
  ) return false;
  if (selectedMethod === 'simulator') {
    return result.trustLevel === 'simulated' && result.assuranceLevel === 'development';
  }
  if (selectedMethod === 'tpm2') {
    return result.trustLevel === 'hardware' && result.assuranceLevel === 'hardware-rooted';
  }
  return false;
}

export class Verifier {
  private readonly deviceKeys = new Map<string, string>();
  private readonly consumedProofs = new Set<string>();
  private readonly providerVerifiers = new Map<AttestationMethod, AttestationProviderVerifier>();
  readonly nonceAuthority: NonceAuthority;

  constructor(private readonly config: VerifierConfig = {}) {
    for (const [deviceId, key] of Object.entries(config.deviceKeys ?? {})) this.deviceKeys.set(deviceId, key);
    if (config.useDefaultProviderVerifiers !== false) {
      this.registerProviderVerifier(new SimulatorAttestationVerifier());
      this.registerProviderVerifier(new Tpm2AttestationVerifier());
    }
    for (const providerVerifier of config.providerVerifiers ?? []) this.registerProviderVerifier(providerVerifier);
    this.nonceAuthority = new NonceAuthority(
      config.nonceTtlSeconds ?? 60,
      () => (this.config.now?.() ?? new Date()).valueOf(),
      config.noncePersistence,
    );
  }

  registerDevice(deviceId: string, publicKeyPem: string): void {
    if (!deviceId.trim()) throw new TypeError('deviceId is required');
    this.deviceKeys.set(deviceId, publicKeyPem);
  }

  registerProviderVerifier(providerVerifier: AttestationProviderVerifier): void {
    if (!providerVerifier || !KNOWN_METHODS.has(providerVerifier.method) || typeof providerVerifier.verify !== 'function') {
      throw new TypeError('provider verifier is malformed or uses an unknown method');
    }
    this.providerVerifiers.set(providerVerifier.method, providerVerifier);
  }

  async verify(
    bundle: AttestationBundle,
    options: { nonce: string; context: NonceContext; publicKeyPem?: string },
  ): Promise<VerificationResult> {
    const at = this.config.now?.() ?? new Date();
    if (!isBundleShape(bundle)) {
      return failure('MALFORMED_BUNDLE', 'bundle fields or types are invalid', at);
    }
    if (!KNOWN_METHODS.has(bundle.method)) {
      return failure('UNSUPPORTED_METHOD', `unsupported attestation method: ${String(bundle.method)}`, at);
    }
    const providerVerifier = this.providerVerifiers.get(bundle.method);
    if (!providerVerifier) {
      return failure('VERIFIER_UNAVAILABLE', `no verifier is registered for attestation method ${bundle.method}`, at);
    }
    if (bundle.nonce !== options.nonce) {
      return failure('NONCE_MISMATCH', 'attestation nonce does not match verifier challenge', at);
    }

    const bundleDigest = sha256(canonicalBytes(bundle));
    if (this.consumedProofs.has(bundleDigest)) {
      return failure('PROOF_REPLAY', 'attestation bundle has already been accepted', at);
    }
    let publicKeyPem = this.deviceKeys.get(bundle.deviceId);
    if (!publicKeyPem && bundle.method === 'simulator' && this.config.allowUnregisteredSimulator) {
      publicKeyPem = options.publicKeyPem;
    }
    if (!publicKeyPem) return failure('UNKNOWN_DEVICE', 'device is not registered with this verifier', at);

    let providerResult: ProviderVerificationResult;
    try {
      providerResult = providerVerifier.verify(bundle, {
        nonce: options.nonce,
        nonceContext: options.context,
        publicKeyPem,
        now: at,
        maxProofAgeSeconds: this.config.maxProofAgeSeconds ?? 30,
        maxFutureSkewSeconds: this.config.maxFutureSkewSeconds ?? 5,
        measurementPolicy: this.config.pcrPolicy ?? {},
        expectedTpmQualifiedSigner: this.config.tpmAkQualifiedNames?.[bundle.deviceId],
        expectedTpmPcrSelection: this.config.tpmPcrSelections?.[bundle.deviceId],
        requireTpmEventLog: this.config.requireTpmEventLog ?? false,
      });
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      return failure('PROVIDER_ERROR', `attestation provider failed closed: ${reason}`, at);
    }
    if (!providerResult || typeof providerResult !== 'object') {
      return failure('PROVIDER_RESULT_INVALID', 'attestation provider returned no structured result', at);
    }
    if (!providerResult.valid) {
      if (
        JSON.stringify(Object.keys(providerResult).sort()) !== JSON.stringify([
          'failureCode', 'failureReason', 'valid',
        ])
        || typeof providerResult.failureCode !== 'string'
        || !FAILURE_CODES.has(providerResult.failureCode)
        || typeof providerResult.failureReason !== 'string'
      ) {
        return failure('PROVIDER_RESULT_INVALID', 'attestation provider failure result is malformed', at);
      }
      return failure(providerResult.failureCode, providerResult.failureReason, at);
    }
    if (!validProviderSuccess(providerResult, bundle.method)) {
      return failure('PROVIDER_RESULT_INVALID', 'attestation provider success result is malformed or overstates trust', at);
    }
    if (providerResult.keyId !== bundle.keyId) {
      return failure('PROVIDER_RESULT_INVALID', 'attestation provider returned a different key identity', at);
    }
    const requiredTrust = this.config.minTrustLevel ?? 'simulated';
    if (TRUST_ORDER[providerResult.trustLevel] < TRUST_ORDER[requiredTrust]) {
      return failure(
        'TRUST_LEVEL_TOO_LOW',
        `verified trust ${providerResult.trustLevel} is below required ${requiredTrust}`,
        at,
      );
    }
    let nonceTransition;
    try {
      nonceTransition = await this.nonceAuthority.consume(options.nonce, options.context);
    } catch {
      return failure('VERIFIER_UNAVAILABLE', 'nonce persistence failed closed', at);
    }
    if (!nonceTransition.accepted) {
      if (nonceTransition.status === 'unknown') {
        return failure('NONCE_UNKNOWN', 'nonce was not issued or registered by this verifier', at);
      }
      if (nonceTransition.status === 'expired') {
        return failure('NONCE_EXPIRED', 'verifier challenge has expired', at);
      }
      if (nonceTransition.status === 'wrong-context') {
        return failure('NONCE_CONTEXT_MISMATCH', 'nonce context does not match its issuance binding', at);
      }
      if (nonceTransition.status === 'malformed') {
        return failure('MALFORMED_NONCE', 'nonce or nonce context is malformed', at);
      }
      return failure('NONCE_REPLAY', 'nonce has already been consumed', at);
    }
    if (!nonceTransition.record) {
      return failure('PROVIDER_RESULT_INVALID', 'nonce authority omitted the accepted transition record', at);
    }

    this.consumedProofs.add(bundleDigest);
    return {
      valid: true,
      deviceId: bundle.deviceId,
      method: providerResult.method,
      trustLevel: providerResult.trustLevel,
      assuranceLevel: providerResult.assuranceLevel,
      keyId: providerResult.keyId,
      measurements: { ...providerResult.measurements },
      bundleDigest,
      nonceContext: { ...nonceTransition.record.context },
      nonceIssuedAt: new Date(nonceTransition.record.issuedAt).toISOString(),
      nonceExpiresAt: new Date(nonceTransition.record.expiresAt).toISOString(),
      verifiedAt: at.toISOString(),
    };
  }
}
