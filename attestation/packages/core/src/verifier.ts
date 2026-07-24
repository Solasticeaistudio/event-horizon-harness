import { canonicalBytes, keyIdFromPublicKey, sha256, verifyDetached } from '@event-horizon/attestation-crypto';
import { NonceStore } from './nonce-store.js';
import { tpm2KeyIdFromPublicKey, verifyTpmQuote } from './tpm.js';
import type {
  AssuranceLevel,
  AttestationBundle,
  AttestationBundleUnsigned,
  TrustLevel,
  VerificationFailure,
  VerificationResult,
  VerifierConfig,
} from './types.js';

const TRUST_ORDER: Record<TrustLevel, number> = { simulated: 0, software: 1, hardware: 2 };

function failure(code: VerificationFailure['failureCode'], reason: string, at: Date): VerificationFailure {
  return { valid: false, failureCode: code, failureReason: reason, verifiedAt: at.toISOString() };
}

function methodTrust(method: string): { trust: TrustLevel; assurance: AssuranceLevel } | null {
  if (method === 'simulator') return { trust: 'simulated', assurance: 'development' };
  if (method === 'tpm2' || method === 'secure-enclave' || method === 'android-keystore') {
    return { trust: 'hardware', assurance: 'hardware-rooted' };
  }
  return null;
}

function unsigned(bundle: AttestationBundle): AttestationBundleUnsigned {
  const { signature: _signature, ...rest } = bundle;
  return rest;
}

export class Verifier {
  private readonly deviceKeys = new Map<string, string>();
  private readonly consumedProofs = new Set<string>();
  readonly nonceStore: NonceStore;

  constructor(private readonly config: VerifierConfig = {}) {
    for (const [deviceId, key] of Object.entries(config.deviceKeys ?? {})) this.deviceKeys.set(deviceId, key);
    this.nonceStore = new NonceStore(
      config.nonceTtlSeconds ?? 60,
      () => (this.config.now?.() ?? new Date()).valueOf(),
    );
  }

  registerDevice(deviceId: string, publicKeyPem: string): void {
    if (!deviceId.trim()) throw new TypeError('deviceId is required');
    this.deviceKeys.set(deviceId, publicKeyPem);
  }

  verify(bundle: AttestationBundle, options: { nonce: string; publicKeyPem?: string }): VerificationResult {
    const at = this.config.now?.() ?? new Date();
    const bundleFields = ['deviceId', 'evidence', 'expiresAt', 'issuedAt', 'keyId', 'measurements', 'method', 'nonce', 'signature', 'version'];
    if (
      !bundle
      || JSON.stringify(Object.keys(bundle).sort()) !== JSON.stringify(bundleFields)
      || bundle.version !== 'eh-attestation-1'
      || !bundle.deviceId
      || !bundle.nonce
      || !bundle.signature
      || !bundle.measurements
      || typeof bundle.measurements !== 'object'
      || !bundle.evidence
      || typeof bundle.evidence !== 'object'
    ) {
      return failure('MALFORMED_BUNDLE', 'bundle is missing required eh-attestation-1 fields', at);
    }
    const trust = methodTrust(bundle.method);
    if (!trust) return failure('UNSUPPORTED_METHOD', `unsupported proof method: ${String(bundle.method)}`, at);
    if (bundle.nonce !== options.nonce) return failure('NONCE_MISMATCH', 'proof nonce does not match verifier challenge', at);

    const issuedAt = new Date(bundle.issuedAt);
    const expiresAt = new Date(bundle.expiresAt);
    if (Number.isNaN(issuedAt.valueOf()) || Number.isNaN(expiresAt.valueOf())) {
      return failure('MALFORMED_BUNDLE', 'invalid proof timestamps', at);
    }
    const skewMs = (this.config.maxFutureSkewSeconds ?? 5) * 1000;
    if (issuedAt.valueOf() > at.valueOf() + skewMs) return failure('PROOF_FROM_FUTURE', 'proof timestamp exceeds future-skew allowance', at);
    if (expiresAt.valueOf() < at.valueOf()) return failure('PROOF_EXPIRED', 'proof has expired', at);
    const ageMs = at.valueOf() - issuedAt.valueOf();
    if (ageMs > (this.config.maxProofAgeSeconds ?? 30) * 1000) return failure('PROOF_TOO_OLD', 'proof exceeds maximum age', at);

    const bundleDigest = sha256(canonicalBytes(bundle));
    if (this.consumedProofs.has(bundleDigest)) return failure('PROOF_REPLAY', 'proof bundle has already been accepted', at);
    const nonceStatus = this.nonceStore.status(options.nonce);
    if (nonceStatus === 'unknown') return failure('NONCE_UNKNOWN', 'nonce was not issued by this verifier', at);
    if (nonceStatus === 'expired') return failure('NONCE_EXPIRED', 'verifier challenge has expired', at);
    if (nonceStatus === 'consumed') return failure('NONCE_REPLAY', 'nonce has already been consumed', at);

    let publicKeyPem = this.deviceKeys.get(bundle.deviceId);
    if (!publicKeyPem && bundle.method === 'simulator' && this.config.allowUnregisteredSimulator) {
      publicKeyPem = options.publicKeyPem;
    }
    if (!publicKeyPem) return failure('UNKNOWN_DEVICE', 'device is not registered with this verifier', at);
    let verifiedMeasurements = { ...bundle.measurements };
    if (bundle.method === 'tpm2') {
      if (tpm2KeyIdFromPublicKey(publicKeyPem) !== bundle.keyId) {
        return failure('KEY_ID_MISMATCH', 'bundle keyId does not match registered TPM AK', at);
      }
      const quoteResult = verifyTpmQuote(bundle.evidence, bundle.signature, {
        nonce: options.nonce,
        publicKeyPem,
        expectedQualifiedSigner: this.config.tpmAkQualifiedNames?.[bundle.deviceId],
        expectedPcrSelection: this.config.tpmPcrSelections?.[bundle.deviceId],
        requireEventLog: this.config.requireTpmEventLog,
      });
      if (!quoteResult.valid) return failure(quoteResult.code, quoteResult.reason, at);
      verifiedMeasurements = quoteResult.measurements;
      if (!canonicalBytes(bundle.measurements).equals(canonicalBytes(verifiedMeasurements))) {
        return failure('TPM_PCR_DIGEST', 'bundle measurements differ from independently verified PCRs', at);
      }
    } else {
      if (keyIdFromPublicKey(publicKeyPem) !== bundle.keyId) {
        return failure('KEY_ID_MISMATCH', 'bundle keyId does not match registered device key', at);
      }
      if (!verifyDetached(canonicalBytes(unsigned(bundle)), bundle.signature, publicKeyPem)) {
        return failure('INVALID_SIGNATURE', 'proof signature is invalid', at);
      }
    }

    const requiredTrust = this.config.minTrustLevel ?? 'simulated';
    if (TRUST_ORDER[trust.trust] < TRUST_ORDER[requiredTrust]) {
      return failure('TRUST_LEVEL_TOO_LOW', `proof trust ${trust.trust} is below required ${requiredTrust}`, at);
    }

    for (const [register, rule] of Object.entries(this.config.pcrPolicy ?? {})) {
      const actual = verifiedMeasurements[register];
      const allowed = rule.type === 'exact' ? actual === rule.value : rule.values.includes(actual ?? '');
      if (!allowed) return failure('MEASUREMENT_POLICY_FAILED', `measurement ${register} failed policy`, at);
    }

    if (!this.nonceStore.consume(options.nonce)) return failure('NONCE_REPLAY', 'nonce could not be consumed', at);

    this.consumedProofs.add(bundleDigest);
    return {
      valid: true,
      deviceId: bundle.deviceId,
      method: bundle.method,
      trustLevel: trust.trust,
      assuranceLevel: trust.assurance,
      keyId: bundle.keyId,
      measurements: verifiedMeasurements,
      bundleDigest,
      verifiedAt: at.toISOString(),
    };
  }
}
