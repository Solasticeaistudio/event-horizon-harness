import { createVerify } from 'node:crypto';
import { canonicalBytes, keyIdFromPublicKey, verifyDetached } from '@event-horizon/attestation-crypto';
import { tpm2KeyIdFromPublicKey, verifyTpmQuote } from './tpm.js';
import type {
  AttestationBundle,
  AttestationBundleUnsigned,
  AttestationProviderVerifier,
  MeasurementRule,
  ProviderVerificationContext,
  ProviderVerificationFailure,
  ProviderVerificationResult,
} from './types.js';

function providerFailure(
  failureCode: ProviderVerificationFailure['failureCode'],
  failureReason: string,
): ProviderVerificationFailure {
  return { valid: false, failureCode, failureReason };
}

function unsigned(bundle: Readonly<AttestationBundle>): AttestationBundleUnsigned {
  const { signature: _signature, ...rest } = bundle;
  return rest;
}

function strictBase64url(value: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) return null;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.length > 0 && decoded.toString('base64url') === value ? decoded : null;
}

function verifyFreshness(
  bundle: Readonly<AttestationBundle>,
  context: Readonly<ProviderVerificationContext>,
): ProviderVerificationFailure | null {
  if (typeof bundle.issuedAt !== 'string' || typeof bundle.expiresAt !== 'string') {
    return providerFailure('MALFORMED_BUNDLE', 'attestation timestamps must be strings');
  }
  const issuedAt = new Date(bundle.issuedAt);
  const expiresAt = new Date(bundle.expiresAt);
  if (
    Number.isNaN(issuedAt.valueOf())
    || Number.isNaN(expiresAt.valueOf())
    || issuedAt.toISOString() !== bundle.issuedAt
    || expiresAt.toISOString() !== bundle.expiresAt
    || expiresAt.valueOf() <= issuedAt.valueOf()
  ) {
    return providerFailure('MALFORMED_BUNDLE', 'attestation timestamps are invalid or non-canonical');
  }
  const skewMs = context.maxFutureSkewSeconds * 1000;
  if (issuedAt.valueOf() > context.now.valueOf() + skewMs) {
    return providerFailure('PROOF_FROM_FUTURE', 'attestation timestamp exceeds future-skew allowance');
  }
  if (expiresAt.valueOf() < context.now.valueOf()) {
    return providerFailure('PROOF_EXPIRED', 'attestation has expired');
  }
  if (context.now.valueOf() - issuedAt.valueOf() > context.maxProofAgeSeconds * 1000) {
    return providerFailure('PROOF_TOO_OLD', 'attestation exceeds maximum age');
  }
  return null;
}

function measurementPolicyFailure(
  measurements: Record<string, string>,
  policy: Record<string, MeasurementRule>,
): ProviderVerificationFailure | null {
  for (const [register, rule] of Object.entries(policy)) {
    const actual = measurements[register];
    const allowed = rule.type === 'exact' ? actual === rule.value : rule.values.includes(actual ?? '');
    if (!allowed) return providerFailure('MEASUREMENT_POLICY_FAILED', `measurement ${register} failed policy`);
  }
  return null;
}

export class SimulatorAttestationVerifier implements AttestationProviderVerifier {
  readonly method = 'simulator' as const;

  verify(
    bundle: Readonly<AttestationBundle>,
    context: Readonly<ProviderVerificationContext>,
  ): ProviderVerificationResult {
    if (bundle.method !== this.method) {
      return providerFailure('PROVIDER_RESULT_INVALID', 'simulator verifier received a different method');
    }
    if (bundle.nonce !== context.nonce) {
      return providerFailure('NONCE_MISMATCH', 'simulator bundle is not bound to the challenge nonce');
    }
    if (context.nonceContext.deviceId !== bundle.deviceId) {
      return providerFailure('NONCE_CONTEXT_MISMATCH', 'simulator bundle device differs from nonce context');
    }
    const freshnessFailure = verifyFreshness(bundle, context);
    if (freshnessFailure) return freshnessFailure;
    if (keyIdFromPublicKey(context.publicKeyPem) !== bundle.keyId) {
      return providerFailure('KEY_ID_MISMATCH', 'bundle keyId does not match the registered simulator key');
    }
    if (!verifyDetached(canonicalBytes(unsigned(bundle)), bundle.signature, context.publicKeyPem)) {
      return providerFailure('INVALID_SIGNATURE', 'simulator bundle signature is invalid');
    }
    const policyFailure = measurementPolicyFailure(bundle.measurements, context.measurementPolicy);
    if (policyFailure) return policyFailure;
    return {
      valid: true,
      method: this.method,
      trustLevel: 'simulated',
      assuranceLevel: 'development',
      keyId: bundle.keyId,
      measurements: { ...bundle.measurements },
    };
  }
}

export class Tpm2AttestationVerifier implements AttestationProviderVerifier {
  readonly method = 'tpm2' as const;

  verify(
    bundle: Readonly<AttestationBundle>,
    context: Readonly<ProviderVerificationContext>,
  ): ProviderVerificationResult {
    if (bundle.method !== this.method) {
      return providerFailure('PROVIDER_RESULT_INVALID', 'TPM verifier received a different method');
    }
    if (bundle.nonce !== context.nonce) {
      return providerFailure('NONCE_MISMATCH', 'TPM bundle is not bound to the challenge nonce');
    }
    if (context.nonceContext.deviceId !== bundle.deviceId) {
      return providerFailure('NONCE_CONTEXT_MISMATCH', 'TPM bundle device differs from nonce context');
    }
    const freshnessFailure = verifyFreshness(bundle, context);
    if (freshnessFailure) return freshnessFailure;
    if (tpm2KeyIdFromPublicKey(context.publicKeyPem) !== bundle.keyId) {
      return providerFailure('KEY_ID_MISMATCH', 'bundle keyId does not match the registered TPM attestation key');
    }
    const quoteResult = verifyTpmQuote(bundle.evidence, {
      nonce: context.nonce,
      publicKeyPem: context.publicKeyPem,
      expectedQualifiedSigner: context.expectedTpmQualifiedSigner,
      expectedPcrSelection: context.expectedTpmPcrSelection,
      requireEventLog: context.requireTpmEventLog,
    });
    if (!quoteResult.valid) return providerFailure(quoteResult.code, quoteResult.reason);
    if (!canonicalBytes(bundle.measurements).equals(canonicalBytes(quoteResult.measurements))) {
      return providerFailure('TPM_PCR_DIGEST', 'bundle measurements differ from independently verified PCRs');
    }
    const outerSignature = strictBase64url(bundle.signature);
    if (!outerSignature) {
      return providerFailure('TPM_BUNDLE_SIGNATURE', 'TPM bundle signature is not canonical base64url');
    }
    const verifier = createVerify('sha256');
    verifier.update(canonicalBytes(unsigned(bundle)));
    verifier.end();
    if (!verifier.verify(context.publicKeyPem, outerSignature)) {
      return providerFailure('TPM_BUNDLE_SIGNATURE', 'TPM attestation key did not sign the complete bundle');
    }
    const policyFailure = measurementPolicyFailure(quoteResult.measurements, context.measurementPolicy);
    if (policyFailure) return policyFailure;
    return {
      valid: true,
      method: this.method,
      trustLevel: 'hardware',
      assuranceLevel: 'hardware-rooted',
      keyId: bundle.keyId,
      measurements: quoteResult.measurements,
    };
  }
}
