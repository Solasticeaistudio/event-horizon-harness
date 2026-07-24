import { canonicalBytes, keyIdFromPublicKey, sha256, verifyDetached } from '@hardproof/crypto';
import { NonceStore } from './nonce-store.js';
const TRUST_ORDER = { simulated: 0, software: 1, hardware: 2 };
function failure(code, reason, at) {
    return { valid: false, failureCode: code, failureReason: reason, verifiedAt: at.toISOString() };
}
function methodTrust(method) {
    if (method === 'simulator')
        return { trust: 'simulated', assurance: 'development' };
    if (method === 'tpm2' || method === 'secure-enclave' || method === 'android-keystore') {
        return { trust: 'hardware', assurance: 'hardware-rooted' };
    }
    return null;
}
function unsigned(bundle) {
    const { signature: _signature, ...rest } = bundle;
    return rest;
}
export class Verifier {
    config;
    deviceKeys = new Map();
    consumedProofs = new Set();
    nonceStore;
    constructor(config = {}) {
        this.config = config;
        for (const [deviceId, key] of Object.entries(config.deviceKeys ?? {}))
            this.deviceKeys.set(deviceId, key);
        this.nonceStore = new NonceStore(60);
    }
    registerDevice(deviceId, publicKeyPem) {
        if (!deviceId.trim())
            throw new TypeError('deviceId is required');
        this.deviceKeys.set(deviceId, publicKeyPem);
    }
    verify(bundle, options) {
        const at = this.config.now?.() ?? new Date();
        if (!bundle || bundle.version !== 'hp1' || !bundle.deviceId || !bundle.nonce || !bundle.signature) {
            return failure('MALFORMED_BUNDLE', 'bundle is missing required hp1 fields', at);
        }
        const trust = methodTrust(bundle.method);
        if (!trust)
            return failure('UNSUPPORTED_METHOD', `unsupported proof method: ${String(bundle.method)}`, at);
        if (bundle.nonce !== options.nonce)
            return failure('NONCE_MISMATCH', 'proof nonce does not match verifier challenge', at);
        const issuedAt = new Date(bundle.issuedAt);
        const expiresAt = new Date(bundle.expiresAt);
        if (Number.isNaN(issuedAt.valueOf()) || Number.isNaN(expiresAt.valueOf())) {
            return failure('MALFORMED_BUNDLE', 'invalid proof timestamps', at);
        }
        const skewMs = (this.config.maxFutureSkewSeconds ?? 5) * 1000;
        if (issuedAt.valueOf() > at.valueOf() + skewMs)
            return failure('PROOF_FROM_FUTURE', 'proof timestamp exceeds future-skew allowance', at);
        if (expiresAt.valueOf() < at.valueOf())
            return failure('PROOF_EXPIRED', 'proof has expired', at);
        const ageMs = at.valueOf() - issuedAt.valueOf();
        if (ageMs > (this.config.maxProofAgeSeconds ?? 30) * 1000)
            return failure('PROOF_TOO_OLD', 'proof exceeds maximum age', at);
        const bundleDigest = sha256(canonicalBytes(bundle));
        if (this.consumedProofs.has(bundleDigest))
            return failure('PROOF_REPLAY', 'proof bundle has already been accepted', at);
        let publicKeyPem = this.deviceKeys.get(bundle.deviceId);
        if (!publicKeyPem && bundle.method === 'simulator' && this.config.allowUnregisteredSimulator) {
            publicKeyPem = options.publicKeyPem;
        }
        if (!publicKeyPem)
            return failure('UNKNOWN_DEVICE', 'device is not registered with this verifier', at);
        if (keyIdFromPublicKey(publicKeyPem) !== bundle.keyId)
            return failure('KEY_ID_MISMATCH', 'bundle keyId does not match registered device key', at);
        if (!verifyDetached(canonicalBytes(unsigned(bundle)), bundle.signature, publicKeyPem)) {
            return failure('INVALID_SIGNATURE', 'proof signature is invalid', at);
        }
        const requiredTrust = this.config.minTrustLevel ?? 'simulated';
        if (TRUST_ORDER[trust.trust] < TRUST_ORDER[requiredTrust]) {
            return failure('TRUST_LEVEL_TOO_LOW', `proof trust ${trust.trust} is below required ${requiredTrust}`, at);
        }
        for (const [register, rule] of Object.entries(this.config.pcrPolicy ?? {})) {
            const actual = bundle.measurements[register];
            const allowed = rule.type === 'exact' ? actual === rule.value : rule.values.includes(actual ?? '');
            if (!allowed)
                return failure('MEASUREMENT_POLICY_FAILED', `measurement ${register} failed policy`, at);
        }
        if (this.nonceStore.isConsumed(options.nonce))
            return failure('NONCE_REPLAY', 'nonce has already been consumed', at);
        // A nonce issued externally is still protected by proof replay. Locally issued nonces are consumed here.
        const locallyIssued = this.nonceStore.consume(options.nonce);
        if (!locallyIssued && this.nonceStore.isConsumed(options.nonce))
            return failure('NONCE_REPLAY', 'nonce has already been consumed', at);
        this.consumedProofs.add(bundleDigest);
        return {
            valid: true,
            deviceId: bundle.deviceId,
            method: bundle.method,
            trustLevel: trust.trust,
            assuranceLevel: trust.assurance,
            keyId: bundle.keyId,
            measurements: { ...bundle.measurements },
            bundleDigest,
            verifiedAt: at.toISOString(),
        };
    }
}
//# sourceMappingURL=verifier.js.map