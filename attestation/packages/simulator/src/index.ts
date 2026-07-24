import {
  canonicalBytes,
  ed25519KeyPairFromSeed,
  exportPublicKeyPem,
  keyIdFromPublicKey,
  sha256,
  signDetached,
} from '@event-horizon/attestation-crypto';
import type { AttestationBundle, AttestationBundleUnsigned } from '@event-horizon/attestation-core';

export interface SimulatorConfig {
  deviceId: string;
  seed?: string;
  ttlSeconds?: number;
  now?: () => Date;
  measurements?: Record<string, string>;
}

export class SimulatorProver {
  readonly method = 'simulator' as const;
  readonly deviceId: string;
  readonly publicKeyPem: string;
  readonly keyId: string;
  readonly measurements: Record<string, string>;
  private readonly keyPair;
  private readonly ttlSeconds: number;
  private readonly now: () => Date;

  constructor(config: SimulatorConfig) {
    if (!config.deviceId.trim()) throw new TypeError('deviceId is required');
    const seed = config.seed ?? `attestation-simulator:${config.deviceId}`;
    this.keyPair = ed25519KeyPairFromSeed(seed);
    this.publicKeyPem = exportPublicKeyPem(this.keyPair.publicKey);
    this.keyId = keyIdFromPublicKey(this.keyPair.publicKey);
    this.deviceId = config.deviceId;
    this.ttlSeconds = config.ttlSeconds ?? 30;
    this.now = config.now ?? (() => new Date());
    this.measurements = config.measurements ?? {
      '0': sha256(`simulator:firmware:${seed}`),
      '7': sha256(`simulator:secure-boot:${seed}`),
      executor: sha256(`simulator:executor:${seed}`),
    };
  }

  async prove(options: { nonce: string }): Promise<AttestationBundle> {
    if (!options.nonce || options.nonce.length < 16) throw new TypeError('nonce must contain at least 16 characters');
    const issuedAt = this.now();
    const unsigned: AttestationBundleUnsigned = {
      version: 'eh-attestation-1',
      method: 'simulator',
      deviceId: this.deviceId,
      nonce: options.nonce,
      issuedAt: issuedAt.toISOString(),
      expiresAt: new Date(issuedAt.valueOf() + this.ttlSeconds * 1000).toISOString(),
      keyId: this.keyId,
      measurements: { ...this.measurements },
      evidence: {
        provider: 'deterministic-simulator',
        warning: 'development evidence only; no hardware root of trust',
      },
    };
    return { ...unsigned, signature: signDetached(canonicalBytes(unsigned), this.keyPair.privateKey) };
  }
}
