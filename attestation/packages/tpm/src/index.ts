import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { spawnSync } from 'node:child_process';
import type { AttestationBundle } from '@event-horizon/attestation-core';

export interface TpmQuoteProvider {
  prove(options: { deviceId: string; nonce: string; pcrSelection: number[] }): Promise<AttestationBundle>;
}

export interface TpmProverConfig {
  deviceId: string;
  pcrSelection?: number[];
  provider?: TpmQuoteProvider;
}

export class TpmProver {
  readonly method = 'tpm2' as const;
  private readonly pcrSelection: number[];

  constructor(private readonly config: TpmProverConfig) {
    if (!config.deviceId.trim()) throw new TypeError('deviceId is required');
    this.pcrSelection = config.pcrSelection ?? [0, 7];
  }

  static async isAvailable(): Promise<boolean> {
    if (!['linux', 'win32'].includes(process.platform)) return false;
    if (process.env.EH_ATTESTATION_TPM_AVAILABLE === '1') return true;
    if (process.platform === 'linux') {
      try {
        await access('/dev/tpmrm0', constants.R_OK | constants.W_OK);
        return true;
      } catch {
        const result = spawnSync('tpm2_getrandom', ['1'], { stdio: 'ignore' });
        return result.status === 0;
      }
    }
    return false;
  }

  async prove(options: { nonce: string }): Promise<AttestationBundle> {
    if (!this.config.provider) {
      const error = new Error('TPM quote provider is not configured; production code must supply a platform-specific provider');
      error.name = 'PROVER_NOT_IMPLEMENTED';
      throw error;
    }
    return this.config.provider.prove({
      deviceId: this.config.deviceId,
      nonce: options.nonce,
      pcrSelection: [...this.pcrSelection],
    });
  }
}

export * from './linux.js';
