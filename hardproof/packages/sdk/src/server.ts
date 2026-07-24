import { Verifier, type HardproofBundle, type VerificationResult, type VerifierConfig } from '@hardproof/core';
import { Emitter } from './emitter.js';
import { HardproofError } from './errors.js';

export interface ServerConfig {
  apiKey?: string;
  cloudUrl?: string;
  mode?: 'cloud' | 'local';
  config?: VerifierConfig;
  debug?: boolean;
}

export interface ServerEvents extends Record<string, unknown> {
  'verify.started': { deviceId: string };
  'verify.success': { deviceId: string; trustLevel: string };
  'verify.failed': { deviceId?: string; reason: string };
  'device.verified': { deviceId: string; trustLevel: string };
  'nonce.issued': { nonce: string };
}

export class Server extends Emitter<ServerEvents> {
  private readonly verifier?: Verifier;
  readonly resolvedMode: 'cloud' | 'local';

  private constructor(private readonly options: ServerConfig) {
    super();
    this.resolvedMode = options.mode ?? (options.apiKey ? 'cloud' : 'local');
    if (this.resolvedMode === 'local') this.verifier = new Verifier(options.config);
  }

  static create(config: ServerConfig = {}): Server {
    if ((config.mode ?? (config.apiKey ? 'cloud' : 'local')) === 'cloud' && !config.apiKey) {
      throw new HardproofError('VERIFIER_NOT_CONFIGURED', 'cloud mode requires apiKey');
    }
    return new Server(config);
  }

  registerDevice(deviceId: string, publicKeyPem: string): void {
    if (!this.verifier) throw new HardproofError('NOT_IMPLEMENTED', 'cloud device registration is not implemented');
    this.verifier.registerDevice(deviceId, publicKeyPem);
  }

  async verify(bundle: HardproofBundle, options: { nonce: string; publicKeyPem?: string }): Promise<VerificationResult> {
    this.emit('verify.started', { deviceId: bundle.deviceId });
    if (!this.verifier) throw new HardproofError('NOT_IMPLEMENTED', 'cloud verification is not implemented');
    const result = this.verifier.verify(bundle, options);
    if (result.valid) {
      this.emit('verify.success', { deviceId: result.deviceId, trustLevel: result.trustLevel });
      this.emit('device.verified', { deviceId: result.deviceId, trustLevel: result.trustLevel });
    } else {
      this.emit('verify.failed', { deviceId: bundle.deviceId, reason: result.failureReason });
    }
    return result;
  }

  readonly nonce = {
    issue: async (): Promise<string> => {
      if (!this.verifier) throw new HardproofError('NOT_IMPLEMENTED', 'cloud nonce issuance is not implemented');
      const nonce = this.verifier.nonceStore.issue();
      this.emit('nonce.issued', { nonce });
      return nonce;
    },
  };

  readonly session = {
    verify: async (_options: { authorizationHeader?: string }): Promise<null> => {
      throw new HardproofError('NOT_IMPLEMENTED', 'session verification is not implemented');
    },
  };
}
