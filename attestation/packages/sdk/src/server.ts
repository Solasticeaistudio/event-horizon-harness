import {
  Verifier,
  type AttestationBundle,
  type NonceContext,
  type VerificationResult,
  type VerifierConfig,
} from '@event-horizon/attestation-core';
import { Emitter } from './emitter.js';
import { AttestationError } from './errors.js';

export interface ServerConfig {
  apiKey?: string;
  serviceUrl?: string;
  mode?: 'service' | 'local';
  config?: VerifierConfig;
  debug?: boolean;
}

export interface ServerEvents extends Record<string, unknown> {
  'verify.started': { deviceId: string };
  'verify.success': { deviceId: string; trustLevel: string };
  'verify.failed': { deviceId?: string; reason: string };
  'device.verified': { deviceId: string; trustLevel: string };
  'nonce.issued': { nonce: string; context: NonceContext };
}

export class Server extends Emitter<ServerEvents> {
  private readonly verifier?: Verifier;
  readonly resolvedMode: 'service' | 'local';

  private constructor(private readonly options: ServerConfig) {
    super();
    this.resolvedMode = options.mode ?? (options.apiKey ? 'service' : 'local');
    if (this.resolvedMode === 'local') this.verifier = new Verifier(options.config);
  }

  static create(config: ServerConfig = {}): Server {
    const resolvedConfig: ServerConfig = {
      ...config,
      apiKey: config.apiKey ?? process.env.EH_ATTESTATION_API_KEY,
      serviceUrl: config.serviceUrl ?? process.env.EH_ATTESTATION_SERVICE_URL,
    };
    if ((resolvedConfig.mode ?? (resolvedConfig.apiKey ? 'service' : 'local')) === 'service' && !resolvedConfig.apiKey) {
      throw new AttestationError('VERIFIER_NOT_CONFIGURED', 'service mode requires apiKey');
    }
    return new Server(resolvedConfig);
  }

  registerDevice(deviceId: string, publicKeyPem: string): void {
    if (!this.verifier) throw new AttestationError('NOT_IMPLEMENTED', 'remote device registration is not implemented');
    this.verifier.registerDevice(deviceId, publicKeyPem);
  }

  async verify(
    bundle: AttestationBundle,
    options: { nonce: string; context: NonceContext; publicKeyPem?: string },
  ): Promise<VerificationResult> {
    this.emit('verify.started', { deviceId: bundle.deviceId });
    if (!this.verifier) throw new AttestationError('NOT_IMPLEMENTED', 'remote verification is not implemented');
    const result = await this.verifier.verify(bundle, options);
    if (result.valid) {
      this.emit('verify.success', { deviceId: result.deviceId, trustLevel: result.trustLevel });
      this.emit('device.verified', { deviceId: result.deviceId, trustLevel: result.trustLevel });
    } else {
      this.emit('verify.failed', { deviceId: bundle.deviceId, reason: result.failureReason });
    }
    return result;
  }

  readonly nonce = {
    issue: async (context: NonceContext): Promise<string> => {
      if (!this.verifier) throw new AttestationError('NOT_IMPLEMENTED', 'remote nonce issuance is not implemented');
      const nonce = await this.verifier.nonceAuthority.issue(context);
      this.emit('nonce.issued', { nonce, context });
      return nonce;
    },
  };

  readonly session = {
    verify: async (_options: { authorizationHeader?: string }): Promise<null> => {
      throw new AttestationError('NOT_IMPLEMENTED', 'session verification is not implemented');
    },
  };
}
