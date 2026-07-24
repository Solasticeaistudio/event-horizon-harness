import type { AttestationBundle, AttestationMethod } from '@event-horizon/attestation-core';
import { SimulatorProver } from '@event-horizon/attestation-simulator';
import { TpmProver } from '@event-horizon/attestation-tpm';
import { Emitter } from './emitter.js';
import { AttestationError, toAttestationError } from './errors.js';

interface Prover {
  readonly method: AttestationMethod;
  prove(options: { nonce: string }): Promise<AttestationBundle>;
}

export interface ClientConfig {
  apiKey?: string;
  serviceUrl?: string;
  deviceId?: string;
  debug?: boolean;
  eager?: boolean;
  method?: AttestationMethod;
  simulatorSeed?: string;
  pcrSelection?: number[];
}

export interface ClientEvents extends Record<string, unknown> {
  'prover.ready': { method: AttestationMethod };
  'prover.unavailable': { reason: string };
  'prove.started': { deviceId: string; nonce: string };
  'prove.completed': { deviceId: string; keyId: string };
  'prove.failed': { deviceId: string; error: AttestationError };
  'device.registered': { deviceId: string };
  'session.started': { token: string; expiresAt: string };
}

export class Client extends Emitter<ClientEvents> {
  private prover?: Prover;
  private constructor(private readonly config: ClientConfig) { super(); }

  static async create(config: ClientConfig = {}): Promise<Client> {
    const resolvedConfig: ClientConfig = {
      ...config,
      apiKey: config.apiKey ?? process.env.EH_ATTESTATION_API_KEY,
      serviceUrl: config.serviceUrl ?? process.env.EH_ATTESTATION_SERVICE_URL,
    };
    const client = new Client(resolvedConfig);
    if (resolvedConfig.eager) await client.resolveProver();
    return client;
  }

  get method(): AttestationMethod | undefined { return this.prover?.method; }

  readonly device = {
    register: async (_options: { token: string; label?: string }): Promise<{ deviceId: string }> => {
      throw new AttestationError('NOT_IMPLEMENTED', 'remote device registration is not implemented in the local rebuild', 'Use an explicit deviceId for local development.');
    },
  };

  readonly session = {
    start: async (_options: { ttlMinutes?: number } = {}): Promise<void> => {
      throw new AttestationError('NOT_IMPLEMENTED', 'attestation sessions are reserved for the remote-service implementation phase');
    },
    token: async (): Promise<string> => {
      throw new AttestationError('NOT_IMPLEMENTED', 'no attestation session is active');
    },
    stop: (): void => undefined,
  };

  async prove(options: { nonce?: string; deviceId?: string } = {}): Promise<AttestationBundle> {
    const deviceId = options.deviceId ?? this.config.deviceId;
    if (!deviceId) throw new AttestationError('INVALID_CONFIG', 'deviceId is required', 'Pass deviceId to Client.create() or prove().');
    if (!options.nonce) {
      if (this.config.apiKey) throw new AttestationError('NOT_IMPLEMENTED', 'remote nonce fetching is not implemented');
      throw new AttestationError('INVALID_CONFIG', 'nonce is required in local mode', 'Issue one from Server.nonce.issue().');
    }
    try {
      const prover = await this.resolveProver(deviceId);
      this.emit('prove.started', { deviceId, nonce: options.nonce });
      const bundle = await prover.prove({ nonce: options.nonce });
      this.emit('prove.completed', { deviceId, keyId: bundle.keyId });
      return bundle;
    } catch (error) {
      const attestationError = toAttestationError(error);
      this.emit('prove.failed', { deviceId, error: attestationError });
      throw attestationError;
    }
  }

  private async resolveProver(deviceId = this.config.deviceId): Promise<Prover> {
    if (this.prover) return this.prover;
    if (!deviceId) throw new AttestationError('INVALID_CONFIG', 'deviceId is required before prover detection');
    const explicit = this.config.method;
    const forceHardware = process.env.EH_ATTESTATION_FORCE_HARDWARE === '1';
    const allowSimulator = !forceHardware
      && (process.env.NODE_ENV === 'test' || process.env.EH_ATTESTATION_ALLOW_SIMULATOR === '1');
    if (forceHardware && explicit === 'simulator') {
      throw new AttestationError('INVALID_CONFIG', 'simulator selection conflicts with EH_ATTESTATION_FORCE_HARDWARE=1');
    }
    if (explicit === 'simulator' || (!explicit && allowSimulator)) {
      this.prover = new SimulatorProver({ deviceId, seed: this.config.simulatorSeed });
    } else if ((explicit === 'tpm2' || !explicit) && await TpmProver.isAvailable()) {
      this.prover = new TpmProver({ deviceId, pcrSelection: this.config.pcrSelection });
    } else {
      this.emit('prover.unavailable', { reason: 'no allowed prover detected' });
      throw new AttestationError('NO_PROVER_AVAILABLE', 'no hardware prover is available and simulator use is disabled', 'Set EH_ATTESTATION_ALLOW_SIMULATOR=1 only for development.');
    }
    this.emit('prover.ready', { method: this.prover.method });
    return this.prover;
  }
}
