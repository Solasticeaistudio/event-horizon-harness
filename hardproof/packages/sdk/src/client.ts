import type { HardproofBundle, ProofMethod } from '@hardproof/core';
import { SimulatorProver } from '@hardproof/simulator';
import { TpmProver } from '@hardproof/prover-tpm';
import { Emitter } from './emitter.js';
import { HardproofError, toHardproofError } from './errors.js';

interface Prover {
  readonly method: ProofMethod;
  prove(options: { nonce: string }): Promise<HardproofBundle>;
}

export interface ClientConfig {
  apiKey?: string;
  cloudUrl?: string;
  deviceId?: string;
  debug?: boolean;
  eager?: boolean;
  method?: ProofMethod;
  simulatorSeed?: string;
  pcrSelection?: number[];
}

export interface ClientEvents extends Record<string, unknown> {
  'prover.ready': { method: ProofMethod };
  'prover.unavailable': { reason: string };
  'prove.started': { deviceId: string; nonce: string };
  'prove.completed': { deviceId: string; keyId: string };
  'prove.failed': { deviceId: string; error: HardproofError };
  'device.registered': { deviceId: string };
  'session.started': { token: string; expiresAt: string };
}

export class Client extends Emitter<ClientEvents> {
  private prover?: Prover;
  private constructor(private readonly config: ClientConfig) { super(); }

  static async create(config: ClientConfig = {}): Promise<Client> {
    const client = new Client(config);
    if (config.eager) await client.resolveProver();
    return client;
  }

  get method(): ProofMethod | undefined { return this.prover?.method; }

  readonly device = {
    register: async (_options: { token: string; label?: string }): Promise<{ deviceId: string }> => {
      throw new HardproofError('NOT_IMPLEMENTED', 'cloud device registration is not implemented in the local rebuild', 'Use an explicit deviceId for local development.');
    },
  };

  readonly session = {
    start: async (_options: { ttlMinutes?: number } = {}): Promise<void> => {
      throw new HardproofError('NOT_IMPLEMENTED', 'attestation sessions are reserved for the cloud/session implementation phase');
    },
    token: async (): Promise<string> => {
      throw new HardproofError('NOT_IMPLEMENTED', 'no attestation session is active');
    },
    stop: (): void => undefined,
  };

  async prove(options: { nonce?: string; deviceId?: string } = {}): Promise<HardproofBundle> {
    const deviceId = options.deviceId ?? this.config.deviceId;
    if (!deviceId) throw new HardproofError('INVALID_CONFIG', 'deviceId is required', 'Pass deviceId to Client.create() or prove().');
    if (!options.nonce) {
      if (this.config.apiKey) throw new HardproofError('NOT_IMPLEMENTED', 'cloud nonce fetching is not implemented');
      throw new HardproofError('INVALID_CONFIG', 'nonce is required in local mode', 'Issue one from Server.nonce.issue().');
    }
    try {
      const prover = await this.resolveProver(deviceId);
      this.emit('prove.started', { deviceId, nonce: options.nonce });
      const bundle = await prover.prove({ nonce: options.nonce });
      this.emit('prove.completed', { deviceId, keyId: bundle.keyId });
      return bundle;
    } catch (error) {
      const hpError = toHardproofError(error);
      this.emit('prove.failed', { deviceId, error: hpError });
      throw hpError;
    }
  }

  private async resolveProver(deviceId = this.config.deviceId): Promise<Prover> {
    if (this.prover) return this.prover;
    if (!deviceId) throw new HardproofError('INVALID_CONFIG', 'deviceId is required before prover detection');
    const explicit = this.config.method;
    const allowSimulator = process.env.NODE_ENV === 'test' || process.env.HARDPROOF_ALLOW_SIMULATOR === '1';
    if (explicit === 'simulator' || (!explicit && allowSimulator)) {
      this.prover = new SimulatorProver({ deviceId, seed: this.config.simulatorSeed });
    } else if ((explicit === 'tpm2' || !explicit) && await TpmProver.isAvailable()) {
      this.prover = new TpmProver({ deviceId, pcrSelection: this.config.pcrSelection });
    } else {
      this.emit('prover.unavailable', { reason: 'no allowed prover detected' });
      throw new HardproofError('NO_PROVER_AVAILABLE', 'no hardware prover is available and simulator use is disabled', 'Set HARDPROOF_ALLOW_SIMULATOR=1 only for development.');
    }
    this.emit('prover.ready', { method: this.prover.method });
    return this.prover;
  }
}
