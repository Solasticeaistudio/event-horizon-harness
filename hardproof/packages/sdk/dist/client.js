import { SimulatorProver } from '@hardproof/simulator';
import { TpmProver } from '@hardproof/prover-tpm';
import { Emitter } from './emitter.js';
import { HardproofError, toHardproofError } from './errors.js';
export class Client extends Emitter {
    config;
    prover;
    constructor(config) {
        super();
        this.config = config;
    }
    static async create(config = {}) {
        const client = new Client(config);
        if (config.eager)
            await client.resolveProver();
        return client;
    }
    get method() { return this.prover?.method; }
    device = {
        register: async (_options) => {
            throw new HardproofError('NOT_IMPLEMENTED', 'cloud device registration is not implemented in the local rebuild', 'Use an explicit deviceId for local development.');
        },
    };
    session = {
        start: async (_options = {}) => {
            throw new HardproofError('NOT_IMPLEMENTED', 'attestation sessions are reserved for the cloud/session implementation phase');
        },
        token: async () => {
            throw new HardproofError('NOT_IMPLEMENTED', 'no attestation session is active');
        },
        stop: () => undefined,
    };
    async prove(options = {}) {
        const deviceId = options.deviceId ?? this.config.deviceId;
        if (!deviceId)
            throw new HardproofError('INVALID_CONFIG', 'deviceId is required', 'Pass deviceId to Client.create() or prove().');
        if (!options.nonce) {
            if (this.config.apiKey)
                throw new HardproofError('NOT_IMPLEMENTED', 'cloud nonce fetching is not implemented');
            throw new HardproofError('INVALID_CONFIG', 'nonce is required in local mode', 'Issue one from Server.nonce.issue().');
        }
        try {
            const prover = await this.resolveProver(deviceId);
            this.emit('prove.started', { deviceId, nonce: options.nonce });
            const bundle = await prover.prove({ nonce: options.nonce });
            this.emit('prove.completed', { deviceId, keyId: bundle.keyId });
            return bundle;
        }
        catch (error) {
            const hpError = toHardproofError(error);
            this.emit('prove.failed', { deviceId, error: hpError });
            throw hpError;
        }
    }
    async resolveProver(deviceId = this.config.deviceId) {
        if (this.prover)
            return this.prover;
        if (!deviceId)
            throw new HardproofError('INVALID_CONFIG', 'deviceId is required before prover detection');
        const explicit = this.config.method;
        const allowSimulator = process.env.NODE_ENV === 'test' || process.env.HARDPROOF_ALLOW_SIMULATOR === '1';
        if (explicit === 'simulator' || (!explicit && allowSimulator)) {
            this.prover = new SimulatorProver({ deviceId, seed: this.config.simulatorSeed });
        }
        else if ((explicit === 'tpm2' || !explicit) && await TpmProver.isAvailable()) {
            this.prover = new TpmProver({ deviceId, pcrSelection: this.config.pcrSelection });
        }
        else {
            this.emit('prover.unavailable', { reason: 'no allowed prover detected' });
            throw new HardproofError('NO_PROVER_AVAILABLE', 'no hardware prover is available and simulator use is disabled', 'Set HARDPROOF_ALLOW_SIMULATOR=1 only for development.');
        }
        this.emit('prover.ready', { method: this.prover.method });
        return this.prover;
    }
}
//# sourceMappingURL=client.js.map