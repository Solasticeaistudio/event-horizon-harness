import { Verifier } from '@hardproof/core';
import { Emitter } from './emitter.js';
import { HardproofError } from './errors.js';
export class Server extends Emitter {
    options;
    verifier;
    resolvedMode;
    constructor(options) {
        super();
        this.options = options;
        this.resolvedMode = options.mode ?? (options.apiKey ? 'cloud' : 'local');
        if (this.resolvedMode === 'local')
            this.verifier = new Verifier(options.config);
    }
    static create(config = {}) {
        if ((config.mode ?? (config.apiKey ? 'cloud' : 'local')) === 'cloud' && !config.apiKey) {
            throw new HardproofError('VERIFIER_NOT_CONFIGURED', 'cloud mode requires apiKey');
        }
        return new Server(config);
    }
    registerDevice(deviceId, publicKeyPem) {
        if (!this.verifier)
            throw new HardproofError('NOT_IMPLEMENTED', 'cloud device registration is not implemented');
        this.verifier.registerDevice(deviceId, publicKeyPem);
    }
    async verify(bundle, options) {
        this.emit('verify.started', { deviceId: bundle.deviceId });
        if (!this.verifier)
            throw new HardproofError('NOT_IMPLEMENTED', 'cloud verification is not implemented');
        const result = this.verifier.verify(bundle, options);
        if (result.valid) {
            this.emit('verify.success', { deviceId: result.deviceId, trustLevel: result.trustLevel });
            this.emit('device.verified', { deviceId: result.deviceId, trustLevel: result.trustLevel });
        }
        else {
            this.emit('verify.failed', { deviceId: bundle.deviceId, reason: result.failureReason });
        }
        return result;
    }
    nonce = {
        issue: async () => {
            if (!this.verifier)
                throw new HardproofError('NOT_IMPLEMENTED', 'cloud nonce issuance is not implemented');
            const nonce = this.verifier.nonceStore.issue();
            this.emit('nonce.issued', { nonce });
            return nonce;
        },
    };
    session = {
        verify: async (_options) => {
            throw new HardproofError('NOT_IMPLEMENTED', 'session verification is not implemented');
        },
    };
}
//# sourceMappingURL=server.js.map