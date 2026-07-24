import { access } from 'node:fs/promises';
import { constants } from 'node:fs';
import { spawnSync } from 'node:child_process';
export class TpmProver {
    config;
    method = 'tpm2';
    pcrSelection;
    constructor(config) {
        this.config = config;
        if (!config.deviceId.trim())
            throw new TypeError('deviceId is required');
        this.pcrSelection = config.pcrSelection ?? [0, 7];
    }
    static async isAvailable() {
        if (!['linux', 'win32'].includes(process.platform))
            return false;
        if (process.env.HARDPROOF_TPM_AVAILABLE === '1')
            return true;
        if (process.platform === 'linux') {
            try {
                await access('/dev/tpmrm0', constants.R_OK | constants.W_OK);
                return true;
            }
            catch {
                const result = spawnSync('tpm2_getrandom', ['1'], { stdio: 'ignore' });
                return result.status === 0;
            }
        }
        return false;
    }
    async prove(options) {
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
//# sourceMappingURL=index.js.map