import { createHash } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { tpm2KeyIdFromPublicKey } from '@hardproof/core';
function errorWithName(name, message) {
    const error = new Error(message);
    error.name = name;
    return error;
}
function strictBase64url(value) {
    if (!/^[A-Za-z0-9_-]{22,}$/.test(value))
        throw new TypeError('nonce must be canonical base64url');
    const decoded = Buffer.from(value, 'base64url');
    if (decoded.toString('base64url') !== value)
        throw new TypeError('nonce must be canonical base64url');
    return decoded;
}
function normalizeTpm2bName(data) {
    if (data.length >= 2 && data.readUInt16BE(0) === data.length - 2)
        return data.subarray(2).toString('hex');
    return data.toString('hex');
}
export class LinuxTpm2ToolsProvider {
    config;
    workDirectory;
    timeoutMs;
    ttlSeconds;
    now;
    registeredAk;
    constructor(config) {
        this.config = config;
        if (process.platform !== 'linux')
            throw errorWithName('TPM_PLATFORM_UNSUPPORTED', 'Linux TPM provider requires Linux');
        if (!config.workDirectory)
            throw new TypeError('TPM workDirectory is required');
        this.workDirectory = resolve(config.workDirectory);
        this.timeoutMs = config.commandTimeoutMs ?? 10_000;
        this.ttlSeconds = config.ttlSeconds ?? 30;
        this.now = config.now ?? (() => new Date());
    }
    static async isAvailable(tcti) {
        if (process.platform !== 'linux')
            return false;
        try {
            await access('/dev/tpmrm0', constants.R_OK | constants.W_OK);
        }
        catch {
            if (!tcti)
                return false;
        }
        const args = ['1'];
        if (tcti)
            args.push('-T', tcti);
        const result = spawnSync('tpm2_getrandom', args, { stdio: 'ignore', timeout: 5_000 });
        return result.status === 0;
    }
    run(command, args) {
        const fullArgs = [...args];
        if (this.config.tcti)
            fullArgs.push('-T', this.config.tcti);
        const result = spawnSync(command, fullArgs, {
            encoding: 'utf8',
            timeout: this.timeoutMs,
            env: { ...process.env, TPM2TOOLS_AUTOFLUSH: 'yes' },
        });
        if (result.error || result.status !== 0) {
            const detail = String(result.stderr || result.error?.message || 'TPM command failed').trim();
            throw errorWithName('TPM_COMMAND_FAILED', `${command} failed: ${detail}`);
        }
        return String(result.stdout ?? '');
    }
    paths() {
        return {
            context: resolve(this.config.akContextPath ?? join(this.workDirectory, 'ak.ctx')),
            publicKey: resolve(this.config.akPublicKeyPath ?? join(this.workDirectory, 'ak.pem')),
            qualifiedName: resolve(this.config.akQualifiedNamePath ?? join(this.workDirectory, 'ak.qname')),
        };
    }
    async provisionAk() {
        await mkdir(this.workDirectory, { recursive: true, mode: 0o700 });
        const paths = this.paths();
        for (const path of Object.values(paths)) {
            try {
                await access(path);
                throw errorWithName('TPM_AK_EXISTS', `refusing to overwrite existing AK material: ${path}`);
            }
            catch (error) {
                if (error instanceof Error && error.name === 'TPM_AK_EXISTS')
                    throw error;
            }
        }
        const ekContext = join(this.workDirectory, 'ek.ctx');
        const ekPublic = join(this.workDirectory, 'ek.pem');
        this.run('tpm2_createek', ['-Q', '-G', 'rsa', '-c', ekContext, '-u', ekPublic, '-f', 'pem']);
        this.run('tpm2_createak', [
            '-Q', '-C', ekContext, '-G', 'rsa', '-g', 'sha256', '-s', 'rsassa',
            '-c', paths.context, '-u', paths.publicKey, '-f', 'pem', '-n', join(this.workDirectory, 'ak.name'),
            '-q', paths.qualifiedName,
        ]);
        return this.loadAk();
    }
    async loadAk() {
        const paths = this.paths();
        const [publicKeyPem, qualifiedNameData] = await Promise.all([
            readFile(paths.publicKey, 'utf8'),
            readFile(paths.qualifiedName),
            access(paths.context, constants.R_OK),
        ]);
        if (!publicKeyPem.includes('BEGIN PUBLIC KEY'))
            throw errorWithName('TPM_AK_INVALID', 'AK public key is not PEM');
        const qualifiedName = normalizeTpm2bName(qualifiedNameData);
        if (!qualifiedName)
            throw errorWithName('TPM_AK_INVALID', 'AK qualified name is missing');
        this.registeredAk = {
            contextPath: paths.context,
            publicKeyPem,
            qualifiedName,
            keyId: tpm2KeyIdFromPublicKey(publicKeyPem),
        };
        return { ...this.registeredAk };
    }
    get attestationKey() {
        if (!this.registeredAk)
            throw errorWithName('TPM_AK_NOT_LOADED', 'AK must be explicitly provisioned or loaded');
        return { ...this.registeredAk };
    }
    async prove(options) {
        const ak = this.attestationKey;
        if (!(await LinuxTpm2ToolsProvider.isAvailable(this.config.tcti))) {
            throw errorWithName('TPM_UNAVAILABLE', 'TPM hardware or tpm2-tools is unavailable');
        }
        if (!options.deviceId.trim())
            throw new TypeError('deviceId is required');
        const nonce = strictBase64url(options.nonce);
        const selection = [...new Set(options.pcrSelection)].sort((left, right) => left - right);
        if (!selection.length || selection.length !== options.pcrSelection.length || selection.some((pcr) => !Number.isInteger(pcr) || pcr < 0 || pcr > 23)) {
            throw new TypeError('PCR selection must contain unique indices from 0 through 23');
        }
        await mkdir(this.workDirectory, { recursive: true, mode: 0o700 });
        const quoteDirectory = await mkdtemp(join(this.workDirectory, 'quote-'));
        if (!quoteDirectory.startsWith(`${this.workDirectory}${sep}`)) {
            throw errorWithName('TPM_WORKDIR_INVALID', 'quote scratch path escaped TPM work directory');
        }
        const noncePath = join(quoteDirectory, 'nonce.bin');
        const quotePath = join(quoteDirectory, 'quote.msg');
        const signaturePath = join(quoteDirectory, 'quote.sig');
        const pcrPath = join(quoteDirectory, 'pcr.values');
        try {
            await writeFile(noncePath, nonce, { mode: 0o600, flag: 'wx' });
            this.run('tpm2_quote', [
                '-Q', '-c', ak.contextPath,
                '-l', `sha256:${selection.join(',')}`,
                '-q', noncePath,
                '-m', quotePath,
                '-s', signaturePath,
                '-f', 'plain',
                '-o', pcrPath,
                '-F', 'values',
                '-g', 'sha256',
            ]);
            const [quote, signature, pcrData] = await Promise.all([
                readFile(quotePath),
                readFile(signaturePath),
                readFile(pcrPath),
            ]);
            if (pcrData.length !== selection.length * 32) {
                throw errorWithName('TPM_PCR_OUTPUT_INVALID', 'tpm2_quote returned an unexpected PCR value length');
            }
            const pcrValues = {};
            const pcrKeys = [];
            for (let index = 0; index < selection.length; index += 1) {
                const key = `sha256:${selection[index]}`;
                pcrKeys.push(key);
                pcrValues[key] = pcrData.subarray(index * 32, (index + 1) * 32).toString('hex');
            }
            let eventLog = null;
            if (this.config.normalizedEventLogPath) {
                const parsed = JSON.parse(await readFile(resolve(this.config.normalizedEventLogPath), 'utf8'));
                if (!Array.isArray(parsed))
                    throw errorWithName('TPM_EVENT_LOG_INVALID', 'normalized event log must be an array');
                eventLog = parsed;
            }
            const executor = createHash('sha256')
                .update(JSON.stringify(Object.fromEntries(Object.entries(pcrValues).sort())))
                .digest('hex');
            const issuedAt = this.now();
            const unsigned = {
                version: 'hp1',
                method: 'tpm2',
                deviceId: options.deviceId,
                nonce: options.nonce,
                issuedAt: issuedAt.toISOString(),
                expiresAt: new Date(issuedAt.valueOf() + this.ttlSeconds * 1000).toISOString(),
                keyId: ak.keyId,
                measurements: { ...pcrValues, executor },
                evidence: {
                    provider: 'linux-tpm2-tools',
                    quote: quote.toString('base64url'),
                    signatureAlgorithm: 'rsassa-sha256',
                    hashAlgorithm: 'sha256',
                    pcrValues,
                    pcrSelection: pcrKeys,
                    eventLog,
                    akQualifiedName: ak.qualifiedName,
                },
            };
            return { ...unsigned, signature: signature.toString('base64url') };
        }
        finally {
            await rm(quoteDirectory, { recursive: true, force: true });
        }
    }
}
//# sourceMappingURL=linux.js.map