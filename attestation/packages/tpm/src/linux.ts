import { createHash } from 'node:crypto';
import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { constants } from 'node:fs';
import { join, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import type { AttestationBundle, AttestationBundleUnsigned } from '@event-horizon/attestation-core';
import { tpm2KeyIdFromPublicKey } from '@event-horizon/attestation-core';
import { canonicalBytes } from '@event-horizon/attestation-crypto';
import type { TpmQuoteProvider } from './index.js';

export interface LinuxTpm2ToolsConfig {
  workDirectory: string;
  tcti?: string;
  commandTimeoutMs?: number;
  ttlSeconds?: number;
  now?: () => Date;
  akContextPath?: string;
  akPublicKeyPath?: string;
  akQualifiedNamePath?: string;
  ekPersistentHandle?: string;
  akPersistentHandle?: string;
  normalizedEventLogPath?: string;
}

export interface RegisteredAttestationKey {
  contextPath: string;
  publicKeyPem: string;
  qualifiedName: string;
  keyId: string;
}

function errorWithName(name: string, message: string): Error {
  const error = new Error(message);
  error.name = name;
  return error;
}

function strictBase64url(value: string): Buffer {
  if (!/^[A-Za-z0-9_-]{22,}$/.test(value)) throw new TypeError('nonce must be canonical base64url');
  const decoded = Buffer.from(value, 'base64url');
  if (decoded.toString('base64url') !== value) throw new TypeError('nonce must be canonical base64url');
  return decoded;
}

function normalizeTpm2bName(data: Buffer): string {
  if (data.length >= 2 && data.readUInt16BE(0) === data.length - 2) return data.subarray(2).toString('hex');
  return data.toString('hex');
}

export class LinuxTpm2ToolsProvider implements TpmQuoteProvider {
  private readonly workDirectory: string;
  private readonly timeoutMs: number;
  private readonly ttlSeconds: number;
  private readonly now: () => Date;
  private registeredAk?: RegisteredAttestationKey;

  constructor(private readonly config: LinuxTpm2ToolsConfig) {
    if (process.platform !== 'linux') throw errorWithName('TPM_PLATFORM_UNSUPPORTED', 'Linux TPM provider requires Linux');
    if (!config.workDirectory) throw new TypeError('TPM workDirectory is required');
    this.workDirectory = resolve(config.workDirectory);
    this.timeoutMs = config.commandTimeoutMs ?? 10_000;
    this.ttlSeconds = config.ttlSeconds ?? 30;
    this.now = config.now ?? (() => new Date());
  }

  static async isAvailable(tcti?: string): Promise<boolean> {
    if (process.platform !== 'linux') return false;
    try {
      await access('/dev/tpmrm0', constants.R_OK | constants.W_OK);
    } catch {
      if (!tcti) return false;
    }
    const args = ['1'];
    if (tcti) args.push('-T', tcti);
    const result = spawnSync('tpm2_getrandom', args, { stdio: 'ignore', timeout: 5_000 });
    return result.status === 0;
  }

  private run(command: string, args: string[]): string {
    const fullArgs = [...args];
    if (this.config.tcti) fullArgs.push('-T', this.config.tcti);
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

  private transientHandles(): Set<string> {
    const output = this.run('tpm2_getcap', ['-Q', 'handles-transient']);
    const handles = output.match(/0x8[0-9a-fA-F]{7}/g) ?? [];
    return new Set(handles.map((handle) => handle.toLowerCase()));
  }

  private persistentHandles(): Set<string> {
    const output = this.run('tpm2_getcap', ['-Q', 'handles-persistent']);
    const handles = output.match(/0x81[0-9a-fA-F]{6}/g) ?? [];
    return new Set(handles.map((handle) => handle.toLowerCase()));
  }

  private persistentHandle(value: string | undefined, fallback: string): string {
    const handle = (value ?? fallback).toLowerCase();
    if (!/^0x81[0-9a-f]{6}$/.test(handle)) throw new TypeError('TPM persistent handle must be in the 0x81xxxxxx range');
    return handle;
  }

  private paths(): { context: string; publicKey: string; qualifiedName: string } {
    return {
      context: resolve(this.config.akContextPath ?? join(this.workDirectory, 'ak.ctx')),
      publicKey: resolve(this.config.akPublicKeyPath ?? join(this.workDirectory, 'ak.pem')),
      qualifiedName: resolve(this.config.akQualifiedNamePath ?? join(this.workDirectory, 'ak.qname')),
    };
  }

  async provisionAk(): Promise<RegisteredAttestationKey> {
    await mkdir(this.workDirectory, { recursive: true, mode: 0o700 });
    const paths = this.paths();
    for (const path of Object.values(paths)) {
      try {
        await access(path);
        throw errorWithName('TPM_AK_EXISTS', `refusing to overwrite existing AK material: ${path}`);
      } catch (error) {
        if (error instanceof Error && error.name === 'TPM_AK_EXISTS') throw error;
      }
    }
    const ekHandle = this.persistentHandle(this.config.ekPersistentHandle, '0x81010001');
    const akHandle = this.persistentHandle(this.config.akPersistentHandle, '0x81010002');
    if (ekHandle === akHandle) throw new TypeError('EK and AK persistent handles must differ');
    const occupied = this.persistentHandles();
    if (occupied.has(ekHandle) || occupied.has(akHandle)) {
      throw errorWithName('TPM_PERSISTENT_HANDLE_EXISTS', 'refusing to overwrite an existing TPM persistent handle');
    }
    const akTransientContext = join(this.workDirectory, 'ak.transient.ctx');
    const ekPublic = join(this.workDirectory, 'ek.pem');
    const handlesBefore = this.transientHandles();
    this.run('tpm2_createek', ['-Q', '-G', 'rsa', '-c', ekHandle, '-u', ekPublic, '-f', 'pem']);
    this.run('tpm2_createak', [
      '-Q', '-C', ekHandle, '-G', 'rsa', '-g', 'sha256', '-s', 'rsassa',
      '-c', akTransientContext, '-u', paths.publicKey, '-f', 'pem', '-n', join(this.workDirectory, 'ak.name'),
      '-q', paths.qualifiedName,
    ]);
    this.run('tpm2_evictcontrol', ['-Q', '-C', 'o', '-c', akTransientContext, '-o', paths.context, akHandle]);
    const providerHandles = [...this.transientHandles()].filter((handle) => !handlesBefore.has(handle));
    if (providerHandles.length > 4) {
      throw errorWithName('TPM_CONTEXT_TRACKING_FAILED', 'could not isolate provider-owned transient handles');
    }
    for (const handle of providerHandles.reverse()) this.run('tpm2_flushcontext', ['-Q', handle]);
    return this.loadAk();
  }

  async loadAk(): Promise<RegisteredAttestationKey> {
    const paths = this.paths();
    const [publicKeyPem, qualifiedNameData] = await Promise.all([
      readFile(paths.publicKey, 'utf8'),
      readFile(paths.qualifiedName),
      access(paths.context, constants.R_OK),
    ]);
    if (!publicKeyPem.includes('BEGIN PUBLIC KEY')) throw errorWithName('TPM_AK_INVALID', 'AK public key is not PEM');
    const qualifiedName = normalizeTpm2bName(qualifiedNameData);
    if (!qualifiedName) throw errorWithName('TPM_AK_INVALID', 'AK qualified name is missing');
    this.registeredAk = {
      contextPath: paths.context,
      publicKeyPem,
      qualifiedName,
      keyId: tpm2KeyIdFromPublicKey(publicKeyPem),
    };
    return { ...this.registeredAk };
  }

  get attestationKey(): RegisteredAttestationKey {
    if (!this.registeredAk) throw errorWithName('TPM_AK_NOT_LOADED', 'AK must be explicitly provisioned or loaded');
    return { ...this.registeredAk };
  }

  async prove(options: { deviceId: string; nonce: string; pcrSelection: number[] }): Promise<AttestationBundle> {
    const ak = this.attestationKey;
    if (!(await LinuxTpm2ToolsProvider.isAvailable(this.config.tcti))) {
      throw errorWithName('TPM_UNAVAILABLE', 'TPM hardware or tpm2-tools is unavailable');
    }
    if (!options.deviceId.trim()) throw new TypeError('deviceId is required');
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
    const quoteSignaturePath = join(quoteDirectory, 'quote.sig');
    const bundlePath = join(quoteDirectory, 'bundle.canonical.json');
    const bundleSignaturePath = join(quoteDirectory, 'bundle.sig');
    const pcrPath = join(quoteDirectory, 'pcr.values');
    try {
      await writeFile(noncePath, nonce, { mode: 0o600, flag: 'wx' });
      this.run('tpm2_quote', [
        '-Q', '-c', ak.contextPath,
        '-l', `sha256:${selection.join(',')}`,
        '-q', noncePath,
        '-m', quotePath,
        '-s', quoteSignaturePath,
        '-f', 'plain',
        '-o', pcrPath,
        '-F', 'values',
        '-g', 'sha256',
      ]);
      const [quote, quoteSignature, pcrData] = await Promise.all([
        readFile(quotePath),
        readFile(quoteSignaturePath),
        readFile(pcrPath),
      ]);
      if (pcrData.length !== selection.length * 32) {
        throw errorWithName('TPM_PCR_OUTPUT_INVALID', 'tpm2_quote returned an unexpected PCR value length');
      }
      const pcrValues: Record<string, string> = {};
      const pcrKeys: string[] = [];
      for (let index = 0; index < selection.length; index += 1) {
        const key = `sha256:${selection[index]}`;
        pcrKeys.push(key);
        pcrValues[key] = pcrData.subarray(index * 32, (index + 1) * 32).toString('hex');
      }
      let eventLog: unknown = null;
      if (this.config.normalizedEventLogPath) {
        const parsed = JSON.parse(await readFile(resolve(this.config.normalizedEventLogPath), 'utf8')) as unknown;
        if (!Array.isArray(parsed)) throw errorWithName('TPM_EVENT_LOG_INVALID', 'normalized event log must be an array');
        eventLog = parsed;
      }
      const executor = createHash('sha256')
        .update(JSON.stringify(Object.fromEntries(Object.entries(pcrValues).sort())))
        .digest('hex');
      const issuedAt = this.now();
      const unsigned: AttestationBundleUnsigned = {
        version: 'eh-attestation-1',
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
          quoteSignature: quoteSignature.toString('base64url'),
          signatureAlgorithm: 'rsassa-sha256',
          hashAlgorithm: 'sha256',
          pcrValues,
          pcrSelection: pcrKeys,
          eventLog,
          akQualifiedName: ak.qualifiedName,
        },
      };
      await writeFile(bundlePath, canonicalBytes(unsigned), { mode: 0o600, flag: 'wx' });
      this.run('tpm2_sign', [
        '-Q', '-c', ak.contextPath,
        '-g', 'sha256',
        '-f', 'plain',
        '-o', bundleSignaturePath,
        bundlePath,
      ]);
      const bundleSignature = await readFile(bundleSignaturePath);
      return { ...unsigned, signature: bundleSignature.toString('base64url') };
    } finally {
      await rm(quoteDirectory, { recursive: true, force: true });
    }
  }
}
