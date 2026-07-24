import {
  constants,
  createHash,
  createPublicKey,
  createVerify,
} from 'node:crypto';

const TPM_GENERATED_VALUE = 0xff544347;
const TPM_ST_ATTEST_QUOTE = 0x8018;

const HASH_ALGORITHMS = new Map<number, { name: string; size: number }>([
  [0x0004, { name: 'sha1', size: 20 }],
  [0x000b, { name: 'sha256', size: 32 }],
  [0x000c, { name: 'sha384', size: 48 }],
  [0x000d, { name: 'sha512', size: 64 }],
]);

export interface TpmPcrSelection {
  algorithmId: number;
  algorithm: string;
  selectedPcrs: number[];
}

export interface ParsedTpmQuote {
  magic: number;
  type: number;
  qualifiedSigner: string;
  extraData: Buffer;
  clock: bigint;
  resetCount: number;
  restartCount: number;
  safe: boolean;
  firmwareVersion: bigint;
  pcrSelections: TpmPcrSelection[];
  pcrDigest: Buffer;
}

class Cursor {
  offset = 0;

  constructor(readonly data: Buffer) {}

  private take(size: number): Buffer {
    if (size < 0 || this.offset + size > this.data.length) throw new TypeError('truncated TPMS_ATTEST');
    const value = this.data.subarray(this.offset, this.offset + size);
    this.offset += size;
    return value;
  }

  u8(): number {
    return this.take(1)[0]!;
  }

  u16(): number {
    return this.take(2).readUInt16BE(0);
  }

  u32(): number {
    return this.take(4).readUInt32BE(0);
  }

  u64(): bigint {
    return this.take(8).readBigUInt64BE(0);
  }

  sized(maximum = 4096): Buffer {
    const size = this.u16();
    if (size > maximum) throw new TypeError('TPM2B field exceeds limit');
    return this.take(size);
  }

  bytes(size: number): Buffer {
    return this.take(size);
  }
}

function unwrapAttest(input: Buffer): Buffer {
  if (input.length >= 6 && input.readUInt16BE(0) === input.length - 2 && input.readUInt32BE(2) === TPM_GENERATED_VALUE) {
    return input.subarray(2);
  }
  return input;
}

export function parseTpmsAttest(input: Uint8Array): ParsedTpmQuote {
  const data = unwrapAttest(Buffer.from(input));
  if (data.length < 32 || data.length > 16_384) throw new TypeError('TPMS_ATTEST size is invalid');
  const cursor = new Cursor(data);
  const magic = cursor.u32();
  const type = cursor.u16();
  if (magic !== TPM_GENERATED_VALUE) throw new TypeError('TPMS_ATTEST magic is invalid');
  if (type !== TPM_ST_ATTEST_QUOTE) throw new TypeError('attestation is not a TPM quote');
  const qualifiedSigner = cursor.sized(128).toString('hex');
  const extraData = cursor.sized(1024);
  const clock = cursor.u64();
  const resetCount = cursor.u32();
  const restartCount = cursor.u32();
  const safeValue = cursor.u8();
  if (safeValue !== 0 && safeValue !== 1) throw new TypeError('TPM clock safe flag is invalid');
  const firmwareVersion = cursor.u64();
  const selectionCount = cursor.u32();
  if (selectionCount < 1 || selectionCount > 8) throw new TypeError('TPM PCR selection count is invalid');
  const pcrSelections: TpmPcrSelection[] = [];
  for (let index = 0; index < selectionCount; index += 1) {
    const algorithmId = cursor.u16();
    const algorithm = HASH_ALGORITHMS.get(algorithmId);
    if (!algorithm) throw new TypeError(`unsupported TPM PCR bank: ${algorithmId}`);
    const sizeOfSelect = cursor.u8();
    if (sizeOfSelect < 1 || sizeOfSelect > 4) throw new TypeError('TPM PCR selection width is invalid');
    const bitmap = cursor.bytes(sizeOfSelect);
    const selectedPcrs: number[] = [];
    for (let byteIndex = 0; byteIndex < bitmap.length; byteIndex += 1) {
      for (let bit = 0; bit < 8; bit += 1) {
        if ((bitmap[byteIndex]! & (1 << bit)) !== 0) selectedPcrs.push(byteIndex * 8 + bit);
      }
    }
    if (!selectedPcrs.length) throw new TypeError('TPM quote selected no PCRs');
    pcrSelections.push({ algorithmId, algorithm: algorithm.name, selectedPcrs });
  }
  const pcrDigest = cursor.sized(128);
  if (cursor.offset !== data.length) throw new TypeError('TPMS_ATTEST has trailing bytes');
  return {
    magic,
    type,
    qualifiedSigner,
    extraData,
    clock,
    resetCount,
    restartCount,
    safe: safeValue === 1,
    firmwareVersion,
    pcrSelections,
    pcrDigest,
  };
}

export type TpmQuoteFailureCode =
  | 'TPM_QUOTE_MALFORMED'
  | 'TPM_NONCE_MISMATCH'
  | 'TPM_AK_MISMATCH'
  | 'TPM_QUOTE_SIGNATURE'
  | 'TPM_PCR_SELECTION'
  | 'TPM_PCR_DIGEST'
  | 'TPM_EVENT_LOG';

export interface TpmQuoteSuccess {
  valid: true;
  measurements: Record<string, string>;
  parsed: ParsedTpmQuote;
}

export interface TpmQuoteFailure {
  valid: false;
  code: TpmQuoteFailureCode;
  reason: string;
}

export type TpmQuoteResult = TpmQuoteSuccess | TpmQuoteFailure;

function quoteFailure(code: TpmQuoteFailureCode, reason: string): TpmQuoteFailure {
  return { valid: false, code, reason };
}

function strictBase64url(value: unknown, name: string): Buffer {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new TypeError(`${name} is not base64url`);
  const decoded = Buffer.from(value, 'base64url');
  if (!decoded.length || decoded.toString('base64url') !== value) throw new TypeError(`${name} is not canonical base64url`);
  return decoded;
}

function expectedPcrKeys(parsed: ParsedTpmQuote): string[] {
  return parsed.pcrSelections.flatMap((selection) =>
    selection.selectedPcrs.map((pcr) => `${selection.algorithm}:${pcr}`),
  );
}

function reconstructPcrDigest(
  parsed: ParsedTpmQuote,
  pcrValues: Record<string, unknown>,
  hashAlgorithm: string,
): { digest: Buffer; values: Record<string, string>; keys: string[] } {
  const keys = expectedPcrKeys(parsed);
  if (JSON.stringify(Object.keys(pcrValues).sort()) !== JSON.stringify([...keys].sort())) {
    throw new TypeError('PCR values do not map exactly to the signed selection');
  }
  const values: Record<string, string> = {};
  const chunks: Buffer[] = [];
  for (const selection of parsed.pcrSelections) {
    const bank = HASH_ALGORITHMS.get(selection.algorithmId)!;
    for (const pcr of selection.selectedPcrs) {
      const key = `${selection.algorithm}:${pcr}`;
      const value = pcrValues[key];
      if (typeof value !== 'string' || !/^[0-9a-f]+$/.test(value) || value.length !== bank.size * 2) {
        throw new TypeError(`PCR value is invalid: ${key}`);
      }
      values[key] = value;
      chunks.push(Buffer.from(value, 'hex'));
    }
  }
  return { digest: createHash(hashAlgorithm).update(Buffer.concat(chunks)).digest(), values, keys };
}

function validateEventLog(
  eventLog: unknown,
  values: Record<string, string>,
  requireEventLog: boolean,
): boolean {
  if (eventLog === null) return !requireEventLog;
  if (!Array.isArray(eventLog) || !eventLog.length) return false;
  const state = new Map<string, Buffer>();
  for (const key of Object.keys(values)) {
    const bankName = key.split(':')[0]!;
    const bank = [...HASH_ALGORITHMS.values()].find((item) => item.name === bankName)!;
    state.set(key, Buffer.alloc(bank.size));
  }
  for (const item of eventLog) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) return false;
    const entry = item as Record<string, unknown>;
    if (JSON.stringify(Object.keys(entry).sort()) !== JSON.stringify(['bank', 'digest', 'pcr'])) return false;
    if (typeof entry.bank !== 'string' || !Number.isInteger(entry.pcr) || typeof entry.digest !== 'string') return false;
    const key = `${entry.bank}:${entry.pcr}`;
    const current = state.get(key);
    if (!current) continue;
    const bank = [...HASH_ALGORITHMS.values()].find((item) => item.name === entry.bank);
    if (!bank || !/^[0-9a-f]+$/.test(entry.digest) || entry.digest.length !== bank.size * 2) return false;
    state.set(key, createHash(entry.bank).update(Buffer.concat([current, Buffer.from(entry.digest, 'hex')])).digest());
  }
  return [...state.entries()].every(([key, value]) => value.toString('hex') === values[key]);
}

export function tpm2KeyIdFromPublicKey(publicKeyPem: string): string {
  const publicKey = createPublicKey(publicKeyPem);
  const der = publicKey.export({ format: 'der', type: 'spki' });
  return `tpm2:${createHash('sha256').update(der).digest('hex').slice(0, 32)}`;
}

export function verifyTpmQuote(
  evidence: Record<string, unknown>,
  signatureValue: unknown,
  options: {
    nonce: string;
    publicKeyPem: string;
    expectedQualifiedSigner?: string;
    expectedPcrSelection?: string[];
    requireEventLog?: boolean;
  },
): TpmQuoteResult {
  try {
    const fields = [
      'akQualifiedName', 'eventLog', 'hashAlgorithm', 'pcrSelection',
      'pcrValues', 'provider', 'quote', 'signatureAlgorithm',
    ];
    if (JSON.stringify(Object.keys(evidence).sort()) !== JSON.stringify(fields)) {
      return quoteFailure('TPM_QUOTE_MALFORMED', 'TPM evidence fields are invalid');
    }
    if (evidence.provider !== 'linux-tpm2-tools' && evidence.provider !== 'tpm2-fixture') {
      return quoteFailure('TPM_QUOTE_MALFORMED', 'TPM evidence provider is invalid');
    }
    if (evidence.hashAlgorithm !== 'sha256' || evidence.signatureAlgorithm !== 'rsassa-sha256') {
      return quoteFailure('TPM_QUOTE_MALFORMED', 'unsupported TPM quote signature parameters');
    }
    const quote = strictBase64url(evidence.quote, 'quote');
    const signature = strictBase64url(signatureValue, 'quote signature');
    const parsed = parseTpmsAttest(quote);
    const nonce = strictBase64url(options.nonce, 'nonce');
    if (!parsed.extraData.equals(nonce)) return quoteFailure('TPM_NONCE_MISMATCH', 'quote nonce does not match challenge');
    if (!parsed.safe) return quoteFailure('TPM_QUOTE_MALFORMED', 'TPM clock was not safe when quoted');
    if (typeof evidence.akQualifiedName !== 'string' || evidence.akQualifiedName !== parsed.qualifiedSigner) {
      return quoteFailure('TPM_AK_MISMATCH', 'quote signer name does not match evidence');
    }
    if (options.expectedQualifiedSigner && parsed.qualifiedSigner !== options.expectedQualifiedSigner) {
      return quoteFailure('TPM_AK_MISMATCH', 'quote signer is not the registered AK');
    }
    if (!evidence.pcrValues || typeof evidence.pcrValues !== 'object' || Array.isArray(evidence.pcrValues)) {
      return quoteFailure('TPM_PCR_DIGEST', 'PCR values are malformed');
    }
    const reconstructed = reconstructPcrDigest(
      parsed,
      evidence.pcrValues as Record<string, unknown>,
      evidence.hashAlgorithm,
    );
    if (!Array.isArray(evidence.pcrSelection) || JSON.stringify(evidence.pcrSelection) !== JSON.stringify(reconstructed.keys)) {
      return quoteFailure('TPM_PCR_SELECTION', 'declared PCR selection differs from signed quote');
    }
    if (options.expectedPcrSelection && JSON.stringify(options.expectedPcrSelection) !== JSON.stringify(reconstructed.keys)) {
      return quoteFailure('TPM_PCR_SELECTION', 'signed PCR selection differs from verifier policy');
    }
    if (!reconstructed.digest.equals(parsed.pcrDigest)) {
      return quoteFailure('TPM_PCR_DIGEST', 'PCR composite digest does not match quote');
    }
    if (!validateEventLog(evidence.eventLog, reconstructed.values, options.requireEventLog ?? false)) {
      return quoteFailure('TPM_EVENT_LOG', 'event log does not reconstruct quoted PCR values');
    }
    const publicKey = createPublicKey(options.publicKeyPem);
    if (publicKey.asymmetricKeyType !== 'rsa') return quoteFailure('TPM_AK_MISMATCH', 'registered AK is not RSA');
    const verifier = createVerify('sha256');
    verifier.update(quote);
    verifier.end();
    const signatureValid = verifier.verify(
      { key: publicKey, padding: constants.RSA_PKCS1_PADDING },
      signature,
    );
    if (!signatureValid) return quoteFailure('TPM_QUOTE_SIGNATURE', 'TPM quote signature is invalid');
    const executor = createHash('sha256')
      .update(JSON.stringify(Object.fromEntries(Object.entries(reconstructed.values).sort())))
      .digest('hex');
    return { valid: true, parsed, measurements: { ...reconstructed.values, executor } };
  } catch (error) {
    return quoteFailure('TPM_QUOTE_MALFORMED', error instanceof Error ? error.message : 'malformed TPM quote');
  }
}
