export type HardproofErrorCode =
  | 'NO_PROVER_AVAILABLE'
  | 'PROVER_NOT_IMPLEMENTED'
  | 'VERIFIER_NOT_CONFIGURED'
  | 'CLOUD_API_ERROR'
  | 'REGISTRATION_FAILED'
  | 'DEVICE_ALREADY_REGISTERED'
  | 'INVALID_CONFIG'
  | 'NOT_IMPLEMENTED';

export class HardproofError extends Error {
  constructor(
    readonly code: HardproofErrorCode,
    message: string,
    readonly suggestion?: string,
    readonly docsUrl?: string,
    readonly context?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'HardproofError';
  }
}

export function toHardproofError(error: unknown): HardproofError {
  if (error instanceof HardproofError) return error;
  if (error instanceof Error && error.name === 'PROVER_NOT_IMPLEMENTED') {
    return new HardproofError('PROVER_NOT_IMPLEMENTED', error.message, 'Configure a concrete TPM quote provider.');
  }
  return new HardproofError('INVALID_CONFIG', error instanceof Error ? error.message : String(error));
}
