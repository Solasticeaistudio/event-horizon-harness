export type AttestationErrorCode =
  | 'NO_PROVER_AVAILABLE'
  | 'PROVER_NOT_IMPLEMENTED'
  | 'VERIFIER_NOT_CONFIGURED'
  | 'SERVICE_API_ERROR'
  | 'REGISTRATION_FAILED'
  | 'DEVICE_ALREADY_REGISTERED'
  | 'INVALID_CONFIG'
  | 'NOT_IMPLEMENTED';

export class AttestationError extends Error {
  constructor(
    readonly code: AttestationErrorCode,
    message: string,
    readonly suggestion?: string,
    readonly docsUrl?: string,
    readonly context?: Record<string, unknown>,
  ) {
    super(message);
    this.name = 'AttestationError';
  }
}

export function toAttestationError(error: unknown): AttestationError {
  if (error instanceof AttestationError) return error;
  if (error instanceof Error && error.name === 'PROVER_NOT_IMPLEMENTED') {
    return new AttestationError('PROVER_NOT_IMPLEMENTED', error.message, 'Configure a concrete TPM quote provider.');
  }
  return new AttestationError('INVALID_CONFIG', error instanceof Error ? error.message : String(error));
}
