import {
  decodeBundle,
  type NonceContext,
  type Server,
  type VerificationSuccess,
} from '@event-horizon/attestation-sdk';

export interface RequestLike {
  headers: Record<string, string | string[] | undefined>;
  body?: { nonce?: string; nonceContext?: NonceContext };
  attestation?: VerificationSuccess;
}
export interface ResponseLike {
  status(code: number): ResponseLike;
  json(body: unknown): unknown;
}
export type NextLike = () => void;

export function attestationMiddleware(options: {
  server: Server;
  nonceFrom?: (request: RequestLike) => string | undefined;
  nonceContextFrom?: (request: RequestLike) => NonceContext | undefined;
}) {
  return async (request: RequestLike, response: ResponseLike, next: NextLike): Promise<unknown> => {
    const raw = request.headers['x-eh-attestation-bundle'];
    const encoded = Array.isArray(raw) ? raw[0] : raw;
    const nonce = options.nonceFrom?.(request) ?? request.body?.nonce;
    const context = options.nonceContextFrom?.(request) ?? request.body?.nonceContext;
    if (!encoded || !nonce || !context) {
      return response.status(401).json({ error: 'attestation_bundle_nonce_and_context_required' });
    }
    try {
      const result = await options.server.verify(decodeBundle(encoded), { nonce, context });
      if (!result.valid) return response.status(401).json({ error: result.failureCode, reason: result.failureReason });
      request.attestation = result;
      return next();
    } catch (error) {
      return response.status(401).json({ error: 'attestation_verification_failed', reason: error instanceof Error ? error.message : String(error) });
    }
  };
}
