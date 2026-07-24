import { decodeBundle, type Server, type VerificationSuccess } from '@hardproof/sdk';

export interface RequestLike {
  headers: Record<string, string | string[] | undefined>;
  body?: { nonce?: string };
  hardproof?: VerificationSuccess;
}
export interface ResponseLike {
  status(code: number): ResponseLike;
  json(body: unknown): unknown;
}
export type NextLike = () => void;

export function hardproofMiddleware(options: { server: Server; nonceFrom?: (request: RequestLike) => string | undefined }) {
  return async (request: RequestLike, response: ResponseLike, next: NextLike): Promise<unknown> => {
    const raw = request.headers['x-hardproof-bundle'];
    const encoded = Array.isArray(raw) ? raw[0] : raw;
    const nonce = options.nonceFrom?.(request) ?? request.body?.nonce;
    if (!encoded || !nonce) return response.status(401).json({ error: 'hardproof_bundle_and_nonce_required' });
    try {
      const result = await options.server.verify(decodeBundle(encoded), { nonce });
      if (!result.valid) return response.status(401).json({ error: result.failureCode, reason: result.failureReason });
      request.hardproof = result;
      return next();
    } catch (error) {
      return response.status(401).json({ error: 'hardproof_verification_failed', reason: error instanceof Error ? error.message : String(error) });
    }
  };
}
