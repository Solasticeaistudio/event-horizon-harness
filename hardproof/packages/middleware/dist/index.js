import { decodeBundle } from '@hardproof/sdk';
export function hardproofMiddleware(options) {
    return async (request, response, next) => {
        const raw = request.headers['x-hardproof-bundle'];
        const encoded = Array.isArray(raw) ? raw[0] : raw;
        const nonce = options.nonceFrom?.(request) ?? request.body?.nonce;
        if (!encoded || !nonce)
            return response.status(401).json({ error: 'hardproof_bundle_and_nonce_required' });
        try {
            const result = await options.server.verify(decodeBundle(encoded), { nonce });
            if (!result.valid)
                return response.status(401).json({ error: result.failureCode, reason: result.failureReason });
            request.hardproof = result;
            return next();
        }
        catch (error) {
            return response.status(401).json({ error: 'hardproof_verification_failed', reason: error instanceof Error ? error.message : String(error) });
        }
    };
}
//# sourceMappingURL=index.js.map