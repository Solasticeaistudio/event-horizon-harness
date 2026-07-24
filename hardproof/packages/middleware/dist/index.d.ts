import { type Server, type VerificationSuccess } from '@hardproof/sdk';
export interface RequestLike {
    headers: Record<string, string | string[] | undefined>;
    body?: {
        nonce?: string;
    };
    hardproof?: VerificationSuccess;
}
export interface ResponseLike {
    status(code: number): ResponseLike;
    json(body: unknown): unknown;
}
export type NextLike = () => void;
export declare function hardproofMiddleware(options: {
    server: Server;
    nonceFrom?: (request: RequestLike) => string | undefined;
}): (request: RequestLike, response: ResponseLike, next: NextLike) => Promise<unknown>;
//# sourceMappingURL=index.d.ts.map