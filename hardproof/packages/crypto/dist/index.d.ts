import { KeyObject } from 'node:crypto';
export type JsonValue = null | boolean | number | string | JsonValue[] | {
    [key: string]: JsonValue;
};
export declare function canonicalize(value: unknown): string;
export declare function canonicalBytes(value: unknown): Buffer;
export declare function sha256(data: string | Uint8Array): string;
export declare function base64urlEncode(data: string | Uint8Array): string;
export declare function base64urlDecode(data: string): Buffer;
export interface Ed25519KeyPair {
    privateKey: KeyObject;
    publicKey: KeyObject;
}
export declare function generateEd25519KeyPair(): Ed25519KeyPair;
export declare function ed25519KeyPairFromSeed(seed: string | Uint8Array): Ed25519KeyPair;
export declare function exportPublicKeyPem(key: KeyObject): string;
export declare function exportPrivateKeyPem(key: KeyObject): string;
export declare function importPublicKeyPem(pem: string): KeyObject;
export declare function importPrivateKeyPem(pem: string): KeyObject;
export declare function keyIdFromPublicKey(key: KeyObject | string): string;
export declare function signDetached(payload: Uint8Array, privateKey: KeyObject | string): string;
export declare function verifyDetached(payload: Uint8Array, signature: string, publicKey: KeyObject | string): boolean;
//# sourceMappingURL=index.d.ts.map