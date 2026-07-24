import type { HardproofBundle } from '@hardproof/core';
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
export declare class LinuxTpm2ToolsProvider implements TpmQuoteProvider {
    private readonly config;
    private readonly workDirectory;
    private readonly timeoutMs;
    private readonly ttlSeconds;
    private readonly now;
    private registeredAk?;
    constructor(config: LinuxTpm2ToolsConfig);
    static isAvailable(tcti?: string): Promise<boolean>;
    private run;
    private transientHandles;
    private persistentHandles;
    private persistentHandle;
    private paths;
    provisionAk(): Promise<RegisteredAttestationKey>;
    loadAk(): Promise<RegisteredAttestationKey>;
    get attestationKey(): RegisteredAttestationKey;
    prove(options: {
        deviceId: string;
        nonce: string;
        pcrSelection: number[];
    }): Promise<HardproofBundle>;
}
//# sourceMappingURL=linux.d.ts.map