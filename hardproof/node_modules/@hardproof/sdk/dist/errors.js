export class HardproofError extends Error {
    code;
    suggestion;
    docsUrl;
    context;
    constructor(code, message, suggestion, docsUrl, context) {
        super(message);
        this.code = code;
        this.suggestion = suggestion;
        this.docsUrl = docsUrl;
        this.context = context;
        this.name = 'HardproofError';
    }
}
export function toHardproofError(error) {
    if (error instanceof HardproofError)
        return error;
    if (error instanceof Error && error.name === 'PROVER_NOT_IMPLEMENTED') {
        return new HardproofError('PROVER_NOT_IMPLEMENTED', error.message, 'Configure a concrete TPM quote provider.');
    }
    return new HardproofError('INVALID_CONFIG', error instanceof Error ? error.message : String(error));
}
//# sourceMappingURL=errors.js.map