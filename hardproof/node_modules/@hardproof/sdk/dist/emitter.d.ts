export type EventMap = Record<string, unknown>;
type Handler<T> = (payload: T) => void;
export declare class Emitter<TEvents extends EventMap> {
    private readonly handlers;
    on<K extends keyof TEvents>(event: K, handler: Handler<TEvents[K]>): this;
    off<K extends keyof TEvents>(event: K, handler: Handler<TEvents[K]>): this;
    protected emit<K extends keyof TEvents>(event: K, payload: TEvents[K]): void;
}
export {};
//# sourceMappingURL=emitter.d.ts.map