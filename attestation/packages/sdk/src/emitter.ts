export type EventMap = Record<string, unknown>;
type Handler<T> = (payload: T) => void;

export class Emitter<TEvents extends EventMap> {
  private readonly handlers = new Map<keyof TEvents, Set<Handler<unknown>>>();

  on<K extends keyof TEvents>(event: K, handler: Handler<TEvents[K]>): this {
    const set = this.handlers.get(event) ?? new Set<Handler<unknown>>();
    set.add(handler as Handler<unknown>);
    this.handlers.set(event, set);
    return this;
  }

  off<K extends keyof TEvents>(event: K, handler: Handler<TEvents[K]>): this {
    this.handlers.get(event)?.delete(handler as Handler<unknown>);
    return this;
  }

  protected emit<K extends keyof TEvents>(event: K, payload: TEvents[K]): void {
    for (const handler of this.handlers.get(event) ?? []) handler(payload);
  }
}
