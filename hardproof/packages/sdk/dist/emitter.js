export class Emitter {
    handlers = new Map();
    on(event, handler) {
        const set = this.handlers.get(event) ?? new Set();
        set.add(handler);
        this.handlers.set(event, set);
        return this;
    }
    off(event, handler) {
        this.handlers.get(event)?.delete(handler);
        return this;
    }
    emit(event, payload) {
        for (const handler of this.handlers.get(event) ?? [])
            handler(payload);
    }
}
//# sourceMappingURL=emitter.js.map