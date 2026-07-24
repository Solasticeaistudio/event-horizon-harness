# attestation — SDK Design

> `@event-horizon/attestation-sdk` is the primary developer-facing package.
> Goal: zero to verified proof in under 5 minutes.
> Every design decision prioritizes developer experience.

**Status:** Phase 5 in progress on branch `feat/phase-5-sdk`. The API shape
below is **locked**; Cloud-backed methods (`register`, session start, cloud
verify) are stubbed until Phase 7 Cloud routes ship. Local prove/verify with
simulator works today.

---

## Design principles

**Two objects, few methods.** Device agents use `Client`. Backends use
`Server`. Most integrations never import anything else from `@event-horizon/attestation-sdk`.

**Zero config for the happy path.** Reads `EH_ATTESTATION_API_KEY` from env.
Auto-detects platform. Fetches nonces from Cloud when an API key is present.
No required configuration to get started.

**TypeScript-first.** Every result is fully typed. Discriminated unions so
TypeScript narrows correctly after `verify()`. No `any`. No casting.

**Errors that actually help.** `AttestationError` with `code`, `message`,
`suggestion`, `docsUrl`, and optional `context` — not bare `Error: failed`.

**Event-driven observability.** Subscribe with `.on(event, handler)` on the
object that owns the action. Sub-object events bubble to the parent so you can
listen in one place for audit logging and metrics.

**Layered for power users.** Simple API for 80% of use cases. Drop to
`@event-horizon/attestation-core` or `@attestation/prover-*` when you need full control.

**Environment-aware.** In `NODE_ENV=test`, `Client` auto-selects simulator.
In production, requires real hardware (configurable).

**Device identity is yours.** The SDK returns a `deviceId` from
`client.device.register()`. Where you store it — env var, filesystem, database,
secrets manager — is entirely your application's decision. attestation does not
read or write device identity to disk.

**Resource-oriented namespaces.** Public API and internal Cloud client use
nested objects by domain (`client.device`, `client.session`, `cloud.device`).
Familiar if you're coming from .NET service/client patterns — explicit over magic.

---

## The three-level model

```
@event-horizon/attestation-sdk              HIGH LEVEL — start here
  Client                    Device / agent: prove, register, sessions
  Server                    Backend: verify, sessions, nonces (local mode)
        ↑
@event-horizon/attestation-core             MID LEVEL
  Verifier                  Self-hosted verification, PCR policy
  makeCredential()          Server-side registration crypto
        ↑
@attestation/prover-*         LOW LEVEL
  TpmProver                 Raw TPM access — custom integrations only
```

Most developers use `@event-horizon/attestation-sdk` only. Security teams and self-hosted
deployments use `@event-horizon/attestation-core` directly. Platform engineers use prover
packages when building on top of attestation.

---

## Public API overview

### Device side — `Client`

| Method / property | Purpose |
|---|---|
| `Client.create(config?)` | Factory. Async — may detect hardware on first use. |
| `client.device.register({ token, label? })` | One-time registration ceremony. |
| `client.prove({ nonce?, deviceId? })` | Generate a proof bundle. |
| `client.session.start({ ttlMinutes? })` | Attest once, establish JWT session. |
| `client.session.token()` | Current session JWT (auto-refresh). |
| `client.session.stop()` | Clear local session state. |
| `client.on(event, handler)` | Subscribe to client + bubbled device/session events. |
| `client.method` | Active prover: `'tpm2' \| 'simulator' \| ...` |

### Server side — `Server`

| Method / property | Purpose |
|---|---|
| `Server.create(config?)` | Factory. Sync — ready immediately. |
| `server.verify(bundle, { nonce, deviceId? })` | Verify a proof bundle. |
| `server.session.verify({ authorizationHeader? })` | Verify session JWT locally. |
| `server.nonce.issue()` | Issue nonce (local / self-hosted mode only). |
| `server.on(event, handler)` | Subscribe to server + bubbled sub-object events. |
| `server.resolvedMode` | `'cloud' \| 'local'` |

### Helpers

| Export | Purpose |
|---|---|
| `encodeBundle(bundle)` | Base64url JSON for `X-Attestation-Bundle` header. |
| `decodeBundle(encoded)` | Parse header back to `AttestationBundle`. |
| `AttestationError` | Typed SDK error with actionable fields. |

---

## Installation

```bash
# Device-side (generates proofs)
sfw pnpm add @event-horizon/attestation-sdk @event-horizon/attestation-tpm   # Linux/Windows TPM

# Server-side (verifies proofs)
sfw pnpm add @event-horizon/attestation-sdk

# Dev/CI (no hardware)
sfw pnpm add @event-horizon/attestation-sdk @event-horizon/attestation-simulator
```

---

## Quick start — device side

### Dev / CI (no registration, no persistence)

The fastest path — simulator, explicit `deviceId`, no Cloud registration:

```typescript
import { Client, encodeBundle } from '@event-horizon/attestation-sdk';

const client = await Client.create({
  deviceId: 'dev_test_agent', // your choice — any stable string for dev
});

const proof = await client.prove({
  nonce: 'abc123nonce45678901234567890123456789012', // from your test server
});

fetch('https://your-api.com/endpoint', {
  headers: { 'X-Attestation-Bundle': encodeBundle(proof) },
});
```

### Production (register once, you store `deviceId`)

Registration is one-time per device. **Your app** loads and saves `deviceId` —
the SDK never persists it.

```typescript
import { Client, encodeBundle } from '@event-horizon/attestation-sdk';

// Your storage layer — env, file, DB, Vault, K8s secret, etc.
async function loadDeviceId(): Promise<string | null> {
  return process.env.MY_APP_DEVICE_ID ?? null; // example only
}
async function saveDeviceId(id: string): Promise<void> {
  // write to wherever your app stores config
  await myConfigStore.set('deviceId', id);
}

let deviceId = await loadDeviceId();

const client = await Client.create({
  apiKey: process.env.EH_ATTESTATION_API_KEY,
  deviceId: deviceId ?? undefined,
});

if (!deviceId) {
  const { deviceId: newId } = await client.device.register({
    token: process.env.EH_ATTESTATION_REGISTRATION_TOKEN!,
    label: 'production-agent-01',
  });
  await saveDeviceId(newId);
  deviceId = newId;
  // Same client instance — no re-creation needed. Pass deviceId to prove().
}

client.on('prove.completed', ({ deviceId }) => {
  metrics.increment('attestation.prove.success', { deviceId });
});

// With apiKey set, nonce is fetched from Cloud automatically
const proof = await client.prove({ deviceId });

fetch('https://your-api.com/endpoint', {
  headers: { 'X-Attestation-Bundle': encodeBundle(proof) },
});
```

The `device.registered` event is for observability (metrics, audit logs) — not
a substitute for saving `deviceId` yourself.

---

## Quick start — server side

```typescript
import { Client, Server, decodeBundle } from '@event-horizon/attestation-sdk';

const server = Server.create({
  apiKey: process.env.EH_ATTESTATION_API_KEY, // Cloud mode (default when key present)
});

server.on('device.verified', ({ deviceId, trustLevel }) => {
  auditLog.write({ event: 'device.verified', deviceId, trustLevel });
});

// In your request handler
app.post('/api/action', async (req, res) => {
  const bundle = decodeBundle(req.headers['x-attestation-bundle'] as string);
  const result = await server.verify(bundle, { nonce: req.body.nonce });

  if (!result.valid) {
    return res.status(401).json({ reason: result.failureReason });
  }

  // deviceId, trustLevel available on success
  return res.json({ ok: true, device: result.deviceId });
});
```

---

## Attestation sessions (recommended for production traffic)

A TPM quote takes 200–500 ms and TPMs serialize operations — attesting on
every request is impractical. Sessions fix this: attest once, get a short-lived
JWT, verify it locally on every subsequent request.

### Device

```typescript
const client = await Client.create({ apiKey, deviceId });

// Listen locally on session, or globally on client (bubbling)
client.session.on('started', ({ token, expiresAt }) => {
  cache.set('session', token, expiresAt);
});
client.on('session.started', ({ token }) => {
  // same event — bubbled from client.session
});

await client.session.start({ ttlMinutes: 10 });

fetch('https://your-api.com/endpoint', {
  headers: {
    Authorization: `Bearer ${await client.session.token()}`,
  },
});
```

### Server

```typescript
const server = Server.create({ apiKey });

server.on('session.verified', ({ claims }) => {
  auditLog.write({ deviceId: claims.deviceId, trust: claims.trustLevel });
});

const claims = await server.session.verify({
  authorizationHeader: req.headers.authorization,
});

if (!claims || claims.trustLevel !== 'hardware') {
  return res.status(401).json({ error: 'invalid session' });
}
```

Local JWT verification never touches attestation Cloud and is unmetered. Only
session establishment counts as an attestation. Use sessions for normal API
traffic; use one-shot `server.verify()` for high-stakes single actions.

---

## Event model

Events subscribe on the **same object** as the method that emits them.
Sub-object events **bubble** to the parent with a `{namespace}.{event}` prefix.

### Client events

Subscribe on `client`:

| Event | When |
|---|---|
| `prover.ready` | Hardware/simulator prover detected |
| `prover.unavailable` | Detection failed |
| `prove.started` | Before `prove()` |
| `prove.completed` | After successful `prove()` |
| `prove.failed` | `prove()` threw |
| `device.registered` | Bubbled from `client.device.register()` |
| `device.register.failed` | Bubbled from `client.device` |
| `session.started` | Bubbled from `client.session` |
| `session.refreshed` | Bubbled from `client.session` |
| `session.expired` | Bubbled from `client.session` |
| `session.stopped` | Bubbled from `client.session` |

Subscribe on `client.device`:

| Event | When |
|---|---|
| `registered` | Registration ceremony completed |
| `register.failed` | Registration threw |

Subscribe on `client.session` (shorter names, same payloads):

| Event | When |
|---|---|
| `started` | Session established |
| `refreshed` | JWT refreshed before expiry |
| `expired` | Session expired |
| `stopped` | `client.session.stop()` called |

### Server events

Subscribe on `server`:

| Event | When |
|---|---|
| `verify.started` | Before `verify()` |
| `verify.success` | Bundle valid |
| `verify.failed` | Bundle invalid |
| `device.verified` | Successful verify — audit hook |
| `session.verified` | Bubbled from `server.session` |
| `session.rejected` | Bubbled from `server.session` |
| `nonce.issued` | Bubbled from `server.nonce` |

Subscribe on `server.session`:

| Event | When |
|---|---|
| `verified` | JWT valid |
| `rejected` | JWT invalid or expired |

Subscribe on `server.nonce` (local mode):

| Event | When |
|---|---|
| `issued` | Nonce generated via `server.nonce.issue()` |

### Bubbling example

```typescript
// Both handlers fire for the same session start
client.session.on('started', handlerA);
client.on('session.started', handlerB);

await client.session.start();
// handlerA and handlerB both called with { token, expiresAt }
```

Use nested subscription when handlers are session-specific. Use parent
subscription (`client.on('session.*')`) for cross-cutting audit logs and
debug tooling.

---

## Device identity storage

attestation assigns a `deviceId` during registration. **The SDK does not store
it.** That is intentional — storage belongs to the application:

| Approach | Example |
|---|---|
| Environment variable | Read in your bootstrap, pass to `Client.create({ deviceId })` |
| Config file | Load on startup, write after `device.register()` |
| Secrets manager | Vault, AWS Secrets Manager, Doppler |
| Database | Fleet management table keyed by host/agent |
| Container orchestration | K8s Secret injected as env at deploy time |

**What the SDK provides:**
- `register()` → `{ deviceId }` via **`client.device.register()`**
- `device.registered` event (for metrics/audit)
- `Client.create({ deviceId })` and `prove({ deviceId })` accept the value
  you supply

**What the SDK does not provide:**
- No default state file path
- No `persist` / `persistPath` config
- No automatic read of `EH_ATTESTATION_DEVICE_ID` or similar env vars

If you use the **CLI** (`attestation device init`, Phase 8), the CLI may manage
its own state file for CLI workflows. That is separate from the SDK — SDK
consumers wire `deviceId` explicitly unless they choose to read from a path
the CLI wrote.

---

## `Client` reference

### `Client.create(config?)`

```typescript
interface ClientConfig {
  apiKey?: string;        // default: EH_ATTESTATION_API_KEY
  cloudUrl?: string;      // default: EH_ATTESTATION_CLOUD_URL or https://api.attestation.app
  deviceId?: string;      // required for prove() — you supply from your storage
  debug?: boolean;        // or DEBUG=attestation:*
  eager?: boolean;        // detect hardware at create() instead of first prove()
  method?: ProofMethod;   // force 'tpm2' | 'simulator' | ...
  simulatorSeed?: string; // deterministic simulator output
  pcrSelection?: number[];// TPM only, default [0, 7]
}
```

Returns `Promise<Client>`.

### `client.device`

```typescript
client.device.register({ token: string; label?: string }): Promise<{ deviceId: string }>
client.device.on(event, handler): this
client.device.off(event, handler): this
```

One-time per device. Runs the full ceremony (Cloud `device.register` +
internal activate). Returns `{ deviceId }` — **your app must store it.** You do
**not** need to re-create `Client` after registration; pass the returned
`deviceId` to `prove({ deviceId })` (or set it in `Client.create()` on the next
process start after loading from your storage). Emits `registered` locally and
`device.registered` on `Client` (bubbled). Does **not** expose `activate()`
publicly — that step is internal.

### `client.prove(options?)`

```typescript
interface ProveOptions {
  nonce?: string;    // required if no apiKey; fetched from Cloud if apiKey set
  deviceId?: string; // default: config.deviceId
}
```

Returns `AttestationBundle`. Emits `prove.started`, `prove.completed`, or
`prove.failed`.

Prover detection is lazy (first `prove()` or `eager: true` at create).
See [Auto-detection](#auto-detection) below.

### `client.session`

```typescript
client.session.start({ ttlMinutes?: number }): Promise<void>
client.session.token(): Promise<string>
client.session.stop(): void
client.session.on(event, handler): this
client.session.off(event, handler): this
```

---

## `Server` reference

### `Server.create(config?)`

```typescript
interface ServerConfig {
  apiKey?: string;           // default: EH_ATTESTATION_API_KEY
  cloudUrl?: string;
  mode?: 'cloud' | 'local';  // inferred: apiKey → cloud, else local
  config?: VerifierConfig;   // passed to @event-horizon/attestation-core in local mode
  debug?: boolean;
}
```

Mode resolution:
- `mode: 'local'` → uses `@event-horizon/attestation-core` `Verifier` locally
- `mode: 'cloud'` or `apiKey` present → delegates to attestation Cloud API
- Neither apiKey nor `mode: 'local'` → throws `VERIFIER_NOT_CONFIGURED`

### `server.verify(bundle, options)`

```typescript
interface VerifyOptions {
  nonce: string;
  deviceId?: string;
}

// Returns VerificationResult (discriminated union on valid)
```

Cloud mode: `POST /v1/verify`. Local mode: `@event-horizon/attestation-core` directly.
Emits `verify.started`, `verify.success` or `verify.failed`, and
`device.verified` on success.

### `server.session`

```typescript
server.session.verify({ authorizationHeader?: string }): Promise<SessionClaims | null>
server.session.on(event, handler): this
```

Verifies JWT against Cloud JWKS (`GET /v1/.well-known/jwks.json`). Cached.
No Cloud round trip per request.

### `server.nonce` (local mode)

```typescript
server.nonce.issue(): Promise<string>
server.nonce.on('issued', handler): this
```

Self-hosted nonce issuance for teams running without attestation Cloud. Cloud
customers use `GET /v1/nonce` via `Client.prove()` automatically.

---

## Auto-detection

`Client` selects the best available prover internally. Developers never call
`createProver()` — that is an implementation detail.

Detection order:

1. Explicit `config.method`
2. `NODE_ENV=test` → simulator (unless `EH_ATTESTATION_FORCE_HARDWARE=1`)
3. `EH_ATTESTATION_ALLOW_SIMULATOR=1` → simulator
4. TPM 2.0 on linux/win32 (`TpmProver.isAvailable()`)
5. Secure Enclave on darwin (Phase 5+ — not yet implemented)
6. Android Keystore (Phase 6+ — not yet implemented)
7. Throw `AttestationError('NO_PROVER_AVAILABLE')` with troubleshooting link

With `debug: true`:

```
[attestation] Checking TPM availability...
[attestation] TPM 2.0 detected (Infineon, firmware 7.85.4.1, physical)
[attestation] Using prover: tpm2
[attestation] Ready
```

---

## Error design

All SDK failures throw `AttestationError`:

```typescript
class AttestationError extends Error {
  readonly code: AttestationErrorCode;
  readonly suggestion?: string;
  readonly docsUrl?: string;
  readonly context?: Record<string, unknown>;
}
```

| Code | When |
|---|---|
| `NO_PROVER_AVAILABLE` | No hardware in production |
| `PROVER_NOT_IMPLEMENTED` | Platform prover not shipped yet |
| `VERIFIER_NOT_CONFIGURED` | No apiKey and no local mode |
| `CLOUD_API_ERROR` | Cloud HTTP failure |
| `REGISTRATION_FAILED` | Registration ceremony failed |
| `DEVICE_ALREADY_REGISTERED` | Duplicate registration attempt |
| `INVALID_CONFIG` | Missing deviceId, nonce, etc. |
| `NOT_IMPLEMENTED` | Method stubbed pending Cloud routes |

```typescript
try {
  await client.prove();
} catch (err) {
  if (err instanceof AttestationError) {
    console.error(err.code);       // 'NO_PROVER_AVAILABLE'
    console.error(err.message);
    console.error(err.suggestion); // what to do next
    console.error(err.docsUrl);
  }
}
```

---

## Self-hosted verification (no Cloud account)

```typescript
import { Client, Server } from '@event-horizon/attestation-sdk';

// Device: same Client API — prover auto-detection unchanged
const client = await Client.create({ deviceId: 'dev_agent_01' });
const nonce = await server.nonce.issue(); // your server issues nonces
const proof = await client.prove({ nonce });

// Server: local mode — uses @event-horizon/attestation-core directly
const server = Server.create({
  mode: 'local',
  config: {
    minTrustLevel: 'hardware',
    maxProofAgeSeconds: 30,
    pcrPolicy: {
      0: { type: 'exact', value: '<known-good-pcr0>' },
      7: { type: 'exact', value: '<known-good-pcr7>' },
    },
  },
});

const result = await server.verify(proof, { nonce });
```

Self-hosted requires you to operate: nonce store, device registry,
registration tokens, credential activation endpoint, CA root updates.
See `SELF_HOSTING.md`. Most teams prefer attestation Cloud.

---

## Environment variables

Only variables the **SDK reads automatically** are listed here. If you store
`deviceId` in an env var, read it in **your** bootstrap code and pass it to
`Client.create({ deviceId })` — the SDK will not read it for you.

| Variable | Effect |
|---|---|
| `EH_ATTESTATION_API_KEY` | Default apiKey for Client and Server |
| `EH_ATTESTATION_CLOUD_URL` | Override Cloud URL (default: `https://api.attestation.app`) |
| `EH_ATTESTATION_ALLOW_SIMULATOR` | Allow simulator outside test env |
| `EH_ATTESTATION_FORCE_HARDWARE` | Force hardware even in test env |
| `NODE_ENV=test` | Client auto-selects simulator |
| `DEBUG=attestation:*` | Enable debug logging |

---

## CloudClient (internal)

Not exported in v1. Typed HTTP client used by `Client` and `Server` in cloud mode.
Uses the **same resource namespaces** as the public API:

```typescript
class CloudClient {
  readonly device: CloudDevice;   // POST /v1/devices/register, /activate
  readonly session: CloudSession; // POST /v1/sessions, GET jwks
  readonly nonce: CloudNonce;     // GET /v1/nonce
  readonly verify: CloudVerify;   // POST /v1/verify
}

cloud.device.register(body)
cloud.device.activate(body)   // called internally by Client.device.register()
cloud.nonce.issue()
cloud.session.create(body)
cloud.session.jwks()
cloud.verify.bundle(body)
```

`Client.device.register()` orchestrates the full ceremony and calls
`cloud.device.register` + activate internally. Developers never call
`CloudClient` directly.

---

## Package exports

```typescript
// @event-horizon/attestation-sdk — primary entry
export { Client, Server };
export { encodeBundle, decodeBundle };
export { AttestationError, toAttestationError };

// Types
export type {
  ClientConfig,
  ClientEventMap,
  ClientDeviceEventMap,
  ClientSessionEventMap,
  ServerConfig,
  ServerEventMap,
  ServerSessionEventMap,
  ServerMode,
  SessionClaims,
  AttestationBundle,
  VerificationResult,
  VerifierConfig,
  ProofMethod,
  TrustLevel,
  AssuranceLevel,
};

// Advanced / internal — not in quick-start docs
export { Emitter } from './events/emitter.js';
export { ClientSession, ClientDevice, ServerSession, ServerNonce } from '...';
```

**Not exported in v1 public API** (use `@event-horizon/attestation-core` or `@attestation/prover-*`
directly):
- `createProver`, `createVerifier`, `ProverClient`, `VerifierClient` — replaced
  by `Client` / `Server`
- `CloudClient` — internal; may export under `@event-horizon/attestation-sdk/cloud` later
- `provision()` — deferred until Cloud `POST /v1/provision` ships
- `@event-horizon/attestation-sdk/react` — deferred; no browser prover in v1

---

## Implementation phases (Phase 5)

| Slice | Status | Delivers |
|---|---|---|
| 1 | Done | `AttestationError`, typed `Emitter` with bubbling, `encodeBundle` |
| 2 | Done | `Client.create()`, auto-detect, `client.prove()` (simulator) |
| 3 | Done | `Server.create()`, `server.verify()` local mode, events |
| 4 | Next | Cloud wiring — `CloudClient.device.*`, nonce fetch, cloud verify |
| 5 | Next | `client.device.register()` full ceremony (needs Cloud Phase 7) |
| 6 | Next | Sessions — `client.session.*`, `server.session.verify()` |
| 7 | Later | `VerificationResult` discriminated union in `@event-horizon/attestation-core` |
| 8 | Later | `@event-horizon/attestation-middleware` wraps `Server.verify()` |

---

## Middleware integration (Phase 6 preview)

Express / Next.js middleware will accept a `Server` instance:

```typescript
import { Server } from '@event-horizon/attestation-sdk';
import { attestationMiddleware } from '@event-horizon/attestation-middleware/express';

const server = Server.create({ apiKey: process.env.EH_ATTESTATION_API_KEY! });
app.use('/api', attestationMiddleware({ server }));
```

Middleware calls `server.verify()` internally and injects `req.attestation`
with `{ deviceId, trustLevel, assuranceLevel }`.

---

## React hook (deferred — not in v1)

A browser/WebAuthn prover and `useAttestation()` hook are planned for a later
phase once a browser-side prover exists. v1 targets Node.js agents and
native mobile provers. Do not implement during Phase 5.

---

## package.json (target)

```json
{
  "name": "@event-horizon/attestation-sdk",
  "version": "0.1.0",
  "description": "attestation SDK — device identity in two objects: Client and Server",
  "license": "Apache-2.0",
  "type": "module",
  "exports": {
    ".": {
      "import": "./dist/index.js",
      "types": "./dist/index.d.ts"
    }
  },
  "files": ["dist"],
  "dependencies": {
    "@event-horizon/attestation-core": "workspace:*",
    "@event-horizon/attestation-crypto": "workspace:*",
    "@event-horizon/attestation-tpm": "workspace:*",
    "@attestation/prover-se": "workspace:*",
    "@attestation/prover-android": "workspace:*",
    "@event-horizon/attestation-simulator": "workspace:*"
  },
  "scripts": {
    "build": "tsc",
    "test": "vitest run",
    "typecheck": "tsc --noEmit",
    "clean": "rm -rf dist"
  },
  "devDependencies": {
    "typescript": "^5.4.0",
    "vitest": "^1.6.0"
  },
  "engines": { "node": ">=20" }
}
```
