import test from 'node:test';
import assert from 'node:assert/strict';

import {
  MAX_REMOTE_REPLAY_RESPONSE_BYTES,
  RemoteReplayProtocolError,
  RemoteReplayResponseTooLargeError,
  createHttpReplayTransport,
} from '../packages/core/dist/index.js';

const encoder = new TextEncoder();

async function withFetch(response, operation) {
  const original = globalThis.fetch;
  globalThis.fetch = async () => response;
  try {
    return await operation(createHttpReplayTransport('https://replay.invalid/v1/transition'));
  } finally {
    globalThis.fetch = original;
  }
}

function trackedResponse(chunks, headers = {}) {
  let produced = 0;
  let cancelled = false;
  let cancellationReason;
  const stream = new ReadableStream({
    pull(controller) {
      if (produced >= chunks.length) {
        controller.close();
        return;
      }
      controller.enqueue(chunks[produced]);
      produced += 1;
    },
    cancel(reason) {
      cancelled = true;
      cancellationReason = reason;
    },
  });
  return {
    response: new Response(stream, { status: 200, headers }),
    state: {
      get produced() { return produced; },
      get cancelled() { return cancelled; },
      get cancellationReason() { return cancellationReason; },
    },
  };
}

test('bounded HTTP transport accepts a canonical response below the byte limit', async () => {
  const body = encoder.encode('{"accepted":true}');
  const tracked = trackedResponse([body], { 'content-length': String(body.byteLength) });
  const result = await withFetch(tracked.response, (transport) => transport({}));
  assert.deepEqual(result, { accepted: true });
  assert.equal(tracked.state.cancelled, false);
});

test('declared oversized response is cancelled before its body is read', async () => {
  const chunks = Array.from({ length: 20 }, () => new Uint8Array(8_192));
  const tracked = trackedResponse(chunks, {
    'content-length': String(MAX_REMOTE_REPLAY_RESPONSE_BYTES + 1),
  });
  await assert.rejects(
    () => withFetch(tracked.response, (transport) => transport({})),
    RemoteReplayResponseTooLargeError,
  );
  assert.equal(tracked.state.cancelled, true);
  assert.equal(tracked.state.produced < chunks.length, true);
});

test('oversized chunked response is rejected without buffering the full source', async () => {
  const chunks = Array.from({ length: 12 }, () => new Uint8Array(20_000));
  const tracked = trackedResponse(chunks);
  await assert.rejects(
    () => withFetch(tracked.response, (transport) => transport({})),
    RemoteReplayResponseTooLargeError,
  );
  assert.equal(tracked.state.cancelled, true);
  assert.equal(tracked.state.produced < chunks.length, true);
});

test('streaming UTF-8 decoder preserves a multibyte character split across chunks', async () => {
  const encoded = encoder.encode('{"value":"é"}');
  const split = encoded.indexOf(0xc3) + 1;
  const tracked = trackedResponse([encoded.slice(0, split), encoded.slice(split)]);
  const result = await withFetch(tracked.response, (transport) => transport({}));
  assert.deepEqual(result, { value: 'é' });
});

test('stream exceeding the limit after several valid chunks is cancelled immediately', async () => {
  const chunks = Array.from({ length: 9 }, () => new Uint8Array(16_384));
  const tracked = trackedResponse(chunks);
  await assert.rejects(
    () => withFetch(tracked.response, (transport) => transport({})),
    RemoteReplayResponseTooLargeError,
  );
  assert.equal(tracked.state.cancelled, true);
  assert.equal(tracked.state.produced <= 6, true);
  assert.equal(tracked.state.cancellationReason instanceof RemoteReplayResponseTooLargeError, true);
});

test('reader is cancelled and released after a bounded-read rejection', async () => {
  const invalidUtf8 = new Uint8Array([0x7b, 0x22, 0x78, 0x22, 0x3a, 0xff]);
  const tracked = trackedResponse([invalidUtf8, encoder.encode('}'), encoder.encode('ignored')]);
  await assert.rejects(
    () => withFetch(tracked.response, (transport) => transport({})),
    RemoteReplayProtocolError,
  );
  assert.equal(tracked.state.cancelled, true);
  assert.equal(tracked.response.body.locked, false);
});

test('successful response without an available body fails closed without response.text fallback', async () => {
  const response = new Response(null, { status: 200 });
  await assert.rejects(
    () => withFetch(response, (transport) => transport({})),
    /body is unavailable/,
  );
});
