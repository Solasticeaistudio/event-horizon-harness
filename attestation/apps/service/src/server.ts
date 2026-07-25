import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import {
  Verifier,
  type AttestationBundle,
  type NonceContext,
} from '@event-horizon/attestation-core';

const verifier = new Verifier({ minTrustLevel: 'simulated', allowUnregisteredSimulator: false });
const port = Number(process.env.PORT ?? 8787);

function json(response: ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  response.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) });
  response.end(data);
}

function readJson(
  request: IncomingMessage,
  response: ServerResponse,
  handle: (body: unknown) => void | Promise<void>,
): void {
  const chunks: Buffer[] = [];
  request.on('data', chunk => chunks.push(Buffer.from(chunk)));
  request.on('end', async () => {
    try {
      await handle(JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown);
    } catch (error) {
      json(response, 400, { error: error instanceof Error ? error.message : String(error) });
    }
  });
}

createServer((request, response) => {
  if (request.method === 'GET' && request.url === '/health') {
    return json(response, 200, { ok: true, mode: 'in-memory-development' });
  }
  if (request.method === 'POST' && request.url === '/v1/nonce') {
    readJson(request, response, async (value) => {
      const body = value as { context: NonceContext };
      json(response, 200, { nonce: await verifier.nonceAuthority.issue(body.context) });
    });
    return;
  }
  if (request.method === 'POST' && request.url === '/v1/verify') {
    readJson(request, response, async (value) => {
      const body = value as {
        bundle: AttestationBundle;
        nonce: string;
        context: NonceContext;
        publicKeyPem?: string;
      };
      const result = await verifier.verify(body.bundle, {
        nonce: body.nonce,
        context: body.context,
        publicKeyPem: body.publicKeyPem,
      });
      json(response, result.valid ? 200 : 401, result);
    });
    return;
  }
  json(response, 404, { error: 'not_found' });
}).listen(port, '127.0.0.1', () => console.log(`Executor Attestation development service listening on http://127.0.0.1:${port}`));
