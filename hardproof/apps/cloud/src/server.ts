import { createServer } from 'node:http';
import { Verifier, type HardproofBundle } from '@hardproof/core';

const verifier = new Verifier({ minTrustLevel: 'simulated', allowUnregisteredSimulator: false });
const port = Number(process.env.PORT ?? 8787);

function json(response: import('node:http').ServerResponse, status: number, body: unknown): void {
  const data = JSON.stringify(body);
  response.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(data) });
  response.end(data);
}

createServer((request, response) => {
  if (request.method === 'GET' && request.url === '/health') return json(response, 200, { ok: true, mode: 'in-memory-development' });
  if (request.method === 'GET' && request.url === '/v1/nonce') return json(response, 200, { nonce: verifier.nonceStore.issue() });
  if (request.method === 'POST' && request.url === '/v1/verify') {
    const chunks: Buffer[] = [];
    request.on('data', chunk => chunks.push(Buffer.from(chunk)));
    request.on('end', () => {
      try {
        const body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as { bundle: HardproofBundle; nonce: string; publicKeyPem?: string };
        const result = verifier.verify(body.bundle, { nonce: body.nonce, publicKeyPem: body.publicKeyPem });
        json(response, result.valid ? 200 : 401, result);
      } catch (error) {
        json(response, 400, { error: error instanceof Error ? error.message : String(error) });
      }
    });
    return;
  }
  json(response, 404, { error: 'not_found' });
}).listen(port, '127.0.0.1', () => console.log(`HardProof development cloud listening on http://127.0.0.1:${port}`));
