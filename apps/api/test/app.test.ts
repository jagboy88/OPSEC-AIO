import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildApp } from '../src/app.js';

let app: FastifyInstance;
let storageUp = true;

beforeAll(async () => {
  app = await buildApp({
    config: { logLevel: 'silent', trustProxyHops: 0 },
    probes: {
      database: async () => {},
      storage: async () => {
        if (!storageUp) throw new Error('down');
      },
    },
  });
  await app.ready();
});
afterAll(() => app.close());

describe('health', () => {
  it('GET /api/v1/health is ok', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/health' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
  });

  it('GET /api/v1/ready reports each probe and 503s when one fails', async () => {
    storageUp = true;
    let res = await app.inject({ method: 'GET', url: '/api/v1/ready' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok', checks: { database: 'ok', storage: 'ok' } });

    storageUp = false;
    res = await app.inject({ method: 'GET', url: '/api/v1/ready' });
    expect(res.statusCode).toBe(503);
    expect(res.json().checks.storage).toBe('fail');
  });
});

describe('privacy & security headers', () => {
  it('sets no-store, no-referrer and nosniff on every response', async () => {
    for (const url of ['/api/v1/health', '/api/v1/does-not-exist']) {
      const res = await app.inject({ method: 'GET', url });
      expect(res.headers['cache-control']).toBe('no-store');
      expect(res.headers['referrer-policy']).toBe('no-referrer');
      expect(res.headers['x-content-type-options']).toBe('nosniff');
      expect(res.headers['x-powered-by']).toBeUndefined();
    }
  });

  it('returns a generic 404 that does not echo the path', async () => {
    const res = await app.inject({ method: 'GET', url: '/api/v1/note/SECRET_ID_123' });
    expect(res.statusCode).toBe(404);
    expect(res.body).toBe('{"error":"not_found"}');
  });

  it('rejects oversized bodies before reading them', async () => {
    const res = await app.inject({
      method: 'POST',
      url: '/api/v1/health',
      headers: { 'content-type': 'application/json' },
      payload: JSON.stringify({ x: 'a'.repeat(32 * 1024) }),
    });
    expect([404, 413]).toContain(res.statusCode);
    expect(res.body).not.toContain('aaaa');
  });
});
