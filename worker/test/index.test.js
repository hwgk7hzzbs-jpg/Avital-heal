import { describe, it, expect } from 'vitest';
import worker from '../index.js';
import { makeFakeD1 } from './testUtils.js';

function req(path, opts = {}) {
  return new Request(`https://x${path}`, opts);
}

describe('fetch — request ID threading', () => {
  it('attaches a unique X-Request-Id header and requestId body field to an error response', async () => {
    const env = { DB: makeFakeD1(), JWT_SECRET: 'k' };
    const res = await worker.fetch(req('/api/stats'), env); // protected, no Authorization header
    expect(res.status).toBe(401);
    const headerId = res.headers.get('X-Request-Id');
    expect(headerId).toBeTruthy();
    const body = await res.json();
    expect(body.requestId).toBe(headerId);
  });

  it('gives two separate requests two different IDs', async () => {
    const env = { DB: makeFakeD1(), JWT_SECRET: 'k' };
    const res1 = await worker.fetch(req('/api/stats'), env);
    const res2 = await worker.fetch(req('/api/stats'), env);
    expect(res1.headers.get('X-Request-Id')).not.toBe(res2.headers.get('X-Request-Id'));
  });

  it('carries the request ID header even on a 404 (a route outside /api/, so it skips the auth gate)', async () => {
    const env = { DB: makeFakeD1(), JWT_SECRET: 'k' };
    const res = await worker.fetch(req('/nonexistent-route'), env);
    expect(res.status).toBe(404);
    const headerId = res.headers.get('X-Request-Id');
    expect(headerId).toBeTruthy();
    const body = await res.json();
    expect(body.requestId).toBe(headerId);
  });
});
