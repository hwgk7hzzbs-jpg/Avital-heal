import { describe, it, expect } from 'vitest';
import { handleHealthCheck } from '../health.js';
import { makeFakeD1 } from './testUtils.js';

describe('handleHealthCheck', () => {
  it('reports ok when the database responds', async () => {
    const env = { DB: makeFakeD1() };
    const res = await handleHealthCheck(env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('ok');
    expect(body.timestamp).toBeTruthy();
  });

  it('reports degraded (503) if the database errors, without leaking error detail', async () => {
    const env = { DB: { prepare() { throw new Error('D1 down: internal connection string xyz'); } } };
    const res = await handleHealthCheck(env);
    expect(res.status).toBe(503);
    const body = await res.json();
    expect(body.status).toBe('degraded');
    expect(JSON.stringify(body)).not.toContain('connection string');
  });

  it('never includes anything beyond status and timestamp', async () => {
    const env = { DB: makeFakeD1() };
    const res = await handleHealthCheck(env);
    const body = await res.json();
    expect(Object.keys(body).sort()).toEqual(['status', 'timestamp']);
  });
});
