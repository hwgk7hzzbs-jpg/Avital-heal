import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { requireRole, verifyTurnstile, checkRateLimit } from '../auth.js';

describe('requireRole', () => {
  it('allows a matching role', () => {
    expect(requireRole({ role: 'admin' }, 'admin', 'therapist')).toBeNull();
    expect(requireRole({ role: 'therapist' }, 'admin', 'therapist')).toBeNull();
  });

  it('blocks a non-matching role with 403', async () => {
    const res = requireRole({ role: 'viewer' }, 'admin', 'therapist');
    expect(res).not.toBeNull();
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBeTruthy();
  });

  it('blocks a missing payload', () => {
    const res = requireRole(null, 'admin');
    expect(res.status).toBe(403);
  });

  it('blocks an unrecognized role string', () => {
    // A role outside the known set must never be treated as authorized.
    const res = requireRole({ role: 'super-admin' }, 'admin', 'therapist', 'viewer');
    expect(res.status).toBe(403);
  });
});

describe('verifyTurnstile', () => {
  const env = { TURNSTILE_SECRET_KEY: 'secret-key' };

  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });
  afterEach(() => vi.unstubAllGlobals());

  it('returns true when Cloudflare reports success', async () => {
    fetch.mockResolvedValue({ json: async () => ({ success: true }) });
    expect(await verifyTurnstile('tok', env, '1.2.3.4')).toBe(true);
    const [url, opts] = fetch.mock.calls[0];
    expect(url).toBe('https://challenges.cloudflare.com/turnstile/v0/siteverify');
    const body = new URLSearchParams(opts.body);
    expect(body.get('secret')).toBe('secret-key');
    expect(body.get('response')).toBe('tok');
    expect(body.get('remoteip')).toBe('1.2.3.4');
  });

  it('returns false when Cloudflare reports failure', async () => {
    fetch.mockResolvedValue({ json: async () => ({ success: false }) });
    expect(await verifyTurnstile('tok', env)).toBe(false);
  });

  it('fails closed when TURNSTILE_SECRET_KEY is not configured', async () => {
    expect(await verifyTurnstile('tok', {})).toBe(false);
    expect(fetch).not.toHaveBeenCalled();
  });

  it('fails closed on a network error', async () => {
    fetch.mockRejectedValue(new Error('network down'));
    expect(await verifyTurnstile('tok', env)).toBe(false);
  });
});

describe('checkRateLimit', () => {
  // Minimal fake D1 covering exactly the queries checkRateLimit issues.
  function makeFakeDB(initial = new Map()) {
    const store = initial;
    return {
      prepare(sql) {
        const bound = { sql, args: [] };
        return {
          bind(...args) {
            bound.args = args;
            return this;
          },
          async first() {
            if (sql.startsWith('SELECT')) {
              const row = store.get(bound.args[0]);
              return row || null;
            }
            return null;
          },
          async run() {
            if (sql.startsWith('INSERT')) {
              // checkRateLimit's INSERT binds only (key, expires_at) — count=1 is a SQL literal.
              const [key, expires_at] = bound.args;
              store.set(key, { count: 1, expires_at });
            } else if (sql.startsWith('UPDATE')) {
              const [key] = bound.args;
              const row = store.get(key);
              if (row) row.count += 1;
            }
            return {};
          },
        };
      },
    };
  }

  it('allows requests under the limit', async () => {
    const env = { DB: makeFakeDB() };
    expect(await checkRateLimit(env, 'k1', 3, 60)).toBe(true);
    expect(await checkRateLimit(env, 'k1', 3, 60)).toBe(true);
    expect(await checkRateLimit(env, 'k1', 3, 60)).toBe(true);
  });

  it('blocks once the limit is reached within the window', async () => {
    const env = { DB: makeFakeDB() };
    await checkRateLimit(env, 'k2', 2, 60);
    await checkRateLimit(env, 'k2', 2, 60);
    expect(await checkRateLimit(env, 'k2', 2, 60)).toBe(false);
  });

  it('resets after the window expires', async () => {
    const store = new Map();
    store.set('k3', { count: 99, expires_at: Math.floor(Date.now() / 1000) - 10 });
    const env = { DB: makeFakeDB(store) };
    expect(await checkRateLimit(env, 'k3', 2, 60)).toBe(true);
  });

  it('fails open if D1 throws (a broken limiter must not take the site down)', async () => {
    const env = { DB: { prepare() { throw new Error('D1 unavailable'); } } };
    expect(await checkRateLimit(env, 'k4', 1, 60)).toBe(true);
  });

  it('tracks separate keys independently', async () => {
    const env = { DB: makeFakeDB() };
    await checkRateLimit(env, 'a', 1, 60);
    expect(await checkRateLimit(env, 'a', 1, 60)).toBe(false);
    expect(await checkRateLimit(env, 'b', 1, 60)).toBe(true);
  });
});
