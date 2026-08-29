import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  requireRole, verifyTurnstile, checkRateLimit,
  getAuthPayload, handleLogin, handleRefresh, handleLogout,
  handleChangePassword, handleExecuteReset, handleRequestReset,
  revokeAllSessions,
} from '../auth.js';
import { hashPassword, createJWT, hashToken } from '../crypto.js';
import { makeFakeD1, mockFetchTurnstile } from './testUtils.js';

function authedRequest(url, token, opts = {}) {
  return new Request(url, {
    ...opts,
    headers: { Authorization: `Bearer ${token}`, ...(opts.headers || {}) },
  });
}

async function makeUser(overrides = {}) {
  return {
    id: 1, email: 'a@x.com', name: 'Admin', role: 'admin', active: 1, token_version: 0,
    password_hash: await hashPassword('CorrectPass1'),
    ...overrides,
  };
}

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

const JWT_SECRET = 'test-jwt-secret';

describe('getAuthPayload', () => {
  it('returns null with no Authorization header', async () => {
    const env = { DB: makeFakeD1(), JWT_SECRET };
    expect(await getAuthPayload(new Request('https://x'), env)).toBeNull();
  });

  it('accepts a token issued by handleLogin end-to-end', async () => {
    mockFetchTurnstile(true);
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };
    const loginRes = await handleLogin(new Request('https://x', {
      method: 'POST',
      body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env);
    const { token } = await loginRes.json();

    const payload = await getAuthPayload(authedRequest('https://x', token), env);
    expect(payload).not.toBeNull();
    expect(payload.userId).toBe(user.id);
  });

  it('rejects a token whose issuer/audience does not match', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET };
    const badToken = await createJWT(
      { userId: user.id, sub: String(user.id), iss: 'someone-else', aud: 'someone-else-app', jti: 'x', tokenVersion: 0 },
      JWT_SECRET
    );
    expect(await getAuthPayload(authedRequest('https://x', badToken), env)).toBeNull();
  });

  it('rejects a token missing jti', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET };
    const badToken = await createJWT(
      { userId: user.id, sub: String(user.id), iss: 'avital-heal-crm', aud: 'avital-heal-crm-app', tokenVersion: 0 },
      JWT_SECRET
    );
    expect(await getAuthPayload(authedRequest('https://x', badToken), env)).toBeNull();
  });

  it('rejects once the user has been deactivated', async () => {
    mockFetchTurnstile(true);
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };
    const { token } = await (await handleLogin(new Request('https://x', {
      method: 'POST',
      body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env)).json();

    user.active = 0;
    expect(await getAuthPayload(authedRequest('https://x', token), env)).toBeNull();
  });

  it('rejects once tokenVersion has been bumped (password changed elsewhere)', async () => {
    mockFetchTurnstile(true);
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };
    const { token } = await (await handleLogin(new Request('https://x', {
      method: 'POST',
      body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env)).json();

    await revokeAllSessions(env, user.id);
    expect(await getAuthPayload(authedRequest('https://x', token), env)).toBeNull();
  });

  it('fails closed if the DB check errors', async () => {
    const token = await createJWT(
      { userId: 1, sub: '1', iss: 'avital-heal-crm', aud: 'avital-heal-crm-app', jti: 'x', tokenVersion: 0 },
      JWT_SECRET
    );
    const env = { DB: { prepare() { throw new Error('D1 down'); } }, JWT_SECRET };
    expect(await getAuthPayload(authedRequest('https://x', token), env)).toBeNull();
  });
});

describe('handleLogin — token pair issuance', () => {
  beforeEach(() => mockFetchTurnstile(true));
  afterEach(() => vi.unstubAllGlobals());

  it('returns an access token and a refresh token, and persists a hash of the refresh token', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleLogin(new Request('https://x', {
      method: 'POST',
      headers: { 'CF-Connecting-IP': '1.2.3.4' },
      body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env);
    const body = await res.json();

    expect(body.token).toBeTruthy();
    expect(body.refreshToken).toBeTruthy();
    expect(db._state.refreshTokens).toHaveLength(1);
    expect(db._state.refreshTokens[0].token_hash).toBe(await hashToken(body.refreshToken));
    expect(db._state.refreshTokens[0].token_hash).not.toBe(body.refreshToken);
  });

  it('opportunistically re-hashes a legacy-format password hash on successful login', async () => {
    // Build a real legacy (2-part, no iteration count) hash so login can succeed.
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('CorrectPass1'), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
    const toHex = buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    const realLegacyHash = `${toHex(salt)}:${toHex(bits)}`;

    const user = await makeUser({ password_hash: realLegacyHash });
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleLogin(new Request('https://x', {
      method: 'POST',
      body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env);
    expect(res.status).toBe(200);
    expect(db._state.users[0].password_hash).not.toBe(realLegacyHash);
    expect(db._state.users[0].password_hash.split(':')).toHaveLength(3);
  });

  it('records last_login_at/last_login_ip and audit metadata (ip, user agent) on success', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };
    await handleLogin(new Request('https://x', {
      method: 'POST',
      headers: { 'CF-Connecting-IP': '9.9.9.9', 'User-Agent': 'TestAgent/1.0' },
      body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env);

    expect(db._state.users[0].last_login_ip).toBe('9.9.9.9');
    expect(db._state.users[0].last_login_at).toBeTruthy();
    const successEntry = db._state.auditLog.find(a => a.action === 'login' && a.result === 'success');
    expect(JSON.parse(successEntry.metadata)).toMatchObject({ ip: '9.9.9.9', userAgent: 'TestAgent/1.0' });
  });
});

describe('handleLogin — progressive lockout', () => {
  beforeEach(() => mockFetchTurnstile(true));
  afterEach(() => vi.unstubAllGlobals());

  async function attemptLogin(env, email, password) {
    return handleLogin(new Request('https://x', {
      method: 'POST',
      body: JSON.stringify({ email, password, 'cf-turnstile-response': 't' }),
    }), env);
  }

  it('locks out after repeated failures, even with the correct password', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };

    let last;
    for (let i = 0; i < 3; i++) {
      last = await attemptLogin(env, user.email, 'WrongPassword');
    }
    expect(last.status).toBe(401); // the 3rd failure itself still reports "wrong password"

    // The lockout kicks in on the *next* attempt, correct password or not.
    const lockedOut = await attemptLogin(env, user.email, 'CorrectPass1');
    expect(lockedOut.status).toBe(429);
  });

  it('does not lock out a fresh account before the failure threshold', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };

    await attemptLogin(env, user.email, 'WrongPassword');
    const res = await attemptLogin(env, user.email, 'CorrectPass1');
    expect(res.status).toBe(200);
  });

  it('clears the lockout counter on a successful login', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };

    await attemptLogin(env, user.email, 'WrongPassword');
    await attemptLogin(env, user.email, 'WrongPassword');
    await attemptLogin(env, user.email, 'CorrectPass1'); // succeeds — only 2 fails, below the 3-fail threshold
    expect(db._state.loginAttempts.find(a => a.email === user.email).failed_count).toBe(0);
  });
});

describe('handleRefresh', () => {
  beforeEach(() => mockFetchTurnstile(true));
  afterEach(() => vi.unstubAllGlobals());

  async function login(env, user) {
    const res = await handleLogin(new Request('https://x', {
      method: 'POST',
      body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env);
    return res.json();
  }

  it('rotates the refresh token and issues a new access token', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };
    const first = await login(env, user);

    const res = await handleRefresh(new Request('https://x', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: first.refreshToken }),
    }), env);
    expect(res.status).toBe(200);
    const second = await res.json();
    expect(second.token).toBeTruthy();
    expect(second.refreshToken).toBeTruthy();
    expect(second.refreshToken).not.toBe(first.refreshToken);

    // The old refresh token is now spent; the new one is still active.
    const oldHash = await hashToken(first.refreshToken);
    const newHash = await hashToken(second.refreshToken);
    const oldRow = db._state.refreshTokens.find(r => r.token_hash === oldHash);
    const newRow = db._state.refreshTokens.find(r => r.token_hash === newHash);
    expect(oldRow.revoked_at).toBeTruthy();
    expect(newRow.revoked_at).toBeFalsy();
  });

  it('rejects an unknown refresh token', async () => {
    const env = { DB: makeFakeD1(), JWT_SECRET };
    const res = await handleRefresh(new Request('https://x', { method: 'POST', body: JSON.stringify({ refreshToken: 'nope' }) }), env);
    expect(res.status).toBe(401);
  });

  it('detects reuse of an already-rotated refresh token and kills every session for that user', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };
    const first = await login(env, user);

    // Rotate once (legitimate use) — this revokes `first.refreshToken`.
    const rotated = await (await handleRefresh(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ refreshToken: first.refreshToken }),
    }), env)).json();

    // Replaying the now-revoked original token is treated as theft.
    const reuseRes = await handleRefresh(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ refreshToken: first.refreshToken }),
    }), env);
    expect(reuseRes.status).toBe(401);

    // Even the legitimately-rotated token from the same chain is now dead.
    const secondAttempt = await handleRefresh(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ refreshToken: rotated.refreshToken }),
    }), env);
    expect(secondAttempt.status).toBe(401);
  });

  it('rejects an expired refresh token', async () => {
    const user = await makeUser();
    const db = makeFakeD1({
      users: [user],
      refreshTokens: [{ id: 1, user_id: 1, token_hash: await hashToken('expired-token'), token_version: 0, expires_at: '2000-01-01T00:00:00.000Z', revoked_at: null }],
    });
    const env = { DB: db, JWT_SECRET };
    const res = await handleRefresh(new Request('https://x', { method: 'POST', body: JSON.stringify({ refreshToken: 'expired-token' }) }), env);
    expect(res.status).toBe(401);
  });

  it('rejects a refresh token for a now-inactive user', async () => {
    const user = await makeUser({ active: 0 });
    const db = makeFakeD1({
      users: [user],
      refreshTokens: [{ id: 1, user_id: 1, token_hash: await hashToken('tok'), token_version: 0, expires_at: '2999-01-01T00:00:00.000Z', revoked_at: null }],
    });
    const env = { DB: db, JWT_SECRET };
    const res = await handleRefresh(new Request('https://x', { method: 'POST', body: JSON.stringify({ refreshToken: 'tok' }) }), env);
    expect(res.status).toBe(403);
  });
});

describe('handleLogout', () => {
  it('revokes the given refresh token', async () => {
    const db = makeFakeD1({
      refreshTokens: [{ id: 1, user_id: 1, token_hash: await hashToken('tok'), token_version: 0, expires_at: '2999-01-01T00:00:00.000Z', revoked_at: null }],
    });
    const env = { DB: db };
    const res = await handleLogout(new Request('https://x', { method: 'POST', body: JSON.stringify({ refreshToken: 'tok' }) }), env);
    expect(res.status).toBe(200);
    expect(db._state.refreshTokens[0].revoked_at).toBeTruthy();
  });

  it('still returns success with no refreshToken in the body', async () => {
    const env = { DB: makeFakeD1() };
    const res = await handleLogout(new Request('https://x', { method: 'POST', body: JSON.stringify({}) }), env);
    expect(res.status).toBe(200);
  });
});

describe('revokeAllSessions', () => {
  it('bumps token_version and revokes only the target user\'s active refresh tokens', async () => {
    const db = makeFakeD1({
      users: [{ id: 1, token_version: 0 }, { id: 2, token_version: 0 }],
      refreshTokens: [
        { id: 1, user_id: 1, token_hash: 'h1', token_version: 0, expires_at: '2999-01-01T00:00:00.000Z', revoked_at: null },
        { id: 2, user_id: 2, token_hash: 'h2', token_version: 0, expires_at: '2999-01-01T00:00:00.000Z', revoked_at: null },
      ],
    });
    const env = { DB: db };
    await revokeAllSessions(env, 1);

    expect(db._state.users[0].token_version).toBe(1);
    expect(db._state.users[1].token_version).toBe(0);
    expect(db._state.refreshTokens[0].revoked_at).toBeTruthy();
    expect(db._state.refreshTokens[1].revoked_at).toBeFalsy();
  });
});

describe('handleChangePassword', () => {
  beforeEach(() => mockFetchTurnstile(true));
  afterEach(() => vi.unstubAllGlobals());

  it('revokes all sessions (including the one used to make the request) on success', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };
    const { token } = await (await handleLogin(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env)).json();

    const res = await handleChangePassword(authedRequest('https://x', token, {
      method: 'POST',
      body: JSON.stringify({ currentPassword: 'CorrectPass1', newPassword: 'NewPassword2' }),
    }), env);
    expect(res.status).toBe(200);
    expect(db._state.users[0].token_version).toBe(1);

    // The token used to make this very request no longer authenticates.
    expect(await getAuthPayload(authedRequest('https://x', token), env)).toBeNull();
  });

  it('rejects an incorrect current password without revoking anything', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k' };
    const { token } = await (await handleLogin(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env)).json();

    const res = await handleChangePassword(authedRequest('https://x', token, {
      method: 'POST',
      body: JSON.stringify({ currentPassword: 'WrongOne', newPassword: 'NewPassword2' }),
    }), env);
    expect(res.status).toBe(401);
    expect(db._state.users[0].token_version).toBe(0);
  });
});

describe('handleRequestReset / handleExecuteReset', () => {
  beforeEach(() => mockFetchTurnstile(true));
  afterEach(() => vi.unstubAllGlobals());

  function captureResetLink() {
    let capturedBody = null;
    vi.stubGlobal('fetch', vi.fn(async (url, opts) => {
      if (String(url).includes('turnstile')) return { json: async () => ({ success: true }) };
      capturedBody = JSON.parse(opts.body);
      return { json: async () => ({}) };
    }));
    return { getRawToken: () => capturedBody.resetLink.split('reset=')[1] };
  }

  it('stores only a hash of the reset token, never the raw value', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, TURNSTILE_SECRET_KEY: 'k', RESET_EMAIL_SCRIPT_URL: 'https://script.example/exec' };
    const { getRawToken } = captureResetLink();

    await handleRequestReset(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, 'cf-turnstile-response': 't' }),
    }), env);

    const rawToken = getRawToken();
    expect(db._state.passwordResets).toHaveLength(1);
    expect(db._state.passwordResets[0].token).not.toBe(rawToken);
    expect(db._state.passwordResets[0].token).toBe(await hashToken(rawToken));
  });

  it('executes a reset with the raw token, updates the password, and revokes sessions', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, TURNSTILE_SECRET_KEY: 'k', RESET_EMAIL_SCRIPT_URL: 'https://script.example/exec' };
    const { getRawToken } = captureResetLink();

    await handleRequestReset(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, 'cf-turnstile-response': 't' }),
    }), env);
    const rawToken = getRawToken();

    const res = await handleExecuteReset(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ token: rawToken, newPassword: 'BrandNewPass9' }),
    }), env);
    expect(res.status).toBe(200);
    expect(db._state.passwordResets[0].used).toBe(1);
    expect(db._state.users[0].token_version).toBe(1);
  });

  it('rejects an unknown reset token', async () => {
    const env = { DB: makeFakeD1() };
    const res = await handleExecuteReset(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ token: 'unknown', newPassword: 'BrandNewPass9' }),
    }), env);
    expect(res.status).toBe(400);
  });

  it('rejects a reset token that was already used', async () => {
    const db = makeFakeD1({
      passwordResets: [{ id: 1, user_id: 1, token: await hashToken('used-token'), expires_at: '2999-01-01T00:00:00.000Z', used: 1 }],
    });
    const env = { DB: db };
    const res = await handleExecuteReset(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ token: 'used-token', newPassword: 'BrandNewPass9' }),
    }), env);
    expect(res.status).toBe(400);
  });
});
