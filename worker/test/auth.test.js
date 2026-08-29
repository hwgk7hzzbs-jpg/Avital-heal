import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  requireRole, verifyTurnstile, checkRateLimit,
  getAuthPayload, handleLogin, handleRefresh, handleLogout,
  handleChangePassword, handleExecuteReset, handleRequestReset,
  revokeAllSessions,
  handleMfaLoginVerify, handleMfaSetupStart, handleMfaSetupVerify, handleMfaDisable,
} from '../auth.js';
import { hashPassword, createJWT, hashToken, generateTotpSecret, encryptField } from '../crypto.js';
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

// Independent TOTP-code generator (RFC 6238, HMAC-SHA1) used only to produce
// a currently-valid code for a given secret in these integration tests — the
// algorithm itself is already cross-checked against the RFC reference vector
// in crypto.test.js, so this exists purely to drive handleMfa*/handleLogin's
// integration, not to re-prove the math.
function base32DecodeForTest(str) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const output = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = alphabet.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) { output.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return new Uint8Array(output);
}
async function computeTotpCodeForTest(secretBase32, timeMs = Date.now()) {
  const counter = Math.floor(timeMs / 1000 / 30);
  const keyBytes = base32DecodeForTest(secretBase32);
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const counterBuf = new ArrayBuffer(8);
  new DataView(counterBuf).setUint32(4, counter, false);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuf));
  const offset = sig[sig.length - 1] & 0xf;
  const binCode = ((sig[offset] & 0x7f) << 24) | ((sig[offset + 1] & 0xff) << 16) | ((sig[offset + 2] & 0xff) << 8) | (sig[offset + 3] & 0xff);
  return String(binCode % 1000000).padStart(6, '0');
}

const ENCRYPTION_KEY = 'a'.repeat(64);

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

  it('does not rehash a legacy-format password hash on successful login, since its implied iteration count already equals the Workers runtime PBKDF2 ceiling', async () => {
    // Build a real legacy (2-part, no iteration count) hash so login can succeed.
    // Regression test: hashPassword's target used to exceed the platform's
    // PBKDF2 iteration cap, so this rehash step crashed every successful login.
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
    expect(db._state.users[0].password_hash).toBe(realLegacyHash);
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

describe('MFA enrollment (handleMfaSetupStart / handleMfaSetupVerify / handleMfaDisable)', () => {
  it('setup start generates and encrypts a secret without enabling MFA yet', async () => {
    const user = await makeUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, ENCRYPTION_KEY };
    const res = await handleMfaSetupStart(new Request('https://x', { method: 'POST' }), env, { userId: user.id });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.secret).toMatch(/^[A-Z2-7]+$/);
    expect(body.otpauthUri).toContain(body.secret);

    expect(db._state.users[0].mfa_secret).not.toBe(body.secret);
    expect(db._state.users[0].mfa_secret.startsWith('encv1.')).toBe(true);
    expect(db._state.users[0].mfa_enabled).toBeFalsy();
  });

  it('setup start refuses to run again once MFA is already enabled', async () => {
    const user = await makeUser({ mfa_enabled: 1 });
    const env = { DB: makeFakeD1({ users: [user] }), ENCRYPTION_KEY };
    const res = await handleMfaSetupStart(new Request('https://x', { method: 'POST' }), env, { userId: user.id });
    expect(res.status).toBe(400);
  });

  it('setup verify enables MFA with a correct code and returns 8 usable backup codes', async () => {
    const secret = generateTotpSecret();
    const user = await makeUser({ mfa_secret: await encryptField({ ENCRYPTION_KEY }, secret) });
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, ENCRYPTION_KEY };
    const code = await computeTotpCodeForTest(secret);

    const res = await handleMfaSetupVerify(new Request('https://x', { method: 'POST', body: JSON.stringify({ code }) }), env, { userId: user.id });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.backupCodes).toHaveLength(8);
    expect(new Set(body.backupCodes).size).toBe(8); // all distinct

    expect(db._state.users[0].mfa_enabled).toBeTruthy();
    expect(db._state.mfaBackupCodes).toHaveLength(8);
    expect(db._state.mfaBackupCodes.every(c => c.code_hash !== body.backupCodes[0])).toBe(true); // stored hashed, not raw
  });

  it('setup verify rejects an incorrect code and leaves MFA disabled', async () => {
    const secret = generateTotpSecret();
    const user = await makeUser({ mfa_secret: await encryptField({ ENCRYPTION_KEY }, secret) });
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, ENCRYPTION_KEY };

    const res = await handleMfaSetupVerify(new Request('https://x', { method: 'POST', body: JSON.stringify({ code: '000000' }) }), env, { userId: user.id });
    expect(res.status).toBe(401);
    expect(db._state.users[0].mfa_enabled).toBeFalsy();
  });

  it('setup verify 400s if setup was never started', async () => {
    const user = await makeUser();
    const env = { DB: makeFakeD1({ users: [user] }), ENCRYPTION_KEY };
    const res = await handleMfaSetupVerify(new Request('https://x', { method: 'POST', body: JSON.stringify({ code: '123456' }) }), env, { userId: user.id });
    expect(res.status).toBe(400);
  });

  it('disable requires the correct current password and clears secret + backup codes', async () => {
    const user = await makeUser({ mfa_enabled: 1, mfa_secret: 'encv1.whatever' });
    const db = makeFakeD1({
      users: [user],
      mfaBackupCodes: [{ id: 1, user_id: user.id, code_hash: 'h', used_at: null }],
    });
    const env = { DB: db, ENCRYPTION_KEY };

    const wrongPass = await handleMfaDisable(new Request('https://x', { method: 'POST', body: JSON.stringify({ currentPassword: 'nope' }) }), env, { userId: user.id });
    expect(wrongPass.status).toBe(401);
    expect(db._state.users[0].mfa_enabled).toBeTruthy();

    const res = await handleMfaDisable(new Request('https://x', { method: 'POST', body: JSON.stringify({ currentPassword: 'CorrectPass1' }) }), env, { userId: user.id });
    expect(res.status).toBe(200);
    expect(db._state.users[0].mfa_enabled).toBeFalsy();
    expect(db._state.users[0].mfa_secret).toBeFalsy();
    expect(db._state.mfaBackupCodes).toHaveLength(0);
  });
});

describe('MFA login (handleLogin gating + handleMfaLoginVerify)', () => {
  beforeEach(() => mockFetchTurnstile(true));
  afterEach(() => vi.unstubAllGlobals());

  async function makeMfaUser(overrides = {}) {
    const secret = generateTotpSecret();
    const user = await makeUser({ mfa_enabled: 1, mfa_secret: await encryptField({ ENCRYPTION_KEY }, secret), ...overrides });
    return { user, secret };
  }

  it('handleLogin returns a challenge instead of tokens when MFA is enabled', async () => {
    const { user } = await makeMfaUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k', ENCRYPTION_KEY };
    const res = await handleLogin(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.mfaRequired).toBe(true);
    expect(body.mfaToken).toBeTruthy();
    expect(body.token).toBeUndefined();
    expect(db._state.refreshTokens).toHaveLength(0); // no session issued until MFA passes
  });

  it('completes login with a correct TOTP code', async () => {
    const { user, secret } = await makeMfaUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k', ENCRYPTION_KEY };
    const { mfaToken } = await (await handleLogin(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env)).json();

    const code = await computeTotpCodeForTest(secret);
    const res = await handleMfaLoginVerify(new Request('https://x', { method: 'POST', body: JSON.stringify({ mfaToken, code }) }), env);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.token).toBeTruthy();
    expect(body.refreshToken).toBeTruthy();
    expect(db._state.users[0].mfa_last_counter).toBeTruthy();
  });

  it('rejects an incorrect TOTP code', async () => {
    const { user } = await makeMfaUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k', ENCRYPTION_KEY };
    const { mfaToken } = await (await handleLogin(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env)).json();

    const res = await handleMfaLoginVerify(new Request('https://x', { method: 'POST', body: JSON.stringify({ mfaToken, code: '000000' }) }), env);
    expect(res.status).toBe(401);
  });

  it('rejects a real access token used as an mfaToken (different audience)', async () => {
    const { user } = await makeMfaUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, ENCRYPTION_KEY };
    const fakeAccessToken = await createJWT(
      { userId: user.id, sub: String(user.id), iss: 'avital-heal-crm', aud: 'avital-heal-crm-app', jti: 'x' },
      JWT_SECRET
    );
    const res = await handleMfaLoginVerify(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ mfaToken: fakeAccessToken, code: '123456' }),
    }), env);
    expect(res.status).toBe(401);
  });

  it('completes login with a valid backup code, and that code cannot be reused', async () => {
    const { user } = await makeMfaUser();
    const db = makeFakeD1({
      users: [user],
      mfaBackupCodes: [{ id: 1, user_id: user.id, code_hash: await hashToken('WXYZ-1234'), used_at: null }],
    });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k', ENCRYPTION_KEY };
    const { mfaToken } = await (await handleLogin(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env)).json();

    const first = await handleMfaLoginVerify(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ mfaToken, backupCode: 'wxyz-1234' }),
    }), env);
    expect(first.status).toBe(200);

    const { mfaToken: mfaToken2 } = await (await handleLogin(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env)).json();
    const second = await handleMfaLoginVerify(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ mfaToken: mfaToken2, backupCode: 'wxyz-1234' }),
    }), env);
    expect(second.status).toBe(401);
  });

  it('rejects a code once a login has already been fully completed with a later counter (replay protection)', async () => {
    const { user, secret } = await makeMfaUser();
    const db = makeFakeD1({ users: [user] });
    const env = { DB: db, JWT_SECRET, TURNSTILE_SECRET_KEY: 'k', ENCRYPTION_KEY };
    const code = await computeTotpCodeForTest(secret);

    const { mfaToken: t1 } = await (await handleLogin(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env)).json();
    const firstUse = await handleMfaLoginVerify(new Request('https://x', { method: 'POST', body: JSON.stringify({ mfaToken: t1, code }) }), env);
    expect(firstUse.status).toBe(200);

    // Same code, fresh challenge token — must not be accepted twice.
    const { mfaToken: t2 } = await (await handleLogin(new Request('https://x', {
      method: 'POST', body: JSON.stringify({ email: user.email, password: 'CorrectPass1', 'cf-turnstile-response': 't' }),
    }), env)).json();
    const secondUse = await handleMfaLoginVerify(new Request('https://x', { method: 'POST', body: JSON.stringify({ mfaToken: t2, code }) }), env);
    expect(secondUse.status).toBe(401);
  });
});
