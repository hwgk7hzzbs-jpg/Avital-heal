/**
 * @file auth.js
 * @description Authentication handlers: login, token refresh/logout, verify,
 *              password reset, and Turnstile CAPTCHA verification.
 * @module Auth
 * @security CRITICAL — handles credentials and session tokens.
 */

import { jsonResponse, errorResponse } from './utils.js';
import {
  hashPassword, verifyPassword, needsRehash, createJWT, verifyJWT, generateToken, hashToken,
  encryptField, decryptField, generateTotpSecret, getTotpUri, verifyTotp, generateBackupCode,
} from './crypto.js';
import { recordAudit } from './auditLog.js';

// Short-lived access token — a stolen one is only useful for a limited window.
const ACCESS_TOKEN_TTL_SECONDS = 20 * 60;
// Refresh sessions last a working day, then re-login is required. Rotated on
// every use (see handleRefresh) and revoked outright on password change/reset
// or an admin deactivating the account (see revokeAllSessions).
const REFRESH_TOKEN_TTL_SECONDS = 12 * 60 * 60;
const JWT_ISSUER = 'avital-heal-crm';
const JWT_AUDIENCE = 'avital-heal-crm-app';
// A distinct audience for the short-lived "password verified, MFA pending"
// token issued mid-login — getAuthPayload's strict aud check means this can
// never be mistaken for (or replayed as) a real access token.
const MFA_CHALLENGE_AUDIENCE = 'avital-heal-crm-mfa-challenge';
const MFA_CHALLENGE_TTL_SECONDS = 5 * 60;

// ─── Turnstile CAPTCHA verification ───

export async function verifyTurnstile(token, env, remoteip) {
  if (!env.TURNSTILE_SECRET_KEY) {
    console.error('Turnstile verification skipped: TURNSTILE_SECRET_KEY not configured');
    return false;
  }
  try {
    const body = new URLSearchParams({
      secret: env.TURNSTILE_SECRET_KEY,
      response: token,
    });
    if (remoteip) body.set('remoteip', remoteip);
    const response = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body,
      }
    );
    const result = await response.json();
    return result.success === true;
  } catch (e) {
    console.error('Turnstile verification error:', e);
    return false;
  }
}

// ─── Rate limiting (D1-backed fixed window) ───
// Table: rate_limits(rl_key TEXT PRIMARY KEY, count INTEGER, expires_at INTEGER)

export async function checkRateLimit(env, key, limit, windowSeconds) {
  const now = Math.floor(Date.now() / 1000);
  try {
    const row = await env.DB.prepare(
      'SELECT count, expires_at FROM rate_limits WHERE rl_key = ?'
    ).bind(key).first();

    if (!row || row.expires_at < now) {
      await env.DB.prepare(
        `INSERT INTO rate_limits (rl_key, count, expires_at) VALUES (?, 1, ?)
         ON CONFLICT(rl_key) DO UPDATE SET count = 1, expires_at = excluded.expires_at`
      ).bind(key, now + windowSeconds).run();
      return true;
    }
    if (row.count >= limit) return false;
    await env.DB.prepare(
      'UPDATE rate_limits SET count = count + 1 WHERE rl_key = ?'
    ).bind(key).run();
    return true;
  } catch (e) {
    // Fail open on infra errors — a broken limiter must not take the site down.
    console.error('Rate limit check error:', e);
    return true;
  }
}

// ─── Token pair issuance (access JWT + opaque refresh token) ───

async function issueTokenPair(env, user) {
  const tokenVersion = user.token_version || 0;
  const accessToken = await createJWT(
    {
      userId: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      tokenVersion,
      sub: String(user.id),
      iss: JWT_ISSUER,
      aud: JWT_AUDIENCE,
      jti: generateToken(16),
    },
    env.JWT_SECRET,
    ACCESS_TOKEN_TTL_SECONDS
  );

  const refreshToken = generateToken(32);
  const expiresAt = new Date(Date.now() + REFRESH_TOKEN_TTL_SECONDS * 1000).toISOString();
  await env.DB.prepare(
    `INSERT INTO refresh_tokens (user_id, token_hash, token_version, expires_at) VALUES (?, ?, ?, ?)`
  ).bind(user.id, await hashToken(refreshToken), tokenVersion, expiresAt).run();

  return { token: accessToken, refreshToken };
}

// Invalidates every outstanding session for a user: bumps tokenVersion (so any
// already-issued access token fails its next getAuthPayload check well before
// it would otherwise expire) and revokes all refresh tokens (so none of them
// can mint a fresh access token either). Used on password change/reset and
// when an admin deactivates a user.
export async function revokeAllSessions(env, userId) {
  await env.DB.prepare('UPDATE users SET token_version = token_version + 1 WHERE id = ?').bind(userId).run();
  await env.DB.prepare(
    "UPDATE refresh_tokens SET revoked_at = datetime('now') WHERE user_id = ? AND revoked_at IS NULL"
  ).bind(userId).run();
}

// ─── Auth middleware check ───
// Validates the JWT's signature/expiry, its structural claims (issuer,
// audience, subject, a jti is present), AND — unlike a stateless JWT check —
// confirms against D1 that the user is still active and that tokenVersion
// hasn't moved since the token was issued. That last part is what makes
// password-change/reset/deactivation actually revoke an already-issued
// short-lived access token instead of just the next refresh.

export async function getAuthPayload(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return null;
  if (
    payload.iss !== JWT_ISSUER ||
    payload.aud !== JWT_AUDIENCE ||
    !payload.jti ||
    payload.sub !== String(payload.userId)
  ) {
    return null;
  }
  try {
    const user = await env.DB.prepare(
      'SELECT active, token_version, mfa_enabled FROM users WHERE id = ?'
    ).bind(payload.userId).first();
    if (!user || user.active === 0 || (user.token_version || 0) !== (payload.tokenVersion || 0)) {
      return null;
    }
    // Freshly read from D1 rather than trusted from the JWT — MFA can be
    // enabled/disabled mid-session, well before the token's own expiry.
    payload.mfaEnabled = !!user.mfa_enabled;
  } catch (e) {
    // Unlike checkRateLimit, an auth check that can't confirm validity must
    // fail closed — a broken DB must not become a way to bypass revocation.
    console.error('Auth payload DB check error:', e);
    return null;
  }
  return payload;
}

// ─── Role-based access control ───

export function requireRole(payload, ...roles) {
  if (!payload || !roles.includes(payload.role)) {
    return errorResponse('אין הרשאה לפעולה זו', 403);
  }
  return null;
}

// ─── Progressive login lockout ───
// Layered on top of (not instead of) the fixed-window rate limits above:
// those cap the *rate* of attempts, this escalates a *block* the longer
// someone keeps failing against one specific email, tracked in D1 so it
// survives across the fixed-window resets. Reset to zero on success.

const LOCKOUT_THRESHOLDS = [
  { attempts: 3, seconds: 30 },
  { attempts: 5, seconds: 5 * 60 },
  { attempts: 8, seconds: 30 * 60 },
  { attempts: 12, seconds: 2 * 60 * 60 },
];

function lockoutSecondsFor(failedCount) {
  let seconds = 0;
  for (const threshold of LOCKOUT_THRESHOLDS) {
    if (failedCount >= threshold.attempts) seconds = threshold.seconds;
  }
  return seconds;
}

async function getLoginLockout(env, email) {
  try {
    return await env.DB.prepare(
      'SELECT failed_count, locked_until FROM login_attempts WHERE email = ?'
    ).bind(email).first();
  } catch (e) {
    // Fail open, same posture as checkRateLimit — a broken lockout tracker
    // must not lock everyone out (or lock no one out) site-wide.
    console.error('Login lockout read error:', e);
    return null;
  }
}

async function recordFailedLogin(env, email) {
  try {
    const existing = await env.DB.prepare(
      'SELECT failed_count FROM login_attempts WHERE email = ?'
    ).bind(email).first();
    const failedCount = (existing?.failed_count || 0) + 1;
    const lockSeconds = lockoutSecondsFor(failedCount);
    const lockedUntil = lockSeconds ? new Date(Date.now() + lockSeconds * 1000).toISOString() : null;
    await env.DB.prepare(
      `INSERT INTO login_attempts (email, failed_count, locked_until, updated_at)
       VALUES (?, ?, ?, datetime('now'))
       ON CONFLICT(email) DO UPDATE SET failed_count = excluded.failed_count, locked_until = excluded.locked_until, updated_at = datetime('now')`
    ).bind(email, failedCount, lockedUntil).run();
  } catch (e) {
    console.error('Record failed login error:', e);
  }
}

async function clearLoginLockout(env, email) {
  try {
    await env.DB.prepare(
      "UPDATE login_attempts SET failed_count = 0, locked_until = NULL, updated_at = datetime('now') WHERE email = ?"
    ).bind(email).run();
  } catch (e) {
    console.error('Clear login lockout error:', e);
  }
}

// Finishes a login once the caller is fully authenticated — password alone
// for non-MFA accounts, or password + verified TOTP/backup code otherwise.
// Shared by handleLogin (non-MFA path) and handleMfaLoginVerify.
async function completeSuccessfulLogin(env, user, auditMeta) {
  await clearLoginLockout(env, user.email);
  await env.DB.prepare(
    "UPDATE users SET last_login_at = datetime('now'), last_login_ip = ? WHERE id = ?"
  ).bind(auditMeta.ip, user.id).run();
  const { token, refreshToken } = await issueTokenPair(env, user);
  await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'login', entityType: 'user', entityId: user.id, result: 'success', metadata: auditMeta });
  return { token, refreshToken, user: { id: user.id, email: user.email, name: user.name, role: user.role, mfaEnabled: !!user.mfa_enabled } };
}

// ─── Login (email + password) ───

export async function handleLogin(request, env) {
  try {
    const { email, password, 'cf-turnstile-response': turnstileToken } = await request.json();
    if (!email || !password) {
      return errorResponse('נדרש אימייל וסיסמה', 400, request);
    }
    const normalizedEmail = email.toLowerCase().trim();
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = (request.headers.get('User-Agent') || 'unknown').slice(0, 200);
    const auditMeta = { ip, userAgent };

    if (!(await checkRateLimit(env, `login:ip:${ip}`, 15, 900))) {
      return errorResponse('יותר מדי ניסיונות כניסה — נסי שוב בעוד כמה דקות', 429, request);
    }
    if (!(await checkRateLimit(env, `login:email:${normalizedEmail}`, 8, 900))) {
      return errorResponse('יותר מדי ניסיונות כניסה — נסי שוב בעוד כמה דקות', 429, request);
    }

    const lockout = await getLoginLockout(env, normalizedEmail);
    if (lockout?.locked_until && new Date(lockout.locked_until) > new Date()) {
      await recordAudit(env, { userEmail: normalizedEmail, action: 'login', entityType: 'user', result: 'failure', metadata: { ...auditMeta, reason: 'locked_out' } });
      return errorResponse('יותר מדי ניסיונות כניסה כושלים — נסי שוב מאוחר יותר', 429, request);
    }

    if (!turnstileToken) {
      return errorResponse('אימות CAPTCHA נדרש', 403, request);
    }
    if (!(await verifyTurnstile(turnstileToken, env, ip))) {
      return errorResponse('אימות CAPTCHA נכשל', 403, request);
    }

    const user = await env.DB.prepare(
      'SELECT id, email, name, role, password_hash, active, token_version, mfa_enabled FROM users WHERE email = ?'
    ).bind(normalizedEmail).first();
    if (!user) {
      await recordFailedLogin(env, normalizedEmail);
      await recordAudit(env, { userEmail: normalizedEmail, action: 'login', entityType: 'user', result: 'failure', metadata: auditMeta });
      return errorResponse('אימייל או סיסמה שגויים', 401, request);
    }
    // Block inactive users
    if (user.active === 0) {
      await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'login', entityType: 'user', entityId: user.id, result: 'failure', metadata: { ...auditMeta, reason: 'inactive' } });
      return errorResponse('החשבון אינו פעיל — פנה למנהל המערכת', 403, request);
    }
    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      await recordFailedLogin(env, normalizedEmail);
      await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'login', entityType: 'user', entityId: user.id, result: 'failure', metadata: auditMeta });
      return errorResponse('אימייל או סיסמה שגויים', 401, request);
    }

    // Opportunistic migration: re-hash with the current iteration count now
    // that we have the plaintext, rather than a bulk background migration.
    if (needsRehash(user.password_hash)) {
      const rehashed = await hashPassword(password);
      await env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(rehashed, user.id).run();
    }

    // Password is correct. If MFA is enabled, the login isn't complete yet —
    // issue a short-lived challenge token (a different audience than a real
    // access token, so it can't be used as one) and require the second factor.
    if (user.mfa_enabled) {
      const mfaToken = await createJWT(
        { userId: user.id, sub: String(user.id), iss: JWT_ISSUER, aud: MFA_CHALLENGE_AUDIENCE, jti: generateToken(16) },
        env.JWT_SECRET,
        MFA_CHALLENGE_TTL_SECONDS
      );
      return jsonResponse({ mfaRequired: true, mfaToken }, 200, request);
    }

    const body = await completeSuccessfulLogin(env, user, auditMeta);
    return jsonResponse(body, 200, request);
  } catch (e) {
    console.error('Login error:', e);
    return errorResponse('שגיאת כניסה', 500, request);
  }
}

// ─── MFA: second step of login (public — auth is the mfaToken itself) ───

async function consumeBackupCode(env, userId, rawCode) {
  const normalized = String(rawCode).trim().toUpperCase();
  const codeHash = await hashToken(normalized);
  const row = await env.DB.prepare(
    'SELECT id FROM mfa_backup_codes WHERE user_id = ? AND code_hash = ? AND used_at IS NULL'
  ).bind(userId, codeHash).first();
  if (!row) return false;
  await env.DB.prepare("UPDATE mfa_backup_codes SET used_at = datetime('now') WHERE id = ?").bind(row.id).run();
  return true;
}

export async function handleMfaLoginVerify(request, env) {
  try {
    const { mfaToken, code, backupCode } = await request.json();
    if (!mfaToken || (!code && !backupCode)) {
      return errorResponse('נדרש קוד אימות', 400, request);
    }
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    const userAgent = (request.headers.get('User-Agent') || 'unknown').slice(0, 200);
    const auditMeta = { ip, userAgent };

    if (!(await checkRateLimit(env, `mfa-verify:ip:${ip}`, 15, 900))) {
      return errorResponse('יותר מדי ניסיונות — נסי שוב מאוחר יותר', 429, request);
    }

    const challenge = await verifyJWT(mfaToken, env.JWT_SECRET);
    if (
      !challenge ||
      challenge.iss !== JWT_ISSUER ||
      challenge.aud !== MFA_CHALLENGE_AUDIENCE ||
      !challenge.jti ||
      challenge.sub !== String(challenge.userId)
    ) {
      return errorResponse('פג תוקף האימות — יש להתחבר מחדש', 401, request);
    }

    const user = await env.DB.prepare(
      'SELECT id, email, name, role, active, token_version, mfa_enabled, mfa_secret, mfa_last_counter FROM users WHERE id = ?'
    ).bind(challenge.userId).first();
    if (!user || user.active === 0 || !user.mfa_enabled) {
      return errorResponse('משתמש לא נמצא או שאימות דו-שלבי אינו פעיל', 401, request);
    }

    if (backupCode) {
      const ok = await consumeBackupCode(env, user.id, backupCode);
      if (!ok) {
        await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'mfa_verify', entityType: 'user', entityId: user.id, result: 'failure', metadata: { ...auditMeta, method: 'backup_code' } });
        return errorResponse('קוד גיבוי שגוי או שכבר נוצל', 401, request);
      }
      const body = await completeSuccessfulLogin(env, user, auditMeta);
      await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'mfa_verify', entityType: 'user', entityId: user.id, result: 'success', metadata: { ...auditMeta, method: 'backup_code' } });
      return jsonResponse(body, 200, request);
    }

    const secret = await decryptField(env, user.mfa_secret);
    const result = await verifyTotp(secret, code, { lastCounter: user.mfa_last_counter });
    if (!result.valid) {
      await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'mfa_verify', entityType: 'user', entityId: user.id, result: 'failure', metadata: { ...auditMeta, method: 'totp' } });
      return errorResponse('קוד אימות שגוי', 401, request);
    }
    await env.DB.prepare('UPDATE users SET mfa_last_counter = ? WHERE id = ?').bind(result.counter, user.id).run();

    const body = await completeSuccessfulLogin(env, user, auditMeta);
    await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'mfa_verify', entityType: 'user', entityId: user.id, result: 'success', metadata: { ...auditMeta, method: 'totp' } });
    return jsonResponse(body, 200, request);
  } catch (e) {
    console.error('MFA verify error:', e);
    return errorResponse('שגיאת אימות דו-שלבי', 500, request);
  }
}

// ─── MFA: self-service enrollment (protected — payload comes from getAuthPayload) ───

export async function handleMfaSetupStart(request, env, payload) {
  try {
    const user = await env.DB.prepare('SELECT id, email, mfa_enabled FROM users WHERE id = ?').bind(payload.userId).first();
    if (!user) return errorResponse('משתמש לא נמצא', 404, request);
    if (user.mfa_enabled) return errorResponse('אימות דו-שלבי כבר פעיל', 400, request);

    const secret = generateTotpSecret();
    await env.DB.prepare('UPDATE users SET mfa_secret = ? WHERE id = ?').bind(await encryptField(env, secret), user.id).run();

    return jsonResponse({ secret, otpauthUri: getTotpUri(secret, user.email) }, 200, request);
  } catch (e) {
    console.error('MFA setup start error:', e);
    return errorResponse('שגיאה בהפעלת אימות דו-שלבי', 500, request);
  }
}

export async function handleMfaSetupVerify(request, env, payload) {
  try {
    const { code } = await request.json();
    if (!code) return errorResponse('נדרש קוד אימות', 400, request);

    const user = await env.DB.prepare('SELECT id, email, mfa_enabled, mfa_secret FROM users WHERE id = ?').bind(payload.userId).first();
    if (!user) return errorResponse('משתמש לא נמצא', 404, request);
    if (user.mfa_enabled) return errorResponse('אימות דו-שלבי כבר פעיל', 400, request);
    if (!user.mfa_secret) return errorResponse('יש להתחיל בתהליך ההגדרה מחדש', 400, request);

    const secret = await decryptField(env, user.mfa_secret);
    const result = await verifyTotp(secret, code);
    if (!result.valid) return errorResponse('קוד אימות שגוי', 401, request);

    await env.DB.prepare(
      'UPDATE users SET mfa_enabled = 1, mfa_last_counter = ? WHERE id = ?'
    ).bind(result.counter, user.id).run();

    const backupCodes = [];
    for (let i = 0; i < 8; i++) {
      const raw = generateBackupCode();
      backupCodes.push(raw);
      await env.DB.prepare(
        'INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES (?, ?)'
      ).bind(user.id, await hashToken(raw.toUpperCase())).run();
    }

    await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'mfa_enable', entityType: 'user', entityId: user.id, result: 'success' });
    return jsonResponse({ message: 'אימות דו-שלבי הופעל בהצלחה', backupCodes }, 200, request);
  } catch (e) {
    console.error('MFA setup verify error:', e);
    return errorResponse('שגיאה באימות הקוד', 500, request);
  }
}

export async function handleMfaDisable(request, env, payload) {
  try {
    const { currentPassword } = await request.json();
    if (!currentPassword) return errorResponse('נדרשת סיסמה נוכחית', 400, request);

    const user = await env.DB.prepare('SELECT id, email, password_hash FROM users WHERE id = ?').bind(payload.userId).first();
    if (!user) return errorResponse('משתמש לא נמצא', 404, request);
    const valid = await verifyPassword(currentPassword, user.password_hash);
    if (!valid) return errorResponse('סיסמה שגויה', 401, request);

    await env.DB.prepare(
      "UPDATE users SET mfa_enabled = 0, mfa_secret = NULL, mfa_last_counter = NULL WHERE id = ?"
    ).bind(user.id).run();
    await env.DB.prepare('DELETE FROM mfa_backup_codes WHERE user_id = ?').bind(user.id).run();

    await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'mfa_disable', entityType: 'user', entityId: user.id, result: 'success' });
    return jsonResponse({ message: 'אימות דו-שלבי בוטל' }, 200, request);
  } catch (e) {
    console.error('MFA disable error:', e);
    return errorResponse('שגיאה בביטול אימות דו-שלבי', 500, request);
  }
}

// ─── Refresh (rotates the refresh token, issues a new access token) ───

export async function handleRefresh(request, env) {
  try {
    const { refreshToken } = await request.json();
    if (!refreshToken) return errorResponse('נדרש טוקן רענון', 400, request);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!(await checkRateLimit(env, `refresh:ip:${ip}`, 60, 900))) {
      return errorResponse('יותר מדי בקשות — נסי שוב מאוחר יותר', 429, request);
    }

    const stored = await env.DB.prepare(
      'SELECT id, user_id, expires_at, revoked_at FROM refresh_tokens WHERE token_hash = ?'
    ).bind(await hashToken(refreshToken)).first();
    if (!stored) return errorResponse('טוקן רענון לא תקין', 401, request);

    // A revoked token being presented again means it was already rotated (or
    // explicitly logged out) and is now being replayed — treat as theft and
    // kill every session for this user rather than trusting either copy.
    if (stored.revoked_at) {
      await env.DB.prepare(
        "UPDATE refresh_tokens SET revoked_at = datetime('now') WHERE user_id = ? AND revoked_at IS NULL"
      ).bind(stored.user_id).run();
      await recordAudit(env, { userId: stored.user_id, action: 'refresh_reuse_detected', entityType: 'user', entityId: stored.user_id, result: 'failure' });
      return errorResponse('טוקן רענון לא תקין', 401, request);
    }
    if (new Date(stored.expires_at) < new Date()) {
      return errorResponse('טוקן רענון פג תוקף', 401, request);
    }

    const user = await env.DB.prepare(
      'SELECT id, email, name, role, active, token_version FROM users WHERE id = ?'
    ).bind(stored.user_id).first();
    if (!user || user.active === 0) {
      return errorResponse('החשבון אינו פעיל', 403, request);
    }

    // Rotate: this refresh token is now spent, whether or not the pair below succeeds.
    await env.DB.prepare("UPDATE refresh_tokens SET revoked_at = datetime('now') WHERE id = ?").bind(stored.id).run();

    const pair = await issueTokenPair(env, user);
    return jsonResponse({ token: pair.token, refreshToken: pair.refreshToken }, 200, request);
  } catch (e) {
    console.error('Refresh error:', e);
    return errorResponse('שגיאה ברענון טוקן', 500, request);
  }
}

// ─── Logout (revokes the refresh token server-side) ───
// Public by design (no Bearer check) — possession of the refresh token is
// itself the authorization to revoke it, same as a password-reset token, and
// this must still work even if the access token already expired.

export async function handleLogout(request, env) {
  try {
    const { refreshToken } = await request.json().catch(() => ({}));
    if (refreshToken) {
      await env.DB.prepare(
        "UPDATE refresh_tokens SET revoked_at = datetime('now') WHERE token_hash = ? AND revoked_at IS NULL"
      ).bind(await hashToken(refreshToken)).run();
    }
  } catch (e) {
    console.error('Logout error:', e);
  }
  // Always report success — the client clears its own storage regardless,
  // and a server-side hiccup here is not something the user needs to see.
  return jsonResponse({ message: 'התנתקת בהצלחה' }, 200, request);
}

// ─── Verify token ───

export async function handleVerify(request, env) {
  const payload = await getAuthPayload(request, env);
  if (!payload) return errorResponse('Token expired', 401, request);
  return jsonResponse({
    valid: true,
    user: { id: payload.userId, email: payload.email, name: payload.name, role: payload.role, mfaEnabled: !!payload.mfaEnabled },
  }, 200, request);
}

// ─── Request password reset ───

export async function handleRequestReset(request, env) {
  try {
    const { email, 'cf-turnstile-response': turnstileToken } = await request.json();
    if (!email) return errorResponse('נדרש אימייל', 400, request);
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    if (!(await checkRateLimit(env, `reset-request:ip:${ip}`, 5, 3600))) {
      return errorResponse('יותר מדי בקשות איפוס — נסי שוב בעוד שעה', 429, request);
    }
    if (!(await checkRateLimit(env, `reset-request:email:${email.toLowerCase().trim()}`, 3, 3600))) {
      return errorResponse('יותר מדי בקשות איפוס — נסי שוב בעוד שעה', 429, request);
    }
    if (!turnstileToken) {
      return errorResponse('אימות CAPTCHA נדרש', 403, request);
    }
    if (!(await verifyTurnstile(turnstileToken, env, ip))) {
      return errorResponse('אימות CAPTCHA נכשל', 403, request);
    }

    const user = await env.DB.prepare(
      'SELECT id, name FROM users WHERE email = ? AND active = 1'
    ).bind(email.toLowerCase().trim()).first();
    // Always return success (prevent email enumeration)
    if (!user) {
      return jsonResponse({ message: 'אם האימייל קיים במערכת, נשלח קישור לאיפוס' }, 200, request);
    }
    const token = generateToken(32);
    const expiresAt = new Date(Date.now() + 3600 * 1000).toISOString();
    // Only the hash is persisted — a database read alone can't redeem this token.
    await env.DB.prepare(
      "INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)"
    ).bind(user.id, await hashToken(token), expiresAt).run();
    // Send reset email via Google Apps Script — the RAW token goes only here.
    try {
      await fetch(env.RESET_EMAIL_SCRIPT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email: email.toLowerCase().trim(),
          name: user.name,
          resetLink: `https://avital-heal.com/admin?reset=${token}`,
        }),
      });
    } catch (emailErr) {
      console.error('Reset email send error:', emailErr);
    }
    return jsonResponse({ message: 'אם האימייל קיים במערכת, נשלח קישור לאיפוס' }, 200, request);
  } catch (e) {
    console.error('Reset request error:', e);
    return errorResponse('שגיאה בבקשת איפוס', 500, request);
  }
}

// ─── Execute password reset ───

export async function handleExecuteReset(request, env) {
  try {
    const { token, newPassword } = await request.json();
    if (!token || !newPassword) {
      return errorResponse('נדרש טוקן וסיסמה חדשה', 400, request);
    }
    if (newPassword.length < 8) {
      return errorResponse('הסיסמה חייבת להכיל לפחות 8 תווים', 400, request);
    }
    const reset = await env.DB.prepare(
      "SELECT id, user_id, expires_at, used FROM password_resets WHERE token = ?"
    ).bind(await hashToken(token)).first();
    if (!reset || reset.used) {
      return errorResponse('קישור איפוס לא תקין או שפג תוקפו', 400, request);
    }
    if (new Date(reset.expires_at) < new Date()) {
      return errorResponse('קישור האיפוס פג תוקף', 400, request);
    }
    const passwordHash = await hashPassword(newPassword);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(passwordHash, reset.user_id).run();
    await env.DB.prepare(
      'UPDATE password_resets SET used = 1 WHERE id = ?'
    ).bind(reset.id).run();
    await revokeAllSessions(env, reset.user_id);
    await recordAudit(env, { userId: reset.user_id, action: 'password_reset', entityType: 'user', entityId: reset.user_id, result: 'success', metadata: { sessionsRevoked: true } });
    return jsonResponse({ message: 'הסיסמה עודכנה בהצלחה' }, 200, request);
  } catch (e) {
    console.error('Reset execute error:', e);
    return errorResponse('שגיאה באיפוס סיסמה', 500, request);
  }
}

// ─── Change password (authenticated) ───

export async function handleChangePassword(request, env) {
  try {
    const payload = await getAuthPayload(request, env);
    if (!payload) return errorResponse('Unauthorized', 401, request);
    const { currentPassword, newPassword } = await request.json();
    if (!currentPassword || !newPassword) {
      return errorResponse('נדרשות סיסמה נוכחית וחדשה', 400, request);
    }
    if (newPassword.length < 8) {
      return errorResponse('הסיסמה חייבת להכיל לפחות 8 תווים', 400, request);
    }
    const user = await env.DB.prepare(
      'SELECT password_hash FROM users WHERE id = ?'
    ).bind(payload.userId).first();
    if (!user) return errorResponse('משתמש לא נמצא', 404, request);
    const valid = await verifyPassword(currentPassword, user.password_hash);
    if (!valid) return errorResponse('סיסמה נוכחית שגויה', 401, request);
    const hash = await hashPassword(newPassword);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(hash, payload.userId).run();
    // Invalidates the very token used to make this request too — the
    // frontend logs the user out immediately after a successful change
    // rather than letting them hit a confusing 401 on their next click.
    await revokeAllSessions(env, payload.userId);
    await recordAudit(env, { userId: payload.userId, userEmail: payload.email, action: 'password_change', entityType: 'user', entityId: payload.userId, result: 'success', metadata: { sessionsRevoked: true } });
    return jsonResponse({ message: 'הסיסמה עודכנה בהצלחה' }, 200, request);
  } catch (e) {
    console.error('Change password error:', e);
    return errorResponse('שגיאה בשינוי סיסמה', 500, request);
  }
}
