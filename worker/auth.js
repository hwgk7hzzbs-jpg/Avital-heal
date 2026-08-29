/**
 * @file auth.js
 * @description Authentication handlers: login, token refresh/logout, verify,
 *              password reset, and Turnstile CAPTCHA verification.
 * @module Auth
 * @security CRITICAL — handles credentials and session tokens.
 */

import { jsonResponse, errorResponse } from './utils.js';
import { hashPassword, verifyPassword, needsRehash, createJWT, verifyJWT, generateToken, hashToken } from './crypto.js';
import { recordAudit } from './auditLog.js';

// Short-lived access token — a stolen one is only useful for a limited window.
const ACCESS_TOKEN_TTL_SECONDS = 20 * 60;
// Refresh sessions last a working day, then re-login is required. Rotated on
// every use (see handleRefresh) and revoked outright on password change/reset
// or an admin deactivating the account (see revokeAllSessions).
const REFRESH_TOKEN_TTL_SECONDS = 12 * 60 * 60;
const JWT_ISSUER = 'avital-heal-crm';
const JWT_AUDIENCE = 'avital-heal-crm-app';

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
      'SELECT active, token_version FROM users WHERE id = ?'
    ).bind(payload.userId).first();
    if (!user || user.active === 0 || (user.token_version || 0) !== (payload.tokenVersion || 0)) {
      return null;
    }
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

// ─── Login (email + password) ───

export async function handleLogin(request, env) {
  try {
    const { email, password, 'cf-turnstile-response': turnstileToken } = await request.json();
    if (!email || !password) {
      return errorResponse('נדרש אימייל וסיסמה', 400, request);
    }
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';

    if (!(await checkRateLimit(env, `login:ip:${ip}`, 15, 900))) {
      return errorResponse('יותר מדי ניסיונות כניסה — נסי שוב בעוד כמה דקות', 429, request);
    }
    if (!(await checkRateLimit(env, `login:email:${email.toLowerCase().trim()}`, 8, 900))) {
      return errorResponse('יותר מדי ניסיונות כניסה — נסי שוב בעוד כמה דקות', 429, request);
    }
    if (!turnstileToken) {
      return errorResponse('אימות CAPTCHA נדרש', 403, request);
    }
    if (!(await verifyTurnstile(turnstileToken, env, ip))) {
      return errorResponse('אימות CAPTCHA נכשל', 403, request);
    }

    const user = await env.DB.prepare(
      'SELECT id, email, name, role, password_hash, active, token_version FROM users WHERE email = ?'
    ).bind(email.toLowerCase().trim()).first();
    if (!user) {
      await recordAudit(env, { userEmail: email.toLowerCase().trim(), action: 'login', entityType: 'user', result: 'failure' });
      return errorResponse('אימייל או סיסמה שגויים', 401, request);
    }
    // Block inactive users
    if (user.active === 0) {
      await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'login', entityType: 'user', entityId: user.id, result: 'failure', metadata: { reason: 'inactive' } });
      return errorResponse('החשבון אינו פעיל — פנה למנהל המערכת', 403, request);
    }
    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'login', entityType: 'user', entityId: user.id, result: 'failure' });
      return errorResponse('אימייל או סיסמה שגויים', 401, request);
    }

    // Opportunistic migration: re-hash with the current iteration count now
    // that we have the plaintext, rather than a bulk background migration.
    if (needsRehash(user.password_hash)) {
      const rehashed = await hashPassword(password);
      await env.DB.prepare("UPDATE users SET password_hash = ? WHERE id = ?").bind(rehashed, user.id).run();
    }

    const { token, refreshToken } = await issueTokenPair(env, user);
    await recordAudit(env, { userId: user.id, userEmail: user.email, action: 'login', entityType: 'user', entityId: user.id, result: 'success' });
    return jsonResponse({ token, refreshToken, user: { id: user.id, email: user.email, name: user.name, role: user.role } }, 200, request);
  } catch (e) {
    console.error('Login error:', e);
    return errorResponse('שגיאת כניסה', 500, request);
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
    user: { id: payload.userId, email: payload.email, name: payload.name, role: payload.role },
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
