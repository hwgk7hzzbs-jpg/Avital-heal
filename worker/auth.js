/**
 * @file auth.js
 * @description Authentication handlers: login, verify, password reset,
 *              user management, and Turnstile CAPTCHA verification.
 * @module Auth
 * @security CRITICAL — handles credentials and session tokens.
 */

import { jsonResponse, errorResponse } from './utils.js';
import { hashPassword, verifyPassword, createJWT, verifyJWT, generateToken } from './crypto.js';

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

// ─── Auth middleware check ───

export async function getAuthPayload(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7);
  return await verifyJWT(token, env.JWT_SECRET);
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
      'SELECT id, email, name, role, password_hash, active FROM users WHERE email = ?'
    ).bind(email.toLowerCase().trim()).first();
    if (!user) {
      return errorResponse('אימייל או סיסמה שגויים', 401, request);
    }
    // Block inactive users
    if (user.active === 0) {
      return errorResponse('החשבון אינו פעיל — פנה למנהל המערכת', 403, request);
    }
    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      return errorResponse('אימייל או סיסמה שגויים', 401, request);
    }
    const token = await createJWT(
      { userId: user.id, email: user.email, name: user.name, role: user.role },
      env.JWT_SECRET
    );
    return jsonResponse({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } }, 200, request);
  } catch (e) {
    console.error('Login error:', e);
    return errorResponse('שגיאת כניסה', 500, request);
  }
}

// ─── Verify token ───

export async function handleVerify(request, env) {
  const authHeader = request.headers.get('Authorization');
  const token = authHeader?.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);
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
    await env.DB.prepare(
      "INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)"
    ).bind(user.id, token, expiresAt).run();
    // Send reset email via Google Apps Script
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
    ).bind(token).first();
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
    return jsonResponse({ message: 'הסיסמה עודכנה בהצלחה' }, 200, request);
  } catch (e) {
    console.error('Reset execute error:', e);
    return errorResponse('שגיאה באיפוס סיסמה', 500, request);
  }
}

// ─── Change password (authenticated) ───

export async function handleChangePassword(request, env) {
  try {
    const authHeader = request.headers.get('Authorization');
    const payload = await verifyJWT(authHeader?.slice(7), env.JWT_SECRET);
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
    return jsonResponse({ message: 'הסיסמה עודכנה בהצלחה' }, 200, request);
  } catch (e) {
    console.error('Change password error:', e);
    return errorResponse('שגיאה בשינוי סיסמה', 500, request);
  }
}
