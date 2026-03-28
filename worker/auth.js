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

export async function verifyTurnstile(token, env) {
  try {
    const response = await fetch(
      'https://challenges.cloudflare.com/turnstile/v0/siteverify',
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          secret: env.TURNSTILE_SECRET_KEY,
          response: token,
        }),
      }
    );
    const result = await response.json();
    return result.success === true;
  } catch (e) {
    console.error('Turnstile verification error:', e);
    return false;
  }
}

// ─── Auth middleware check ───

export async function isAuthorized(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  const token = authHeader.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);
  return payload !== null;
}

// ─── Login (email + password) ───

export async function handleLogin(request, env) {
  try {
    const { email, password } = await request.json();
    if (!email || !password) {
      return errorResponse('נדרש אימייל וסיסמה', 400);
    }
    const user = await env.DB.prepare(
      'SELECT id, email, name, role, password_hash, active FROM users WHERE email = ?'
    ).bind(email.toLowerCase().trim()).first();
    if (!user) {
      return errorResponse('אימייל או סיסמה שגויים', 401);
    }
    // Block inactive users
    if (user.active === 0) {
      return errorResponse('החשבון אינו פעיל — פנה למנהל המערכת', 403);
    }
    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      return errorResponse('אימייל או סיסמה שגויים', 401);
    }
    const token = await createJWT(
      { userId: user.id, email: user.email, name: user.name, role: user.role },
      env.JWT_SECRET
    );
    return jsonResponse({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    console.error('Login error:', e);
    return errorResponse('שגיאת כניסה', 500);
  }
}

// ─── Verify token ───

export async function handleVerify(request, env) {
  const authHeader = request.headers.get('Authorization');
  const token = authHeader?.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return errorResponse('Token expired', 401);
  return jsonResponse({
    valid: true,
    user: { id: payload.userId, email: payload.email, name: payload.name, role: payload.role },
  });
}

// ─── Request password reset ───

export async function handleRequestReset(request, env) {
  try {
    const { email } = await request.json();
    if (!email) return errorResponse('נדרש אימייל', 400);
    const user = await env.DB.prepare(
      'SELECT id, name FROM users WHERE email = ? AND active = 1'
    ).bind(email.toLowerCase().trim()).first();
    // Always return success (prevent email enumeration)
    if (!user) {
      return jsonResponse({ message: 'אם האימייל קיים במערכת, נשלח קישור לאיפוס' });
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
    return jsonResponse({ message: 'אם האימייל קיים במערכת, נשלח קישור לאיפוס' });
  } catch (e) {
    console.error('Reset request error:', e);
    return errorResponse('שגיאה בבקשת איפוס', 500);
  }
}

// ─── Execute password reset ───

export async function handleExecuteReset(request, env) {
  try {
    const { token, newPassword } = await request.json();
    if (!token || !newPassword) {
      return errorResponse('נדרש טוקן וסיסמה חדשה', 400);
    }
    if (newPassword.length < 8) {
      return errorResponse('הסיסמה חייבת להכיל לפחות 8 תווים', 400);
    }
    const reset = await env.DB.prepare(
      "SELECT id, user_id, expires_at, used FROM password_resets WHERE token = ?"
    ).bind(token).first();
    if (!reset || reset.used) {
      return errorResponse('קישור איפוס לא תקין או שפג תוקפו', 400);
    }
    if (new Date(reset.expires_at) < new Date()) {
      return errorResponse('קישור האיפוס פג תוקף', 400);
    }
    const passwordHash = await hashPassword(newPassword);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(passwordHash, reset.user_id).run();
    await env.DB.prepare(
      'UPDATE password_resets SET used = 1 WHERE id = ?'
    ).bind(reset.id).run();
    return jsonResponse({ message: 'הסיסמה עודכנה בהצלחה' });
  } catch (e) {
    console.error('Reset execute error:', e);
    return errorResponse('שגיאה באיפוס סיסמה', 500);
  }
}

// ─── Change password (authenticated) ───

export async function handleChangePassword(request, env) {
  try {
    const authHeader = request.headers.get('Authorization');
    const payload = await verifyJWT(authHeader?.slice(7), env.JWT_SECRET);
    if (!payload) return errorResponse('Unauthorized', 401);
    const { currentPassword, newPassword } = await request.json();
    if (!currentPassword || !newPassword) {
      return errorResponse('נדרשות סיסמה נוכחית וחדשה', 400);
    }
    if (newPassword.length < 8) {
      return errorResponse('הסיסמה חייבת להכיל לפחות 8 תווים', 400);
    }
    const user = await env.DB.prepare(
      'SELECT password_hash FROM users WHERE id = ?'
    ).bind(payload.userId).first();
    if (!user) return errorResponse('משתמש לא נמצא', 404);
    const valid = await verifyPassword(currentPassword, user.password_hash);
    if (!valid) return errorResponse('סיסמה נוכחית שגויה', 401);
    const hash = await hashPassword(newPassword);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(hash, payload.userId).run();
    return jsonResponse({ message: 'הסיסמה עודכנה בהצלחה' });
  } catch (e) {
    console.error('Change password error:', e);
    return errorResponse('שגיאה בשינוי סיסמה', 500);
  }
}
