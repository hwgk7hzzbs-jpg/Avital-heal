/**
 * @file users.js
 * @description User management CRUD — admin only.
 * @module Users
 * @security All endpoints require admin role.
 */

import { jsonResponse, errorResponse } from './utils.js';
import { hashPassword, verifyJWT } from './crypto.js';
import { recordAudit } from './auditLog.js';

// ─── Helper: extract user from JWT ───

async function getAuthUser(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7);
  return await verifyJWT(token, env.JWT_SECRET);
}

// ─── Helper: require admin role ───

function requireAdmin(payload) {
  if (!payload || payload.role !== 'admin') {
    return errorResponse('אין הרשאה — נדרש תפקיד מנהל', 403);
  }
  return null;
}

// ─── Validation helpers ───

function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
  if (password.length < 8) return 'הסיסמה חייבת להכיל לפחות 8 תווים';
  if (!/[A-Z]/.test(password)) return 'הסיסמה חייבת להכיל אות גדולה';
  if (!/[a-z]/.test(password)) return 'הסיסמה חייבת להכיל אות קטנה';
  if (!/[0-9]/.test(password)) return 'הסיסמה חייבת להכיל מספר';
  return null;
}

const VALID_ROLES = ['admin', 'therapist', 'viewer'];

// ─── GET /api/users ───

export async function handleGetUsers(request, env) {
  const payload = await getAuthUser(request, env);
  const denied = requireAdmin(payload);
  if (denied) return denied;

  try {
    const { results } = await env.DB.prepare(
      'SELECT id, name, email, role, active, created_at, updated_at FROM users ORDER BY id'
    ).all();
    return jsonResponse(results || []);
  } catch (e) {
    console.error('Get users error:', e);
    return errorResponse('שגיאה בטעינת משתמשים', 500);
  }
}

// ─── POST /api/users ───

export async function handleCreateUser(request, env) {
  const payload = await getAuthUser(request, env);
  const denied = requireAdmin(payload);
  if (denied) return denied;

  try {
    const { name, email, password, role } = await request.json();

    // Validate
    if (!name || name.trim().length < 2) {
      return errorResponse('שם חייב להכיל לפחות 2 תווים', 400);
    }
    if (!email || !validateEmail(email)) {
      return errorResponse('אימייל לא תקין', 400);
    }
    if (!password) {
      return errorResponse('נדרשת סיסמה', 400);
    }
    const passErr = validatePassword(password);
    if (passErr) return errorResponse(passErr, 400);

    if (!role || !VALID_ROLES.includes(role)) {
      return errorResponse('תפקיד לא תקין — admin/therapist/viewer', 400);
    }

    // Check unique email
    const existing = await env.DB.prepare(
      'SELECT id FROM users WHERE email = ?'
    ).bind(email.toLowerCase().trim()).first();
    if (existing) {
      return errorResponse('כבר קיים משתמש עם אימייל זה', 409);
    }

    const passwordHash = await hashPassword(password);
    const result = await env.DB.prepare(
      `INSERT INTO users (name, email, role, password_hash, active, created_at, updated_at)
       VALUES (?, ?, ?, ?, 1, datetime('now'), datetime('now'))`
    ).bind(name.trim(), email.toLowerCase().trim(), role, passwordHash).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'create', entityType: 'user', entityId: result.meta.last_row_id, result: 'success',
      metadata: { role },
    });

    return jsonResponse({
      id: result.meta.last_row_id,
      name: name.trim(),
      email: email.toLowerCase().trim(),
      role,
      active: 1,
    }, 201);
  } catch (e) {
    console.error('Create user error:', e);
    return errorResponse('שגיאה ביצירת משתמש', 500);
  }
}

// ─── PUT /api/users/:id ───

export async function handleUpdateUser(request, env, userId) {
  const payload = await getAuthUser(request, env);
  const denied = requireAdmin(payload);
  if (denied) return denied;

  try {
    const { name, email, role, active } = await request.json();

    // Check user exists
    const user = await env.DB.prepare('SELECT id, role FROM users WHERE id = ?').bind(userId).first();
    if (!user) return errorResponse('משתמש לא נמצא', 404);

    // Validate
    if (name !== undefined && name.trim().length < 2) {
      return errorResponse('שם חייב להכיל לפחות 2 תווים', 400);
    }
    if (email !== undefined && !validateEmail(email)) {
      return errorResponse('אימייל לא תקין', 400);
    }
    if (role !== undefined && !VALID_ROLES.includes(role)) {
      return errorResponse('תפקיד לא תקין — admin/therapist/viewer', 400);
    }

    // Check unique email (if changing)
    if (email !== undefined) {
      const existing = await env.DB.prepare(
        'SELECT id FROM users WHERE email = ? AND id != ?'
      ).bind(email.toLowerCase().trim(), userId).first();
      if (existing) {
        return errorResponse('כבר קיים משתמש עם אימייל זה', 409);
      }
    }

    // Prevent deactivating / demoting last admin
    if ((role !== undefined && role !== 'admin') || (active !== undefined && !active)) {
      if (user.role === 'admin') {
        const adminCount = await env.DB.prepare(
          "SELECT COUNT(*) as cnt FROM users WHERE role = 'admin' AND active = 1 AND id != ?"
        ).bind(userId).first();
        if (adminCount.cnt === 0) {
          return errorResponse('לא ניתן להסיר את המנהל האחרון', 403);
        }
      }
    }

    // Build dynamic update
    const fields = [];
    const values = [];
    if (name !== undefined) { fields.push('name = ?'); values.push(name.trim()); }
    if (email !== undefined) { fields.push('email = ?'); values.push(email.toLowerCase().trim()); }
    if (role !== undefined) { fields.push('role = ?'); values.push(role); }
    if (active !== undefined) { fields.push('active = ?'); values.push(active ? 1 : 0); }
    fields.push("updated_at = datetime('now')");

    if (fields.length === 1) {
      return errorResponse('אין שדות לעדכון', 400);
    }

    values.push(userId);
    await env.DB.prepare(
      `UPDATE users SET ${fields.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    // Return updated user
    const updated = await env.DB.prepare(
      'SELECT id, name, email, role, active, created_at, updated_at FROM users WHERE id = ?'
    ).bind(userId).first();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'update', entityType: 'user', entityId: userId, result: 'success',
      metadata: { fields: [name, email, role, active].map((v, i) => v !== undefined ? ['name', 'email', 'role', 'active'][i] : null).filter(Boolean) },
    });

    return jsonResponse(updated);
  } catch (e) {
    console.error('Update user error:', e);
    return errorResponse('שגיאה בעדכון משתמש', 500);
  }
}

// ─── DELETE /api/users/:id ───

export async function handleDeleteUser(request, env, userId) {
  const payload = await getAuthUser(request, env);
  const denied = requireAdmin(payload);
  if (denied) return denied;

  try {
    // Can't delete yourself
    if (parseInt(userId) === payload.userId) {
      return errorResponse('לא ניתן למחוק את עצמך', 403);
    }

    const user = await env.DB.prepare('SELECT id, role FROM users WHERE id = ?').bind(userId).first();
    if (!user) return errorResponse('משתמש לא נמצא', 404);

    // Can't delete last admin
    if (user.role === 'admin') {
      const adminCount = await env.DB.prepare(
        "SELECT COUNT(*) as cnt FROM users WHERE role = 'admin' AND id != ?"
      ).bind(userId).first();
      if (adminCount.cnt === 0) {
        return errorResponse('לא ניתן למחוק את המנהל האחרון', 403);
      }
    }

    await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(userId).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'delete', entityType: 'user', entityId: userId, result: 'success',
    });

    return jsonResponse({ message: 'המשתמש נמחק בהצלחה' });
  } catch (e) {
    console.error('Delete user error:', e);
    return errorResponse('שגיאה במחיקת משתמש', 500);
  }
}

// ─── POST /api/users/:id/reset-password ───

export async function handleAdminResetPassword(request, env, userId) {
  const payload = await getAuthUser(request, env);
  const denied = requireAdmin(payload);
  if (denied) return denied;

  try {
    const { newPassword } = await request.json();
    if (!newPassword) return errorResponse('נדרשת סיסמה חדשה', 400);

    const passErr = validatePassword(newPassword);
    if (passErr) return errorResponse(passErr, 400);

    const user = await env.DB.prepare('SELECT id FROM users WHERE id = ?').bind(userId).first();
    if (!user) return errorResponse('משתמש לא נמצא', 404);

    const passwordHash = await hashPassword(newPassword);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(passwordHash, userId).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'password_reset', entityType: 'user', entityId: userId, result: 'success',
      metadata: { by: 'admin' },
    });

    return jsonResponse({ message: 'הסיסמה עודכנה בהצלחה' });
  } catch (e) {
    console.error('Admin reset password error:', e);
    return errorResponse('שגיאה באיפוס סיסמה', 500);
  }
}
