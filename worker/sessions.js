/**
 * @file sessions.js
 * @description Treatment session CRUD handlers.
 * @module Sessions
 */

import { jsonResponse, errorResponse } from './utils.js';
import { requireRole } from './auth.js';
import { encryptField, decryptField } from './crypto.js';
import { recordAudit } from './auditLog.js';
import { validate, isValidDate, isNonNegativeAmount, isPositiveInteger, SESSION_TYPES, PAYMENT_METHODS } from './validation.js';

const SESSION_CREATE_SCHEMA = {
  client_id: { required: true, integer: true, validate: isPositiveInteger, message: 'Client ID must be a positive integer' },
  session_date: { required: true, validate: isValidDate, message: 'Session date is invalid' },
  session_type: { enum: SESSION_TYPES },
  duration_minutes: { integer: true, validate: isPositiveInteger, message: 'Duration must be a positive number of minutes' },
  amount: { number: true, validate: isNonNegativeAmount, message: 'Amount cannot be negative' },
  payment_method: { enum: PAYMENT_METHODS },
};

// Same rules as create, minus client_id (never changes after creation) and
// with session_date optional (only validated if the caller is changing it).
const SESSION_UPDATE_SCHEMA = {
  session_date: { validate: isValidDate, message: 'Session date is invalid' },
  session_type: { enum: SESSION_TYPES },
  duration_minutes: { integer: true, validate: isPositiveInteger, message: 'Duration must be a positive number of minutes' },
  amount: { number: true, validate: isNonNegativeAmount, message: 'Amount cannot be negative' },
  payment_method: { enum: PAYMENT_METHODS },
};

async function decryptSessionRow(env, row) {
  return {
    ...row,
    summary: await decryptField(env, row.summary),
    next_session_notes: await decryptField(env, row.next_session_notes),
  };
}

// ─── Get sessions (with filters, excludes soft-deleted) ───

export async function handleGetSessions(url, env) {
  try {
    const clientId = url.searchParams.get('client_id');
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    const limit = parseInt(url.searchParams.get('limit') || '50');

    let query = `SELECT s.*, c.full_name as client_name
                 FROM sessions s JOIN clients c ON s.client_id = c.id
                 WHERE s.deleted_at IS NULL`;
    const bindings = [];

    if (clientId) { query += ' AND s.client_id = ?'; bindings.push(clientId); }
    if (from) { query += ' AND s.session_date >= ?'; bindings.push(from); }
    if (to) { query += ' AND s.session_date <= ?'; bindings.push(to); }

    query += ' ORDER BY s.session_date DESC LIMIT ?';
    bindings.push(limit);

    const result = await env.DB.prepare(query).bind(...bindings).all();
    const rows = await Promise.all(result.results.map(row => decryptSessionRow(env, row)));
    return jsonResponse(rows);
  } catch (e) {
    console.error('Get sessions error:', e);
    return errorResponse('Failed to load sessions', 500);
  }
}

// ─── Get client sessions ───

export async function handleGetClientSessions(clientId, env) {
  try {
    const result = await env.DB.prepare(
      'SELECT * FROM sessions WHERE client_id = ? AND deleted_at IS NULL ORDER BY session_date DESC'
    ).bind(clientId).all();
    const rows = await Promise.all(result.results.map(row => decryptSessionRow(env, row)));
    return jsonResponse(rows);
  } catch (e) {
    console.error('Get client sessions error:', e);
    return errorResponse('Failed to load sessions', 500);
  }
}

// ─── Create session ───

export async function handleCreateSession(request, env, payload) {
  const forbidden = requireRole(payload, 'admin', 'therapist');
  if (forbidden) return forbidden;
  try {
    const data = await request.json();
    const { valid, data: v, errors } = validate(data, SESSION_CREATE_SCHEMA);
    if (!valid) return errorResponse(errors[0].message, 400, request, 'VALIDATION_ERROR');
    const { client_id, session_date, session_type, duration_minutes, amount, payment_method } = v;
    const { summary, next_session_notes, paid, invoice_number } = data;

    const client = await env.DB.prepare(
      'SELECT id FROM clients WHERE id = ? AND deleted_at IS NULL'
    ).bind(client_id).first();
    if (!client) return errorResponse('Client not found', 404, request);

    const result = await env.DB.prepare(
      `INSERT INTO sessions
       (client_id, session_date, session_type, duration_minutes, summary,
        next_session_notes, paid, amount, payment_method, invoice_number)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      client_id, session_date, session_type || null,
      duration_minutes ?? 50,
      await encryptField(env, summary || null),
      await encryptField(env, next_session_notes || null),
      paid ? 1 : 0, amount ?? 0, payment_method || null, invoice_number || null
    ).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'create', entityType: 'session', entityId: result.meta.last_row_id, result: 'success',
      metadata: { client_id },
    });

    return jsonResponse({ id: result.meta.last_row_id, message: 'Session created' }, 201);
  } catch (e) {
    console.error('Create session error:', e);
    return errorResponse('Failed to create session', 500);
  }
}

// ─── Update session ───

export async function handleUpdateSession(id, request, env, payload) {
  const forbidden = requireRole(payload, 'admin', 'therapist');
  if (forbidden) return forbidden;
  try {
    const data = await request.json();
    const { valid, data: v, errors } = validate(data, SESSION_UPDATE_SCHEMA);
    if (!valid) return errorResponse(errors[0].message, 400, request, 'VALIDATION_ERROR');

    const fields = [];
    const values = [];
    const allowed = [
      'session_date', 'session_type', 'duration_minutes', 'summary',
      'next_session_notes', 'paid', 'amount', 'payment_method', 'invoice_number',
    ];

    for (const field of allowed) {
      if (data[field] !== undefined) {
        fields.push(`${field} = ?`);
        let value = field in v ? v[field] : data[field];
        if (field === 'paid') value = value ? 1 : 0;
        else if (field === 'summary' || field === 'next_session_notes') value = await encryptField(env, value);
        values.push(value);
      }
    }
    if (fields.length === 0) return errorResponse('No fields to update', 400, request);

    fields.push("updated_at = datetime('now')");
    values.push(id);

    await env.DB.prepare(
      `UPDATE sessions SET ${fields.join(', ')} WHERE id = ? AND deleted_at IS NULL`
    ).bind(...values).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'update', entityType: 'session', entityId: id, result: 'success',
      metadata: { fields: allowed.filter(f => data[f] !== undefined) },
    });

    return jsonResponse({ message: 'Session updated' });
  } catch (e) {
    console.error('Update session error:', e);
    return errorResponse('Failed to update session', 500);
  }
}

// ─── Soft-delete session ───

export async function handleDeleteSession(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const result = await env.DB.prepare(
      "UPDATE sessions SET deleted_at = datetime('now'), deleted_by = ? WHERE id = ? AND deleted_at IS NULL"
    ).bind(payload.userId, id).run();
    if (!result.meta.changes) return errorResponse('Session not found', 404);

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'delete', entityType: 'session', entityId: id, result: 'success',
    });

    return jsonResponse({ message: 'Session moved to recycle bin' });
  } catch (e) {
    console.error('Delete session error:', e);
    return errorResponse('Failed to delete session', 500);
  }
}

// ─── Recycle bin: list soft-deleted sessions ───

export async function handleGetDeletedSessions(env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const result = await env.DB.prepare(
      `SELECT s.*, c.full_name as client_name, u.name as deleted_by_name
       FROM sessions s
       JOIN clients c ON s.client_id = c.id
       LEFT JOIN users u ON u.id = s.deleted_by
       WHERE s.deleted_at IS NOT NULL ORDER BY s.deleted_at DESC`
    ).all();
    const rows = await Promise.all(result.results.map(row => decryptSessionRow(env, row)));
    return jsonResponse(rows);
  } catch (e) {
    console.error('Get deleted sessions error:', e);
    return errorResponse('Failed to load recycle bin', 500);
  }
}

// ─── Restore a soft-deleted session ───

export async function handleRestoreSession(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const result = await env.DB.prepare(
      "UPDATE sessions SET deleted_at = NULL, deleted_by = NULL WHERE id = ? AND deleted_at IS NOT NULL"
    ).bind(id).run();
    if (!result.meta.changes) return errorResponse('Session not found in recycle bin', 404);

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'restore', entityType: 'session', entityId: id, result: 'success',
    });

    return jsonResponse({ message: 'Session restored' });
  } catch (e) {
    console.error('Restore session error:', e);
    return errorResponse('Failed to restore session', 500);
  }
}

// ─── Permanently delete a soft-deleted session (admin, explicit confirmation) ───

export async function handlePermanentDeleteSession(id, request, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const { confirm } = await request.json().catch(() => ({}));
    if (confirm !== true) {
      return errorResponse('נדרש אישור מפורש למחיקה סופית', 400);
    }
    const session = await env.DB.prepare(
      'SELECT id FROM sessions WHERE id = ? AND deleted_at IS NOT NULL'
    ).bind(id).first();
    if (!session) return errorResponse('Session not found in recycle bin', 404);

    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'permanent_delete', entityType: 'session', entityId: id, result: 'success',
    });

    return jsonResponse({ message: 'Session permanently deleted' });
  } catch (e) {
    console.error('Permanent delete session error:', e);
    return errorResponse('Failed to permanently delete session', 500);
  }
}
