/**
 * @file sessions.js
 * @description Treatment session CRUD handlers.
 * @module Sessions
 */

import { jsonResponse, errorResponse } from './utils.js';
import { requireRole } from './auth.js';

// ─── Get sessions (with filters) ───

export async function handleGetSessions(url, env) {
  try {
    const clientId = url.searchParams.get('client_id');
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    const limit = parseInt(url.searchParams.get('limit') || '50');

    let query = `SELECT s.*, c.full_name as client_name
                 FROM sessions s JOIN clients c ON s.client_id = c.id WHERE 1=1`;
    const bindings = [];

    if (clientId) { query += ' AND s.client_id = ?'; bindings.push(clientId); }
    if (from) { query += ' AND s.session_date >= ?'; bindings.push(from); }
    if (to) { query += ' AND s.session_date <= ?'; bindings.push(to); }

    query += ' ORDER BY s.session_date DESC LIMIT ?';
    bindings.push(limit);

    const result = await env.DB.prepare(query).bind(...bindings).all();
    return jsonResponse(result.results);
  } catch (e) {
    console.error('Get sessions error:', e);
    return errorResponse('Failed to load sessions', 500);
  }
}

// ─── Get client sessions ───

export async function handleGetClientSessions(clientId, env) {
  try {
    const result = await env.DB.prepare(
      'SELECT * FROM sessions WHERE client_id = ? ORDER BY session_date DESC'
    ).bind(clientId).all();
    return jsonResponse(result.results);
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
    const {
      client_id, session_date, session_type, duration_minutes,
      summary, next_session_notes, paid, amount, payment_method, invoice_number,
    } = data;

    if (!client_id || !session_date) {
      return errorResponse('Client ID and session date are required');
    }

    const client = await env.DB.prepare(
      'SELECT id FROM clients WHERE id = ?'
    ).bind(client_id).first();
    if (!client) return errorResponse('Client not found', 404);

    const result = await env.DB.prepare(
      `INSERT INTO sessions
       (client_id, session_date, session_type, duration_minutes, summary,
        next_session_notes, paid, amount, payment_method, invoice_number)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      client_id, session_date, session_type || null,
      duration_minutes || 50, summary || null, next_session_notes || null,
      paid ? 1 : 0, amount || 0, payment_method || null, invoice_number || null
    ).run();

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
    const fields = [];
    const values = [];
    const allowed = [
      'session_date', 'session_type', 'duration_minutes', 'summary',
      'next_session_notes', 'paid', 'amount', 'payment_method', 'invoice_number',
    ];

    for (const field of allowed) {
      if (data[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(field === 'paid' ? (data[field] ? 1 : 0) : data[field]);
      }
    }
    if (fields.length === 0) return errorResponse('No fields to update');

    fields.push("updated_at = datetime('now')");
    values.push(id);

    await env.DB.prepare(
      `UPDATE sessions SET ${fields.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    return jsonResponse({ message: 'Session updated' });
  } catch (e) {
    console.error('Update session error:', e);
    return errorResponse('Failed to update session', 500);
  }
}

// ─── Delete session ───

export async function handleDeleteSession(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run();
    return jsonResponse({ message: 'Session deleted' });
  } catch (e) {
    console.error('Delete session error:', e);
    return errorResponse('Failed to delete session', 500);
  }
}
