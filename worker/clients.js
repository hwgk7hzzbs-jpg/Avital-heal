/**
 * @file clients.js
 * @description Client CRUD handlers and CSV export.
 * @module Clients
 */

import { jsonResponse, errorResponse, csvResponse } from './utils.js';
import { requireRole } from './auth.js';

// ─── Get all clients ───

export async function handleGetClients(url, env) {
  try {
    const search = url.searchParams.get('search') || '';
    const status = url.searchParams.get('status') || '';
    const limit = parseInt(url.searchParams.get('limit') || '100');
    const offset = parseInt(url.searchParams.get('offset') || '0');

    let query = `SELECT c.*,
      (SELECT COUNT(*) FROM sessions WHERE client_id = c.id) as session_count,
      (SELECT MAX(session_date) FROM sessions WHERE client_id = c.id) as last_session
      FROM clients c WHERE 1=1`;
    const bindings = [];

    if (search) {
      query += ' AND (c.full_name LIKE ? OR c.email LIKE ? OR c.phone LIKE ?)';
      bindings.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    if (status) {
      query += ' AND c.status = ?';
      bindings.push(status);
    }
    query += ' ORDER BY c.created_at DESC LIMIT ? OFFSET ?';
    bindings.push(limit, offset);

    const stmt = env.DB.prepare(query);
    const result = await (bindings.length ? stmt.bind(...bindings) : stmt).all();
    return jsonResponse(result.results);
  } catch (e) {
    console.error('Get clients error:', e);
    return errorResponse('Failed to load clients', 500);
  }
}

// ─── Get single client ───

export async function handleGetClient(id, env) {
  try {
    const client = await env.DB.prepare(
      'SELECT * FROM clients WHERE id = ?'
    ).bind(id).first();
    if (!client) return errorResponse('Client not found', 404);

    const sessions = await env.DB.prepare(
      'SELECT * FROM sessions WHERE client_id = ? ORDER BY session_date DESC'
    ).bind(id).all();

    return jsonResponse({ ...client, sessions: sessions.results });
  } catch (e) {
    console.error('Get client error:', e);
    return errorResponse('Failed to load client', 500);
  }
}

// ─── Create client ───

export async function handleCreateClient(request, env, payload) {
  const forbidden = requireRole(payload, 'admin', 'therapist');
  if (forbidden) return forbidden;
  try {
    const data = await request.json();
    const { full_name, email, phone, address, birth_date, treatment_type, notes } = data;
    if (!full_name) return errorResponse('Full name is required');

    const result = await env.DB.prepare(
      `INSERT INTO clients (full_name, email, phone, address, birth_date, treatment_type, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      full_name, email || null, phone || null, address || null,
      birth_date || null, treatment_type || null, notes || null
    ).run();

    return jsonResponse({ id: result.meta.last_row_id, message: 'Client created' }, 201);
  } catch (e) {
    console.error('Create client error:', e);
    return errorResponse('Failed to create client', 500);
  }
}

// ─── Update client ───

export async function handleUpdateClient(id, request, env, payload) {
  const forbidden = requireRole(payload, 'admin', 'therapist');
  if (forbidden) return forbidden;
  try {
    const data = await request.json();
    const fields = [];
    const values = [];
    const allowed = [
      'full_name', 'email', 'phone', 'address', 'birth_date',
      'status', 'treatment_type', 'consent_signed', 'consent_date', 'notes',
    ];

    for (const field of allowed) {
      if (data[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(data[field]);
      }
    }
    if (fields.length === 0) return errorResponse('No fields to update');

    fields.push("updated_at = datetime('now')");
    values.push(id);

    await env.DB.prepare(
      `UPDATE clients SET ${fields.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    return jsonResponse({ message: 'Client updated' });
  } catch (e) {
    console.error('Update client error:', e);
    return errorResponse('Failed to update client', 500);
  }
}

// ─── Delete client ───

export async function handleDeleteClient(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    await env.DB.prepare('DELETE FROM sessions WHERE client_id = ?').bind(id).run();
    await env.DB.prepare('DELETE FROM clients WHERE id = ?').bind(id).run();
    return jsonResponse({ message: 'Client deleted' });
  } catch (e) {
    console.error('Delete client error:', e);
    return errorResponse('Failed to delete client', 500);
  }
}

// ─── Export clients CSV ───

export async function handleExportClients(env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const clients = await env.DB.prepare(
      `SELECT c.*,
       (SELECT COUNT(*) FROM sessions WHERE client_id = c.id) as session_count,
       (SELECT COALESCE(SUM(amount), 0) FROM sessions WHERE client_id = c.id AND paid = 1) as total_paid,
       (SELECT COALESCE(SUM(amount), 0) FROM sessions WHERE client_id = c.id AND paid = 0) as total_unpaid
       FROM clients c ORDER BY c.full_name`
    ).all();

    let csv = 'שם מלא,אימייל,טלפון,סטטוס,סוג טיפול,הסכמה חתומה,תאריך הצטרפות,מספר טיפולים,שולם,לא שולם\n';
    for (const c of clients.results) {
      csv += `"${c.full_name || ''}","${c.email || ''}","${c.phone || ''}",`;
      csv += `"${c.status || ''}","${c.treatment_type || ''}",`;
      csv += `"${c.consent_signed ? 'כן' : 'לא'}","${c.join_date || ''}",`;
      csv += `${c.session_count},${c.total_paid},${c.total_unpaid}\n`;
    }

    return csvResponse(csv, 'clients-export.csv');
  } catch (e) {
    console.error('Export error:', e);
    return errorResponse('Failed to export', 500);
  }
}
