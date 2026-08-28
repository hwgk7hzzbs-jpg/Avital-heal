/**
 * @file clients.js
 * @description Client CRUD handlers and CSV export.
 * @module Clients
 */

import { jsonResponse, errorResponse, csvResponse } from './utils.js';
import { requireRole } from './auth.js';
import { encryptField, decryptField } from './crypto.js';
import { recordAudit } from './auditLog.js';

// ─── Get all clients (excludes soft-deleted) ───

export async function handleGetClients(url, env) {
  try {
    const search = url.searchParams.get('search') || '';
    const status = url.searchParams.get('status') || '';
    const limit = parseInt(url.searchParams.get('limit') || '100');
    const offset = parseInt(url.searchParams.get('offset') || '0');

    let query = `SELECT c.*,
      (SELECT COUNT(*) FROM sessions WHERE client_id = c.id) as session_count,
      (SELECT MAX(session_date) FROM sessions WHERE client_id = c.id) as last_session
      FROM clients c WHERE c.deleted_at IS NULL`;
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
    const rows = await Promise.all(result.results.map(async c => ({ ...c, notes: await decryptField(env, c.notes) })));
    return jsonResponse(rows);
  } catch (e) {
    console.error('Get clients error:', e);
    return errorResponse('Failed to load clients', 500);
  }
}

// ─── Get single client ───

export async function handleGetClient(id, env, payload) {
  try {
    const client = await env.DB.prepare(
      'SELECT * FROM clients WHERE id = ? AND deleted_at IS NULL'
    ).bind(id).first();
    if (!client) return errorResponse('Client not found', 404);

    const sessions = await env.DB.prepare(
      'SELECT * FROM sessions WHERE client_id = ? AND deleted_at IS NULL ORDER BY session_date DESC'
    ).bind(id).all();
    const sessionRows = await Promise.all(sessions.results.map(async s => ({
      ...s,
      summary: await decryptField(env, s.summary),
      next_session_notes: await decryptField(env, s.next_session_notes),
    })));

    await recordAudit(env, {
      userId: payload?.userId, userEmail: payload?.email,
      action: 'view', entityType: 'client', entityId: id, result: 'success',
    });

    return jsonResponse({ ...client, notes: await decryptField(env, client.notes), sessions: sessionRows });
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
      birth_date || null, treatment_type || null, await encryptField(env, notes || null)
    ).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'create', entityType: 'client', entityId: result.meta.last_row_id, result: 'success',
    });

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
        values.push(field === 'notes' ? await encryptField(env, data[field]) : data[field]);
      }
    }
    if (fields.length === 0) return errorResponse('No fields to update');

    fields.push("updated_at = datetime('now')");
    values.push(id);

    await env.DB.prepare(
      `UPDATE clients SET ${fields.join(', ')} WHERE id = ? AND deleted_at IS NULL`
    ).bind(...values).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'update', entityType: 'client', entityId: id, result: 'success',
      metadata: { fields: allowed.filter(f => data[f] !== undefined) },
    });

    return jsonResponse({ message: 'Client updated' });
  } catch (e) {
    console.error('Update client error:', e);
    return errorResponse('Failed to update client', 500);
  }
}

// ─── Soft-delete client ───
// Does NOT cascade to her sessions — each entity has its own recycle bin
// and is restored/deleted independently.

export async function handleDeleteClient(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const result = await env.DB.prepare(
      "UPDATE clients SET deleted_at = datetime('now'), deleted_by = ? WHERE id = ? AND deleted_at IS NULL"
    ).bind(payload.userId, id).run();
    if (!result.meta.changes) return errorResponse('Client not found', 404);

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'delete', entityType: 'client', entityId: id, result: 'success',
    });

    return jsonResponse({ message: 'Client moved to recycle bin' });
  } catch (e) {
    console.error('Delete client error:', e);
    return errorResponse('Failed to delete client', 500);
  }
}

// ─── Recycle bin: list soft-deleted clients ───

export async function handleGetDeletedClients(env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const result = await env.DB.prepare(
      `SELECT c.*, u.name as deleted_by_name
       FROM clients c LEFT JOIN users u ON u.id = c.deleted_by
       WHERE c.deleted_at IS NOT NULL ORDER BY c.deleted_at DESC`
    ).all();
    return jsonResponse(result.results || []);
  } catch (e) {
    console.error('Get deleted clients error:', e);
    return errorResponse('Failed to load recycle bin', 500);
  }
}

// ─── Restore a soft-deleted client ───

export async function handleRestoreClient(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const result = await env.DB.prepare(
      "UPDATE clients SET deleted_at = NULL, deleted_by = NULL WHERE id = ? AND deleted_at IS NOT NULL"
    ).bind(id).run();
    if (!result.meta.changes) return errorResponse('Client not found in recycle bin', 404);

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'restore', entityType: 'client', entityId: id, result: 'success',
    });

    return jsonResponse({ message: 'Client restored' });
  } catch (e) {
    console.error('Restore client error:', e);
    return errorResponse('Failed to restore client', 500);
  }
}

// ─── Permanently delete a soft-deleted client (admin, explicit confirmation) ───

export async function handlePermanentDeleteClient(id, request, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const { confirm } = await request.json().catch(() => ({}));
    if (confirm !== true) {
      return errorResponse('נדרש אישור מפורש למחיקה סופית', 400);
    }
    const client = await env.DB.prepare(
      'SELECT id FROM clients WHERE id = ? AND deleted_at IS NOT NULL'
    ).bind(id).first();
    if (!client) return errorResponse('Client not found in recycle bin', 404);

    await env.DB.prepare('DELETE FROM clients WHERE id = ?').bind(id).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'permanent_delete', entityType: 'client', entityId: id, result: 'success',
    });

    return jsonResponse({ message: 'Client permanently deleted' });
  } catch (e) {
    console.error('Permanent delete client error:', e);
    return errorResponse('Failed to permanently delete client', 500);
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
       FROM clients c WHERE c.deleted_at IS NULL ORDER BY c.full_name`
    ).all();

    let csv = 'שם מלא,אימייל,טלפון,סטטוס,סוג טיפול,הסכמה חתומה,תאריך הצטרפות,מספר טיפולים,שולם,לא שולם\n';
    for (const c of clients.results) {
      csv += `"${c.full_name || ''}","${c.email || ''}","${c.phone || ''}",`;
      csv += `"${c.status || ''}","${c.treatment_type || ''}",`;
      csv += `"${c.consent_signed ? 'כן' : 'לא'}","${c.join_date || ''}",`;
      csv += `${c.session_count},${c.total_paid},${c.total_unpaid}\n`;
    }

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'export', entityType: 'client', result: 'success', metadata: { format: 'csv', count: clients.results.length },
    });

    return csvResponse(csv, 'clients-export.csv');
  } catch (e) {
    console.error('Export error:', e);
    return errorResponse('Failed to export', 500);
  }
}

// ─── Export one client's full record (subject access / portability request) ───
// Distinct from handleExportClients (a CSV of everyone, for business reporting):
// this returns one person's complete data — profile, sessions, consent history —
// decrypted and in full, for responding to a "what data do you have on me" /
// "give me a copy of my data" request.

export async function handleExportClientData(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const client = await env.DB.prepare('SELECT * FROM clients WHERE id = ?').bind(id).first();
    if (!client) return errorResponse('Client not found', 404);

    const sessions = await env.DB.prepare(
      'SELECT * FROM sessions WHERE client_id = ? ORDER BY session_date DESC'
    ).bind(id).all();
    const sessionRows = await Promise.all(sessions.results.map(async s => ({
      ...s,
      summary: await decryptField(env, s.summary),
      next_session_notes: await decryptField(env, s.next_session_notes),
    })));

    const consents = await env.DB.prepare(
      'SELECT * FROM consents WHERE client_id = ? ORDER BY signed_at DESC'
    ).bind(id).all();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'export', entityType: 'client', entityId: id, result: 'success', metadata: { format: 'full_record' },
    });

    return jsonResponse({
      exported_at: new Date().toISOString(),
      client: { ...client, notes: await decryptField(env, client.notes) },
      sessions: sessionRows,
      consents: consents.results,
    });
  } catch (e) {
    console.error('Export client data error:', e);
    return errorResponse('Failed to export client data', 500);
  }
}
