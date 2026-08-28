/**
 * @file auditLog.js
 * @description Append-only audit trail. No update/delete endpoint exists for
 *              this table anywhere in the app — the only way a row is ever
 *              written is via recordAudit() below, and the only way rows are
 *              ever read back is handleGetAuditLog() (admin only).
 * @module AuditLog
 */

import { jsonResponse, errorResponse } from './utils.js';
import { requireRole } from './auth.js';

/**
 * Record one audit event. Never pass sensitive content (health/session
 * content, tokens, full request bodies) in `metadata` — only small,
 * non-sensitive context (e.g. a changed field's *name*, not its value).
 */
export async function recordAudit(env, { userId = null, userEmail = null, action, entityType, entityId = null, result = 'success', metadata = null }) {
  try {
    await env.DB.prepare(
      `INSERT INTO audit_log (user_id, user_email, action, entity_type, entity_id, result, metadata, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`
    ).bind(
      userId, userEmail, action, entityType,
      entityId != null ? String(entityId) : null,
      result,
      metadata ? JSON.stringify(metadata) : null
    ).run();
  } catch (e) {
    // Audit logging must never break the primary operation it's observing.
    console.error('Audit log write error:', e);
  }
}

// ─── List audit log entries (admin only, read-only, paginated) ───

export async function handleGetAuditLog(url, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '100'), 500);
    const offset = parseInt(url.searchParams.get('offset') || '0');
    const entityType = url.searchParams.get('entity_type');
    const action = url.searchParams.get('action');

    let query = 'SELECT * FROM audit_log WHERE 1=1';
    const bindings = [];
    if (entityType) { query += ' AND entity_type = ?'; bindings.push(entityType); }
    if (action) { query += ' AND action = ?'; bindings.push(action); }
    query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
    bindings.push(limit, offset);

    const result = await env.DB.prepare(query).bind(...bindings).all();
    return jsonResponse(result.results || []);
  } catch (e) {
    console.error('Get audit log error:', e);
    return errorResponse('Failed to load audit log', 500);
  }
}
