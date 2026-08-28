/**
 * @file consents.js
 * @description Historical, versioned consent records. Every signature — the
 *              treatment agreement or a workshop registration's consent —
 *              gets its own append-only row here, on top of (not instead of)
 *              the quick-lookup boolean flags already on clients/
 *              workshop_registrations.
 * @module Consents
 */

import { jsonResponse, errorResponse } from './utils.js';
import { requireRole } from './auth.js';
import { CONSENT_DOCUMENTS, hashDocument } from './consentDocuments.js';
import { recordAudit } from './auditLog.js';

/**
 * Record one signed consent. Called by consent.js and workshops.js right
 * after a signature is accepted — never client-invocable directly.
 *
 * consent_version/document_hash come from the server-side document
 * registry (never the client), and signed_at is the server's own clock —
 * both per the plan's explicit requirement that these not be trusted from
 * the submitter.
 */
export async function recordConsent(env, { consentType, clientId = null, workshopRegistrationId = null, ip = null }) {
  const doc = CONSENT_DOCUMENTS[consentType];
  if (!doc) throw new Error(`Unknown consent type: ${consentType}`);
  const documentHash = await hashDocument(doc.text);
  const signedAt = new Date().toISOString();
  await env.DB.prepare(
    `INSERT INTO consents
     (consent_type, client_id, workshop_registration_id, consent_version, document_hash, source, status, ip, signed_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, 'active', ?, ?, datetime('now'))`
  ).bind(consentType, clientId, workshopRegistrationId, doc.version, documentHash, doc.source, ip || null, signedAt).run();
}

// ─── Get a client's consent history (protected — any authenticated role) ───

export async function handleGetClientConsents(clientId, env) {
  try {
    const result = await env.DB.prepare(
      'SELECT * FROM consents WHERE client_id = ? ORDER BY signed_at DESC'
    ).bind(clientId).all();
    return jsonResponse(result.results || []);
  } catch (e) {
    console.error('Get client consents error:', e);
    return errorResponse('Failed to load consent history', 500);
  }
}

// ─── Revoke a consent record (admin only) ───

export async function handleRevokeConsent(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const existing = await env.DB.prepare('SELECT id, status FROM consents WHERE id = ?').bind(id).first();
    if (!existing) return errorResponse('Consent record not found', 404);
    if (existing.status === 'revoked') return errorResponse('Consent already revoked', 400);
    await env.DB.prepare(
      "UPDATE consents SET status = 'revoked', revoked_at = datetime('now') WHERE id = ?"
    ).bind(id).run();
    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'revoke', entityType: 'consent', entityId: id, result: 'success',
    });
    return jsonResponse({ message: 'Consent revoked' });
  } catch (e) {
    console.error('Revoke consent error:', e);
    return errorResponse('Failed to revoke consent', 500);
  }
}
