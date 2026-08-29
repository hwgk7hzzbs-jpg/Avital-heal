/**
 * @file contacts.js
 * @description Contact form submission (public) and contact inquiry CRUD (protected).
 * @module Contacts
 */

import { jsonResponse, errorResponse, sendNotification } from './utils.js';
import { verifyTurnstile, checkRateLimit, requireRole } from './auth.js';
import { recordAudit } from './auditLog.js';
import { normalizeEmail, normalizePhone, isValidEmail, isValidPhone, CONTACT_STATUSES } from './validation.js';

const MAX_FIELD_LEN = 2000;

// ─── Contact form submission (public) ───

export async function handleContactSubmission(request, env) {
  try {
    let data;
    const contentType = request.headers.get('Content-Type') || '';
    if (contentType.includes('application/json')) {
      data = await request.json();
    } else {
      const formData = await request.formData();
      data = Object.fromEntries(formData);
    }

    const { fullName, phone, email, message, turnstileToken } = data;

    // Honeypot: a hidden field real users never fill in
    if (data.website) {
      return jsonResponse({ success: true, message: 'הפנייה נקלטה בהצלחה' });
    }

    if (!fullName || !fullName.trim()) {
      return errorResponse('שם מלא הוא שדה חובה', 400);
    }
    if (!phone && !email) {
      return errorResponse('יש למלא טלפון או אימייל ליצירת קשר', 400);
    }
    if ([fullName, phone, email, message].some(v => typeof v === 'string' && v.length > MAX_FIELD_LEN)) {
      return errorResponse('שדה חורג מהאורך המותר', 400);
    }
    if (email && !isValidEmail(String(email).trim())) {
      return errorResponse('כתובת אימייל לא תקינה', 400);
    }
    if (phone && !isValidPhone(String(phone).trim())) {
      return errorResponse('מספר טלפון לא תקין', 400);
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!(await checkRateLimit(env, `contact:ip:${ip}`, 10, 3600))) {
      return errorResponse('יותר מדי בקשות — נסי שוב מאוחר יותר', 429);
    }

    if (!turnstileToken) {
      return errorResponse('אימות CAPTCHA נדרש', 403);
    }
    const valid = await verifyTurnstile(turnstileToken, env, ip);
    if (!valid) return errorResponse('אימות CAPTCHA נכשל', 403);

    await env.DB.prepare(
      `INSERT INTO contacts (full_name, phone, email, message, source, status, created_at)
       VALUES (?, ?, ?, ?, 'website', 'new', datetime('now'))`
    ).bind(
      fullName.trim(),
      phone ? normalizePhone(phone) : null,
      email ? normalizeEmail(email) : null,
      message ? message.trim() : null
    ).run();

    // Notify Avital (fire & forget) — generic notice only, no PII/message content
    // sent off-platform (see docs/apps-script-notifications.md for the matching template).
    await sendNotification(env, 'new-contact', {
      notice: 'התקבלה פנייה חדשה מהאתר',
      crmLink: 'https://app.avital-heal.com',
      timestamp: new Date().toISOString(),
    });

    return jsonResponse({ success: true, message: 'הפנייה נקלטה בהצלחה' });
  } catch (e) {
    console.error('Contact submission error:', e);
    return errorResponse('שגיאה בשליחת הטופס', 500);
  }
}

// ─── Get all contacts (protected) ───

export async function handleGetContacts(url, env) {
  try {
    const status = url.searchParams.get('status');
    let query = 'SELECT * FROM contacts WHERE deleted_at IS NULL';
    const params = [];
    if (status) {
      query += ' AND status = ?';
      params.push(status);
    }
    query += ' ORDER BY created_at DESC';

    const stmt = params.length > 0
      ? env.DB.prepare(query).bind(...params)
      : env.DB.prepare(query);

    const contacts = await stmt.all();
    return jsonResponse(contacts.results);
  } catch (e) {
    console.error('Get contacts error:', e);
    return errorResponse('Failed to fetch contacts', 500);
  }
}

// ─── Update contact status (protected) ───

export async function handleUpdateContact(id, request, env, payload) {
  const forbidden = requireRole(payload, 'admin', 'therapist');
  if (forbidden) return forbidden;
  try {
    const data = await request.json();
    const fields = [];
    const values = [];

    if (data.status !== undefined) {
      if (!CONTACT_STATUSES.includes(data.status)) {
        return errorResponse('סטטוס לא תקין', 400);
      }
      fields.push('status = ?'); values.push(data.status);
    }
    if (data.notes !== undefined) { fields.push('notes = ?'); values.push(data.notes); }

    if (fields.length === 0) return errorResponse('No fields to update', 400);
    values.push(id);

    await env.DB.prepare(
      `UPDATE contacts SET ${fields.join(', ')} WHERE id = ? AND deleted_at IS NULL`
    ).bind(...values).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'update', entityType: 'contact', entityId: id, result: 'success',
    });

    return jsonResponse({ message: 'Contact updated' });
  } catch (e) {
    console.error('Update contact error:', e);
    return errorResponse('Failed to update contact', 500);
  }
}

// ─── Soft-delete contact (protected) ───

export async function handleDeleteContact(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const result = await env.DB.prepare(
      "UPDATE contacts SET deleted_at = datetime('now'), deleted_by = ? WHERE id = ? AND deleted_at IS NULL"
    ).bind(payload.userId, id).run();
    if (!result.meta.changes) return errorResponse('Contact not found', 404);

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'delete', entityType: 'contact', entityId: id, result: 'success',
    });

    return jsonResponse({ message: 'Contact moved to recycle bin' });
  } catch (e) {
    console.error('Delete contact error:', e);
    return errorResponse('Failed to delete contact', 500);
  }
}

// ─── Recycle bin: list soft-deleted contacts ───

export async function handleGetDeletedContacts(env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const result = await env.DB.prepare(
      `SELECT c.*, u.name as deleted_by_name
       FROM contacts c LEFT JOIN users u ON u.id = c.deleted_by
       WHERE c.deleted_at IS NOT NULL ORDER BY c.deleted_at DESC`
    ).all();
    return jsonResponse(result.results || []);
  } catch (e) {
    console.error('Get deleted contacts error:', e);
    return errorResponse('Failed to load recycle bin', 500);
  }
}

// ─── Restore a soft-deleted contact ───

export async function handleRestoreContact(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const result = await env.DB.prepare(
      "UPDATE contacts SET deleted_at = NULL, deleted_by = NULL WHERE id = ? AND deleted_at IS NOT NULL"
    ).bind(id).run();
    if (!result.meta.changes) return errorResponse('Contact not found in recycle bin', 404);

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'restore', entityType: 'contact', entityId: id, result: 'success',
    });

    return jsonResponse({ message: 'Contact restored' });
  } catch (e) {
    console.error('Restore contact error:', e);
    return errorResponse('Failed to restore contact', 500);
  }
}

// ─── Permanently delete a soft-deleted contact (admin, explicit confirmation) ───

export async function handlePermanentDeleteContact(id, request, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    const { confirm } = await request.json().catch(() => ({}));
    if (confirm !== true) {
      return errorResponse('נדרש אישור מפורש למחיקה סופית', 400);
    }
    const contact = await env.DB.prepare(
      'SELECT id FROM contacts WHERE id = ? AND deleted_at IS NOT NULL'
    ).bind(id).first();
    if (!contact) return errorResponse('Contact not found in recycle bin', 404);

    await env.DB.prepare('DELETE FROM contacts WHERE id = ?').bind(id).run();

    await recordAudit(env, {
      userId: payload.userId, userEmail: payload.email,
      action: 'permanent_delete', entityType: 'contact', entityId: id, result: 'success',
    });

    return jsonResponse({ message: 'Contact permanently deleted' });
  } catch (e) {
    console.error('Permanent delete contact error:', e);
    return errorResponse('Failed to permanently delete contact', 500);
  }
}
