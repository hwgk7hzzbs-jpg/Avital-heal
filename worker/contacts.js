/**
 * @file contacts.js
 * @description Contact form submission (public) and contact inquiry CRUD (protected).
 * @module Contacts
 */

import { jsonResponse, errorResponse, sendNotification } from './utils.js';
import { verifyTurnstile, checkRateLimit, requireRole } from './auth.js';

const MAX_FIELD_LEN = 2000;
const CONTACT_STATUSES = ['new', 'contacted', 'converted', 'closed'];

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
      phone ? phone.trim() : null,
      email ? email.trim() : null,
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
    let query = 'SELECT * FROM contacts';
    const params = [];
    if (status) {
      query += ' WHERE status = ?';
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
      `UPDATE contacts SET ${fields.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    return jsonResponse({ message: 'Contact updated' });
  } catch (e) {
    console.error('Update contact error:', e);
    return errorResponse('Failed to update contact', 500);
  }
}

// ─── Delete contact (protected) ───

export async function handleDeleteContact(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    await env.DB.prepare('DELETE FROM contacts WHERE id = ?').bind(id).run();
    return jsonResponse({ message: 'Contact deleted' });
  } catch (e) {
    console.error('Delete contact error:', e);
    return errorResponse('Failed to delete contact', 500);
  }
}
