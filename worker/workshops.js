/**
 * @file workshops.js
 * @description Workshop and workshop registration handlers.
 * @module Workshops
 */

import { jsonResponse, errorResponse, sendNotification } from './utils.js';
import { verifyTurnstile, checkRateLimit, requireRole } from './auth.js';
import { recordConsent } from './consents.js';

const MAX_FIELD_LEN = 2000;
const REGISTRATION_STATUSES = ['new', 'contacted', 'confirmed', 'cancelled'];

// ─── Public: Workshop registration (from brochure) ───

export async function handleWorkshopRegister(request, env) {
  try {
    const data = await request.json();
    const {
      fullName,
      phone,
      email,
      workshopId,
      dateOption,      // date option id (e.g., 'june-3-1730')
      notes,
      consentAgreed,
      turnstileToken,
      website, // honeypot — real users never fill this in
    } = data;

    if (website) {
      return jsonResponse({ success: true, message: 'ההרשמה נקלטה בהצלחה' });
    }

    // Validate
    if (!fullName || !fullName.trim()) {
      return errorResponse('שם מלא הוא שדה חובה', 400);
    }
    if (!phone || !phone.trim()) {
      return errorResponse('טלפון הוא שדה חובה', 400);
    }
    if (!workshopId) {
      return errorResponse('סדנה לא נבחרה', 400);
    }
    if (!dateOption) {
      return errorResponse('יש לבחור מועד סדנה', 400);
    }
    if (consentAgreed !== true) {
      return errorResponse('יש לאשר את הסכם הסדנה והצהרת הבריאות', 400);
    }
    if ([fullName, phone, email, notes].some(v => typeof v === 'string' && v.length > MAX_FIELD_LEN)) {
      return errorResponse('שדה חורג מהאורך המותר', 400);
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!(await checkRateLimit(env, `workshop-register:ip:${ip}`, 10, 3600))) {
      return errorResponse('יותר מדי בקשות — נסי שוב מאוחר יותר', 429);
    }

    // Turnstile CAPTCHA (required)
    if (!turnstileToken) {
      return errorResponse('אימות CAPTCHA נדרש', 403);
    }
    const valid = await verifyTurnstile(turnstileToken, env, ip);
    if (!valid) return errorResponse('אימות CAPTCHA נכשל', 403);

    // Confirm workshop exists and is active (also fetch name + dates for notification)
    const workshop = await env.DB.prepare(
      'SELECT id, name, dates FROM workshops WHERE id = ? AND active = 1'
    ).bind(workshopId).first();
    if (!workshop) {
      return errorResponse('סדנה לא נמצאה', 404);
    }

    // Resolve + validate the date option against the workshop's actual dates
    let dates = [];
    try { dates = JSON.parse(workshop.dates || '[]'); } catch (_) {}
    const matchedDate = dates.find(x => x.id === dateOption);
    if (!matchedDate) {
      return errorResponse('מועד הסדנה שנבחר אינו קיים', 400);
    }

    // Insert registration — IP is recorded once, on the consents row below.
    const inserted = await env.DB.prepare(
      `INSERT INTO workshop_registrations
       (workshop_id, full_name, phone, email, date_option, notes, status,
        consent_agreed, consent_date, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'new', 1, datetime('now'), datetime('now'))`
    ).bind(
      workshopId,
      fullName.trim(),
      phone.trim(),
      email ? email.trim() : null,
      dateOption,
      notes ? notes.trim() : null
    ).run();

    await recordConsent(env, {
      consentType: 'workshop',
      workshopRegistrationId: inserted.meta.last_row_id,
      ip,
    });

    // Notify Avital (fire & forget) — generic notice only, no PII/notes content
    // sent off-platform (see docs/apps-script-notifications.md for the matching template).
    await sendNotification(env, 'new-workshop-registration', {
      notice: `התקבלה הרשמה חדשה לסדנה "${workshop.name || ''}"`,
      crmLink: 'https://app.avital-heal.com',
      timestamp: new Date().toISOString(),
    });

    return jsonResponse({ success: true, message: 'ההרשמה נקלטה בהצלחה' });
  } catch (e) {
    console.error('Workshop register error:', e);
    return errorResponse('שגיאה ברישום לסדנה', 500);
  }
}

// ─── Protected: Get all workshops ───

export async function handleGetWorkshops(env) {
  try {
    const { results } = await env.DB.prepare(
      `SELECT w.*,
        (SELECT COUNT(*) FROM workshop_registrations WHERE workshop_id = w.id) as registration_count
       FROM workshops w
       ORDER BY w.created_at DESC`
    ).all();
    return jsonResponse(results || []);
  } catch (e) {
    console.error('Get workshops error:', e);
    return errorResponse('שגיאה בטעינת סדנאות', 500);
  }
}

// ─── Protected: Get workshop with registrations ───

export async function handleGetWorkshop(id, env) {
  try {
    const workshop = await env.DB.prepare(
      'SELECT * FROM workshops WHERE id = ?'
    ).bind(id).first();
    if (!workshop) return errorResponse('סדנה לא נמצאה', 404);

    const regs = await env.DB.prepare(
      `SELECT * FROM workshop_registrations
       WHERE workshop_id = ?
       ORDER BY created_at DESC`
    ).bind(id).all();

    // Parse dates JSON
    let dates = [];
    try { dates = JSON.parse(workshop.dates || '[]'); } catch (_) {}

    return jsonResponse({
      ...workshop,
      dates,
      registrations: regs.results || [],
    });
  } catch (e) {
    console.error('Get workshop error:', e);
    return errorResponse('שגיאה בטעינת הסדנה', 500);
  }
}

// ─── Protected: Get workshop registrations only ───

export async function handleGetWorkshopRegistrations(id, env) {
  try {
    const regs = await env.DB.prepare(
      `SELECT * FROM workshop_registrations
       WHERE workshop_id = ?
       ORDER BY created_at DESC`
    ).bind(id).all();
    return jsonResponse(regs.results || []);
  } catch (e) {
    console.error('Get registrations error:', e);
    return errorResponse('שגיאה בטעינת הרשמות', 500);
  }
}

// ─── Protected: Update registration status ───

export async function handleUpdateRegistration(id, request, env, payload) {
  const forbidden = requireRole(payload, 'admin', 'therapist');
  if (forbidden) return forbidden;
  try {
    const data = await request.json();
    const fields = [];
    const values = [];
    const allowed = ['status', 'notes', 'date_option'];

    if (data.status !== undefined && !REGISTRATION_STATUSES.includes(data.status)) {
      return errorResponse('סטטוס לא תקין', 400);
    }

    for (const field of allowed) {
      if (data[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(data[field]);
      }
    }
    if (fields.length === 0) return errorResponse('אין שדות לעדכון', 400);

    values.push(id);
    await env.DB.prepare(
      `UPDATE workshop_registrations SET ${fields.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    return jsonResponse({ message: 'ההרשמה עודכנה' });
  } catch (e) {
    console.error('Update registration error:', e);
    return errorResponse('שגיאה בעדכון הרשמה', 500);
  }
}

// ─── Protected: Delete registration ───

export async function handleDeleteRegistration(id, env, payload) {
  const forbidden = requireRole(payload, 'admin');
  if (forbidden) return forbidden;
  try {
    await env.DB.prepare('DELETE FROM workshop_registrations WHERE id = ?').bind(id).run();
    return jsonResponse({ message: 'ההרשמה נמחקה' });
  } catch (e) {
    console.error('Delete registration error:', e);
    return errorResponse('שגיאה במחיקת הרשמה', 500);
  }
}
