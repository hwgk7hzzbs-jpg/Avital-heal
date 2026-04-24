/**
 * @file workshops.js
 * @description Workshop and workshop registration handlers.
 * @module Workshops
 */

import { jsonResponse, errorResponse, sendNotification } from './utils.js';
import { verifyTurnstile } from './auth.js';

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
    } = data;

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

    // Turnstile CAPTCHA
    if (turnstileToken && env.TURNSTILE_SECRET_KEY) {
      const valid = await verifyTurnstile(turnstileToken, env);
      if (!valid) return errorResponse('אימות CAPTCHA נכשל', 403);
    }

    // Confirm workshop exists (also fetch name + dates for notification)
    const workshop = await env.DB.prepare(
      'SELECT id, name, dates FROM workshops WHERE id = ?'
    ).bind(workshopId).first();
    if (!workshop) {
      return errorResponse('סדנה לא נמצאה', 404);
    }

    // Resolve the friendly date label from the dates JSON
    let dateLabel = dateOption;
    try {
      const dates = JSON.parse(workshop.dates || '[]');
      const d = dates.find(x => x.id === dateOption);
      if (d && d.label) dateLabel = d.label;
    } catch (_) { /* keep raw id */ }

    const consentIp = request.headers.get('CF-Connecting-IP') || '';

    // Insert registration
    await env.DB.prepare(
      `INSERT INTO workshop_registrations
       (workshop_id, full_name, phone, email, date_option, notes, status,
        consent_agreed, consent_date, consent_ip, created_at)
       VALUES (?, ?, ?, ?, ?, ?, 'new', 1, datetime('now'), ?, datetime('now'))`
    ).bind(
      workshopId,
      fullName.trim(),
      phone.trim(),
      email ? email.trim() : null,
      dateOption,
      notes ? notes.trim() : null,
      consentIp
    ).run();

    // Notify Avital (fire & forget)
    await sendNotification(env, 'new-workshop-registration', {
      workshopId,
      workshopName: workshop.name || '',
      fullName: fullName.trim(),
      phone: phone.trim(),
      email: email ? email.trim() : '',
      dateOption,
      dateLabel,
      notes: notes ? notes.trim() : '',
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

export async function handleUpdateRegistration(id, request, env) {
  try {
    const data = await request.json();
    const fields = [];
    const values = [];
    const allowed = ['status', 'notes', 'date_option'];

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

export async function handleDeleteRegistration(id, env) {
  try {
    await env.DB.prepare('DELETE FROM workshop_registrations WHERE id = ?').bind(id).run();
    return jsonResponse({ message: 'ההרשמה נמחקה' });
  } catch (e) {
    console.error('Delete registration error:', e);
    return errorResponse('שגיאה במחיקת הרשמה', 500);
  }
}
