/**
 * @file consent.js
 * @description Consent form submission handler (public endpoint).
 * @module Consent
 */

import { jsonResponse, errorResponse } from './utils.js';
import { verifyTurnstile } from './auth.js';

// ─── Consent form submission (public) ───

export async function handleConsentSubmission(request, env) {
  try {
    let data;
    const contentType = request.headers.get('Content-Type') || '';

    if (contentType.includes('application/json')) {
      data = await request.json();
    } else {
      const formData = await request.text();
      const params = new URLSearchParams(formData);
      data = Object.fromEntries(params.entries());
    }

    const {
      email, fullName, date, healthDeclaration,
      agreementConfirmation, timestamp, userAgent,
    } = data;
    const turnstileToken = data['cf-turnstile-response'] || '';

    // Validate required fields
    if (!email || !fullName || !date) {
      return errorResponse('Missing required fields');
    }
    if (healthDeclaration !== 'true' && healthDeclaration !== true) {
      return errorResponse('Health declaration required');
    }
    if (agreementConfirmation !== 'true' && agreementConfirmation !== true) {
      return errorResponse('Agreement confirmation required');
    }

    // Verify Turnstile
    if (turnstileToken) {
      const verified = await verifyTurnstile(turnstileToken, env);
      if (!verified) {
        return errorResponse('CAPTCHA verification failed', 403);
      }
    }

    // Check if client already exists by email
    const existing = await env.DB.prepare(
      'SELECT id FROM clients WHERE email = ?'
    ).bind(email).first();

    if (existing) {
      await env.DB.prepare(
        "UPDATE clients SET consent_signed = 1, consent_date = ?, updated_at = datetime('now') WHERE id = ?"
      ).bind(timestamp || new Date().toISOString(), existing.id).run();
    } else {
      await env.DB.prepare(
        `INSERT INTO clients
         (full_name, email, consent_signed, consent_date, consent_ip, created_at, updated_at)
         VALUES (?, ?, 1, ?, ?, datetime('now'), datetime('now'))`
      ).bind(
        fullName, email,
        timestamp || new Date().toISOString(),
        request.headers.get('CF-Connecting-IP') || ''
      ).run();
    }

    return jsonResponse({ status: 'success', message: 'Form submitted successfully' });
  } catch (e) {
    console.error('Consent error:', e);
    return errorResponse('Internal server error', 500);
  }
}
