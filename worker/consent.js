/**
 * @file consent.js
 * @description Consent form submission handler (public endpoint).
 * @module Consent
 */

import { jsonResponse, errorResponse } from './utils.js';
import { verifyTurnstile, checkRateLimit } from './auth.js';
import { recordConsent } from './consents.js';

const MAX_FIELD_LEN = 2000;

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
      agreementConfirmation,
    } = data;
    const turnstileToken = data['cf-turnstile-response'] || '';

    // Honeypot: a hidden field real users never fill in
    if (data.website) {
      return jsonResponse({ status: 'success', message: 'Form submitted successfully' });
    }

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
    if ([email, fullName].some(v => typeof v === 'string' && v.length > MAX_FIELD_LEN)) {
      return errorResponse('Field too long');
    }

    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (!(await checkRateLimit(env, `consent:ip:${ip}`, 10, 3600))) {
      return errorResponse('Too many requests — please try again later', 429);
    }

    // Verify Turnstile (required)
    if (!turnstileToken) {
      return errorResponse('CAPTCHA verification required', 403);
    }
    const verified = await verifyTurnstile(turnstileToken, env, ip);
    if (!verified) {
      return errorResponse('CAPTCHA verification failed', 403);
    }

    // Signing time is set by the server — never trusted from the client.
    const signedAt = new Date().toISOString();

    // Check if client already exists by email
    const existing = await env.DB.prepare(
      'SELECT id FROM clients WHERE email = ?'
    ).bind(email).first();

    let clientId;
    if (existing) {
      clientId = existing.id;
      await env.DB.prepare(
        "UPDATE clients SET consent_signed = 1, consent_date = ?, updated_at = datetime('now') WHERE id = ?"
      ).bind(signedAt, existing.id).run();
    } else {
      // IP is recorded once, on the consents row below — not duplicated here too.
      const result = await env.DB.prepare(
        `INSERT INTO clients
         (full_name, email, consent_signed, consent_date, created_at, updated_at)
         VALUES (?, ?, 1, ?, datetime('now'), datetime('now'))`
      ).bind(fullName, email, signedAt).run();
      clientId = result.meta.last_row_id;
    }

    await recordConsent(env, { consentType: 'treatment', clientId, ip });

    return jsonResponse({ status: 'success', message: 'Form submitted successfully' });
  } catch (e) {
    console.error('Consent error:', e);
    return errorResponse('Internal server error', 500);
  }
}
