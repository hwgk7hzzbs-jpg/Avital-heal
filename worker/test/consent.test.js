import { describe, it, expect, afterEach, vi } from 'vitest';
import { handleConsentSubmission } from '../consent.js';
import { makeFakeD1, mockFetchTurnstile } from './testUtils.js';

function makeRequest(body) {
  return new Request('https://avital-heal-crm.tgthf7frmp.workers.dev/api/consent', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '5.5.5.5' },
    body: JSON.stringify(body),
  });
}

const validBody = {
  email: 'client@example.com',
  fullName: 'Client Name',
  date: '2026-01-01',
  healthDeclaration: true,
  agreementConfirmation: true,
  'cf-turnstile-response': 'tok',
};

describe('handleConsentSubmission', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('rejects with no Turnstile token', async () => {
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleConsentSubmission(makeRequest({ ...validBody, 'cf-turnstile-response': undefined }), env);
    expect(res.status).toBe(403);
  });

  it('rejects without a health declaration', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleConsentSubmission(makeRequest({ ...validBody, healthDeclaration: false }), env);
    expect(res.status).toBe(400);
  });

  it('creates a new client and a matching consents row on first signature', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleConsentSubmission(makeRequest(validBody), env);
    expect(res.status).toBe(200);

    expect(env.DB._state.clients).toHaveLength(1);
    const client = env.DB._state.clients[0];
    expect(client.email).toBe('client@example.com');
    expect(client.consent_signed).toBe(1);

    expect(env.DB._state.consents).toHaveLength(1);
    const consent = env.DB._state.consents[0];
    expect(consent.consent_type).toBe('treatment');
    expect(consent.client_id).toBe(client.id);
    expect(consent.ip).toBe('5.5.5.5');
  });

  it('re-signing an existing email updates the client and appends a new consent row (not a duplicate client)', async () => {
    mockFetchTurnstile(true);
    const env = {
      DB: makeFakeD1({ clients: [{ id: 3, email: 'client@example.com', consent_signed: 0 }] }),
      TURNSTILE_SECRET_KEY: 'k',
    };
    const res = await handleConsentSubmission(makeRequest(validBody), env);
    expect(res.status).toBe(200);
    expect(env.DB._state.clients).toHaveLength(1);
    expect(env.DB._state.clients[0].consent_signed).toBe(1);
    expect(env.DB._state.consents).toHaveLength(1);
    expect(env.DB._state.consents[0].client_id).toBe(3);
  });

  it('ignores a client-supplied timestamp — signing time is server-authoritative', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const attackerTimestamp = '1999-01-01T00:00:00.000Z';
    await handleConsentSubmission(makeRequest({ ...validBody, timestamp: attackerTimestamp }), env);
    expect(env.DB._state.clients[0].consent_date).not.toBe(attackerTimestamp);
    expect(env.DB._state.consents[0].signed_at).not.toBe(attackerTimestamp);
  });

  it('drops honeypot-triggered submissions without creating a client', async () => {
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleConsentSubmission(makeRequest({ ...validBody, website: 'spam' }), env);
    expect(res.status).toBe(200);
    expect(env.DB._state.clients).toHaveLength(0);
    expect(env.DB._state.consents).toHaveLength(0);
  });
});
