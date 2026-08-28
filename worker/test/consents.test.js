import { describe, it, expect } from 'vitest';
import { recordConsent, handleGetClientConsents, handleRevokeConsent } from '../consents.js';
import { CONSENT_DOCUMENTS, hashDocument } from '../consentDocuments.js';
import { makeFakeD1 } from './testUtils.js';

describe('recordConsent', () => {
  it('writes a row with server-controlled version/hash, not anything client-supplied', async () => {
    const env = { DB: makeFakeD1() };
    await recordConsent(env, { consentType: 'treatment', clientId: 42, ip: '1.2.3.4' });

    const row = env.DB._state.consents[0];
    expect(row.consent_type).toBe('treatment');
    expect(row.client_id).toBe(42);
    expect(row.workshop_registration_id).toBeNull();
    expect(row.consent_version).toBe(CONSENT_DOCUMENTS.treatment.version);
    expect(row.document_hash).toBe(await hashDocument(CONSENT_DOCUMENTS.treatment.text));
    expect(row.status).toBe('active');
    expect(row.ip).toBe('1.2.3.4');
    expect(row.signed_at).toBeTruthy();
  });

  it('records a workshop consent against a registration id, not a client id', async () => {
    const env = { DB: makeFakeD1() };
    await recordConsent(env, { consentType: 'workshop', workshopRegistrationId: 7, ip: '9.9.9.9' });

    const row = env.DB._state.consents[0];
    expect(row.consent_type).toBe('workshop');
    expect(row.workshop_registration_id).toBe(7);
    expect(row.client_id).toBeNull();
    expect(row.consent_version).toBe(CONSENT_DOCUMENTS.workshop.version);
  });

  it('throws on an unknown consent type rather than silently recording garbage', async () => {
    const env = { DB: makeFakeD1() };
    await expect(recordConsent(env, { consentType: 'bogus', clientId: 1 })).rejects.toThrow();
  });
});

describe('handleGetClientConsents', () => {
  it('returns only that client\'s consents, newest first', async () => {
    const env = {
      DB: makeFakeD1({
        consents: [
          { id: 1, client_id: 5, signed_at: '2026-01-01T00:00:00.000Z' },
          { id: 2, client_id: 5, signed_at: '2026-06-01T00:00:00.000Z' },
          { id: 3, client_id: 9, signed_at: '2026-03-01T00:00:00.000Z' },
        ],
      }),
    };
    const res = await handleGetClientConsents(5, env);
    const body = await res.json();
    expect(body.map(r => r.id)).toEqual([2, 1]);
  });
});

describe('handleRevokeConsent — RBAC', () => {
  it('blocks non-admin roles', async () => {
    const env = { DB: makeFakeD1({ consents: [{ id: 1, status: 'active' }] }) };
    const res = await handleRevokeConsent(1, env, { role: 'therapist' });
    expect(res.status).toBe(403);
  });

  it('allows admin and sets revoked_at', async () => {
    const env = { DB: makeFakeD1({ consents: [{ id: 1, status: 'active' }] }) };
    const res = await handleRevokeConsent(1, env, { role: 'admin' });
    expect(res.status).toBe(200);
    expect(env.DB._state.consents[0].status).toBe('revoked');
    expect(env.DB._state.consents[0].revoked_at).toBeTruthy();
  });

  it('rejects revoking an already-revoked consent', async () => {
    const env = { DB: makeFakeD1({ consents: [{ id: 1, status: 'revoked' }] }) };
    const res = await handleRevokeConsent(1, env, { role: 'admin' });
    expect(res.status).toBe(400);
  });

  it('404s on a non-existent consent id', async () => {
    const env = { DB: makeFakeD1({ consents: [] }) };
    const res = await handleRevokeConsent(999, env, { role: 'admin' });
    expect(res.status).toBe(404);
  });
});
