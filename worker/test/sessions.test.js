import { describe, it, expect } from 'vitest';
import { handleCreateSession, handleGetSessions, handleGetClientSessions, handleUpdateSession, handleDeleteSession, handleGetDeletedSessions, handleRestoreSession, handlePermanentDeleteSession } from '../sessions.js';
import { makeFakeD1 } from './testUtils.js';

const env = { ENCRYPTION_KEY: 'a'.repeat(64) };
function withDB(db) { return { ...env, DB: db }; }

function req(body) {
  return new Request('https://x/api/sessions', { method: 'POST', body: JSON.stringify(body) });
}

describe('session summary / next_session_notes are encrypted at rest', () => {
  it('stores summary and next_session_notes encrypted, not as plaintext', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'Client' }] });
    const e = withDB(db);
    await handleCreateSession(
      req({ client_id: 1, session_date: '2026-01-01', summary: 'clinical summary content', next_session_notes: 'plan for next time' }),
      e, { role: 'admin' }
    );

    const stored = db._state.sessions[0];
    expect(stored.summary).not.toContain('clinical summary content');
    expect(stored.summary.startsWith('encv1.')).toBe(true);
    expect(stored.next_session_notes.startsWith('encv1.')).toBe(true);
  });

  it('handleGetClientSessions returns decrypted content', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'Client' }] });
    const e = withDB(db);
    await handleCreateSession(
      req({ client_id: 1, session_date: '2026-01-01', summary: 'clinical summary content', next_session_notes: 'plan for next time' }),
      e, { role: 'admin' }
    );

    const res = await handleGetClientSessions(1, e);
    const body = await res.json();
    expect(body[0].summary).toBe('clinical summary content');
    expect(body[0].next_session_notes).toBe('plan for next time');
  });

  it('handleGetSessions (list, joined with clients) returns decrypted content', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'Client' }] });
    const e = withDB(db);
    await handleCreateSession(
      req({ client_id: 1, session_date: '2026-01-01', summary: 'clinical summary content' }),
      e, { role: 'admin' }
    );

    const res = await handleGetSessions(new URL('https://x/api/sessions'), e);
    const body = await res.json();
    expect(body[0].summary).toBe('clinical summary content');
  });

  it('handleUpdateSession re-encrypts an updated summary', async () => {
    const db = makeFakeD1({ sessions: [{ id: 5, client_id: 1, session_date: '2026-01-01', summary: null }] });
    const e = withDB(db);
    await handleUpdateSession('5', new Request('https://x', { method: 'PUT', body: JSON.stringify({ summary: 'revised summary' }) }), e, { role: 'admin' });

    expect(db._state.sessions[0].summary.startsWith('encv1.')).toBe(true);
    const res = await handleGetClientSessions(1, e);
    expect((await res.json())[0].summary).toBe('revised summary');
  });

  it('rejects a session with no client_id', async () => {
    const res = await handleCreateSession(req({ session_date: '2026-01-01' }), withDB(makeFakeD1()), { role: 'admin' });
    expect(res.status).toBe(400);
  });
});

describe('handleCreateSession / handleUpdateSession — field validation', () => {
  it('rejects a negative amount on create', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'Client' }] });
    const res = await handleCreateSession(req({ client_id: 1, session_date: '2026-01-01', amount: -50 }), withDB(db), { role: 'admin' });
    expect(res.status).toBe(400);
  });

  it('rejects an invalid session_date', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'Client' }] });
    const res = await handleCreateSession(req({ client_id: 1, session_date: 'not-a-date' }), withDB(db), { role: 'admin' });
    expect(res.status).toBe(400);
  });

  it('rejects a session_type outside the closed list', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'Client' }] });
    const res = await handleCreateSession(req({ client_id: 1, session_date: '2026-01-01', session_type: 'not-a-real-type' }), withDB(db), { role: 'admin' });
    expect(res.status).toBe(400);
  });

  it('rejects a non-positive duration_minutes', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'Client' }] });
    const res = await handleCreateSession(req({ client_id: 1, session_date: '2026-01-01', duration_minutes: 0 }), withDB(db), { role: 'admin' });
    expect(res.status).toBe(400);
  });

  it('accepts a valid session with all optional fields at their boundary values', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'Client' }] });
    const res = await handleCreateSession(req({
      client_id: 1, session_date: '2026-01-01', session_type: 'combined',
      duration_minutes: 50, amount: 0, payment_method: 'cash',
    }), withDB(db), { role: 'admin' });
    expect(res.status).toBe(201);
  });

  it('rejects a negative amount on update', async () => {
    const db = makeFakeD1({ sessions: [{ id: 5, client_id: 1, session_date: '2026-01-01' }] });
    const res = await handleUpdateSession('5', new Request('https://x', { method: 'PUT', body: JSON.stringify({ amount: -1 }) }), withDB(db), { role: 'admin' });
    expect(res.status).toBe(400);
  });

  it('rejects an invalid payment_method on update', async () => {
    const db = makeFakeD1({ sessions: [{ id: 5, client_id: 1, session_date: '2026-01-01' }] });
    const res = await handleUpdateSession('5', new Request('https://x', { method: 'PUT', body: JSON.stringify({ payment_method: 'bitcoin' }) }), withDB(db), { role: 'admin' });
    expect(res.status).toBe(400);
  });

  it('allows updating just an unrelated field (e.g. summary) without touching validated fields', async () => {
    const db = makeFakeD1({ sessions: [{ id: 5, client_id: 1, session_date: '2026-01-01' }] });
    const res = await handleUpdateSession('5', new Request('https://x', { method: 'PUT', body: JSON.stringify({ summary: 'just a note' }) }), withDB(db), { role: 'admin' });
    expect(res.status).toBe(200);
  });
});

describe('handleCreateSession / handleUpdateSession — RBAC', () => {
  it('blocks viewer from creating a session', async () => {
    const res = await handleCreateSession(req({ client_id: 1, session_date: '2026-01-01' }), withDB(makeFakeD1()), { role: 'viewer' });
    expect(res.status).toBe(403);
  });
});

describe('soft-delete recycle bin — sessions', () => {
  it('soft-deleted session disappears from lists but appears in the recycle bin', async () => {
    const db = makeFakeD1({
      clients: [{ id: 1, full_name: 'Client' }],
      sessions: [{ id: 5, client_id: 1, session_date: '2026-01-01', summary: null }],
    });
    const e = withDB(db);
    const delRes = await handleDeleteSession('5', e, { role: 'admin', userId: 9, email: 'a@x.com' });
    expect(delRes.status).toBe(200);

    const clientSessions = await handleGetClientSessions(1, e);
    expect(await clientSessions.json()).toEqual([]);

    const binRes = await handleGetDeletedSessions(e, { role: 'admin' });
    const bin = await binRes.json();
    expect(bin).toHaveLength(1);
    expect(bin[0].id).toBe(5);

    expect(db._state.auditLog.some(a => a.action === 'delete' && a.entity_type === 'session')).toBe(true);
  });

  it('a second delete on an already-deleted session 404s', async () => {
    const db = makeFakeD1({ sessions: [{ id: 5, client_id: 1, session_date: '2026-01-01' }] });
    const e = withDB(db);
    await handleDeleteSession('5', e, { role: 'admin', userId: 9 });
    const res = await handleDeleteSession('5', e, { role: 'admin', userId: 9 });
    expect(res.status).toBe(404);
  });

  it('restore brings a soft-deleted session back', async () => {
    const db = makeFakeD1({ sessions: [{ id: 5, client_id: 1, session_date: '2026-01-01' }] });
    const e = withDB(db);
    await handleDeleteSession('5', e, { role: 'admin', userId: 9 });

    const restoreRes = await handleRestoreSession('5', e, { role: 'admin', userId: 9 });
    expect(restoreRes.status).toBe(200);

    const clientSessions = await handleGetClientSessions(1, e);
    expect(await clientSessions.json()).toHaveLength(1);
  });

  it('permanent delete requires explicit confirm:true and only works on a soft-deleted session', async () => {
    const db = makeFakeD1({ sessions: [{ id: 5, client_id: 1, session_date: '2026-01-01' }] });
    const e = withDB(db);

    const beforeDelete = await handlePermanentDeleteSession('5', new Request('https://x', { method: 'DELETE', body: JSON.stringify({ confirm: true }) }), e, { role: 'admin', userId: 9 });
    expect(beforeDelete.status).toBe(404);

    await handleDeleteSession('5', e, { role: 'admin', userId: 9 });
    const confirmed = await handlePermanentDeleteSession('5', new Request('https://x', { method: 'DELETE', body: JSON.stringify({ confirm: true }) }), e, { role: 'admin', userId: 9 });
    expect(confirmed.status).toBe(200);
    expect(db._state.sessions).toHaveLength(0);
  });
});
