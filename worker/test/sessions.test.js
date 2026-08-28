import { describe, it, expect } from 'vitest';
import { handleCreateSession, handleGetSessions, handleGetClientSessions, handleUpdateSession } from '../sessions.js';
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

describe('handleCreateSession / handleUpdateSession — RBAC', () => {
  it('blocks viewer from creating a session', async () => {
    const res = await handleCreateSession(req({ client_id: 1, session_date: '2026-01-01' }), withDB(makeFakeD1()), { role: 'viewer' });
    expect(res.status).toBe(403);
  });
});
