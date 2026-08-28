import { describe, it, expect } from 'vitest';
import { handleCreateClient, handleGetClient, handleUpdateClient, handleGetClients, handleExportClientData, handleDeleteClient, handleGetDeletedClients, handleRestoreClient, handlePermanentDeleteClient } from '../clients.js';
import { makeFakeD1 } from './testUtils.js';

const env = { DB: null, ENCRYPTION_KEY: 'a'.repeat(64) };
function withDB(db) { return { ...env, DB: db }; }

function req(body) {
  return new Request('https://x/api/clients', { method: 'POST', body: JSON.stringify(body) });
}

describe('client notes are encrypted at rest', () => {
  it('stores notes encrypted in D1, not as plaintext', async () => {
    const db = makeFakeD1();
    const e = withDB(db);
    await handleCreateClient(req({ full_name: 'Test Client', notes: 'sensitive therapy notes' }), e, { role: 'admin' });

    const stored = db._state.clients[0].notes;
    expect(stored).not.toBe('sensitive therapy notes');
    expect(stored).not.toContain('sensitive therapy notes');
    expect(stored.startsWith('encv1.')).toBe(true);
  });

  it('handleGetClient returns decrypted notes', async () => {
    const db = makeFakeD1();
    const e = withDB(db);
    const createRes = await handleCreateClient(req({ full_name: 'Test Client', notes: 'sensitive therapy notes' }), e, { role: 'admin' });
    const { id } = await createRes.json();

    const res = await handleGetClient(String(id), e);
    const body = await res.json();
    expect(body.notes).toBe('sensitive therapy notes');
  });

  it('handleGetClients (list) also returns decrypted notes', async () => {
    const db = makeFakeD1();
    const e = withDB(db);
    await handleCreateClient(req({ full_name: 'Test Client', notes: 'sensitive therapy notes' }), e, { role: 'admin' });

    const res = await handleGetClients(new URL('https://x/api/clients'), e);
    const body = await res.json();
    expect(body[0].notes).toBe('sensitive therapy notes');
  });

  it('handleUpdateClient re-encrypts updated notes', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'A', notes: null }] });
    const e = withDB(db);
    await handleUpdateClient('1', new Request('https://x', { method: 'PUT', body: JSON.stringify({ notes: 'updated sensitive note' }) }), e, { role: 'admin' });

    expect(db._state.clients[0].notes.startsWith('encv1.')).toBe(true);
    const res = await handleGetClient('1', e);
    expect((await res.json()).notes).toBe('updated sensitive note');
  });

  it('handles a client with no notes without throwing', async () => {
    const db = makeFakeD1();
    const e = withDB(db);
    const res = await handleCreateClient(req({ full_name: 'No Notes Client' }), e, { role: 'admin' });
    expect(res.status).toBe(201);
  });
});

describe('handleExportClientData — subject access request export', () => {
  it('admin gets the full record with notes decrypted', async () => {
    const db = makeFakeD1();
    const e = withDB(db);
    const createRes = await handleCreateClient(req({ full_name: 'Export Me', notes: 'private clinical note' }), e, { role: 'admin' });
    const { id } = await createRes.json();

    const res = await handleExportClientData(String(id), e, { role: 'admin' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.client.notes).toBe('private clinical note');
    expect(Array.isArray(body.sessions)).toBe(true);
    expect(Array.isArray(body.consents)).toBe(true);
    expect(body.exported_at).toBeTruthy();
  });

  it('blocks non-admin roles', async () => {
    const res = await handleExportClientData('1', withDB(makeFakeD1({ clients: [{ id: 1 }] })), { role: 'therapist' });
    expect(res.status).toBe(403);
  });

  it('404s for a client that does not exist', async () => {
    const res = await handleExportClientData('999', withDB(makeFakeD1()), { role: 'admin' });
    expect(res.status).toBe(404);
  });
});

describe('handleCreateClient / handleUpdateClient — RBAC', () => {
  it('blocks viewer from creating a client', async () => {
    const res = await handleCreateClient(req({ full_name: 'X' }), withDB(makeFakeD1()), { role: 'viewer' });
    expect(res.status).toBe(403);
  });

  it('blocks viewer from updating a client', async () => {
    const res = await handleUpdateClient('1', req({ notes: 'x' }), withDB(makeFakeD1()), { role: 'viewer' });
    expect(res.status).toBe(403);
  });
});

describe('soft-delete recycle bin — clients', () => {
  it('soft-deleted client disappears from the normal list and detail view, but appears in the recycle bin', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'X' }] });
    const e = withDB(db);
    const delRes = await handleDeleteClient('1', e, { role: 'admin', userId: 9, email: 'a@x.com' });
    expect(delRes.status).toBe(200);

    const listRes = await handleGetClients(new URL('https://x/api/clients'), e);
    expect(await listRes.json()).toEqual([]);

    const detailRes = await handleGetClient('1', e, { role: 'admin' });
    expect(detailRes.status).toBe(404);

    const binRes = await handleGetDeletedClients(e, { role: 'admin' });
    const bin = await binRes.json();
    expect(bin).toHaveLength(1);
    expect(bin[0].id).toBe(1);

    expect(db._state.auditLog.some(a => a.action === 'delete' && a.entity_type === 'client')).toBe(true);
  });

  it('does not cascade-delete the client\'s sessions', async () => {
    const db = makeFakeD1({
      clients: [{ id: 1, full_name: 'X' }],
      sessions: [{ id: 5, client_id: 1, session_date: '2026-01-01' }],
    });
    const e = withDB(db);
    await handleDeleteClient('1', e, { role: 'admin', userId: 9 });
    expect(db._state.sessions).toHaveLength(1);
  });

  it('a second delete on an already-deleted client 404s', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'X' }] });
    const e = withDB(db);
    await handleDeleteClient('1', e, { role: 'admin', userId: 9 });
    const res = await handleDeleteClient('1', e, { role: 'admin', userId: 9 });
    expect(res.status).toBe(404);
  });

  it('restore brings a soft-deleted client back', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'X' }] });
    const e = withDB(db);
    await handleDeleteClient('1', e, { role: 'admin', userId: 9 });

    const restoreRes = await handleRestoreClient('1', e, { role: 'admin', userId: 9 });
    expect(restoreRes.status).toBe(200);

    const detailRes = await handleGetClient('1', e, { role: 'admin' });
    expect(detailRes.status).toBe(200);
  });

  it('restore 404s for a client that is not in the recycle bin', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'X' }] });
    const res = await handleRestoreClient('1', withDB(db), { role: 'admin', userId: 9 });
    expect(res.status).toBe(404);
  });

  it('permanent delete requires explicit confirm:true and only works on a soft-deleted client', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'X' }] });
    const e = withDB(db);

    const beforeDelete = await handlePermanentDeleteClient('1', new Request('https://x', { method: 'DELETE', body: JSON.stringify({ confirm: true }) }), e, { role: 'admin', userId: 9 });
    expect(beforeDelete.status).toBe(404);

    await handleDeleteClient('1', e, { role: 'admin', userId: 9 });

    const noConfirm = await handlePermanentDeleteClient('1', new Request('https://x', { method: 'DELETE', body: JSON.stringify({}) }), e, { role: 'admin', userId: 9 });
    expect(noConfirm.status).toBe(400);
    expect(db._state.clients).toHaveLength(1);

    const confirmed = await handlePermanentDeleteClient('1', new Request('https://x', { method: 'DELETE', body: JSON.stringify({ confirm: true }) }), e, { role: 'admin', userId: 9 });
    expect(confirmed.status).toBe(200);
    expect(db._state.clients).toHaveLength(0);
    expect(db._state.auditLog.some(a => a.action === 'permanent_delete' && a.entity_type === 'client')).toBe(true);
  });

  it('blocks non-admin from the recycle bin, restore, and permanent delete', async () => {
    const db = makeFakeD1({ clients: [{ id: 1, full_name: 'X' }] });
    const e = withDB(db);
    expect((await handleGetDeletedClients(e, { role: 'therapist' })).status).toBe(403);
    expect((await handleRestoreClient('1', e, { role: 'therapist' })).status).toBe(403);
    expect((await handlePermanentDeleteClient('1', new Request('https://x', { method: 'DELETE' }), e, { role: 'therapist' })).status).toBe(403);
  });
});
