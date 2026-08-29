import { describe, it, expect, afterEach } from 'vitest';
import { handleContactSubmission, handleGetContacts, handleUpdateContact, handleDeleteContact, handleGetDeletedContacts, handleRestoreContact, handlePermanentDeleteContact } from '../contacts.js';
import { makeFakeD1, mockFetchTurnstile } from './testUtils.js';
import { vi } from 'vitest';

function makeRequest(body, headers = {}) {
  return new Request('https://avital-heal-crm.tgthf7frmp.workers.dev/api/contact', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '9.9.9.9', ...headers },
    body: JSON.stringify(body),
  });
}

describe('handleContactSubmission', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('rejects a submission with no Turnstile token', async () => {
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleContactSubmission(
      makeRequest({ fullName: 'Test User', phone: '0500000000' }),
      env
    );
    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toMatch(/CAPTCHA/);
  });

  it('accepts a valid submission with a verified Turnstile token', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleContactSubmission(
      makeRequest({ fullName: 'Test User', phone: '0500000000', turnstileToken: 'valid-token' }),
      env
    );
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.success).toBe(true);
  });

  it('rejects when Turnstile verification fails', async () => {
    mockFetchTurnstile(false);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleContactSubmission(
      makeRequest({ fullName: 'Test User', phone: '0500000000', turnstileToken: 'bad-token' }),
      env
    );
    expect(res.status).toBe(403);
  });

  it('silently drops honeypot-triggered spam without writing to the DB', async () => {
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleContactSubmission(
      makeRequest({ fullName: 'Bot', phone: '0500000000', website: 'http://spam.example' }),
      env
    );
    expect(res.status).toBe(200);
    expect(env.DB._state.contacts).toHaveLength(0);
  });

  it('requires a full name', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleContactSubmission(
      makeRequest({ phone: '0500000000', turnstileToken: 't' }),
      env
    );
    expect(res.status).toBe(400);
  });

  it('requires at least a phone or email', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleContactSubmission(
      makeRequest({ fullName: 'Test User', turnstileToken: 't' }),
      env
    );
    expect(res.status).toBe(400);
  });

  it('rejects fields exceeding the max length', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleContactSubmission(
      makeRequest({ fullName: 'A'.repeat(3000), phone: '0500000000', turnstileToken: 't' }),
      env
    );
    expect(res.status).toBe(400);
  });

  it('rejects a malformed email', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleContactSubmission(
      makeRequest({ fullName: 'Test User', email: 'not-an-email', turnstileToken: 't' }),
      env
    );
    expect(res.status).toBe(400);
  });

  it('rejects a malformed phone number', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleContactSubmission(
      makeRequest({ fullName: 'Test User', phone: 'abc', turnstileToken: 't' }),
      env
    );
    expect(res.status).toBe(400);
  });

  it('normalizes email and phone before storing', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    await handleContactSubmission(
      makeRequest({ fullName: 'Test User', email: '  Test@Example.COM ', phone: '050-123 4567', turnstileToken: 't' }),
      env
    );
    expect(env.DB._state.contacts[0].email).toBe('test@example.com');
    expect(env.DB._state.contacts[0].phone).toBe('0501234567');
  });

  it('is rate limited after too many requests from one IP', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1(), TURNSTILE_SECRET_KEY: 'k' };
    let last;
    for (let i = 0; i < 11; i++) {
      last = await handleContactSubmission(
        makeRequest({ fullName: 'Test User', phone: '0500000000', turnstileToken: 't' }),
        env
      );
    }
    expect(last.status).toBe(429);
  });
});

describe('handleUpdateContact — RBAC', () => {
  it('allows admin', async () => {
    const env = { DB: makeFakeD1() };
    const req = new Request('https://x/api/contacts/1', {
      method: 'PUT',
      body: JSON.stringify({ status: 'contacted' }),
    });
    const res = await handleUpdateContact('1', req, env, { role: 'admin' });
    expect(res.status).toBe(200);
  });

  it('allows therapist', async () => {
    const env = { DB: makeFakeD1() };
    const req = new Request('https://x/api/contacts/1', {
      method: 'PUT',
      body: JSON.stringify({ status: 'contacted' }),
    });
    const res = await handleUpdateContact('1', req, env, { role: 'therapist' });
    expect(res.status).toBe(200);
  });

  it('blocks viewer', async () => {
    const env = { DB: makeFakeD1() };
    const req = new Request('https://x/api/contacts/1', {
      method: 'PUT',
      body: JSON.stringify({ status: 'contacted' }),
    });
    const res = await handleUpdateContact('1', req, env, { role: 'viewer' });
    expect(res.status).toBe(403);
  });

  it('rejects an out-of-enum status value', async () => {
    const env = { DB: makeFakeD1() };
    const req = new Request('https://x/api/contacts/1', {
      method: 'PUT',
      body: JSON.stringify({ status: 'deleted-forever' }),
    });
    const res = await handleUpdateContact('1', req, env, { role: 'admin' });
    expect(res.status).toBe(400);
  });

  it('accepts "rejected" as a valid status', async () => {
    const env = { DB: makeFakeD1() };
    const req = new Request('https://x/api/contacts/1', {
      method: 'PUT',
      body: JSON.stringify({ status: 'rejected' }),
    });
    const res = await handleUpdateContact('1', req, env, { role: 'admin' });
    expect(res.status).toBe(200);
  });
});

describe('handleDeleteContact — RBAC', () => {
  it('blocks non-admin roles', async () => {
    const env = { DB: makeFakeD1({ contacts: [{ id: 1, full_name: 'X' }] }) };
    const res = await handleDeleteContact('1', env, { role: 'therapist' });
    expect(res.status).toBe(403);
  });

  it('allows admin', async () => {
    const env = { DB: makeFakeD1({ contacts: [{ id: 1, full_name: 'X' }] }) };
    const res = await handleDeleteContact('1', env, { role: 'admin', userId: 9, email: 'a@x.com' });
    expect(res.status).toBe(200);
  });

  it('404s for a contact that does not exist', async () => {
    const env = { DB: makeFakeD1() };
    const res = await handleDeleteContact('999', env, { role: 'admin', userId: 9 });
    expect(res.status).toBe(404);
  });
});

describe('soft-delete recycle bin — contacts', () => {
  it('soft-deleted contact disappears from the normal list and appears in the recycle bin', async () => {
    const db = makeFakeD1({ contacts: [{ id: 1, full_name: 'X' }] });
    const env = { DB: db };
    await handleDeleteContact('1', env, { role: 'admin', userId: 9, email: 'a@x.com' });

    const listRes = await handleGetContacts(new URL('https://x/api/contacts'), env);
    expect(await listRes.json()).toEqual([]);

    const binRes = await handleGetDeletedContacts(env, { role: 'admin' });
    const bin = await binRes.json();
    expect(bin).toHaveLength(1);
    expect(bin[0].id).toBe(1);
  });

  it('a second delete on an already-deleted contact 404s', async () => {
    const db = makeFakeD1({ contacts: [{ id: 1, full_name: 'X' }] });
    const env = { DB: db };
    await handleDeleteContact('1', env, { role: 'admin', userId: 9 });
    const res = await handleDeleteContact('1', env, { role: 'admin', userId: 9 });
    expect(res.status).toBe(404);
  });

  it('restore brings a soft-deleted contact back to the normal list', async () => {
    const db = makeFakeD1({ contacts: [{ id: 1, full_name: 'X' }] });
    const env = { DB: db };
    await handleDeleteContact('1', env, { role: 'admin', userId: 9 });

    const restoreRes = await handleRestoreContact('1', env, { role: 'admin', userId: 9 });
    expect(restoreRes.status).toBe(200);

    const listRes = await handleGetContacts(new URL('https://x/api/contacts'), env);
    expect(await listRes.json()).toHaveLength(1);
  });

  it('restore 404s for a contact that is not in the recycle bin', async () => {
    const db = makeFakeD1({ contacts: [{ id: 1, full_name: 'X' }] });
    const env = { DB: db };
    const res = await handleRestoreContact('1', env, { role: 'admin', userId: 9 });
    expect(res.status).toBe(404);
  });

  it('permanent delete requires explicit confirm:true', async () => {
    const db = makeFakeD1({ contacts: [{ id: 1, full_name: 'X' }] });
    const env = { DB: db };
    await handleDeleteContact('1', env, { role: 'admin', userId: 9 });

    const noConfirm = await handlePermanentDeleteContact('1', new Request('https://x', { method: 'DELETE', body: JSON.stringify({}) }), env, { role: 'admin', userId: 9 });
    expect(noConfirm.status).toBe(400);
    expect(db._state.contacts).toHaveLength(1);

    const confirmed = await handlePermanentDeleteContact('1', new Request('https://x', { method: 'DELETE', body: JSON.stringify({ confirm: true }) }), env, { role: 'admin', userId: 9 });
    expect(confirmed.status).toBe(200);
    expect(db._state.contacts).toHaveLength(0);
  });

  it('permanent delete 404s for a contact that is not soft-deleted', async () => {
    const db = makeFakeD1({ contacts: [{ id: 1, full_name: 'X' }] });
    const env = { DB: db };
    const res = await handlePermanentDeleteContact('1', new Request('https://x', { method: 'DELETE', body: JSON.stringify({ confirm: true }) }), env, { role: 'admin', userId: 9 });
    expect(res.status).toBe(404);
  });

  it('blocks non-admin from viewing the recycle bin', async () => {
    const res = await handleGetDeletedContacts({ DB: makeFakeD1() }, { role: 'therapist' });
    expect(res.status).toBe(403);
  });
});
