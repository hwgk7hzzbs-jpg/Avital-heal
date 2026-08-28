import { describe, it, expect, afterEach } from 'vitest';
import { handleContactSubmission, handleUpdateContact, handleDeleteContact } from '../contacts.js';
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
});

describe('handleDeleteContact — RBAC', () => {
  it('blocks non-admin roles', async () => {
    const env = { DB: makeFakeD1() };
    const res = await handleDeleteContact('1', env, { role: 'therapist' });
    expect(res.status).toBe(403);
  });

  it('allows admin', async () => {
    const env = { DB: makeFakeD1() };
    const res = await handleDeleteContact('1', env, { role: 'admin' });
    expect(res.status).toBe(200);
  });
});
