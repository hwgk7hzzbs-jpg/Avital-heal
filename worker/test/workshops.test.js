import { describe, it, expect, afterEach } from 'vitest';
import { handleWorkshopRegister, handleUpdateRegistration } from '../workshops.js';
import { makeFakeD1, mockFetchTurnstile } from './testUtils.js';
import { vi } from 'vitest';

const WORKSHOP = {
  id: 'test-workshop',
  name: 'Test Workshop',
  dates: JSON.stringify([{ id: 'date-1', label: '1.1.2026', date: '2026-01-01T10:00:00' }]),
  active: 1,
};

function makeRequest(body) {
  return new Request('https://x/api/workshop-register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'CF-Connecting-IP': '9.9.9.9' },
    body: JSON.stringify(body),
  });
}

function validBody(overrides = {}) {
  return {
    fullName: 'Test User', phone: '0501234567', email: 'a@b.com',
    workshopId: WORKSHOP.id, dateOption: 'date-1', consentAgreed: true,
    turnstileToken: 't',
    ...overrides,
  };
}

describe('handleWorkshopRegister', () => {
  afterEach(() => vi.unstubAllGlobals());

  it('registers successfully with valid data', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1({ workshops: [WORKSHOP] }), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleWorkshopRegister(makeRequest(validBody()), env);
    expect(res.status).toBe(200);
    expect(env.DB._state.workshopRegistrations).toHaveLength(1);
  });

  it('rejects a malformed phone number', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1({ workshops: [WORKSHOP] }), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleWorkshopRegister(makeRequest(validBody({ phone: 'call-me' })), env);
    expect(res.status).toBe(400);
  });

  it('rejects a malformed email when provided', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1({ workshops: [WORKSHOP] }), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleWorkshopRegister(makeRequest(validBody({ email: 'not-an-email' })), env);
    expect(res.status).toBe(400);
  });

  it('normalizes phone and email before storing', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1({ workshops: [WORKSHOP] }), TURNSTILE_SECRET_KEY: 'k' };
    await handleWorkshopRegister(makeRequest(validBody({ phone: '050-123 4567', email: '  A@B.COM ' })), env);
    expect(env.DB._state.workshopRegistrations[0].phone).toBe('0501234567');
    expect(env.DB._state.workshopRegistrations[0].email).toBe('a@b.com');
  });

  it('rejects a duplicate registration for the same phone/workshop/date', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1({ workshops: [WORKSHOP] }), TURNSTILE_SECRET_KEY: 'k' };
    const first = await handleWorkshopRegister(makeRequest(validBody()), env);
    expect(first.status).toBe(200);

    const second = await handleWorkshopRegister(makeRequest(validBody()), env);
    expect(second.status).toBe(400);
    expect(env.DB._state.workshopRegistrations).toHaveLength(1);
  });

  it('allows re-registering after the previous registration for that slot was cancelled', async () => {
    mockFetchTurnstile(true);
    const env = {
      DB: makeFakeD1({
        workshops: [WORKSHOP],
        workshopRegistrations: [{ id: 1, workshop_id: WORKSHOP.id, date_option: 'date-1', phone: '0501234567', status: 'cancelled' }],
      }),
      TURNSTILE_SECRET_KEY: 'k',
    };
    const res = await handleWorkshopRegister(makeRequest(validBody()), env);
    expect(res.status).toBe(200);
  });

  it('allows the same phone to register for a different date option', async () => {
    mockFetchTurnstile(true);
    const twoDateWorkshop = { ...WORKSHOP, dates: JSON.stringify([
      { id: 'date-1', label: '1.1.2026', date: '2026-01-01T10:00:00' },
      { id: 'date-2', label: '2.1.2026', date: '2026-01-02T10:00:00' },
    ]) };
    const env = {
      DB: makeFakeD1({
        workshops: [twoDateWorkshop],
        workshopRegistrations: [{ id: 1, workshop_id: WORKSHOP.id, date_option: 'date-1', phone: '0501234567', status: 'new' }],
      }),
      TURNSTILE_SECRET_KEY: 'k',
    };
    const res = await handleWorkshopRegister(makeRequest(validBody({ dateOption: 'date-2' })), env);
    expect(res.status).toBe(200);
  });

  it('rejects a date option that does not belong to the workshop', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1({ workshops: [WORKSHOP] }), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleWorkshopRegister(makeRequest(validBody({ dateOption: 'nonexistent' })), env);
    expect(res.status).toBe(400);
  });

  it('rejects registration for an inactive/nonexistent workshop', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1({ workshops: [{ ...WORKSHOP, active: 0 }] }), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleWorkshopRegister(makeRequest(validBody()), env);
    expect(res.status).toBe(404);
  });

  it('requires consent agreement', async () => {
    mockFetchTurnstile(true);
    const env = { DB: makeFakeD1({ workshops: [WORKSHOP] }), TURNSTILE_SECRET_KEY: 'k' };
    const res = await handleWorkshopRegister(makeRequest(validBody({ consentAgreed: false })), env);
    expect(res.status).toBe(400);
  });

  it('silently drops honeypot-triggered spam without writing to the DB', async () => {
    const env = { DB: makeFakeD1({ workshops: [WORKSHOP] }) };
    const res = await handleWorkshopRegister(makeRequest(validBody({ website: 'http://spam.example' })), env);
    expect(res.status).toBe(200);
    expect(env.DB._state.workshopRegistrations).toHaveLength(0);
  });
});

describe('handleUpdateRegistration — status enum', () => {
  it('accepts every status in the closed list', async () => {
    for (const status of ['new', 'contacted', 'confirmed', 'cancelled']) {
      const db = makeFakeD1({ workshopRegistrations: [{ id: 1, workshop_id: WORKSHOP.id, status: 'new' }] });
      const req = new Request('https://x', { method: 'PUT', body: JSON.stringify({ status }) });
      const res = await handleUpdateRegistration('1', req, { DB: db }, { role: 'admin', userId: 9 });
      expect(res.status).toBe(200);
    }
  });

  it('rejects an out-of-enum status', async () => {
    const db = makeFakeD1({ workshopRegistrations: [{ id: 1, workshop_id: WORKSHOP.id, status: 'new' }] });
    const req = new Request('https://x', { method: 'PUT', body: JSON.stringify({ status: 'maybe' }) });
    const res = await handleUpdateRegistration('1', req, { DB: db }, { role: 'admin', userId: 9 });
    expect(res.status).toBe(400);
  });

  it('blocks viewer from updating a registration', async () => {
    const db = makeFakeD1({ workshopRegistrations: [{ id: 1, workshop_id: WORKSHOP.id, status: 'new' }] });
    const req = new Request('https://x', { method: 'PUT', body: JSON.stringify({ status: 'confirmed' }) });
    const res = await handleUpdateRegistration('1', req, { DB: db }, { role: 'viewer' });
    expect(res.status).toBe(403);
  });
});
