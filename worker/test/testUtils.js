import { vi } from 'vitest';

/**
 * A minimal in-memory fake D1 database. Supports the small set of query
 * shapes the worker actually issues (SELECT ... WHERE col = ?, INSERT,
 * UPDATE, DELETE) against named in-memory tables, keyed by a caller-supplied
 * matcher rather than a real SQL parser — good enough for unit tests without
 * pulling in a full SQLite engine.
 */
export function makeFakeD1({ contacts = [], workshops = [], rateLimits = new Map(), clients = [], consents = [], workshopRegistrations = [] } = {}) {
  let nextContactId = 1;
  let nextClientId = clients.reduce((m, c) => Math.max(m, c.id || 0), 0) + 1;
  let nextConsentId = 1;
  let nextRegistrationId = 1;
  const state = { contacts, workshops, rateLimits, clients, consents, workshopRegistrations };

  return {
    _state: state,
    prepare(sql) {
      const call = { sql, args: [] };
      const api = {
        bind(...args) {
          call.args = args;
          return api;
        },
        async first() {
          if (/FROM rate_limits/.test(sql)) {
            return state.rateLimits.get(call.args[0]) || null;
          }
          if (/FROM workshops WHERE id = \?/.test(sql)) {
            return state.workshops.find(w => w.id === call.args[0] && (!/active = 1/.test(sql) || w.active)) || null;
          }
          if (/FROM clients WHERE email = \?/.test(sql)) {
            return state.clients.find(c => c.email === call.args[0]) || null;
          }
          if (/FROM consents WHERE id = \?/.test(sql)) {
            return state.consents.find(c => c.id === call.args[0]) || null;
          }
          return null;
        },
        async all() {
          if (/FROM consents WHERE client_id = \?/.test(sql)) {
            const rows = state.consents
              .filter(c => c.client_id === call.args[0])
              .sort((a, b) => b.signed_at.localeCompare(a.signed_at));
            return { results: rows };
          }
          return { results: [] };
        },
        async run() {
          if (/INSERT INTO rate_limits/.test(sql)) {
            const [key, expires_at] = call.args;
            state.rateLimits.set(key, { count: 1, expires_at });
          } else if (/UPDATE rate_limits/.test(sql)) {
            const [key] = call.args;
            const row = state.rateLimits.get(key);
            if (row) row.count += 1;
          } else if (/INSERT INTO contacts/.test(sql)) {
            const [full_name, phone, email, message] = call.args;
            state.contacts.push({ id: nextContactId++, full_name, phone, email, message, status: 'new' });
          } else if (/INSERT INTO clients/.test(sql)) {
            const [full_name, email, consent_date, ip] = call.args;
            const id = nextClientId++;
            state.clients.push({ id, full_name, email, consent_signed: 1, consent_date, consent_ip: ip });
            return { meta: { last_row_id: id } };
          } else if (/UPDATE clients SET consent_signed/.test(sql)) {
            const [consent_date, id] = call.args;
            const c = state.clients.find(x => x.id === id);
            if (c) { c.consent_signed = 1; c.consent_date = consent_date; }
          } else if (/INSERT INTO consents/.test(sql)) {
            const [consent_type, client_id, workshop_registration_id, consent_version, document_hash, source, ip, signed_at] = call.args;
            const id = nextConsentId++;
            state.consents.push({ id, consent_type, client_id, workshop_registration_id, consent_version, document_hash, source, status: 'active', ip, signed_at, revoked_at: null });
            return { meta: { last_row_id: id } };
          } else if (/UPDATE consents SET status = 'revoked'/.test(sql)) {
            const [id] = call.args;
            const c = state.consents.find(x => x.id === id);
            if (c) { c.status = 'revoked'; c.revoked_at = 'now'; }
          } else if (/INSERT INTO workshop_registrations/.test(sql)) {
            const [workshop_id, full_name, phone, email, date_option, notes, ip] = call.args;
            const id = nextRegistrationId++;
            state.workshopRegistrations.push({ id, workshop_id, full_name, phone, email, date_option, notes, status: 'new', consent_ip: ip });
            return { meta: { last_row_id: id } };
          }
          return { meta: { last_row_id: nextContactId - 1 } };
        },
      };
      return api;
    },
  };
}

export function mockFetchTurnstile(success = true) {
  vi.stubGlobal('fetch', vi.fn(async (url) => {
    if (String(url).includes('turnstile')) {
      return { json: async () => ({ success }) };
    }
    return { json: async () => ({}) };
  }));
}
