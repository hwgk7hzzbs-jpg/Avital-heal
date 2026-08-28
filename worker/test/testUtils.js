import { vi } from 'vitest';

function applyDynamicUpdate(sql, args, collection) {
  const setClause = sql.match(/SET\s+([\s\S]+?)\s+WHERE/i)[1];
  const fieldNames = setClause
    .split(',')
    .map(s => s.trim())
    .filter(p => p.endsWith('= ?'))
    .map(p => p.replace(/\s*=\s*\?$/, ''));
  const id = args[args.length - 1];
  const row = collection.find(r => String(r.id) === String(id));
  if (row) fieldNames.forEach((f, i) => { row[f] = args[i]; });
  return row;
}

/**
 * A minimal in-memory fake D1 database. Supports the small set of query
 * shapes the worker actually issues (SELECT ... WHERE col = ?, INSERT,
 * UPDATE, DELETE) against named in-memory tables, keyed by a caller-supplied
 * matcher rather than a real SQL parser — good enough for unit tests without
 * pulling in a full SQLite engine.
 */
export function makeFakeD1({ contacts = [], workshops = [], rateLimits = new Map(), clients = [], consents = [], workshopRegistrations = [], sessions = [], passwordResets = [] } = {}) {
  let nextContactId = 1;
  let nextClientId = clients.reduce((m, c) => Math.max(m, c.id || 0), 0) + 1;
  let nextConsentId = 1;
  let nextRegistrationId = 1;
  let nextSessionId = sessions.reduce((m, s) => Math.max(m, s.id || 0), 0) + 1;
  const state = { contacts, workshops, rateLimits, clients, consents, workshopRegistrations, sessions, passwordResets };

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
          if (/FROM clients WHERE id = \?/.test(sql)) {
            return state.clients.find(c => String(c.id) === String(call.args[0])) || null;
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
          if (/FROM sessions s JOIN clients/.test(sql)) {
            // handleGetSessions: optional client_id/from/to filters + a trailing LIMIT ?,
            // none of which this fake bothers emulating precisely — return everything,
            // enough to test the decrypt-on-read behavior these tests care about.
            const rows = state.sessions.map(s => ({ ...s, client_name: (state.clients.find(c => String(c.id) === String(s.client_id)) || {}).full_name }));
            return { results: rows.sort((a, b) => (b.session_date || '').localeCompare(a.session_date || '')) };
          }
          if (/FROM sessions WHERE client_id = \?/.test(sql)) {
            const clientId = call.args[0];
            const rows = state.sessions.filter(s => String(s.client_id) === String(clientId));
            return { results: rows.sort((a, b) => (b.session_date || '').localeCompare(a.session_date || '')) };
          }
          if (/FROM clients c WHERE 1=1/.test(sql)) {
            return { results: state.clients.slice() };
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
          } else if (/INSERT INTO clients \(full_name, email, phone/.test(sql)) {
            // handleCreateClient's shape: (full_name, email, phone, address, birth_date, treatment_type, notes)
            const [full_name, email, phone, address, birth_date, treatment_type, notes] = call.args;
            const id = nextClientId++;
            state.clients.push({ id, full_name, email, phone, address, birth_date, treatment_type, notes, consent_signed: 0 });
            return { meta: { last_row_id: id } };
          } else if (/INSERT INTO clients/.test(sql)) {
            // consent.js's shape: (full_name, email, consent_signed, consent_date, ...)
            const [full_name, email, consent_date] = call.args;
            const id = nextClientId++;
            state.clients.push({ id, full_name, email, consent_signed: 1, consent_date });
            return { meta: { last_row_id: id } };
          } else if (/UPDATE clients SET consent_signed/.test(sql)) {
            const [consent_date, id] = call.args;
            const c = state.clients.find(x => x.id === id);
            if (c) { c.consent_signed = 1; c.consent_date = consent_date; }
          } else if (/UPDATE clients SET/.test(sql)) {
            applyDynamicUpdate(sql, call.args, state.clients);
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
            const [workshop_id, full_name, phone, email, date_option, notes] = call.args;
            const id = nextRegistrationId++;
            state.workshopRegistrations.push({ id, workshop_id, full_name, phone, email, date_option, notes, status: 'new' });
            return { meta: { last_row_id: id } };
          } else if (/INSERT INTO sessions/.test(sql)) {
            const [client_id, session_date, session_type, duration_minutes, summary, next_session_notes, paid, amount, payment_method, invoice_number] = call.args;
            const id = nextSessionId++;
            state.sessions.push({ id, client_id, session_date, session_type, duration_minutes, summary, next_session_notes, paid, amount, payment_method, invoice_number });
            return { meta: { last_row_id: id } };
          } else if (/UPDATE sessions SET/.test(sql)) {
            applyDynamicUpdate(sql, call.args, state.sessions);
          } else if (/DELETE FROM sessions/.test(sql)) {
            const [id] = call.args;
            state.sessions = state.sessions.filter(s => String(s.id) !== String(id));
          } else if (/DELETE FROM rate_limits WHERE expires_at < \?/.test(sql)) {
            const [cutoff] = call.args;
            const before = state.rateLimits.size;
            for (const [k, v] of state.rateLimits) if (v.expires_at < cutoff) state.rateLimits.delete(k);
            return { meta: { changes: before - state.rateLimits.size } };
          } else if (/DELETE FROM password_resets/.test(sql)) {
            // Test rows carry a pre-computed `expired` boolean instead of a real
            // datetime('now') comparison — see makeFakeD1's passwordResets param.
            const before = state.passwordResets.length;
            state.passwordResets = state.passwordResets.filter(r => !r.used && !r.expired);
            return { meta: { changes: before - state.passwordResets.length } };
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
