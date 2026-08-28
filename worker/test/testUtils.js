import { vi } from 'vitest';

/**
 * Applies an `UPDATE <table> SET <assignments> WHERE id = ? [AND deleted_at IS [NOT] NULL]`
 * statement to an in-memory row collection. Handles both bound placeholders
 * (`field = ?`) and the two literal forms the worker actually emits
 * (`field = datetime('now')`, `field = NULL`) — enough to fake soft-delete /
 * restore semantics, including the changes=0 result a real WHERE-guarded
 * UPDATE would produce when the row doesn't match the guard.
 */
function applyDynamicUpdate(sql, args, collection) {
  const setClause = sql.match(/SET\s+([\s\S]+?)\s+WHERE/i)[1];
  const whereClause = sql.match(/WHERE([\s\S]+)$/i)[1];

  const assignments = setClause.split(',').map(s => s.trim()).map(a => {
    const eq = a.indexOf('=');
    const field = a.slice(0, eq).trim();
    const rawValue = a.slice(eq + 1).trim();
    if (rawValue === '?') return { field, placeholder: true };
    if (/^datetime\(/i.test(rawValue)) return { field, literal: new Date().toISOString() };
    if (/^NULL$/i.test(rawValue)) return { field, literal: null };
    return { field, literal: rawValue.replace(/^'|'$/g, '') };
  });

  const placeholderCount = assignments.filter(a => a.placeholder).length;
  const id = args[placeholderCount];
  const row = collection.find(r => String(r.id) === String(id));
  if (!row) return { row: null, changed: false };

  if (/deleted_at\s+IS\s+NOT\s+NULL/i.test(whereClause) && !row.deleted_at) return { row, changed: false };
  if (/deleted_at\s+IS\s+NULL/i.test(whereClause) && !/NOT\s+NULL/i.test(whereClause) && row.deleted_at) return { row, changed: false };

  let pIdx = 0;
  assignments.forEach(a => { row[a.field] = a.placeholder ? args[pIdx++] : a.literal; });
  return { row, changed: true };
}

/**
 * A minimal in-memory fake D1 database. Supports the small set of query
 * shapes the worker actually issues (SELECT ... WHERE col = ?, INSERT,
 * UPDATE, DELETE) against named in-memory tables, keyed by a caller-supplied
 * matcher rather than a real SQL parser — good enough for unit tests without
 * pulling in a full SQLite engine.
 */
export function makeFakeD1({ contacts = [], workshops = [], rateLimits = new Map(), clients = [], consents = [], workshopRegistrations = [], sessions = [], passwordResets = [], auditLog = [], users = [] } = {}) {
  let nextContactId = contacts.reduce((m, c) => Math.max(m, c.id || 0), 0) + 1;
  let nextClientId = clients.reduce((m, c) => Math.max(m, c.id || 0), 0) + 1;
  let nextConsentId = 1;
  let nextRegistrationId = workshopRegistrations.reduce((m, r) => Math.max(m, r.id || 0), 0) + 1;
  let nextSessionId = sessions.reduce((m, s) => Math.max(m, s.id || 0), 0) + 1;
  let nextAuditId = 1;
  const state = { contacts, workshops, rateLimits, clients, consents, workshopRegistrations, sessions, passwordResets, auditLog, users };

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
          if (/FROM clients WHERE email = \? AND deleted_at IS NULL/.test(sql)) {
            return state.clients.find(c => c.email === call.args[0] && !c.deleted_at) || null;
          }
          if (/FROM clients WHERE email = \?/.test(sql)) {
            return state.clients.find(c => c.email === call.args[0]) || null;
          }
          if (/FROM clients WHERE id = \? AND deleted_at IS NOT NULL/.test(sql)) {
            const c = state.clients.find(x => String(x.id) === String(call.args[0]));
            return (c && c.deleted_at) ? c : null;
          }
          if (/FROM clients WHERE id = \? AND deleted_at IS NULL/.test(sql)) {
            const c = state.clients.find(x => String(x.id) === String(call.args[0]));
            return (c && !c.deleted_at) ? c : null;
          }
          if (/FROM clients WHERE id = \?/.test(sql)) {
            return state.clients.find(c => String(c.id) === String(call.args[0])) || null;
          }
          if (/FROM sessions WHERE id = \? AND deleted_at IS NOT NULL/.test(sql)) {
            const s = state.sessions.find(x => String(x.id) === String(call.args[0]));
            return (s && s.deleted_at) ? s : null;
          }
          if (/FROM contacts WHERE id = \? AND deleted_at IS NOT NULL/.test(sql)) {
            const c = state.contacts.find(x => String(x.id) === String(call.args[0]));
            return (c && c.deleted_at) ? c : null;
          }
          if (/FROM workshop_registrations WHERE id = \? AND deleted_at IS NOT NULL/.test(sql)) {
            const r = state.workshopRegistrations.find(x => String(x.id) === String(call.args[0]));
            return (r && r.deleted_at) ? r : null;
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
            const rows = state.sessions
              .filter(s => !s.deleted_at)
              .map(s => ({ ...s, client_name: (state.clients.find(c => String(c.id) === String(s.client_id)) || {}).full_name }));
            return { results: rows.sort((a, b) => (b.session_date || '').localeCompare(a.session_date || '')) };
          }
          if (/sessions s\s+JOIN clients c ON s\.client_id = c\.id\s+LEFT JOIN users/.test(sql)) {
            const rows = state.sessions
              .filter(s => s.deleted_at)
              .map(s => ({ ...s, client_name: (state.clients.find(c => String(c.id) === String(s.client_id)) || {}).full_name }));
            return { results: rows };
          }
          if (/FROM sessions WHERE client_id = \?/.test(sql)) {
            const clientId = call.args[0];
            const rows = state.sessions.filter(s => String(s.client_id) === String(clientId) && !s.deleted_at);
            return { results: rows.sort((a, b) => (b.session_date || '').localeCompare(a.session_date || '')) };
          }
          if (/FROM clients c LEFT JOIN users/.test(sql)) {
            const rows = state.clients.filter(c => c.deleted_at);
            return { results: rows };
          }
          if (/FROM clients c WHERE c\.deleted_at IS NULL/.test(sql)) {
            return { results: state.clients.filter(c => !c.deleted_at) };
          }
          if (/FROM contacts c LEFT JOIN users/.test(sql)) {
            const rows = state.contacts.filter(c => c.deleted_at);
            return { results: rows };
          }
          if (/FROM contacts WHERE deleted_at IS NULL/.test(sql)) {
            let rows = state.contacts.filter(c => !c.deleted_at);
            if (/AND status = \?/.test(sql)) rows = rows.filter(c => c.status === call.args[0]);
            return { results: rows };
          }
          if (/FROM workshop_registrations r/.test(sql) && /deleted_at IS NOT NULL/.test(sql)) {
            const rows = state.workshopRegistrations.filter(r => r.deleted_at);
            return { results: rows };
          }
          if (/FROM audit_log WHERE 1=1/.test(sql)) {
            let idx = 0;
            const hasEntityType = /AND entity_type = \?/.test(sql);
            const hasAction = /AND action = \?/.test(sql);
            const entityType = hasEntityType ? call.args[idx++] : null;
            const action = hasAction ? call.args[idx++] : null;
            const limit = call.args[idx++];
            const offset = call.args[idx++];
            let rows = state.auditLog.slice().sort((a, b) => b.id - a.id);
            if (hasEntityType) rows = rows.filter(r => r.entity_type === entityType);
            if (hasAction) rows = rows.filter(r => r.action === action);
            rows = rows.slice(offset, offset + limit);
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
            const id = nextContactId++;
            state.contacts.push({ id, full_name, phone, email, message, status: 'new' });
            return { meta: { last_row_id: id } };
          } else if (/UPDATE contacts SET/.test(sql)) {
            const { changed } = applyDynamicUpdate(sql, call.args, state.contacts);
            return { meta: { changes: changed ? 1 : 0 } };
          } else if (/DELETE FROM contacts WHERE id = \?/.test(sql)) {
            const [id] = call.args;
            state.contacts = state.contacts.filter(c => String(c.id) !== String(id));
          } else if (/INSERT INTO audit_log/.test(sql)) {
            const [user_id, user_email, action, entity_type, entity_id, result, metadata] = call.args;
            const id = nextAuditId++;
            state.auditLog.push({ id, user_id, user_email, action, entity_type, entity_id, result, metadata, created_at: new Date().toISOString() });
            return { meta: { last_row_id: id } };
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
            const { changed } = applyDynamicUpdate(sql, call.args, state.clients);
            return { meta: { changes: changed ? 1 : 0 } };
          } else if (/DELETE FROM clients WHERE id = \?/.test(sql)) {
            const [id] = call.args;
            state.clients = state.clients.filter(c => String(c.id) !== String(id));
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
          } else if (/UPDATE workshop_registrations SET/.test(sql)) {
            const { changed } = applyDynamicUpdate(sql, call.args, state.workshopRegistrations);
            return { meta: { changes: changed ? 1 : 0 } };
          } else if (/DELETE FROM workshop_registrations WHERE id = \?/.test(sql)) {
            const [id] = call.args;
            state.workshopRegistrations = state.workshopRegistrations.filter(r => String(r.id) !== String(id));
          } else if (/INSERT INTO sessions/.test(sql)) {
            const [client_id, session_date, session_type, duration_minutes, summary, next_session_notes, paid, amount, payment_method, invoice_number] = call.args;
            const id = nextSessionId++;
            state.sessions.push({ id, client_id, session_date, session_type, duration_minutes, summary, next_session_notes, paid, amount, payment_method, invoice_number });
            return { meta: { last_row_id: id } };
          } else if (/UPDATE sessions SET/.test(sql)) {
            const { changed } = applyDynamicUpdate(sql, call.args, state.sessions);
            return { meta: { changes: changed ? 1 : 0 } };
          } else if (/DELETE FROM sessions WHERE id = \?/.test(sql)) {
            const [id] = call.args;
            state.sessions = state.sessions.filter(s => String(s.id) !== String(id));
          } else if (/DELETE FROM sessions/.test(sql)) {
            const [id] = call.args;
            state.sessions = state.sessions.filter(s => String(s.client_id) !== String(id));
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
