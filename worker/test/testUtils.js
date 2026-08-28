import { vi } from 'vitest';

/**
 * A minimal in-memory fake D1 database. Supports the small set of query
 * shapes the worker actually issues (SELECT ... WHERE col = ?, INSERT,
 * UPDATE, DELETE) against named in-memory tables, keyed by a caller-supplied
 * matcher rather than a real SQL parser — good enough for unit tests without
 * pulling in a full SQLite engine.
 */
export function makeFakeD1({ contacts = [], workshops = [], rateLimits = new Map() } = {}) {
  let nextContactId = 1;
  const state = { contacts, workshops, rateLimits };

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
          return null;
        },
        async all() {
          return { results: [] };
        },
        async run() {
          if (/INSERT INTO rate_limits/.test(sql)) {
            const [key, count, expires_at] = call.args;
            state.rateLimits.set(key, { count, expires_at });
          } else if (/UPDATE rate_limits/.test(sql)) {
            const [key] = call.args;
            const row = state.rateLimits.get(key);
            if (row) row.count += 1;
          } else if (/INSERT INTO contacts/.test(sql)) {
            const [full_name, phone, email, message] = call.args;
            state.contacts.push({ id: nextContactId++, full_name, phone, email, message, status: 'new' });
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
