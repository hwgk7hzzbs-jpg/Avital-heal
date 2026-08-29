import { describe, it, expect } from 'vitest';
import worker from '../index.js';
import { makeFakeD1 } from './testUtils.js';

describe('scheduled (daily retention cleanup)', () => {
  it('removes expired rate_limits rows but keeps unexpired ones', async () => {
    const now = Math.floor(Date.now() / 1000);
    const rateLimits = new Map([
      ['expired-key', { count: 5, expires_at: now - 100 }],
      ['fresh-key', { count: 1, expires_at: now + 3600 }],
    ]);
    const db = makeFakeD1({ rateLimits });
    const env = { DB: db };

    await worker.scheduled({}, env);

    expect(db._state.rateLimits.has('expired-key')).toBe(false);
    expect(db._state.rateLimits.has('fresh-key')).toBe(true);
  });

  it('removes used or expired password_resets but keeps valid ones', async () => {
    const db = makeFakeD1({
      passwordResets: [
        { id: 1, used: true, expired: false },
        { id: 2, used: false, expired: true },
        { id: 3, used: false, expired: false },
      ],
    });
    const env = { DB: db };

    await worker.scheduled({}, env);

    expect(db._state.passwordResets.map(r => r.id)).toEqual([3]);
  });

  it('does not touch client/session/contact/consent business data', async () => {
    const db = makeFakeD1({
      clients: [{ id: 1, full_name: 'Should Survive' }],
      consents: [{ id: 1, client_id: 1 }],
    });
    const env = { DB: db };

    await worker.scheduled({}, env);

    expect(db._state.clients).toHaveLength(1);
    expect(db._state.consents).toHaveLength(1);
  });

  it('removes revoked or expired refresh_tokens but keeps active, unexpired ones', async () => {
    const db = makeFakeD1({
      refreshTokens: [
        { id: 1, user_id: 1, token_hash: 'revoked', token_version: 0, expires_at: '2999-01-01T00:00:00.000Z', revoked_at: '2020-01-01T00:00:00.000Z' },
        { id: 2, user_id: 1, token_hash: 'expired', token_version: 0, expires_at: '2000-01-01T00:00:00.000Z', revoked_at: null },
        { id: 3, user_id: 1, token_hash: 'active', token_version: 0, expires_at: '2999-01-01T00:00:00.000Z', revoked_at: null },
      ],
    });
    const env = { DB: db };

    await worker.scheduled({}, env);

    expect(db._state.refreshTokens.map(r => r.token_hash)).toEqual(['active']);
  });

  it('does not throw if D1 errors — cleanup failure must not crash the cron trigger', async () => {
    const env = { DB: { prepare() { throw new Error('D1 down'); } } };
    await expect(worker.scheduled({}, env)).resolves.toBeUndefined();
  });
});
