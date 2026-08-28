import { describe, it, expect } from 'vitest';
import { recordAudit, handleGetAuditLog } from '../auditLog.js';
import { makeFakeD1 } from './testUtils.js';

function withDB(db) { return { DB: db }; }

describe('recordAudit', () => {
  it('writes a row with the given fields, JSON-encoding metadata', async () => {
    const db = makeFakeD1();
    await recordAudit(withDB(db), {
      userId: 1, userEmail: 'a@x.com', action: 'login', entityType: 'user', entityId: 1,
      result: 'success', metadata: { foo: 'bar' },
    });
    expect(db._state.auditLog).toHaveLength(1);
    const row = db._state.auditLog[0];
    expect(row.action).toBe('login');
    expect(row.entity_type).toBe('user');
    expect(row.entity_id).toBe('1');
    expect(row.result).toBe('success');
    expect(JSON.parse(row.metadata)).toEqual({ foo: 'bar' });
  });

  it('defaults result to success and metadata to null when omitted', async () => {
    const db = makeFakeD1();
    await recordAudit(withDB(db), { action: 'view', entityType: 'client', entityId: 5 });
    const row = db._state.auditLog[0];
    expect(row.result).toBe('success');
    expect(row.metadata).toBeNull();
  });

  it('never throws when the DB write fails — audit logging must not break the primary operation', async () => {
    const brokenEnv = { DB: { prepare() { throw new Error('D1 down'); } } };
    await expect(recordAudit(brokenEnv, { action: 'login', entityType: 'user' })).resolves.toBeUndefined();
  });
});

describe('handleGetAuditLog', () => {
  it('blocks non-admin roles', async () => {
    const res = await handleGetAuditLog(new URL('https://x/api/audit-log'), withDB(makeFakeD1()), { role: 'therapist' });
    expect(res.status).toBe(403);
  });

  it('returns logged entries, most recent first', async () => {
    const db = makeFakeD1();
    const env = withDB(db);
    await recordAudit(env, { action: 'login', entityType: 'user', entityId: 1 });
    await recordAudit(env, { action: 'create', entityType: 'client', entityId: 2 });

    const res = await handleGetAuditLog(new URL('https://x/api/audit-log'), env, { role: 'admin' });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toHaveLength(2);
    expect(body[0].action).toBe('create');
    expect(body[1].action).toBe('login');
  });

  it('filters by entity_type and action', async () => {
    const db = makeFakeD1();
    const env = withDB(db);
    await recordAudit(env, { action: 'login', entityType: 'user', entityId: 1 });
    await recordAudit(env, { action: 'create', entityType: 'client', entityId: 2 });
    await recordAudit(env, { action: 'delete', entityType: 'client', entityId: 2 });

    const res = await handleGetAuditLog(new URL('https://x/api/audit-log?entity_type=client&action=delete'), env, { role: 'admin' });
    const body = await res.json();
    expect(body).toHaveLength(1);
    expect(body[0].action).toBe('delete');
  });

  it('caps limit at 500', async () => {
    const res = await handleGetAuditLog(new URL('https://x/api/audit-log?limit=99999'), withDB(makeFakeD1()), { role: 'admin' });
    expect(res.status).toBe(200);
  });
});
