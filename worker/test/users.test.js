import { describe, it, expect } from 'vitest';
import { handleGetUsers, handleCreateUser, handleUpdateUser, handleDeleteUser, handleAdminResetPassword } from '../users.js';
import { makeFakeD1 } from './testUtils.js';

function req(body) {
  return new Request('https://x', { method: 'POST', body: JSON.stringify(body) });
}

const admin = { userId: 9, email: 'admin@x.com', role: 'admin' };

describe('RBAC — every endpoint requires admin', () => {
  const nonAdmin = { userId: 5, email: 'therapist@x.com', role: 'therapist' };

  it('blocks handleGetUsers', async () => {
    expect((await handleGetUsers({ DB: makeFakeD1() }, nonAdmin)).status).toBe(403);
  });
  it('blocks handleCreateUser', async () => {
    expect((await handleCreateUser(req({}), { DB: makeFakeD1() }, nonAdmin)).status).toBe(403);
  });
  it('blocks handleUpdateUser', async () => {
    expect((await handleUpdateUser('1', req({}), { DB: makeFakeD1() }, nonAdmin)).status).toBe(403);
  });
  it('blocks handleDeleteUser', async () => {
    expect((await handleDeleteUser('1', { DB: makeFakeD1() }, nonAdmin)).status).toBe(403);
  });
  it('blocks handleAdminResetPassword', async () => {
    expect((await handleAdminResetPassword('1', req({}), { DB: makeFakeD1() }, nonAdmin)).status).toBe(403);
  });
});

describe('handleCreateUser', () => {
  it('creates a user and logs an audit entry attributed to the acting admin', async () => {
    const db = makeFakeD1();
    const res = await handleCreateUser(req({ name: 'New Therapist', email: 'new@x.com', password: 'GoodPass1', role: 'therapist' }), { DB: db }, admin);
    expect(res.status).toBe(201);
    expect(db._state.users).toHaveLength(1);
    expect(db._state.users[0].password_hash).not.toContain('GoodPass1');
    expect(db._state.auditLog.some(a => a.action === 'create' && a.entity_type === 'user' && a.user_id === admin.userId)).toBe(true);
  });

  it('rejects a duplicate email', async () => {
    const db = makeFakeD1({ users: [{ id: 1, email: 'taken@x.com', role: 'therapist' }] });
    const res = await handleCreateUser(req({ name: 'Someone Else', email: 'taken@x.com', password: 'GoodPass1', role: 'therapist' }), { DB: db }, admin);
    expect(res.status).toBe(409);
  });
});

describe('handleUpdateUser — deactivation revokes sessions', () => {
  it('bumps token_version and revokes refresh tokens when active is set to false', async () => {
    const db = makeFakeD1({
      users: [{ id: 2, role: 'therapist', active: 1, token_version: 0 }],
      refreshTokens: [{ id: 1, user_id: 2, token_hash: 'h', token_version: 0, expires_at: '2999-01-01T00:00:00.000Z', revoked_at: null }],
    });
    const res = await handleUpdateUser('2', req({ active: false }), { DB: db }, admin);
    expect(res.status).toBe(200);
    expect(db._state.users[0].token_version).toBe(1);
    expect(db._state.refreshTokens[0].revoked_at).toBeTruthy();
  });

  it('does not touch token_version when updating unrelated fields', async () => {
    const db = makeFakeD1({ users: [{ id: 2, name: 'Old Name', role: 'therapist', active: 1, token_version: 0 }] });
    await handleUpdateUser('2', req({ name: 'New Name' }), { DB: db }, admin);
    expect(db._state.users[0].token_version).toBe(0);
    expect(db._state.users[0].name).toBe('New Name');
  });

  it('blocks deactivating the last active admin', async () => {
    const db = makeFakeD1({ users: [{ id: 1, role: 'admin', active: 1, token_version: 0 }] });
    const res = await handleUpdateUser('1', req({ active: false }), { DB: db }, admin);
    expect(res.status).toBe(403);
  });

  it('404s for a user that does not exist', async () => {
    const res = await handleUpdateUser('999', req({ name: 'X' }), { DB: makeFakeD1() }, admin);
    expect(res.status).toBe(404);
  });
});

describe('handleDeleteUser', () => {
  it('cannot delete yourself', async () => {
    const db = makeFakeD1({ users: [{ id: 9, role: 'admin' }] });
    const res = await handleDeleteUser('9', { DB: db }, admin);
    expect(res.status).toBe(403);
  });

  it('cannot delete the last admin', async () => {
    const db = makeFakeD1({ users: [{ id: 1, role: 'admin' }] });
    const res = await handleDeleteUser('1', { DB: db }, admin);
    expect(res.status).toBe(403);
  });

  it('deletes the user and their refresh tokens', async () => {
    const db = makeFakeD1({
      users: [{ id: 1, role: 'admin' }, { id: 2, role: 'therapist' }],
      refreshTokens: [{ id: 1, user_id: 2, token_hash: 'h', token_version: 0, expires_at: '2999-01-01T00:00:00.000Z', revoked_at: null }],
    });
    const res = await handleDeleteUser('2', { DB: db }, admin);
    expect(res.status).toBe(200);
    expect(db._state.users.find(u => u.id === 2)).toBeUndefined();
    expect(db._state.refreshTokens).toHaveLength(0);
  });
});

describe('handleAdminResetPassword', () => {
  it('updates the password hash and revokes the target user\'s sessions', async () => {
    const db = makeFakeD1({
      users: [{ id: 2, role: 'therapist', token_version: 0 }],
      refreshTokens: [{ id: 1, user_id: 2, token_hash: 'h', token_version: 0, expires_at: '2999-01-01T00:00:00.000Z', revoked_at: null }],
    });
    const res = await handleAdminResetPassword('2', req({ newPassword: 'BrandNewPass9' }), { DB: db }, admin);
    expect(res.status).toBe(200);
    expect(db._state.users[0].token_version).toBe(1);
    expect(db._state.refreshTokens[0].revoked_at).toBeTruthy();
  });

  it('rejects a weak new password', async () => {
    const db = makeFakeD1({ users: [{ id: 2, role: 'therapist' }] });
    const res = await handleAdminResetPassword('2', req({ newPassword: 'weak' }), { DB: db }, admin);
    expect(res.status).toBe(400);
  });
});
