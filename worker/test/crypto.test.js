import { describe, it, expect, vi, afterEach } from 'vitest';
import { hashPassword, verifyPassword, createJWT, verifyJWT, generateToken } from '../crypto.js';

describe('password hashing', () => {
  it('verifies a correct password', async () => {
    const hash = await hashPassword('S3curePass!');
    expect(await verifyPassword('S3curePass!', hash)).toBe(true);
  });

  it('rejects a wrong password', async () => {
    const hash = await hashPassword('S3curePass!');
    expect(await verifyPassword('wrong-password', hash)).toBe(false);
  });

  it('produces a different hash each time (random salt)', async () => {
    const a = await hashPassword('same-password');
    const b = await hashPassword('same-password');
    expect(a).not.toBe(b);
  });

  it('rejects a malformed stored hash', async () => {
    expect(await verifyPassword('anything', 'not-a-valid-hash')).toBe(false);
  });
});

describe('JWT', () => {
  const secret = 'test-secret-key';

  it('round-trips a payload', async () => {
    const token = await createJWT({ userId: 1, role: 'admin' }, secret);
    const payload = await verifyJWT(token, secret);
    expect(payload.userId).toBe(1);
    expect(payload.role).toBe('admin');
  });

  it('rejects a token signed with a different secret', async () => {
    const token = await createJWT({ userId: 1 }, secret);
    expect(await verifyJWT(token, 'wrong-secret')).toBeNull();
  });

  it('rejects a tampered token', async () => {
    const token = await createJWT({ userId: 1, role: 'viewer' }, secret);
    const [header, , sig] = token.split('.');
    // Flip the role claim without re-signing
    const tamperedBody = Buffer.from(JSON.stringify({ userId: 1, role: 'admin' })).toString('base64url');
    expect(await verifyJWT(`${header}.${tamperedBody}.${sig}`, secret)).toBeNull();
  });

  it('rejects an expired token', async () => {
    const token = await createJWT({ userId: 1 }, secret);
    // createJWT always sets exp = now + 24h relative to real time, so to test
    // expiry we advance the clock the verifier sees rather than forging exp.
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 25 * 3600 * 1000);
    expect(await verifyJWT(token, secret)).toBeNull();
  });

  afterEach(() => vi.useRealTimers());

  it('rejects garbage input', async () => {
    expect(await verifyJWT('not-a-jwt', secret)).toBeNull();
    expect(await verifyJWT('', secret)).toBeNull();
  });
});

describe('generateToken', () => {
  it('generates hex tokens of the expected length', () => {
    const token = generateToken(32);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it('generates unique tokens', () => {
    expect(generateToken(32)).not.toBe(generateToken(32));
  });
});
