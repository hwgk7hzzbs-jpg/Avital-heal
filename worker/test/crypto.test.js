import { describe, it, expect, vi, afterEach } from 'vitest';
import { hashPassword, verifyPassword, needsRehash, createJWT, verifyJWT, generateToken, hashToken, encryptField, decryptField, generateTotpSecret, getTotpUri, verifyTotp, generateBackupCode } from '../crypto.js';

// Independent base32 encoder (RFC 4648) used only to feed the RFC 6238
// reference vector's raw ASCII key through verifyTotp's public API, which
// always expects a base32 secret — this is deliberately NOT imported from
// crypto.js, so the test cross-checks against an independent implementation.
function base32EncodeForTest(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) { output += alphabet[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) output += alphabet[(value << (5 - bits)) & 31];
  return output;
}

// 32 bytes, hex-encoded — matches how ENCRYPTION_KEY is expected to be provisioned.
const TEST_KEY = 'a'.repeat(64);

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

  it('stores the iteration count in the hash, in "iterations:salt:hash" form', async () => {
    const hash = await hashPassword('S3curePass!');
    const parts = hash.split(':');
    expect(parts).toHaveLength(3);
    expect(Number(parts[0])).toBeGreaterThan(0);
  });

  it('verifies a legacy two-part "salt:hash" hash (no embedded iteration count)', async () => {
    // Replicates the pre-hardening format directly, so this doesn't depend on
    // hashPassword() itself still being able to produce the old shape.
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('LegacyPass1'), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256);
    const toHex = buf => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    const legacyHash = `${toHex(salt)}:${toHex(bits)}`;

    expect(await verifyPassword('LegacyPass1', legacyHash)).toBe(true);
    expect(await verifyPassword('wrong', legacyHash)).toBe(false);
  });
});

describe('needsRehash', () => {
  it('is false for a hash just created with the current settings', async () => {
    expect(needsRehash(await hashPassword('S3curePass!'))).toBe(false);
  });

  it('is false for a legacy two-part hash, since its implied iteration count already equals the platform maximum', () => {
    expect(needsRehash('deadbeef:c0ffee')).toBe(false);
  });

  it('is true for a hash whose embedded iteration count is lower than current', () => {
    expect(needsRehash('1000:deadbeef:c0ffee')).toBe(true);
  });

  it('is true for an unparseable hash', () => {
    expect(needsRehash('not-a-valid-hash')).toBe(true);
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
    // createJWT's default expiry (20 min) is relative to real time, so to
    // test expiry we advance the clock the verifier sees rather than forging exp.
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 21 * 60 * 1000);
    expect(await verifyJWT(token, secret)).toBeNull();
  });

  it('honors a custom expiry', async () => {
    const token = await createJWT({ userId: 1 }, secret, 5);
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 10 * 1000);
    expect(await verifyJWT(token, secret)).toBeNull();
  });

  afterEach(() => vi.useRealTimers());

  it('rejects garbage input', async () => {
    expect(await verifyJWT('not-a-jwt', secret)).toBeNull();
    expect(await verifyJWT('', secret)).toBeNull();
  });
});

describe('hashToken', () => {
  it('is deterministic — same input always hashes the same', async () => {
    expect(await hashToken('some-token-value')).toBe(await hashToken('some-token-value'));
  });

  it('produces different hashes for different inputs', async () => {
    expect(await hashToken('token-a')).not.toBe(await hashToken('token-b'));
  });

  it('produces a hex-encoded SHA-256 digest (64 hex chars)', async () => {
    expect(await hashToken('anything')).toMatch(/^[0-9a-f]{64}$/);
  });

  it('never contains the original token as a substring', async () => {
    expect(await hashToken('a-very-identifiable-refresh-token')).not.toContain('a-very-identifiable-refresh-token');
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

describe('encryptField / decryptField', () => {
  const env = { ENCRYPTION_KEY: TEST_KEY };

  it('round-trips plaintext', async () => {
    const enc = await encryptField(env, 'session summary with sensitive content');
    expect(await decryptField(env, enc)).toBe('session summary with sensitive content');
  });

  it('does not store the plaintext anywhere in the encrypted value', async () => {
    const enc = await encryptField(env, 'a very identifiable secret phrase');
    expect(enc).not.toContain('a very identifiable secret phrase');
  });

  it('produces a different ciphertext each time (random IV), same plaintext decrypts equal', async () => {
    const a = await encryptField(env, 'same text');
    const b = await encryptField(env, 'same text');
    expect(a).not.toBe(b);
    expect(await decryptField(env, a)).toBe(await decryptField(env, b));
  });

  it('passes legacy plaintext through decryptField unchanged (no "encv1." prefix)', async () => {
    expect(await decryptField(env, 'plain old note from before encryption existed')).toBe(
      'plain old note from before encryption existed'
    );
  });

  it('passes null/empty through both functions unchanged', async () => {
    expect(await encryptField(env, null)).toBeNull();
    expect(await encryptField(env, '')).toBe('');
    expect(await decryptField(env, null)).toBeNull();
  });

  it('fails decryption under a different key (tamper/wrong-key detection via GCM auth tag)', async () => {
    const enc = await encryptField(env, 'secret');
    const wrongEnv = { ENCRYPTION_KEY: 'b'.repeat(64) };
    await expect(decryptField(wrongEnv, enc)).rejects.toThrow();
  });

  it('throws clearly if ENCRYPTION_KEY is not configured', async () => {
    await expect(encryptField({}, 'text')).rejects.toThrow(/ENCRYPTION_KEY/);
  });
});

describe('TOTP', () => {
  afterEach(() => vi.useRealTimers());

  it('matches the RFC 6238 reference test vector (SHA1, T=59s)', async () => {
    // https://www.rfc-editor.org/rfc/rfc6238#appendix-B — 8-digit vector is
    // 94287082 for the ASCII key "12345678901234567890" at T=1 (59s / 30).
    // The low 6 digits of that same computation are what a 6-digit TOTP
    // (what we actually implement) would produce.
    const secret = base32EncodeForTest(new TextEncoder().encode('12345678901234567890'));
    vi.useFakeTimers();
    vi.setSystemTime(59 * 1000);
    expect(await verifyTotp(secret, '287082', { window: 0 })).toMatchObject({ valid: true });
    expect(await verifyTotp(secret, '287083', { window: 0 })).toMatchObject({ valid: false });
  });

  it('generates a base32 secret usable end-to-end with verifyTotp', async () => {
    const secret = generateTotpSecret();
    expect(secret).toMatch(/^[A-Z2-7]+$/);
    // We can't know the "right" code without reimplementing the algorithm,
    // but a wrong one must always be rejected.
    expect(await verifyTotp(secret, '000000')).toMatchObject({ valid: false });
  });

  it('rejects non-6-digit input outright', async () => {
    const secret = generateTotpSecret();
    expect(await verifyTotp(secret, '12345')).toMatchObject({ valid: false });
    expect(await verifyTotp(secret, 'abcdef')).toMatchObject({ valid: false });
    expect(await verifyTotp(secret, '')).toMatchObject({ valid: false });
  });

  it('tolerates clock drift within the window but not beyond it', async () => {
    const secret = base32EncodeForTest(new TextEncoder().encode('12345678901234567890'));
    // T=1's code is 287082 (see RFC vector above); one step later is T=2 (60-89s).
    vi.useFakeTimers();
    vi.setSystemTime(61 * 1000);
    expect(await verifyTotp(secret, '287082', { window: 1 })).toMatchObject({ valid: true });
    expect(await verifyTotp(secret, '287082', { window: 0 })).toMatchObject({ valid: false });
  });

  it('rejects a code at or before lastCounter (replay protection)', async () => {
    const secret = base32EncodeForTest(new TextEncoder().encode('12345678901234567890'));
    vi.useFakeTimers();
    vi.setSystemTime(59 * 1000); // T=1
    expect(await verifyTotp(secret, '287082', { window: 0, lastCounter: 1 })).toMatchObject({ valid: false });
    expect(await verifyTotp(secret, '287082', { window: 0, lastCounter: 0 })).toMatchObject({ valid: true, counter: 1 });
  });

  it('getTotpUri produces a well-formed otpauth:// URI containing the secret and email', () => {
    const secret = generateTotpSecret();
    const uri = getTotpUri(secret, 'admin@x.com');
    expect(uri).toMatch(/^otpauth:\/\/totp\//);
    expect(uri).toContain(`secret=${secret}`);
    expect(uri).toContain(encodeURIComponent('admin@x.com'));
  });
});

describe('generateBackupCode', () => {
  it('produces codes in XXXX-XXXX format from an unambiguous alphabet', () => {
    const code = generateBackupCode();
    expect(code).toMatch(/^[A-HJ-NP-Z2-9]{4}-[A-HJ-NP-Z2-9]{4}$/);
  });

  it('generates unique codes', () => {
    expect(generateBackupCode()).not.toBe(generateBackupCode());
  });
});
