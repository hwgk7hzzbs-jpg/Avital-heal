/**
 * @file crypto.js
 * @description Password hashing (PBKDF2), JWT creation/verification,
 *              and secure token generation using Web Crypto API.
 * @module Crypto
 * @security CRITICAL — handles all credential operations.
 */

// 2023 OWASP guidance for PBKDF2-HMAC-SHA256. The iteration count is stored
// alongside each hash (see hashPassword) so raising this constant never
// invalidates passwords hashed under an older value — verifyPassword reads
// whatever count the hash itself was created with.
const PBKDF2_ITERATIONS = 600000;
// Original, pre-hardening iteration count. Hashes written before this file
// started embedding the count in the stored value have exactly two ':'-parts
// (salt:hash, no leading iteration count) and are assumed to use this value.
const LEGACY_PBKDF2_ITERATIONS = 100000;
const SALT_LENGTH = 16;

// ─── Password Hashing (PBKDF2-SHA256) ───

export async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const bits = await deriveBits(password, salt, PBKDF2_ITERATIONS);
  return `${PBKDF2_ITERATIONS}:${bufToHex(salt)}:${bufToHex(new Uint8Array(bits))}`;
}

export async function verifyPassword(password, storedHash) {
  const parsed = parseStoredHash(storedHash);
  if (!parsed) return false;
  const { iterations, salt, hash } = parsed;
  const bits = await deriveBits(password, salt, iterations);
  return timingSafeEqual(bufToHex(new Uint8Array(bits)), hash);
}

// True when a hash was created with fewer iterations than the current
// target — callers (login) use this to opportunistically re-hash with the
// plaintext password they already have on hand, migrating old hashes to the
// current standard one successful login at a time rather than all at once.
export function needsRehash(storedHash) {
  const parsed = parseStoredHash(storedHash);
  return !parsed || parsed.iterations < PBKDF2_ITERATIONS;
}

function parseStoredHash(storedHash) {
  const parts = storedHash.split(':');
  if (parts.length === 3) {
    const iterations = parseInt(parts[0], 10);
    if (!iterations || !parts[1] || !parts[2]) return null;
    return { iterations, salt: hexToBuf(parts[1]), hash: parts[2] };
  }
  if (parts.length === 2) {
    if (!parts[0] || !parts[1]) return null;
    return { iterations: LEGACY_PBKDF2_ITERATIONS, salt: hexToBuf(parts[0]), hash: parts[1] };
  }
  return null;
}

async function deriveBits(password, salt, iterations) {
  const key = await crypto.subtle.importKey(
    'raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']
  );
  return crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' }, key, 256
  );
}

// Constant-time string comparison — avoids leaking hash match position via timing.
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return diff === 0;
}

// ─── UTF-8 safe Base64url ───

function utf8ToB64url(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=+$/, '');
}

function b64urlToUtf8(b64) {
  const binary = atob(b64.replace(/-/g, '+').replace(/_/g, '/'));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}

// ─── JWT (HMAC-SHA256) ───

export async function createJWT(payload, secret, expirySeconds = 20 * 60) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + expirySeconds };
  const headerB64 = utf8ToB64url(JSON.stringify(header));
  const bodyB64 = utf8ToB64url(JSON.stringify(body));
  const data = `${headerB64}.${bodyB64}`;
  const key = await importHMACKey(secret);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  const sigBytes = new Uint8Array(sig);
  let sigBinary = '';
  for (let i = 0; i < sigBytes.length; i++) {
    sigBinary += String.fromCharCode(sigBytes[i]);
  }
  const sigB64 = btoa(sigBinary).replace(/[+]/g, '-').replace(/[/]/g, '_').replace(/=+$/, '');
  return `${data}.${sigB64}`;
}

export async function verifyJWT(token, secret) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const key = await importHMACKey(secret);
    const sigStr = atob(parts[2].replace(/-/g, '+').replace(/_/g, '/'));
    const sigBuf = new Uint8Array(sigStr.length);
    for (let i = 0; i < sigStr.length; i++) {
      sigBuf[i] = sigStr.charCodeAt(i);
    }
    const valid = await crypto.subtle.verify(
      'HMAC', key, sigBuf,
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
    );
    if (!valid) return null;
    const payload = JSON.parse(b64urlToUtf8(parts[1]));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

// ─── Random Token ───

export function generateToken(length = 32) {
  return bufToHex(crypto.getRandomValues(new Uint8Array(length)));
}

// ─── One-way token hashing (SHA-256) ───
// Used for password-reset and refresh tokens: only this hash is ever
// persisted to D1, so a database read alone can't be used to redeem a
// still-valid token — the raw value only ever exists in the response sent
// to the legitimate holder (email link / login response).

export async function hashToken(token) {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(token));
  return bufToHex(new Uint8Array(digest));
}

// ─── Field-level encryption (AES-256-GCM) ───
// Used for sensitive free-text fields (session summaries, next-session notes,
// client notes) so their content isn't sitting in D1 as plaintext. Values are
// tagged with an "encv1." prefix so decryptField() can tell an encrypted
// value apart from legacy plaintext written before this existed — old rows
// keep working unmodified; only new writes get encrypted.

const ENC_PREFIX = 'encv1.';

async function importEncryptionKey(env) {
  if (!env.ENCRYPTION_KEY) {
    throw new Error('ENCRYPTION_KEY is not configured');
  }
  const keyBytes = hexToBuf(env.ENCRYPTION_KEY);
  return crypto.subtle.importKey('raw', keyBytes, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

export async function encryptField(env, plaintext) {
  if (plaintext == null || plaintext === '') return plaintext;
  const key = await importEncryptionKey(env);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(String(plaintext))
  );
  return ENC_PREFIX + bufToHex(iv) + '.' + bufToHex(new Uint8Array(ciphertext));
}

export async function decryptField(env, value) {
  if (value == null || !value.startsWith(ENC_PREFIX)) return value; // legacy plaintext, pass through
  const [, ivHex, dataHex] = value.split('.');
  const key = await importEncryptionKey(env);
  const iv = hexToBuf(ivHex);
  const plaintext = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv }, key, hexToBuf(dataHex)
  );
  return new TextDecoder().decode(plaintext);
}

// ─── Helpers ───

async function importHMACKey(secret) {
  return crypto.subtle.importKey(
    'raw', new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']
  );
}

function bufToHex(buf) {
  return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join('');
}

function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}
