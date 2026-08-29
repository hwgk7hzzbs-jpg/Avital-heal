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

// ─── TOTP (RFC 6238) two-factor authentication ───
// Standard 6-digit, 30-second-step TOTP over HMAC-SHA1 — the algorithm every
// mainstream authenticator app (Google Authenticator, Authy, 1Password, ...)
// expects by default. The shared secret is encrypted at rest by the caller
// (see encryptField) the same way clinical notes are — it's a credential,
// not a UI string.

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const TOTP_STEP_SECONDS = 30;
const TOTP_DIGITS = 6;

function base32Encode(bytes) {
  let bits = 0, value = 0, output = '';
  for (let i = 0; i < bytes.length; i++) {
    value = (value << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) {
      output += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) output += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return output;
}

function base32Decode(str) {
  const clean = str.toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = 0, value = 0;
  const output = [];
  for (let i = 0; i < clean.length; i++) {
    const idx = BASE32_ALPHABET.indexOf(clean[i]);
    if (idx === -1) continue;
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return new Uint8Array(output);
}

// Generates a fresh 160-bit (20-byte) shared secret, base32-encoded the way
// authenticator apps expect it typed/scanned.
export function generateTotpSecret() {
  return base32Encode(crypto.getRandomValues(new Uint8Array(20)));
}

// otpauth:// URI — most authenticator apps' "enter manually" flow also
// accepts pasting this directly, in addition to scanning a QR code of it.
export function getTotpUri(secret, email, issuer = 'Avital Heal CRM') {
  const label = encodeURIComponent(`${issuer}:${email}`);
  return `otpauth://totp/${label}?secret=${secret}&issuer=${encodeURIComponent(issuer)}&digits=${TOTP_DIGITS}&period=${TOTP_STEP_SECONDS}`;
}

async function hotp(keyBytes, counter) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  const counterBuf = new ArrayBuffer(8);
  // Counter fits comfortably in the low 32 bits until the year 6429 (2^32
  // steps of 30s) — the high word is deliberately left zero.
  new DataView(counterBuf).setUint32(4, counter, false);
  const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterBuf));
  const offset = sig[sig.length - 1] & 0xf;
  const binCode =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  return String(binCode % 10 ** TOTP_DIGITS).padStart(TOTP_DIGITS, '0');
}

/**
 * Verifies a 6-digit TOTP code against `secret`, tolerating ±`window` steps
 * of clock drift (default: one 30s step either way). When `lastCounter` is
 * given, any code from that step or earlier is rejected even if otherwise
 * correct — replay protection against a captured/observed code being reused
 * within its own validity window.
 */
export async function verifyTotp(secret, code, { window = 1, lastCounter = null } = {}) {
  if (!/^\d{6}$/.test(String(code || ''))) return { valid: false };
  const keyBytes = base32Decode(secret);
  const currentCounter = Math.floor(Date.now() / 1000 / TOTP_STEP_SECONDS);
  for (let drift = -window; drift <= window; drift++) {
    const counter = currentCounter + drift;
    if (lastCounter != null && counter <= lastCounter) continue;
    if ((await hotp(keyBytes, counter)) === code) {
      return { valid: true, counter };
    }
  }
  return { valid: false };
}

// ─── MFA backup/recovery codes ───
// Single-use codes for when the authenticator device is unavailable. Human-
// typeable alphabet (no 0/O/1/I) to cut down on transcription errors.

const BACKUP_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

export function generateBackupCode() {
  const bytes = crypto.getRandomValues(new Uint8Array(8));
  let code = '';
  for (let i = 0; i < bytes.length; i++) code += BACKUP_CODE_ALPHABET[bytes[i] % BACKUP_CODE_ALPHABET.length];
  return `${code.slice(0, 4)}-${code.slice(4)}`;
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
