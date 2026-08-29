import { describe, it, expect } from 'vitest';
import {
  normalizeEmail, normalizePhone, isValidEmail, isValidPhone, isValidDate,
  isNonNegativeAmount, isPositiveInteger, validate,
  CLIENT_STATUSES, SESSION_TYPES, USER_ROLES,
} from '../validation.js';

describe('normalizeEmail', () => {
  it('trims and lowercases', () => {
    expect(normalizeEmail('  Someone@Example.COM ')).toBe('someone@example.com');
  });
  it('passes non-strings through unchanged', () => {
    expect(normalizeEmail(null)).toBeNull();
    expect(normalizeEmail(undefined)).toBeUndefined();
  });
});

describe('normalizePhone', () => {
  it('strips non-digits', () => {
    expect(normalizePhone('050-123 4567')).toBe('0501234567');
  });
  it('keeps a leading + for international numbers', () => {
    expect(normalizePhone('+972 50-123-4567')).toBe('+972501234567');
  });
  it('passes non-strings through unchanged', () => {
    expect(normalizePhone(12345)).toBe(12345);
  });
});

describe('isValidEmail', () => {
  it('accepts well-formed addresses', () => {
    expect(isValidEmail('a@b.com')).toBe(true);
    expect(isValidEmail('a.b+c@sub.example.co.il')).toBe(true);
  });
  it('rejects malformed addresses', () => {
    expect(isValidEmail('not-an-email')).toBe(false);
    expect(isValidEmail('missing@domain')).toBe(false);
    expect(isValidEmail('@nolocal.com')).toBe(false);
    expect(isValidEmail('')).toBe(false);
    expect(isValidEmail(null)).toBe(false);
  });
});

describe('isValidPhone', () => {
  it('accepts local and international formats', () => {
    expect(isValidPhone('0501234567')).toBe(true);
    expect(isValidPhone('050-123-4567')).toBe(true);
    expect(isValidPhone('+972501234567')).toBe(true);
  });
  it('rejects too-short, too-long, or non-numeric input', () => {
    expect(isValidPhone('12345')).toBe(false);
    expect(isValidPhone('1'.repeat(20))).toBe(false);
    expect(isValidPhone('call-me-maybe')).toBe(false);
    expect(isValidPhone(null)).toBe(false);
  });
});

describe('isValidDate', () => {
  it('accepts real dates and datetimes', () => {
    expect(isValidDate('2026-01-15')).toBe(true);
    expect(isValidDate('2026-01-15T10:30:00')).toBe(true);
    expect(isValidDate(new Date())).toBe(true);
  });
  it('rejects garbage and non-date types', () => {
    expect(isValidDate('not-a-date')).toBe(false);
    expect(isValidDate(null)).toBe(false);
    expect(isValidDate(42)).toBe(false);
  });
});

describe('isNonNegativeAmount', () => {
  it('accepts zero and positive numbers', () => {
    expect(isNonNegativeAmount(0)).toBe(true);
    expect(isNonNegativeAmount(500)).toBe(true);
    expect(isNonNegativeAmount('250')).toBe(true);
  });
  it('rejects negative numbers, NaN, and non-numeric strings', () => {
    expect(isNonNegativeAmount(-1)).toBe(false);
    expect(isNonNegativeAmount(NaN)).toBe(false);
    expect(isNonNegativeAmount('abc')).toBe(false);
    expect(isNonNegativeAmount(Infinity)).toBe(false);
  });
});

describe('isPositiveInteger', () => {
  it('accepts positive integers, including numeric strings', () => {
    expect(isPositiveInteger(5)).toBe(true);
    expect(isPositiveInteger('5')).toBe(true);
  });
  it('rejects zero, negatives, and non-integers', () => {
    expect(isPositiveInteger(0)).toBe(false);
    expect(isPositiveInteger(-3)).toBe(false);
    expect(isPositiveInteger(2.5)).toBe(false);
    expect(isPositiveInteger('abc')).toBe(false);
  });
});

describe('validate', () => {
  it('returns normalized data when everything passes', () => {
    const result = validate(
      { email: '  A@B.com ', amount: '250' },
      {
        email: { required: true, normalize: normalizeEmail, validate: isValidEmail },
        amount: { number: true, validate: isNonNegativeAmount },
      }
    );
    expect(result.valid).toBe(true);
    expect(result.data.email).toBe('a@b.com');
    expect(result.data.amount).toBe(250);
  });

  it('collects one error per failing field, not just the first', () => {
    const result = validate(
      { email: 'bad', amount: -5 },
      {
        email: { required: true, validate: isValidEmail, message: 'bad email' },
        amount: { number: true, validate: isNonNegativeAmount, message: 'bad amount' },
      }
    );
    expect(result.valid).toBe(false);
    expect(result.errors).toHaveLength(2);
    expect(result.errors.map(e => e.field).sort()).toEqual(['amount', 'email']);
  });

  it('flags a missing required field without running its other checks', () => {
    const result = validate({}, { email: { required: true, validate: isValidEmail } });
    expect(result.valid).toBe(false);
    expect(result.errors[0].field).toBe('email');
  });

  it('silently skips an absent optional field', () => {
    const result = validate({}, { notes: { validate: () => false } });
    expect(result.valid).toBe(true);
    expect(result.data).toEqual({});
  });

  it('treats an explicit empty string as absent (not a validation failure) when optional', () => {
    const result = validate({ notes: '' }, { notes: { validate: v => v.length > 0 } });
    expect(result.valid).toBe(true);
    expect(result.data.notes).toBeUndefined();
  });

  it('enforces enum membership', () => {
    const bad = validate({ status: 'bogus' }, { status: { enum: CLIENT_STATUSES } });
    expect(bad.valid).toBe(false);
    const good = validate({ status: 'active' }, { status: { enum: CLIENT_STATUSES } });
    expect(good.valid).toBe(true);
    expect(good.data.status).toBe('active');
  });

  it('coerces integer fields', () => {
    const result = validate({ client_id: '42' }, { client_id: { integer: true, validate: isPositiveInteger } });
    expect(result.valid).toBe(true);
    expect(result.data.client_id).toBe(42);
    expect(Number.isInteger(result.data.client_id)).toBe(true);
  });

  it('ignores fields not mentioned in the schema', () => {
    const result = validate({ extra: 'whatever', name: 'X' }, { name: {} });
    expect(result.valid).toBe(true);
    expect(result.data).toEqual({ name: 'X' });
    expect(result.data.extra).toBeUndefined();
  });
});

describe('enums are the expected closed lists', () => {
  it('exports the enums handlers rely on', () => {
    expect(CLIENT_STATUSES).toContain('active');
    expect(SESSION_TYPES).toContain('emotional');
    expect(USER_ROLES).toEqual(['admin', 'therapist', 'viewer']);
  });
});
