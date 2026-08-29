/**
 * @file validation.js
 * @description Centralized request validation: reusable field validators/
 *              normalizers, the closed-list enums used across handlers, and
 *              a small schema-driven validate() function so each handler
 *              declares its rules once instead of re-implementing ad hoc
 *              checks inline.
 * @module Validation
 */

// ─── Closed-list enums ("להגביל ערכי Status לרשימה סגורה") ───
// Single source of truth — handlers import from here instead of each
// declaring (and risking drifting) their own copy.

export const CLIENT_STATUSES = ['active', 'inactive', 'completed'];
export const TREATMENT_TYPES = ['emotional', 'spiritual', 'combined', 'other'];
export const SESSION_TYPES = ['emotional', 'spiritual', 'combined'];
export const PAYMENT_METHODS = ['cash', 'transfer', 'card'];
export const CONTACT_STATUSES = ['new', 'contacted', 'converted', 'closed', 'rejected'];
export const REGISTRATION_STATUSES = ['new', 'contacted', 'confirmed', 'cancelled'];
export const USER_ROLES = ['admin', 'therapist', 'viewer'];

// ─── Field validators / normalizers ───

export function normalizeEmail(email) {
  return typeof email === 'string' ? email.trim().toLowerCase() : email;
}

// Keeps a leading "+" (international prefix) if present, strips everything
// else that isn't a digit — "050-123 4567" and "+972 50-123-4567" both end
// up in one consistent, comparable shape.
export function normalizePhone(phone) {
  if (typeof phone !== 'string') return phone;
  const trimmed = phone.trim();
  const digits = trimmed.replace(/\D/g, '');
  return trimmed.startsWith('+') ? `+${digits}` : digits;
}

export function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// Deliberately loose (7-15 digits, optional leading +) rather than
// Israel-only — the CRM's own phone fields don't enforce a single country.
export function isValidPhone(phone) {
  if (typeof phone !== 'string') return false;
  return /^\+?\d{7,15}$/.test(normalizePhone(phone));
}

export function isValidDate(value) {
  if (typeof value !== 'string' && !(value instanceof Date)) return false;
  const d = new Date(value);
  return !Number.isNaN(d.getTime());
}

export function isNonNegativeAmount(value) {
  const n = Number(value);
  return Number.isFinite(n) && n >= 0;
}

export function isPositiveInteger(value) {
  const n = Number(value);
  return Number.isInteger(n) && n > 0;
}

/**
 * Validates `data` against `schema` and returns either the normalized,
 * validated fields or a list of per-field errors — never both.
 *
 * schema: { [field]: {
 *   required?: boolean,
 *   normalize?: (raw) => any,       // applied before any check below
 *   validate?: (value) => boolean,  // custom check; paired with `message`
 *   enum?: any[],                   // closed-list check
 *   integer?: boolean,              // coerce with parseInt
 *   number?: boolean,               // coerce with Number
 *   message?: string,               // shown when `validate`/`enum` fails
 * } }
 *
 * Fields not mentioned in the schema are ignored (callers that need an
 * allow-list for UPDATE still build one separately — this only validates
 * the fields it's told about).
 */
export function validate(data, schema) {
  const errors = [];
  const result = {};

  for (const [field, rule] of Object.entries(schema)) {
    let value = data[field];
    const missing = value === undefined || value === null || value === '';

    if (missing) {
      if (rule.required) errors.push({ field, message: rule.requiredMessage || `${field} is required` });
      continue;
    }

    if (rule.normalize) value = rule.normalize(value);
    if (rule.integer) value = parseInt(value, 10);
    else if (rule.number) value = Number(value);

    if (rule.enum && !rule.enum.includes(value)) {
      errors.push({ field, message: rule.message || `${field} must be one of: ${rule.enum.join(', ')}` });
      continue;
    }
    if (rule.validate && !rule.validate(value)) {
      errors.push({ field, message: rule.message || `${field} is invalid` });
      continue;
    }

    result[field] = value;
  }

  return errors.length ? { valid: false, errors } : { valid: true, data: result };
}
