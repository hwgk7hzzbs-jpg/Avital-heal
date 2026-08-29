-- Migration number: 0001 	 2026-08-29T12:30:11.049Z
--
-- Baseline schema — a byte-accurate snapshot of the live production D1
-- database as of 2026-08-29, captured via:
--   SELECT name, sql FROM sqlite_master WHERE type='table' ...
--   SELECT name, tbl_name, sql FROM sqlite_master WHERE type='index' ...
--
-- This migration is NOT run against the production database — it was
-- already applied there, statement by statement, via the old ad-hoc
-- migration runner that used to live in worker/index.js's request path
-- (removed in this same change). It is instead marked as already-applied
-- in production's d1_migrations table. Its purpose from here on is what
-- the plan calls for: "a full schema that can stand up a new D1 from
-- scratch" — `wrangler d1 migrations apply --local` against a fresh
-- database reconstructs this exact schema. All *future* schema changes are
-- real, numbered migrations applied for real on both local and remote.
--
-- `users`, `clients`, `sessions`, `contacts`, and `password_resets` predate
-- any migration tooling and were created directly against D1 early in the
-- project — this is the first time their schema exists anywhere in source
-- control rather than only in the live database.

CREATE TABLE users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT DEFAULT 'admin',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  active BOOLEAN DEFAULT 1,
  token_version INTEGER NOT NULL DEFAULT 0,
  last_login_at DATETIME,
  last_login_ip TEXT,
  mfa_enabled BOOLEAN NOT NULL DEFAULT 0,
  mfa_secret TEXT,
  mfa_last_counter INTEGER
);

CREATE TABLE clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  email TEXT,
  phone TEXT,
  address TEXT,
  birth_date TEXT,
  join_date TEXT DEFAULT (date('now')),
  status TEXT DEFAULT 'active',
  treatment_type TEXT,
  consent_signed INTEGER DEFAULT 0,
  consent_date TEXT,
  consent_ip TEXT,
  notes TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  deleted_at DATETIME,
  deleted_by INTEGER
);
CREATE INDEX idx_clients_email ON clients(email);

CREATE TABLE sessions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id INTEGER NOT NULL,
  session_date TEXT NOT NULL,
  session_type TEXT,
  duration_minutes INTEGER DEFAULT 50,
  summary TEXT,
  next_session_notes TEXT,
  paid INTEGER DEFAULT 0,
  amount REAL DEFAULT 0,
  payment_method TEXT,
  invoice_number TEXT,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now')),
  deleted_at DATETIME,
  deleted_by INTEGER,
  FOREIGN KEY (client_id) REFERENCES clients(id)
);
CREATE INDEX idx_sessions_client_id ON sessions(client_id);
CREATE INDEX idx_sessions_date ON sessions(session_date);

CREATE TABLE contacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  full_name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  message TEXT,
  source TEXT DEFAULT 'website',
  status TEXT DEFAULT 'new',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  notes TEXT,
  deleted_at DATETIME,
  deleted_by INTEGER
);

CREATE TABLE password_resets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token TEXT UNIQUE NOT NULL,
  expires_at DATETIME NOT NULL,
  used INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE workshops (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  dates TEXT,
  price REAL,
  sessions_count INTEGER,
  duration_minutes INTEGER,
  location TEXT,
  active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT (datetime('now')),
  updated_at DATETIME DEFAULT (datetime('now'))
);

CREATE TABLE workshop_registrations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  workshop_id TEXT NOT NULL,
  full_name TEXT NOT NULL,
  phone TEXT,
  email TEXT,
  date_option TEXT,
  status TEXT DEFAULT 'new',
  notes TEXT,
  created_at DATETIME DEFAULT (datetime('now')),
  consent_agreed BOOLEAN DEFAULT 0,
  consent_date DATETIME,
  consent_ip TEXT,
  deleted_at DATETIME,
  deleted_by INTEGER,
  FOREIGN KEY (workshop_id) REFERENCES workshops(id)
);

CREATE TABLE consents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  consent_type TEXT NOT NULL,
  client_id INTEGER,
  workshop_registration_id INTEGER,
  consent_version TEXT NOT NULL,
  document_hash TEXT NOT NULL,
  source TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  ip TEXT,
  signed_at DATETIME NOT NULL,
  revoked_at DATETIME,
  created_at DATETIME DEFAULT (datetime('now')),
  FOREIGN KEY (client_id) REFERENCES clients(id),
  FOREIGN KEY (workshop_registration_id) REFERENCES workshop_registrations(id)
);
CREATE INDEX idx_consents_client ON consents(client_id);
CREATE INDEX idx_consents_workshop_reg ON consents(workshop_registration_id);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  user_email TEXT,
  action TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  entity_id TEXT,
  result TEXT NOT NULL DEFAULT 'success',
  metadata TEXT,
  created_at DATETIME DEFAULT (datetime('now'))
);
CREATE INDEX idx_audit_log_entity ON audit_log(entity_type, entity_id);
CREATE INDEX idx_audit_log_created ON audit_log(created_at);

CREATE TABLE login_attempts (
  email TEXT PRIMARY KEY,
  failed_count INTEGER NOT NULL DEFAULT 0,
  locked_until DATETIME,
  updated_at DATETIME DEFAULT (datetime('now'))
);

CREATE TABLE mfa_backup_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  code_hash TEXT NOT NULL,
  used_at DATETIME,
  created_at DATETIME DEFAULT (datetime('now'))
);
CREATE INDEX idx_mfa_backup_codes_user ON mfa_backup_codes(user_id);

CREATE TABLE refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  token_hash TEXT NOT NULL UNIQUE,
  token_version INTEGER NOT NULL DEFAULT 0,
  expires_at DATETIME NOT NULL,
  revoked_at DATETIME,
  created_at DATETIME DEFAULT (datetime('now'))
);
CREATE INDEX idx_refresh_tokens_user ON refresh_tokens(user_id);

CREATE TABLE rate_limits (
  rl_key TEXT PRIMARY KEY,
  count INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

-- Seed data: the one workshop that has existed since this feature launched.
-- INSERT OR IGNORE is safe to re-run and safe on a fresh database alike.
INSERT OR IGNORE INTO workshops (id, name, description, dates, price, sessions_count, duration_minutes, location, active)
VALUES (
  'mirpaa-shel-atzmi',
  'להיות המרפאה של עצמי',
  'סדנת נשים אינטימית — 5 מפגשים, פעם בשבוע, בשיטת מסע הנשמה',
  '[{"id":"june-3-1730","label":"3 ביוני, 17:30","date":"2026-06-03T17:30:00"}]',
  1000,
  5,
  120,
  'מורדכי רומנו 27, תל אביב',
  1
);
