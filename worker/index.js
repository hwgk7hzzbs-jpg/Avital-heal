/**
 * @file index.js
 * @description Central entry point — routing ONLY. No business logic.
 * @module Core
 * @security Auth check applied before protected routes.
 */

import { SECURITY_HEADERS, getCorsHeaders } from './utils.js';
import { errorResponse } from './utils.js';
import { getAuthPayload, handleLogin, handleRefresh, handleLogout, handleVerify } from './auth.js';
import { handleRequestReset, handleExecuteReset, handleChangePassword } from './auth.js';
import { handleMfaLoginVerify, handleMfaSetupStart, handleMfaSetupVerify, handleMfaDisable } from './auth.js';
import { handleConsentSubmission } from './consent.js';
import { handleGetClientConsents, handleRevokeConsent } from './consents.js';
import { handleContactSubmission, handleGetContacts, handleUpdateContact, handleDeleteContact, handleGetDeletedContacts, handleRestoreContact, handlePermanentDeleteContact } from './contacts.js';
import { handleGetClients, handleGetClient, handleCreateClient, handleUpdateClient, handleDeleteClient, handleExportClients, handleExportClientData, handleGetDeletedClients, handleRestoreClient, handlePermanentDeleteClient } from './clients.js';
import { handleGetSessions, handleGetClientSessions, handleCreateSession, handleUpdateSession, handleDeleteSession, handleGetDeletedSessions, handleRestoreSession, handlePermanentDeleteSession } from './sessions.js';
import { handleStats } from './dashboard.js';
import { handleGetUsers, handleCreateUser, handleUpdateUser, handleDeleteUser, handleAdminResetPassword, handleAdminDisableMfa } from './users.js';
import {
  handleWorkshopRegister,
  handleGetWorkshops,
  handleGetWorkshop,
  handleGetWorkshopRegistrations,
  handleUpdateRegistration,
  handleDeleteRegistration,
  handleGetDeletedRegistrations,
  handleRestoreRegistration,
  handlePermanentDeleteRegistration,
} from './workshops.js';
import { handleGetAuditLog } from './auditLog.js';

// ─── One-time DB migration ───
async function runMigrations(env) {
  try {
    // Add 'active' column to users if not exists
    const cols = await env.DB.prepare("PRAGMA table_info(users)").all();
    const hasActive = cols.results.some(c => c.name === 'active');
    if (!hasActive) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN active BOOLEAN DEFAULT 1").run();
      // Set all existing users as active
      await env.DB.prepare("UPDATE users SET active = 1 WHERE active IS NULL").run();
    }

    // Create consents table (historical, versioned — one row per signature,
    // in addition to the quick-lookup boolean flags on clients/workshop_registrations)
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS consents (
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
      )
    `).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_consents_client ON consents(client_id)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_consents_workshop_reg ON consents(workshop_registration_id)`).run();

    // Create audit_log table (append-only — see worker/auditLog.js)
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        user_email TEXT,
        action TEXT NOT NULL,
        entity_type TEXT NOT NULL,
        entity_id TEXT,
        result TEXT NOT NULL DEFAULT 'success',
        metadata TEXT,
        created_at DATETIME DEFAULT (datetime('now'))
      )
    `).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_audit_log_entity ON audit_log(entity_type, entity_id)`).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_audit_log_created ON audit_log(created_at)`).run();

    // Add last-login tracking to users (for admin visibility — see
    // worker/auth.js handleLogin). Full IP/device history for every attempt,
    // not just the last successful one, lives in audit_log instead.
    if (!cols.results.some(c => c.name === 'last_login_at')) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN last_login_at DATETIME").run();
    }
    if (!cols.results.some(c => c.name === 'last_login_ip')) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN last_login_ip TEXT").run();
    }

    // Create login_attempts table — tracks consecutive failed logins per
    // email so handleLogin can apply a progressive lockout (see auth.js),
    // on top of (not instead of) the fixed-window rate limiting already in
    // place. Reset to zero on a successful login.
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS login_attempts (
        email TEXT PRIMARY KEY,
        failed_count INTEGER NOT NULL DEFAULT 0,
        locked_until DATETIME,
        updated_at DATETIME DEFAULT (datetime('now'))
      )
    `).run();

    // Add MFA (TOTP) columns to users. mfa_secret is encrypted at rest
    // (worker/crypto.js encryptField) the same way clinical notes are — it's
    // a credential, not a UI string. mfa_last_counter blocks replaying an
    // already-used TOTP code within its own validity window.
    if (!cols.results.some(c => c.name === 'mfa_enabled')) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN mfa_enabled BOOLEAN NOT NULL DEFAULT 0").run();
    }
    if (!cols.results.some(c => c.name === 'mfa_secret')) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN mfa_secret TEXT").run();
    }
    if (!cols.results.some(c => c.name === 'mfa_last_counter')) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN mfa_last_counter INTEGER").run();
    }

    // Create mfa_backup_codes table — single-use recovery codes issued when
    // MFA is enabled (worker/auth.js handleMfaSetupVerify). Only a hash of
    // each code is ever stored (worker/crypto.js hashToken).
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS mfa_backup_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code_hash TEXT NOT NULL,
        used_at DATETIME,
        created_at DATETIME DEFAULT (datetime('now'))
      )
    `).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user ON mfa_backup_codes(user_id)`).run();

    // Add token_version to users (bumped to invalidate every outstanding
    // access/refresh token on password change/reset or deactivation)
    if (!cols.results.some(c => c.name === 'token_version')) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0").run();
    }

    // Create refresh_tokens table — only a hash of each token is ever stored
    // (see worker/crypto.js hashToken). Rotated on every /api/refresh call;
    // revoked wholesale by revokeAllSessions() in worker/auth.js.
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        token_version INTEGER NOT NULL DEFAULT 0,
        expires_at DATETIME NOT NULL,
        revoked_at DATETIME,
        created_at DATETIME DEFAULT (datetime('now'))
      )
    `).run();
    await env.DB.prepare(`CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user ON refresh_tokens(user_id)`).run();

    // Add soft-delete columns (deleted_at/deleted_by) to the entities that
    // support a recycle bin. Deleting a client no longer cascades to her
    // sessions (each entity's delete/restore is now independent).
    for (const table of ['clients', 'sessions', 'contacts', 'workshop_registrations']) {
      const tableCols = await env.DB.prepare(`PRAGMA table_info(${table})`).all();
      const names = tableCols.results.map(c => c.name);
      if (!names.includes('deleted_at')) {
        await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN deleted_at DATETIME`).run();
      }
      if (!names.includes('deleted_by')) {
        await env.DB.prepare(`ALTER TABLE ${table} ADD COLUMN deleted_by INTEGER`).run();
      }
    }

    // Create rate_limits table (fixed-window rate limiting for public endpoints)
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS rate_limits (
        rl_key TEXT PRIMARY KEY,
        count INTEGER NOT NULL,
        expires_at INTEGER NOT NULL
      )
    `).run();

    // Create workshops table
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS workshops (
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
      )
    `).run();

    // Create workshop_registrations table
    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS workshop_registrations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        workshop_id TEXT NOT NULL,
        full_name TEXT NOT NULL,
        phone TEXT,
        email TEXT,
        date_option TEXT,
        status TEXT DEFAULT 'new',
        notes TEXT,
        created_at DATETIME DEFAULT (datetime('now')),
        FOREIGN KEY (workshop_id) REFERENCES workshops(id)
      )
    `).run();

    // Add consent columns to workshop_registrations if missing
    const regCols = await env.DB.prepare("PRAGMA table_info(workshop_registrations)").all();
    const hasConsent = regCols.results.some(c => c.name === 'consent_agreed');
    if (!hasConsent) {
      await env.DB.prepare("ALTER TABLE workshop_registrations ADD COLUMN consent_agreed BOOLEAN DEFAULT 0").run();
      await env.DB.prepare("ALTER TABLE workshop_registrations ADD COLUMN consent_date DATETIME").run();
      await env.DB.prepare("ALTER TABLE workshop_registrations ADD COLUMN consent_ip TEXT").run();
    }

    // Seed default workshop if missing
    const existing = await env.DB.prepare(
      "SELECT id FROM workshops WHERE id = ?"
    ).bind('mirpaa-shel-atzmi').first();

    if (!existing) {
      const dates = JSON.stringify([
        { id: 'june-3-1730', label: '3 ביוני, 17:30', date: '2026-06-03T17:30:00' },
      ]);
      await env.DB.prepare(`
        INSERT INTO workshops (id, name, description, dates, price, sessions_count, duration_minutes, location, active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
      `).bind(
        'mirpaa-shel-atzmi',
        'להיות המרפאה של עצמי',
        'סדנת נשים אינטימית — 5 מפגשים, פעם בשבוע, בשיטת מסע הנשמה',
        dates,
        1000,
        5,
        120,
        'מורדכי רומנו 27, תל אביב'
      ).run();
    }
  } catch (e) {
    console.error('Migration error:', e);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    const corsHeaders = getCorsHeaders(request);

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { ...corsHeaders, ...SECURITY_HEADERS },
      });
    }

    // Run migrations on first request (idempotent)
    if (!env._migrated) {
      await runMigrations(env);
      env._migrated = true;
    }

    // Helper: ensure every response has correct CORS for this origin
    function withCors(response) {
      const newHeaders = new Headers(response.headers);
      for (const [k, v] of Object.entries(corsHeaders)) {
        newHeaders.set(k, v);
      }
      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: newHeaders,
      });
    }

    // ─── Public endpoints (no auth required) ───
    if (path === '/api/consent' && method === 'POST') {
      return withCors(await handleConsentSubmission(request, env));
    }
    if (path === '/api/contact' && method === 'POST') {
      return withCors(await handleContactSubmission(request, env));
    }
    if (path === '/api/login' && method === 'POST') {
      return withCors(await handleLogin(request, env));
    }
    if (path === '/api/refresh' && method === 'POST') {
      return withCors(await handleRefresh(request, env));
    }
    if (path === '/api/logout' && method === 'POST') {
      return withCors(await handleLogout(request, env));
    }
    if (path === '/api/mfa/login-verify' && method === 'POST') {
      return withCors(await handleMfaLoginVerify(request, env));
    }
    if (path === '/api/reset-request' && method === 'POST') {
      return withCors(await handleRequestReset(request, env));
    }
    if (path === '/api/reset-execute' && method === 'POST') {
      return withCors(await handleExecuteReset(request, env));
    }
    if (path === '/api/workshop-register' && method === 'POST') {
      return withCors(await handleWorkshopRegister(request, env));
    }

    // ─── Auth check for all /api/* routes below ───
    let authPayload = null;
    if (path.startsWith('/api/')) {
      authPayload = await getAuthPayload(request, env);
      if (!authPayload) {
        return withCors(errorResponse('Unauthorized', 401));
      }
    }

    // ─── Protected endpoints ───
    if (path === '/api/verify' && method === 'GET') {
      return withCors(await handleVerify(request, env));
    }
    if (path === '/api/change-password' && method === 'POST') {
      return withCors(await handleChangePassword(request, env));
    }
    if (path === '/api/mfa/setup/start' && method === 'POST') {
      return withCors(await handleMfaSetupStart(request, env, authPayload));
    }
    if (path === '/api/mfa/setup/verify' && method === 'POST') {
      return withCors(await handleMfaSetupVerify(request, env, authPayload));
    }
    if (path === '/api/mfa/disable' && method === 'POST') {
      return withCors(await handleMfaDisable(request, env, authPayload));
    }
    if (path === '/api/stats' && method === 'GET') {
      return withCors(await handleStats(env));
    }

    // Clients
    if (path === '/api/clients/deleted' && method === 'GET') {
      return withCors(await handleGetDeletedClients(env, authPayload));
    }
    if (path === '/api/clients' && method === 'GET') {
      return withCors(await handleGetClients(url, env));
    }
    if (path === '/api/clients' && method === 'POST') {
      return withCors(await handleCreateClient(request, env, authPayload));
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'GET') {
      return withCors(await handleGetClient(path.split('/').pop(), env, authPayload));
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'PUT') {
      return withCors(await handleUpdateClient(path.split('/').pop(), request, env, authPayload));
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'DELETE') {
      return withCors(await handleDeleteClient(path.split('/').pop(), env, authPayload));
    }
    if (path.match(/^\/api\/clients\/\d+\/restore$/) && method === 'POST') {
      return withCors(await handleRestoreClient(path.split('/')[3], env, authPayload));
    }
    if (path.match(/^\/api\/clients\/\d+\/permanent$/) && method === 'DELETE') {
      return withCors(await handlePermanentDeleteClient(path.split('/')[3], request, env, authPayload));
    }

    // Sessions
    if (path === '/api/sessions/deleted' && method === 'GET') {
      return withCors(await handleGetDeletedSessions(env, authPayload));
    }
    if (path === '/api/sessions' && method === 'GET') {
      return withCors(await handleGetSessions(url, env));
    }
    if (path === '/api/sessions' && method === 'POST') {
      return withCors(await handleCreateSession(request, env, authPayload));
    }
    if (path.match(/^\/api\/sessions\/\d+$/) && method === 'PUT') {
      return withCors(await handleUpdateSession(path.split('/').pop(), request, env, authPayload));
    }
    if (path.match(/^\/api\/sessions\/\d+$/) && method === 'DELETE') {
      return withCors(await handleDeleteSession(path.split('/').pop(), env, authPayload));
    }
    if (path.match(/^\/api\/sessions\/\d+\/restore$/) && method === 'POST') {
      return withCors(await handleRestoreSession(path.split('/')[3], env, authPayload));
    }
    if (path.match(/^\/api\/sessions\/\d+\/permanent$/) && method === 'DELETE') {
      return withCors(await handlePermanentDeleteSession(path.split('/')[3], request, env, authPayload));
    }
    if (path.match(/^\/api\/clients\/\d+\/sessions$/) && method === 'GET') {
      return withCors(await handleGetClientSessions(path.split('/')[3], env));
    }
    if (path.match(/^\/api\/clients\/\d+\/export$/) && method === 'GET') {
      return withCors(await handleExportClientData(path.split('/')[3], env, authPayload));
    }

    // Consents
    if (path.match(/^\/api\/clients\/\d+\/consents$/) && method === 'GET') {
      return withCors(await handleGetClientConsents(path.split('/')[3], env));
    }
    if (path.match(/^\/api\/consents\/\d+\/revoke$/) && method === 'POST') {
      return withCors(await handleRevokeConsent(path.split('/')[3], env, authPayload));
    }

    // Contacts
    if (path === '/api/contacts/deleted' && method === 'GET') {
      return withCors(await handleGetDeletedContacts(env, authPayload));
    }
    if (path === '/api/contacts' && method === 'GET') {
      return withCors(await handleGetContacts(url, env));
    }
    if (path.match(/^\/api\/contacts\/\d+$/) && method === 'PUT') {
      return withCors(await handleUpdateContact(path.split('/').pop(), request, env, authPayload));
    }
    if (path.match(/^\/api\/contacts\/\d+$/) && method === 'DELETE') {
      return withCors(await handleDeleteContact(path.split('/').pop(), env, authPayload));
    }
    if (path.match(/^\/api\/contacts\/\d+\/restore$/) && method === 'POST') {
      return withCors(await handleRestoreContact(path.split('/')[3], env, authPayload));
    }
    if (path.match(/^\/api\/contacts\/\d+\/permanent$/) && method === 'DELETE') {
      return withCors(await handlePermanentDeleteContact(path.split('/')[3], request, env, authPayload));
    }

    // Export
    if (path === '/api/export/clients' && method === 'GET') {
      return withCors(await handleExportClients(env, authPayload));
    }

    // Users (admin only — role check inside handlers)
    if (path === '/api/users' && method === 'GET') {
      return withCors(await handleGetUsers(env, authPayload));
    }
    if (path === '/api/users' && method === 'POST') {
      return withCors(await handleCreateUser(request, env, authPayload));
    }
    if (path.match(/^\/api\/users\/\d+$/) && method === 'PUT') {
      return withCors(await handleUpdateUser(path.split('/').pop(), request, env, authPayload));
    }
    if (path.match(/^\/api\/users\/\d+$/) && method === 'DELETE') {
      return withCors(await handleDeleteUser(path.split('/').pop(), env, authPayload));
    }
    if (path.match(/^\/api\/users\/\d+\/reset-password$/) && method === 'POST') {
      const parts = path.split('/');
      return withCors(await handleAdminResetPassword(parts[3], request, env, authPayload));
    }
    if (path.match(/^\/api\/users\/\d+\/disable-mfa$/) && method === 'POST') {
      const parts = path.split('/');
      return withCors(await handleAdminDisableMfa(parts[3], env, authPayload));
    }

    // Workshops (protected)
    if (path === '/api/workshops' && method === 'GET') {
      return withCors(await handleGetWorkshops(env));
    }
    if (path.match(/^\/api\/workshops\/[\w-]+$/) && method === 'GET') {
      return withCors(await handleGetWorkshop(path.split('/').pop(), env));
    }
    if (path.match(/^\/api\/workshops\/[\w-]+\/registrations$/) && method === 'GET') {
      const parts = path.split('/');
      return withCors(await handleGetWorkshopRegistrations(parts[3], env));
    }
    if (path === '/api/workshop-registrations/deleted' && method === 'GET') {
      return withCors(await handleGetDeletedRegistrations(env, authPayload));
    }
    if (path.match(/^\/api\/workshop-registrations\/\d+$/) && method === 'PUT') {
      return withCors(await handleUpdateRegistration(path.split('/').pop(), request, env, authPayload));
    }
    if (path.match(/^\/api\/workshop-registrations\/\d+$/) && method === 'DELETE') {
      return withCors(await handleDeleteRegistration(path.split('/').pop(), env, authPayload));
    }
    if (path.match(/^\/api\/workshop-registrations\/\d+\/restore$/) && method === 'POST') {
      return withCors(await handleRestoreRegistration(path.split('/')[3], env, authPayload));
    }
    if (path.match(/^\/api\/workshop-registrations\/\d+\/permanent$/) && method === 'DELETE') {
      return withCors(await handlePermanentDeleteRegistration(path.split('/')[3], request, env, authPayload));
    }

    // Audit log (admin only — role check inside handler)
    if (path === '/api/audit-log' && method === 'GET') {
      return withCors(await handleGetAuditLog(url, env, authPayload));
    }

    return withCors(errorResponse('Not found', 404));
  },

  // Daily cleanup of expired operational data (see docs/data-retention-policy.md).
  // Deliberately limited to data with no independent business value once expired —
  // it never touches clients/sessions/contacts/consents.
  async scheduled(event, env) {
    try {
      const now = Math.floor(Date.now() / 1000);
      const rl = await env.DB.prepare('DELETE FROM rate_limits WHERE expires_at < ?').bind(now).run();
      const pr = await env.DB.prepare(
        "DELETE FROM password_resets WHERE used = 1 OR expires_at < datetime('now')"
      ).run();
      const rt = await env.DB.prepare(
        "DELETE FROM refresh_tokens WHERE revoked_at IS NOT NULL OR expires_at < datetime('now')"
      ).run();
      console.log(`Retention cleanup: removed ${rl.meta?.changes ?? 0} rate_limits, ${pr.meta?.changes ?? 0} password_resets, ${rt.meta?.changes ?? 0} refresh_tokens`);
    } catch (e) {
      console.error('Retention cleanup error:', e);
    }
  },
};
