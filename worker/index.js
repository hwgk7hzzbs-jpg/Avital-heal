/**
 * @file index.js
 * @description Central entry point — routing ONLY. No business logic.
 * @module Core
 * @security Auth check applied before protected routes.
 */

import { CORS_HEADERS, SECURITY_HEADERS, getCorsHeaders } from './utils.js';
import { errorResponse } from './utils.js';
import { getAuthPayload, handleLogin, handleVerify } from './auth.js';
import { handleRequestReset, handleExecuteReset, handleChangePassword } from './auth.js';
import { handleConsentSubmission } from './consent.js';
import { handleContactSubmission, handleGetContacts, handleUpdateContact, handleDeleteContact } from './contacts.js';
import { handleGetClients, handleGetClient, handleCreateClient, handleUpdateClient, handleDeleteClient, handleExportClients } from './clients.js';
import { handleGetSessions, handleGetClientSessions, handleCreateSession, handleUpdateSession, handleDeleteSession } from './sessions.js';
import { handleStats } from './dashboard.js';
import { handleGetUsers, handleCreateUser, handleUpdateUser, handleDeleteUser, handleAdminResetPassword } from './users.js';
import {
  handleWorkshopRegister,
  handleGetWorkshops,
  handleGetWorkshop,
  handleGetWorkshopRegistrations,
  handleUpdateRegistration,
  handleDeleteRegistration,
} from './workshops.js';

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
    if (path === '/api/stats' && method === 'GET') {
      return withCors(await handleStats(env));
    }

    // Clients
    if (path === '/api/clients' && method === 'GET') {
      return withCors(await handleGetClients(url, env));
    }
    if (path === '/api/clients' && method === 'POST') {
      return withCors(await handleCreateClient(request, env, authPayload));
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'GET') {
      return withCors(await handleGetClient(path.split('/').pop(), env));
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'PUT') {
      return withCors(await handleUpdateClient(path.split('/').pop(), request, env, authPayload));
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'DELETE') {
      return withCors(await handleDeleteClient(path.split('/').pop(), env, authPayload));
    }

    // Sessions
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
    if (path.match(/^\/api\/clients\/\d+\/sessions$/) && method === 'GET') {
      return withCors(await handleGetClientSessions(path.split('/')[3], env));
    }

    // Contacts
    if (path === '/api/contacts' && method === 'GET') {
      return withCors(await handleGetContacts(url, env));
    }
    if (path.match(/^\/api\/contacts\/\d+$/) && method === 'PUT') {
      return withCors(await handleUpdateContact(path.split('/').pop(), request, env, authPayload));
    }
    if (path.match(/^\/api\/contacts\/\d+$/) && method === 'DELETE') {
      return withCors(await handleDeleteContact(path.split('/').pop(), env, authPayload));
    }

    // Export
    if (path === '/api/export/clients' && method === 'GET') {
      return withCors(await handleExportClients(env, authPayload));
    }

    // Users (admin only — role check inside handlers)
    if (path === '/api/users' && method === 'GET') {
      return withCors(await handleGetUsers(request, env));
    }
    if (path === '/api/users' && method === 'POST') {
      return withCors(await handleCreateUser(request, env));
    }
    if (path.match(/^\/api\/users\/\d+$/) && method === 'PUT') {
      return withCors(await handleUpdateUser(request, env, path.split('/').pop()));
    }
    if (path.match(/^\/api\/users\/\d+$/) && method === 'DELETE') {
      return withCors(await handleDeleteUser(request, env, path.split('/').pop()));
    }
    if (path.match(/^\/api\/users\/\d+\/reset-password$/) && method === 'POST') {
      const parts = path.split('/');
      return withCors(await handleAdminResetPassword(request, env, parts[3]));
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
    if (path.match(/^\/api\/workshop-registrations\/\d+$/) && method === 'PUT') {
      return withCors(await handleUpdateRegistration(path.split('/').pop(), request, env, authPayload));
    }
    if (path.match(/^\/api\/workshop-registrations\/\d+$/) && method === 'DELETE') {
      return withCors(await handleDeleteRegistration(path.split('/').pop(), env, authPayload));
    }

    return withCors(errorResponse('Not found', 404));
  },
};
