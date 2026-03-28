/**
 * @file index.js
 * @description Central entry point — routing ONLY. No business logic.
 * @module Core
 * @security Auth check applied before protected routes.
 */

import { CORS_HEADERS, SECURITY_HEADERS } from './utils.js';
import { errorResponse } from './utils.js';
import { isAuthorized, handleLogin, handleVerify } from './auth.js';
import { handleRequestReset, handleExecuteReset, handleChangePassword } from './auth.js';
import { handleConsentSubmission } from './consent.js';
import { handleContactSubmission, handleGetContacts, handleUpdateContact, handleDeleteContact } from './contacts.js';
import { handleGetClients, handleGetClient, handleCreateClient, handleUpdateClient, handleDeleteClient, handleExportClients } from './clients.js';
import { handleGetSessions, handleGetClientSessions, handleCreateSession, handleUpdateSession, handleDeleteSession } from './sessions.js';
import { handleStats } from './dashboard.js';
import { handleGetUsers, handleCreateUser, handleUpdateUser, handleDeleteUser, handleAdminResetPassword } from './users.js';

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
  } catch (e) {
    console.error('Migration error:', e);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: { ...CORS_HEADERS, ...SECURITY_HEADERS },
      });
    }

    // Run migrations on first request (idempotent)
    if (!env._migrated) {
      await runMigrations(env);
      env._migrated = true;
    }

    // ─── Public endpoints (no auth required) ───
    if (path === '/api/consent' && method === 'POST') {
      return handleConsentSubmission(request, env);
    }
    if (path === '/api/contact' && method === 'POST') {
      return handleContactSubmission(request, env);
    }
    if (path === '/api/login' && method === 'POST') {
      return handleLogin(request, env);
    }
    if (path === '/api/reset-request' && method === 'POST') {
      return handleRequestReset(request, env);
    }
    if (path === '/api/reset-execute' && method === 'POST') {
      return handleExecuteReset(request, env);
    }

    // ─── Auth check for all /api/* routes below ───
    if (path.startsWith('/api/')) {
      if (!(await isAuthorized(request, env))) {
        return errorResponse('Unauthorized', 401);
      }
    }

    // ─── Protected endpoints ───
    if (path === '/api/verify' && method === 'GET') {
      return handleVerify(request, env);
    }
    if (path === '/api/change-password' && method === 'POST') {
      return handleChangePassword(request, env);
    }
    if (path === '/api/stats' && method === 'GET') {
      return handleStats(env);
    }

    // Clients
    if (path === '/api/clients' && method === 'GET') {
      return handleGetClients(url, env);
    }
    if (path === '/api/clients' && method === 'POST') {
      return handleCreateClient(request, env);
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'GET') {
      return handleGetClient(path.split('/').pop(), env);
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'PUT') {
      return handleUpdateClient(path.split('/').pop(), request, env);
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'DELETE') {
      return handleDeleteClient(path.split('/').pop(), env);
    }

    // Sessions
    if (path === '/api/sessions' && method === 'GET') {
      return handleGetSessions(url, env);
    }
    if (path === '/api/sessions' && method === 'POST') {
      return handleCreateSession(request, env);
    }
    if (path.match(/^\/api\/sessions\/\d+$/) && method === 'PUT') {
      return handleUpdateSession(path.split('/').pop(), request, env);
    }
    if (path.match(/^\/api\/sessions\/\d+$/) && method === 'DELETE') {
      return handleDeleteSession(path.split('/').pop(), env);
    }
    if (path.match(/^\/api\/clients\/\d+\/sessions$/) && method === 'GET') {
      return handleGetClientSessions(path.split('/')[3], env);
    }

    // Contacts
    if (path === '/api/contacts' && method === 'GET') {
      return handleGetContacts(url, env);
    }
    if (path.match(/^\/api\/contacts\/\d+$/) && method === 'PUT') {
      return handleUpdateContact(path.split('/').pop(), request, env);
    }
    if (path.match(/^\/api\/contacts\/\d+$/) && method === 'DELETE') {
      return handleDeleteContact(path.split('/').pop(), env);
    }

    // Export
    if (path === '/api/export/clients' && method === 'GET') {
      return handleExportClients(env);
    }

    // Users (admin only — role check inside handlers)
    if (path === '/api/users' && method === 'GET') {
      return handleGetUsers(request, env);
    }
    if (path === '/api/users' && method === 'POST') {
      return handleCreateUser(request, env);
    }
    if (path.match(/^\/api\/users\/\d+$/) && method === 'PUT') {
      return handleUpdateUser(request, env, path.split('/').pop());
    }
    if (path.match(/^\/api\/users\/\d+$/) && method === 'DELETE') {
      return handleDeleteUser(request, env, path.split('/').pop());
    }
    if (path.match(/^\/api\/users\/\d+\/reset-password$/) && method === 'POST') {
      const parts = path.split('/');
      return handleAdminResetPassword(request, env, parts[3]);
    }

    return errorResponse('Not found', 404);
  },
};
