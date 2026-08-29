/**
 * @file index.js
 * @description Central entry point — routing ONLY. No business logic.
 * @module Core
 * @security Auth check applied before protected routes.
 *
 * Schema migrations do NOT run here (or anywhere in the request path). They
 * live as numbered SQL files in worker/migrations/, applied only as an
 * explicit deploy step:
 *   npx wrangler d1 migrations apply avital-heal-crm --remote
 * A failed migration halts there (and rolls itself back) — deploy the
 * Worker only after `apply` reports success. See worker/migrations/README.md.
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
