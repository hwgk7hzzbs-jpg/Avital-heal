/**
 * @file dashboard.js
 * @description Dashboard statistics handler.
 * @module Dashboard
 */

import { jsonResponse, errorResponse } from './utils.js';

// ─── Dashboard stats ───

export async function handleStats(env) {
  try {
    const totalClients = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM clients WHERE deleted_at IS NULL'
    ).first();
    const activeClients = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM clients WHERE status = 'active' AND deleted_at IS NULL"
    ).first();
    const consentSigned = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM clients WHERE consent_signed = 1 AND deleted_at IS NULL'
    ).first();
    const totalSessions = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM sessions WHERE deleted_at IS NULL'
    ).first();

    const thisMonth = new Date().toISOString().slice(0, 7);
    const monthSessions = await env.DB.prepare(
      'SELECT COUNT(*) as count FROM sessions WHERE session_date LIKE ? AND deleted_at IS NULL'
    ).bind(thisMonth + '%').first();
    const monthRevenue = await env.DB.prepare(
      'SELECT COALESCE(SUM(amount), 0) as total FROM sessions WHERE session_date LIKE ? AND paid = 1 AND deleted_at IS NULL'
    ).bind(thisMonth + '%').first();
    const unpaid = await env.DB.prepare(
      'SELECT COALESCE(SUM(amount), 0) as total FROM sessions WHERE paid = 0 AND amount > 0 AND deleted_at IS NULL'
    ).first();

    const recentClients = await env.DB.prepare(
      'SELECT id, full_name, email, join_date, consent_signed FROM clients WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 5'
    ).all();

    const newContacts = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM contacts WHERE status = 'new' AND deleted_at IS NULL"
    ).first();
    const recentContacts = await env.DB.prepare(
      'SELECT id, full_name, phone, email, message, status, created_at FROM contacts WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT 5'
    ).all();

    return jsonResponse({
      totalClients: totalClients.count,
      activeClients: activeClients.count,
      consentSigned: consentSigned.count,
      totalSessions: totalSessions.count,
      monthSessions: monthSessions.count,
      monthRevenue: monthRevenue.total,
      unpaidTotal: unpaid.total,
      recentClients: recentClients.results,
      newContacts: newContacts.count,
      recentContacts: recentContacts.results,
    });
  } catch (e) {
    console.error('Stats error:', e);
    return errorResponse('Failed to load stats', 500);
  }
}
