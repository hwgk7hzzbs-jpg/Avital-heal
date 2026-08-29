/**
 * @file health.js
 * @description Unauthenticated liveness/readiness check for uptime
 *              monitoring. Deliberately returns nothing beyond a status and
 *              timestamp — no version info, no config, no error detail that
 *              could help an attacker fingerprint the deployment.
 * @module Health
 */

import { jsonResponse } from './utils.js';

export async function handleHealthCheck(env, request) {
  try {
    await env.DB.prepare('SELECT 1').first();
    return jsonResponse({ status: 'ok', timestamp: new Date().toISOString() }, 200, request);
  } catch (e) {
    console.error('Health check error:', e);
    return jsonResponse({ status: 'degraded', timestamp: new Date().toISOString() }, 503, request);
  }
}
