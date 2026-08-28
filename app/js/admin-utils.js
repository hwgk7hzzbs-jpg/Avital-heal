/**
 * @file admin-utils.js
 * @description Shared helpers for the CRM admin SPA. Loaded before all other admin-*.js files.
 * @module AdminUtils
 */

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}
