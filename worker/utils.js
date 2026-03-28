/**
 * @file utils.js
 * @description Shared utilities: CORS headers, JSON/error responses.
 * @module Utils
 */

const ALLOWED_ORIGINS = [
  'https://avital-heal.com',
  'https://app.avital-heal.com',
  'https://info.avital-heal.com',
];

export function getCorsHeaders(request) {
  const origin = request?.headers?.get('Origin') || '';
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0];
  return {
    'Access-Control-Allow-Origin': allowedOrigin,
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Max-Age': '86400',
    'Vary': 'Origin',
  };
}

// Backward-compatible static export (used where request is not available)
export const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'https://avital-heal.com',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

export const SECURITY_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=()',
  'X-XSS-Protection': '1; mode=block',
  'Cache-Control': 'no-store, no-cache, must-revalidate',
  'Pragma': 'no-cache',
};

export function jsonResponse(data, status = 200, request = null) {
  const cors = request ? getCorsHeaders(request) : CORS_HEADERS;
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      ...cors,
      ...SECURITY_HEADERS,
    },
  });
}

export function errorResponse(message, status = 400, request = null) {
  return jsonResponse({ error: message }, status, request);
}

export function csvResponse(csv, filename, request = null) {
  const cors = request ? getCorsHeaders(request) : CORS_HEADERS;
  return new Response(csv, {
    headers: {
      'Content-Type': 'text/csv; charset=utf-8',
      'Content-Disposition': `attachment; filename="${filename}"`,
      ...cors,
      ...SECURITY_HEADERS,
    },
  });
}
