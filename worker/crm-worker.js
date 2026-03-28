// ═══════════════════════════════════════════════════════════════
// Avital Heal CRM — Cloudflare Worker API
// ═══════════════════════════════════════════════════════════════
// Database: D1 (avital-heal-crm)
// Auth: Simple password-based (single user — Avital)
// ═══════════════════════════════════════════════════════════════

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': 'https://avital-heal.com',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Max-Age': '86400',
};

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...CORS_HEADERS },
  });
}

function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}

// Simple auth check — compare against env secret
function isAuthorized(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) return false;
  return authHeader.slice(7) === env.CRM_AUTH_TOKEN;
}

// ─── Turnstile verification ───
async function verifyTurnstile(token, env) {
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: env.TURNSTILE_SECRET_KEY,
        response: token,
      }),
    });
    const result = await response.json();
    return result.success === true;
  } catch (e) {
    console.error('Turnstile verification error:', e);
    return false;
  }
}

// ═══════════════════════════════════════════════════════════════
// Route handler
// ═══════════════════════════════════════════════════════════════

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // Handle CORS preflight
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    // ─── Public endpoint: consent form submission ───
    if (path === '/api/consent' && method === 'POST') {
      return handleConsentSubmission(request, env);
    }

    // ─── Auth check for all /api/* routes ───
    if (path.startsWith('/api/')) {
      if (!isAuthorized(request, env)) {
        return errorResponse('Unauthorized', 401);
      }
    }

    // ─── Login / token validation ───
    if (path === '/api/login' && method === 'POST') {
      return handleLogin(request, env);
    }
    if (path === '/api/verify' && method === 'GET') {
      return jsonResponse({ valid: true });
    }

    // ─── Dashboard stats ───
    if (path === '/api/stats' && method === 'GET') {
      return handleStats(env);
    }

    // ─── Clients CRUD ───
    if (path === '/api/clients' && method === 'GET') {
      return handleGetClients(url, env);
    }
    if (path === '/api/clients' && method === 'POST') {
      return handleCreateClient(request, env);
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'GET') {
      const id = path.split('/').pop();
      return handleGetClient(id, env);
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'PUT') {
      const id = path.split('/').pop();
      return handleUpdateClient(id, request, env);
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === 'DELETE') {
      const id = path.split('/').pop();
      return handleDeleteClient(id, env);
    }

    // ─── Sessions CRUD ───
    if (path === '/api/sessions' && method === 'GET') {
      return handleGetSessions(url, env);
    }
    if (path === '/api/sessions' && method === 'POST') {
      return handleCreateSession(request, env);
    }
    if (path.match(/^\/api\/sessions\/\d+$/) && method === 'PUT') {
      const id = path.split('/').pop();
      return handleUpdateSession(id, request, env);
    }
    if (path.match(/^\/api\/sessions\/\d+$/) && method === 'DELETE') {
      const id = path.split('/').pop();
      return handleDeleteSession(id, env);
    }

    // ─── Client sessions ───
    if (path.match(/^\/api\/clients\/\d+\/sessions$/) && method === 'GET') {
      const clientId = path.split('/')[3];
      return handleGetClientSessions(clientId, env);
    }

    // ─── Export ───
    if (path === '/api/export/clients' && method === 'GET') {
      return handleExportClients(env);
    }

    return errorResponse('Not found', 404);
  },
};

// ═══════════════════════════════════════════════════════════════
// Handler functions
// ═══════════════════════════════════════════════════════════════

// ─── Login ───
async function handleLogin(request, env) {
  try {
    const { password } = await request.json();
    if (password === env.CRM_PASSWORD) {
      return jsonResponse({ token: env.CRM_AUTH_TOKEN });
    }
    return errorResponse('Invalid password', 401);
  } catch (e) {
    return errorResponse('Invalid request body', 400);
  }
}

// ─── Consent form (public) ───
async function handleConsentSubmission(request, env) {
  try {
    let data;
    const contentType = request.headers.get('Content-Type') || '';

    if (contentType.includes('application/json')) {
      data = await request.json();
    } else {
      // URL-encoded form data
      const formData = await request.text();
      const params = new URLSearchParams(formData);
      data = Object.fromEntries(params.entries());
    }

    const { email, fullName, date, healthDeclaration, agreementConfirmation, timestamp, userAgent } = data;
    const turnstileToken = data['cf-turnstile-response'] || '';

    // Validate required fields
    if (!email || !fullName || !date) {
      return errorResponse('Missing required fields');
    }
    if (healthDeclaration !== 'true' && healthDeclaration !== true) {
      return errorResponse('Health declaration required');
    }
    if (agreementConfirmation !== 'true' && agreementConfirmation !== true) {
      return errorResponse('Agreement confirmation required');
    }

    // Verify Turnstile
    if (turnstileToken) {
      const verified = await verifyTurnstile(turnstileToken, env);
      if (!verified) {
        return errorResponse('CAPTCHA verification failed', 403);
      }
    }

    // Check if client already exists by email
    const existing = await env.DB.prepare(
      'SELECT id FROM clients WHERE email = ?'
    ).bind(email).first();

    if (existing) {
      // Update existing client consent
      await env.DB.prepare(
        'UPDATE clients SET consent_signed = 1, consent_date = ?, updated_at = datetime(\'now\') WHERE id = ?'
      ).bind(timestamp || new Date().toISOString(), existing.id).run();
    } else {
      // Create new client from consent form
      await env.DB.prepare(
        'INSERT INTO clients (full_name, email, consent_signed, consent_date, consent_ip, created_at, updated_at) VALUES (?, ?, 1, ?, ?, datetime(\'now\'), datetime(\'now\'))'
      ).bind(
        fullName,
        email,
        timestamp || new Date().toISOString(),
        request.headers.get('CF-Connecting-IP') || ''
      ).run();
    }

    return jsonResponse({ status: 'success', message: 'Form submitted successfully' });
  } catch (e) {
    console.error('Consent error:', e);
    return errorResponse('Internal server error', 500);
  }
}

// ─── Dashboard stats ───
async function handleStats(env) {
  try {
    const totalClients = await env.DB.prepare('SELECT COUNT(*) as count FROM clients').first();
    const activeClients = await env.DB.prepare('SELECT COUNT(*) as count FROM clients WHERE status = \'active\'').first();
    const consentSigned = await env.DB.prepare('SELECT COUNT(*) as count FROM clients WHERE consent_signed = 1').first();
    const totalSessions = await env.DB.prepare('SELECT COUNT(*) as count FROM sessions').first();
    const thisMonth = new Date().toISOString().slice(0, 7); // YYYY-MM
    const monthSessions = await env.DB.prepare('SELECT COUNT(*) as count FROM sessions WHERE session_date LIKE ?').bind(thisMonth + '%').first();
    const monthRevenue = await env.DB.prepare('SELECT COALESCE(SUM(amount), 0) as total FROM sessions WHERE session_date LIKE ? AND paid = 1').bind(thisMonth + '%').first();
    const unpaid = await env.DB.prepare('SELECT COALESCE(SUM(amount), 0) as total FROM sessions WHERE paid = 0 AND amount > 0').first();

    // Recent clients
    const recentClients = await env.DB.prepare('SELECT id, full_name, email, join_date, consent_signed FROM clients ORDER BY created_at DESC LIMIT 5').all();

    return jsonResponse({
      totalClients: totalClients.count,
      activeClients: activeClients.count,
      consentSigned: consentSigned.count,
      totalSessions: totalSessions.count,
      monthSessions: monthSessions.count,
      monthRevenue: monthRevenue.total,
      unpaidTotal: unpaid.total,
      recentClients: recentClients.results,
    });
  } catch (e) {
    console.error('Stats error:', e);
    return errorResponse('Failed to load stats', 500);
  }
}

// ─── Get all clients ───
async function handleGetClients(url, env) {
  try {
    const search = url.searchParams.get('search') || '';
    const status = url.searchParams.get('status') || '';
    const limit = parseInt(url.searchParams.get('limit') || '100');
    const offset = parseInt(url.searchParams.get('offset') || '0');

    let query = 'SELECT c.*, (SELECT COUNT(*) FROM sessions WHERE client_id = c.id) as session_count, (SELECT MAX(session_date) FROM sessions WHERE client_id = c.id) as last_session FROM clients c WHERE 1=1';
    const bindings = [];

    if (search) {
      query += ' AND (c.full_name LIKE ? OR c.email LIKE ? OR c.phone LIKE ?)';
      bindings.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    if (status) {
      query += ' AND c.status = ?';
      bindings.push(status);
    }

    query += ' ORDER BY c.created_at DESC LIMIT ? OFFSET ?';
    bindings.push(limit, offset);

    const stmt = env.DB.prepare(query);
    const result = await (bindings.length ? stmt.bind(...bindings) : stmt).all();

    return jsonResponse(result.results);
  } catch (e) {
    console.error('Get clients error:', e);
    return errorResponse('Failed to load clients', 500);
  }
}

// ─── Get single client ───
async function handleGetClient(id, env) {
  try {
    const client = await env.DB.prepare('SELECT * FROM clients WHERE id = ?').bind(id).first();
    if (!client) return errorResponse('Client not found', 404);

    const sessions = await env.DB.prepare(
      'SELECT * FROM sessions WHERE client_id = ? ORDER BY session_date DESC'
    ).bind(id).all();

    return jsonResponse({ ...client, sessions: sessions.results });
  } catch (e) {
    console.error('Get client error:', e);
    return errorResponse('Failed to load client', 500);
  }
}

// ─── Create client ───
async function handleCreateClient(request, env) {
  try {
    const data = await request.json();
    const { full_name, email, phone, address, birth_date, treatment_type, notes } = data;

    if (!full_name) return errorResponse('Full name is required');

    const result = await env.DB.prepare(
      'INSERT INTO clients (full_name, email, phone, address, birth_date, treatment_type, notes) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).bind(full_name, email || null, phone || null, address || null, birth_date || null, treatment_type || null, notes || null).run();

    return jsonResponse({ id: result.meta.last_row_id, message: 'Client created' }, 201);
  } catch (e) {
    console.error('Create client error:', e);
    return errorResponse('Failed to create client', 500);
  }
}

// ─── Update client ───
async function handleUpdateClient(id, request, env) {
  try {
    const data = await request.json();
    const fields = [];
    const values = [];

    const allowedFields = ['full_name', 'email', 'phone', 'address', 'birth_date', 'status', 'treatment_type', 'consent_signed', 'consent_date', 'notes'];

    for (const field of allowedFields) {
      if (data[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(data[field]);
      }
    }

    if (fields.length === 0) return errorResponse('No fields to update');

    fields.push('updated_at = datetime(\'now\')');
    values.push(id);

    await env.DB.prepare(
      `UPDATE clients SET ${fields.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    return jsonResponse({ message: 'Client updated' });
  } catch (e) {
    console.error('Update client error:', e);
    return errorResponse('Failed to update client', 500);
  }
}

// ─── Delete client ───
async function handleDeleteClient(id, env) {
  try {
    await env.DB.prepare('DELETE FROM sessions WHERE client_id = ?').bind(id).run();
    await env.DB.prepare('DELETE FROM clients WHERE id = ?').bind(id).run();
    return jsonResponse({ message: 'Client deleted' });
  } catch (e) {
    console.error('Delete client error:', e);
    return errorResponse('Failed to delete client', 500);
  }
}

// ─── Get sessions ───
async function handleGetSessions(url, env) {
  try {
    const clientId = url.searchParams.get('client_id');
    const from = url.searchParams.get('from');
    const to = url.searchParams.get('to');
    const limit = parseInt(url.searchParams.get('limit') || '50');

    let query = 'SELECT s.*, c.full_name as client_name FROM sessions s JOIN clients c ON s.client_id = c.id WHERE 1=1';
    const bindings = [];

    if (clientId) {
      query += ' AND s.client_id = ?';
      bindings.push(clientId);
    }
    if (from) {
      query += ' AND s.session_date >= ?';
      bindings.push(from);
    }
    if (to) {
      query += ' AND s.session_date <= ?';
      bindings.push(to);
    }

    query += ' ORDER BY s.session_date DESC LIMIT ?';
    bindings.push(limit);

    const result = await env.DB.prepare(query).bind(...bindings).all();
    return jsonResponse(result.results);
  } catch (e) {
    console.error('Get sessions error:', e);
    return errorResponse('Failed to load sessions', 500);
  }
}

// ─── Get client sessions ───
async function handleGetClientSessions(clientId, env) {
  try {
    const result = await env.DB.prepare(
      'SELECT * FROM sessions WHERE client_id = ? ORDER BY session_date DESC'
    ).bind(clientId).all();
    return jsonResponse(result.results);
  } catch (e) {
    console.error('Get client sessions error:', e);
    return errorResponse('Failed to load sessions', 500);
  }
}

// ─── Create session ───
async function handleCreateSession(request, env) {
  try {
    const data = await request.json();
    const { client_id, session_date, session_type, duration_minutes, summary, next_session_notes, paid, amount, payment_method, invoice_number } = data;

    if (!client_id || !session_date) return errorResponse('Client ID and session date are required');

    // Verify client exists
    const client = await env.DB.prepare('SELECT id FROM clients WHERE id = ?').bind(client_id).first();
    if (!client) return errorResponse('Client not found', 404);

    const result = await env.DB.prepare(
      'INSERT INTO sessions (client_id, session_date, session_type, duration_minutes, summary, next_session_notes, paid, amount, payment_method, invoice_number) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(
      client_id, session_date,
      session_type || null,
      duration_minutes || 50,
      summary || null,
      next_session_notes || null,
      paid ? 1 : 0,
      amount || 0,
      payment_method || null,
      invoice_number || null
    ).run();

    return jsonResponse({ id: result.meta.last_row_id, message: 'Session created' }, 201);
  } catch (e) {
    console.error('Create session error:', e);
    return errorResponse('Failed to create session', 500);
  }
}

// ─── Update session ───
async function handleUpdateSession(id, request, env) {
  try {
    const data = await request.json();
    const fields = [];
    const values = [];

    const allowedFields = ['session_date', 'session_type', 'duration_minutes', 'summary', 'next_session_notes', 'paid', 'amount', 'payment_method', 'invoice_number'];

    for (const field of allowedFields) {
      if (data[field] !== undefined) {
        fields.push(`${field} = ?`);
        values.push(field === 'paid' ? (data[field] ? 1 : 0) : data[field]);
      }
    }

    if (fields.length === 0) return errorResponse('No fields to update');

    fields.push('updated_at = datetime(\'now\')');
    values.push(id);

    await env.DB.prepare(
      `UPDATE sessions SET ${fields.join(', ')} WHERE id = ?`
    ).bind(...values).run();

    return jsonResponse({ message: 'Session updated' });
  } catch (e) {
    console.error('Update session error:', e);
    return errorResponse('Failed to update session', 500);
  }
}

// ─── Delete session ───
async function handleDeleteSession(id, env) {
  try {
    await env.DB.prepare('DELETE FROM sessions WHERE id = ?').bind(id).run();
    return jsonResponse({ message: 'Session deleted' });
  } catch (e) {
    console.error('Delete session error:', e);
    return errorResponse('Failed to delete session', 500);
  }
}

// ─── Export clients CSV ───
async function handleExportClients(env) {
  try {
    const clients = await env.DB.prepare(
      'SELECT c.*, (SELECT COUNT(*) FROM sessions WHERE client_id = c.id) as session_count, (SELECT COALESCE(SUM(amount), 0) FROM sessions WHERE client_id = c.id AND paid = 1) as total_paid, (SELECT COALESCE(SUM(amount), 0) FROM sessions WHERE client_id = c.id AND paid = 0) as total_unpaid FROM clients c ORDER BY c.full_name'
    ).all();

    let csv = 'שם מלא,אימייל,טלפון,סטטוס,סוג טיפול,הסכמה חתומה,תאריך הצטרפות,מספר טיפולים,שולם,לא שולם\n';
    for (const c of clients.results) {
      csv += `"${c.full_name || ''}","${c.email || ''}","${c.phone || ''}","${c.status || ''}","${c.treatment_type || ''}","${c.consent_signed ? 'כן' : 'לא'}","${c.join_date || ''}",${c.session_count},${c.total_paid},${c.total_unpaid}\n`;
    }

    return new Response(csv, {
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="clients-export.csv"',
        ...CORS_HEADERS,
      },
    });
  } catch (e) {
    console.error('Export error:', e);
    return errorResponse('Failed to export', 500);
  }
}
