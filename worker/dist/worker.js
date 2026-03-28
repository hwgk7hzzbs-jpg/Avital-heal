// utils.js
var CORS_HEADERS = {
  "Access-Control-Allow-Origin": "https://avital-heal.com",
  "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Access-Control-Max-Age": "86400"
};
var SECURITY_HEADERS = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=()",
  "X-XSS-Protection": "1; mode=block",
  "Cache-Control": "no-store, no-cache, must-revalidate",
  "Pragma": "no-cache"
};
function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS,
      ...SECURITY_HEADERS
    }
  });
}
function errorResponse(message, status = 400) {
  return jsonResponse({ error: message }, status);
}
function csvResponse(csv, filename) {
  return new Response(csv, {
    headers: {
      "Content-Type": "text/csv; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
      ...CORS_HEADERS,
      ...SECURITY_HEADERS
    }
  });
}

// crypto.js
var PBKDF2_ITERATIONS = 1e5;
var SALT_LENGTH = 16;
var JWT_EXPIRY_HOURS = 24;
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  return bufToHex(salt) + ":" + bufToHex(new Uint8Array(bits));
}
async function verifyPassword(password, storedHash) {
  const parts = storedHash.split(":");
  if (parts.length !== 2) return false;
  const salt = hexToBuf(parts[0]);
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: PBKDF2_ITERATIONS, hash: "SHA-256" },
    key,
    256
  );
  return bufToHex(new Uint8Array(bits)) === parts[1];
}
function utf8ToB64url(str) {
  const bytes = new TextEncoder().encode(str);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/[+]/g, "-").replace(/[/]/g, "_").replace(/=+$/, "");
}
function b64urlToUtf8(b64) {
  const binary = atob(b64.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return new TextDecoder().decode(bytes);
}
async function createJWT(payload, secret) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1e3);
  const body = { ...payload, iat: now, exp: now + JWT_EXPIRY_HOURS * 3600 };
  const headerB64 = utf8ToB64url(JSON.stringify(header));
  const bodyB64 = utf8ToB64url(JSON.stringify(body));
  const data = `${headerB64}.${bodyB64}`;
  const key = await importHMACKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(data));
  const sigBytes = new Uint8Array(sig);
  let sigBinary = "";
  for (let i = 0; i < sigBytes.length; i++) {
    sigBinary += String.fromCharCode(sigBytes[i]);
  }
  const sigB64 = btoa(sigBinary).replace(/[+]/g, "-").replace(/[/]/g, "_").replace(/=+$/, "");
  return `${data}.${sigB64}`;
}
async function verifyJWT(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const key = await importHMACKey(secret);
    const sigStr = atob(parts[2].replace(/-/g, "+").replace(/_/g, "/"));
    const sigBuf = new Uint8Array(sigStr.length);
    for (let i = 0; i < sigStr.length; i++) {
      sigBuf[i] = sigStr.charCodeAt(i);
    }
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      sigBuf,
      new TextEncoder().encode(`${parts[0]}.${parts[1]}`)
    );
    if (!valid) return null;
    const payload = JSON.parse(b64urlToUtf8(parts[1]));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1e3)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}
function generateToken(length = 32) {
  return bufToHex(crypto.getRandomValues(new Uint8Array(length)));
}
async function importHMACKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}
function bufToHex(buf) {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBuf(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

// auth.js
async function verifyTurnstile(token, env) {
  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          secret: env.TURNSTILE_SECRET_KEY,
          response: token
        })
      }
    );
    const result = await response.json();
    return result.success === true;
  } catch (e) {
    console.error("Turnstile verification error:", e);
    return false;
  }
}
async function isAuthorized(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return false;
  const token = authHeader.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);
  return payload !== null;
}
async function handleLogin(request, env) {
  try {
    const { email, password } = await request.json();
    if (!email || !password) {
      return errorResponse("\u05E0\u05D3\u05E8\u05E9 \u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05D5\u05E1\u05D9\u05E1\u05DE\u05D4", 400);
    }
    const user = await env.DB.prepare(
      "SELECT id, email, name, role, password_hash, active FROM users WHERE email = ?"
    ).bind(email.toLowerCase().trim()).first();
    if (!user) {
      return errorResponse("\u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05D0\u05D5 \u05E1\u05D9\u05E1\u05DE\u05D4 \u05E9\u05D2\u05D5\u05D9\u05D9\u05DD", 401);
    }
    if (user.active === 0) {
      return errorResponse("\u05D4\u05D7\u05E9\u05D1\u05D5\u05DF \u05D0\u05D9\u05E0\u05D5 \u05E4\u05E2\u05D9\u05DC \u2014 \u05E4\u05E0\u05D4 \u05DC\u05DE\u05E0\u05D4\u05DC \u05D4\u05DE\u05E2\u05E8\u05DB\u05EA", 403);
    }
    const valid = await verifyPassword(password, user.password_hash);
    if (!valid) {
      return errorResponse("\u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05D0\u05D5 \u05E1\u05D9\u05E1\u05DE\u05D4 \u05E9\u05D2\u05D5\u05D9\u05D9\u05DD", 401);
    }
    const token = await createJWT(
      { userId: user.id, email: user.email, name: user.name, role: user.role },
      env.JWT_SECRET
    );
    return jsonResponse({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch (e) {
    console.error("Login error:", e);
    return errorResponse("\u05E9\u05D2\u05D9\u05D0\u05EA \u05DB\u05E0\u05D9\u05E1\u05D4: " + (e.message || String(e)), 500);
  }
}
async function handleVerify(request, env) {
  const authHeader = request.headers.get("Authorization");
  const token = authHeader?.slice(7);
  const payload = await verifyJWT(token, env.JWT_SECRET);
  if (!payload) return errorResponse("Token expired", 401);
  return jsonResponse({
    valid: true,
    user: { id: payload.userId, email: payload.email, name: payload.name, role: payload.role }
  });
}
async function handleRequestReset(request, env) {
  try {
    const { email } = await request.json();
    if (!email) return errorResponse("\u05E0\u05D3\u05E8\u05E9 \u05D0\u05D9\u05DE\u05D9\u05D9\u05DC", 400);
    const user = await env.DB.prepare(
      "SELECT id, name FROM users WHERE email = ? AND active = 1"
    ).bind(email.toLowerCase().trim()).first();
    if (!user) {
      return jsonResponse({ message: "\u05D0\u05DD \u05D4\u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05E7\u05D9\u05D9\u05DD \u05D1\u05DE\u05E2\u05E8\u05DB\u05EA, \u05E0\u05E9\u05DC\u05D7 \u05E7\u05D9\u05E9\u05D5\u05E8 \u05DC\u05D0\u05D9\u05E4\u05D5\u05E1" });
    }
    const token = generateToken(32);
    const expiresAt = new Date(Date.now() + 3600 * 1e3).toISOString();
    await env.DB.prepare(
      "INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)"
    ).bind(user.id, token, expiresAt).run();
    try {
      await fetch(env.RESET_EMAIL_SCRIPT_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          email: email.toLowerCase().trim(),
          name: user.name,
          resetLink: `https://avital-heal.com/admin?reset=${token}`
        })
      });
    } catch (emailErr) {
      console.error("Reset email send error:", emailErr);
    }
    return jsonResponse({ message: "\u05D0\u05DD \u05D4\u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05E7\u05D9\u05D9\u05DD \u05D1\u05DE\u05E2\u05E8\u05DB\u05EA, \u05E0\u05E9\u05DC\u05D7 \u05E7\u05D9\u05E9\u05D5\u05E8 \u05DC\u05D0\u05D9\u05E4\u05D5\u05E1" });
  } catch (e) {
    console.error("Reset request error:", e);
    return errorResponse("\u05E9\u05D2\u05D9\u05D0\u05D4 \u05D1\u05D1\u05E7\u05E9\u05EA \u05D0\u05D9\u05E4\u05D5\u05E1", 500);
  }
}
async function handleExecuteReset(request, env) {
  try {
    const { token, newPassword } = await request.json();
    if (!token || !newPassword) {
      return errorResponse("\u05E0\u05D3\u05E8\u05E9 \u05D8\u05D5\u05E7\u05DF \u05D5\u05E1\u05D9\u05E1\u05DE\u05D4 \u05D7\u05D3\u05E9\u05D4", 400);
    }
    if (newPassword.length < 8) {
      return errorResponse("\u05D4\u05E1\u05D9\u05E1\u05DE\u05D4 \u05D7\u05D9\u05D9\u05D1\u05EA \u05DC\u05D4\u05DB\u05D9\u05DC \u05DC\u05E4\u05D7\u05D5\u05EA 8 \u05EA\u05D5\u05D5\u05D9\u05DD", 400);
    }
    const reset = await env.DB.prepare(
      "SELECT id, user_id, expires_at, used FROM password_resets WHERE token = ?"
    ).bind(token).first();
    if (!reset || reset.used) {
      return errorResponse("\u05E7\u05D9\u05E9\u05D5\u05E8 \u05D0\u05D9\u05E4\u05D5\u05E1 \u05DC\u05D0 \u05EA\u05E7\u05D9\u05DF \u05D0\u05D5 \u05E9\u05E4\u05D2 \u05EA\u05D5\u05E7\u05E4\u05D5", 400);
    }
    if (new Date(reset.expires_at) < /* @__PURE__ */ new Date()) {
      return errorResponse("\u05E7\u05D9\u05E9\u05D5\u05E8 \u05D4\u05D0\u05D9\u05E4\u05D5\u05E1 \u05E4\u05D2 \u05EA\u05D5\u05E7\u05E3", 400);
    }
    const passwordHash = await hashPassword(newPassword);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(passwordHash, reset.user_id).run();
    await env.DB.prepare(
      "UPDATE password_resets SET used = 1 WHERE id = ?"
    ).bind(reset.id).run();
    return jsonResponse({ message: "\u05D4\u05E1\u05D9\u05E1\u05DE\u05D4 \u05E2\u05D5\u05D3\u05DB\u05E0\u05D4 \u05D1\u05D4\u05E6\u05DC\u05D7\u05D4" });
  } catch (e) {
    console.error("Reset execute error:", e);
    return errorResponse("\u05E9\u05D2\u05D9\u05D0\u05D4 \u05D1\u05D0\u05D9\u05E4\u05D5\u05E1 \u05E1\u05D9\u05E1\u05DE\u05D4", 500);
  }
}
async function handleChangePassword(request, env) {
  try {
    const authHeader = request.headers.get("Authorization");
    const payload = await verifyJWT(authHeader?.slice(7), env.JWT_SECRET);
    if (!payload) return errorResponse("Unauthorized", 401);
    const { currentPassword, newPassword } = await request.json();
    if (!currentPassword || !newPassword) {
      return errorResponse("\u05E0\u05D3\u05E8\u05E9\u05D5\u05EA \u05E1\u05D9\u05E1\u05DE\u05D4 \u05E0\u05D5\u05DB\u05D7\u05D9\u05EA \u05D5\u05D7\u05D3\u05E9\u05D4", 400);
    }
    if (newPassword.length < 8) {
      return errorResponse("\u05D4\u05E1\u05D9\u05E1\u05DE\u05D4 \u05D7\u05D9\u05D9\u05D1\u05EA \u05DC\u05D4\u05DB\u05D9\u05DC \u05DC\u05E4\u05D7\u05D5\u05EA 8 \u05EA\u05D5\u05D5\u05D9\u05DD", 400);
    }
    const user = await env.DB.prepare(
      "SELECT password_hash FROM users WHERE id = ?"
    ).bind(payload.userId).first();
    if (!user) return errorResponse("\u05DE\u05E9\u05EA\u05DE\u05E9 \u05DC\u05D0 \u05E0\u05DE\u05E6\u05D0", 404);
    const valid = await verifyPassword(currentPassword, user.password_hash);
    if (!valid) return errorResponse("\u05E1\u05D9\u05E1\u05DE\u05D4 \u05E0\u05D5\u05DB\u05D7\u05D9\u05EA \u05E9\u05D2\u05D5\u05D9\u05D4", 401);
    const hash = await hashPassword(newPassword);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(hash, payload.userId).run();
    return jsonResponse({ message: "\u05D4\u05E1\u05D9\u05E1\u05DE\u05D4 \u05E2\u05D5\u05D3\u05DB\u05E0\u05D4 \u05D1\u05D4\u05E6\u05DC\u05D7\u05D4" });
  } catch (e) {
    console.error("Change password error:", e);
    return errorResponse("\u05E9\u05D2\u05D9\u05D0\u05D4 \u05D1\u05E9\u05D9\u05E0\u05D5\u05D9 \u05E1\u05D9\u05E1\u05DE\u05D4", 500);
  }
}

// consent.js
async function handleConsentSubmission(request, env) {
  try {
    let data;
    const contentType = request.headers.get("Content-Type") || "";
    if (contentType.includes("application/json")) {
      data = await request.json();
    } else {
      const formData = await request.text();
      const params = new URLSearchParams(formData);
      data = Object.fromEntries(params.entries());
    }
    const {
      email,
      fullName,
      date,
      healthDeclaration,
      agreementConfirmation,
      timestamp,
      userAgent
    } = data;
    const turnstileToken = data["cf-turnstile-response"] || "";
    if (!email || !fullName || !date) {
      return errorResponse("Missing required fields");
    }
    if (healthDeclaration !== "true" && healthDeclaration !== true) {
      return errorResponse("Health declaration required");
    }
    if (agreementConfirmation !== "true" && agreementConfirmation !== true) {
      return errorResponse("Agreement confirmation required");
    }
    if (turnstileToken) {
      const verified = await verifyTurnstile(turnstileToken, env);
      if (!verified) {
        return errorResponse("CAPTCHA verification failed", 403);
      }
    }
    const existing = await env.DB.prepare(
      "SELECT id FROM clients WHERE email = ?"
    ).bind(email).first();
    if (existing) {
      await env.DB.prepare(
        "UPDATE clients SET consent_signed = 1, consent_date = ?, updated_at = datetime('now') WHERE id = ?"
      ).bind(timestamp || (/* @__PURE__ */ new Date()).toISOString(), existing.id).run();
    } else {
      await env.DB.prepare(
        `INSERT INTO clients
         (full_name, email, consent_signed, consent_date, consent_ip, created_at, updated_at)
         VALUES (?, ?, 1, ?, ?, datetime('now'), datetime('now'))`
      ).bind(
        fullName,
        email,
        timestamp || (/* @__PURE__ */ new Date()).toISOString(),
        request.headers.get("CF-Connecting-IP") || ""
      ).run();
    }
    return jsonResponse({ status: "success", message: "Form submitted successfully" });
  } catch (e) {
    console.error("Consent error:", e);
    return errorResponse("Internal server error", 500);
  }
}

// contacts.js
async function handleContactSubmission(request, env) {
  try {
    let data;
    const contentType = request.headers.get("Content-Type") || "";
    if (contentType.includes("application/json")) {
      data = await request.json();
    } else {
      const formData = await request.formData();
      data = Object.fromEntries(formData);
    }
    const { fullName, phone, email, message, turnstileToken } = data;
    if (!fullName || !fullName.trim()) {
      return errorResponse("\u05E9\u05DD \u05DE\u05DC\u05D0 \u05D4\u05D5\u05D0 \u05E9\u05D3\u05D4 \u05D7\u05D5\u05D1\u05D4", 400);
    }
    if (!phone && !email) {
      return errorResponse("\u05D9\u05E9 \u05DC\u05DE\u05DC\u05D0 \u05D8\u05DC\u05E4\u05D5\u05DF \u05D0\u05D5 \u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05DC\u05D9\u05E6\u05D9\u05E8\u05EA \u05E7\u05E9\u05E8", 400);
    }
    if (turnstileToken && env.TURNSTILE_SECRET_KEY) {
      const valid = await verifyTurnstile(turnstileToken, env);
      if (!valid) return errorResponse("\u05D0\u05D9\u05DE\u05D5\u05EA CAPTCHA \u05E0\u05DB\u05E9\u05DC", 403);
    }
    await env.DB.prepare(
      `INSERT INTO contacts (full_name, phone, email, message, source, status, created_at)
       VALUES (?, ?, ?, ?, 'website', 'new', datetime('now'))`
    ).bind(
      fullName.trim(),
      phone ? phone.trim() : null,
      email ? email.trim() : null,
      message ? message.trim() : null
    ).run();
    return jsonResponse({ success: true, message: "\u05D4\u05E4\u05E0\u05D9\u05D9\u05D4 \u05E0\u05E7\u05DC\u05D8\u05D4 \u05D1\u05D4\u05E6\u05DC\u05D7\u05D4" });
  } catch (e) {
    console.error("Contact submission error:", e);
    return errorResponse("\u05E9\u05D2\u05D9\u05D0\u05D4 \u05D1\u05E9\u05DC\u05D9\u05D7\u05EA \u05D4\u05D8\u05D5\u05E4\u05E1", 500);
  }
}
async function handleGetContacts(url, env) {
  try {
    const status = url.searchParams.get("status");
    let query = "SELECT * FROM contacts";
    const params = [];
    if (status) {
      query += " WHERE status = ?";
      params.push(status);
    }
    query += " ORDER BY created_at DESC";
    const stmt = params.length > 0 ? env.DB.prepare(query).bind(...params) : env.DB.prepare(query);
    const contacts = await stmt.all();
    return jsonResponse(contacts.results);
  } catch (e) {
    console.error("Get contacts error:", e);
    return errorResponse("Failed to fetch contacts", 500);
  }
}
async function handleUpdateContact(id, request, env) {
  try {
    const data = await request.json();
    const fields = [];
    const values = [];
    if (data.status !== void 0) {
      fields.push("status = ?");
      values.push(data.status);
    }
    if (data.notes !== void 0) {
      fields.push("notes = ?");
      values.push(data.notes);
    }
    if (fields.length === 0) return errorResponse("No fields to update", 400);
    values.push(id);
    await env.DB.prepare(
      `UPDATE contacts SET ${fields.join(", ")} WHERE id = ?`
    ).bind(...values).run();
    return jsonResponse({ message: "Contact updated" });
  } catch (e) {
    console.error("Update contact error:", e);
    return errorResponse("Failed to update contact", 500);
  }
}
async function handleDeleteContact(id, env) {
  try {
    await env.DB.prepare("DELETE FROM contacts WHERE id = ?").bind(id).run();
    return jsonResponse({ message: "Contact deleted" });
  } catch (e) {
    console.error("Delete contact error:", e);
    return errorResponse("Failed to delete contact", 500);
  }
}

// clients.js
async function handleGetClients(url, env) {
  try {
    const search = url.searchParams.get("search") || "";
    const status = url.searchParams.get("status") || "";
    const limit = parseInt(url.searchParams.get("limit") || "100");
    const offset = parseInt(url.searchParams.get("offset") || "0");
    let query = `SELECT c.*,
      (SELECT COUNT(*) FROM sessions WHERE client_id = c.id) as session_count,
      (SELECT MAX(session_date) FROM sessions WHERE client_id = c.id) as last_session
      FROM clients c WHERE 1=1`;
    const bindings = [];
    if (search) {
      query += " AND (c.full_name LIKE ? OR c.email LIKE ? OR c.phone LIKE ?)";
      bindings.push(`%${search}%`, `%${search}%`, `%${search}%`);
    }
    if (status) {
      query += " AND c.status = ?";
      bindings.push(status);
    }
    query += " ORDER BY c.created_at DESC LIMIT ? OFFSET ?";
    bindings.push(limit, offset);
    const stmt = env.DB.prepare(query);
    const result = await (bindings.length ? stmt.bind(...bindings) : stmt).all();
    return jsonResponse(result.results);
  } catch (e) {
    console.error("Get clients error:", e);
    return errorResponse("Failed to load clients", 500);
  }
}
async function handleGetClient(id, env) {
  try {
    const client = await env.DB.prepare(
      "SELECT * FROM clients WHERE id = ?"
    ).bind(id).first();
    if (!client) return errorResponse("Client not found", 404);
    const sessions = await env.DB.prepare(
      "SELECT * FROM sessions WHERE client_id = ? ORDER BY session_date DESC"
    ).bind(id).all();
    return jsonResponse({ ...client, sessions: sessions.results });
  } catch (e) {
    console.error("Get client error:", e);
    return errorResponse("Failed to load client", 500);
  }
}
async function handleCreateClient(request, env) {
  try {
    const data = await request.json();
    const { full_name, email, phone, address, birth_date, treatment_type, notes } = data;
    if (!full_name) return errorResponse("Full name is required");
    const result = await env.DB.prepare(
      `INSERT INTO clients (full_name, email, phone, address, birth_date, treatment_type, notes)
       VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      full_name,
      email || null,
      phone || null,
      address || null,
      birth_date || null,
      treatment_type || null,
      notes || null
    ).run();
    return jsonResponse({ id: result.meta.last_row_id, message: "Client created" }, 201);
  } catch (e) {
    console.error("Create client error:", e);
    return errorResponse("Failed to create client", 500);
  }
}
async function handleUpdateClient(id, request, env) {
  try {
    const data = await request.json();
    const fields = [];
    const values = [];
    const allowed = [
      "full_name",
      "email",
      "phone",
      "address",
      "birth_date",
      "status",
      "treatment_type",
      "consent_signed",
      "consent_date",
      "notes"
    ];
    for (const field of allowed) {
      if (data[field] !== void 0) {
        fields.push(`${field} = ?`);
        values.push(data[field]);
      }
    }
    if (fields.length === 0) return errorResponse("No fields to update");
    fields.push("updated_at = datetime('now')");
    values.push(id);
    await env.DB.prepare(
      `UPDATE clients SET ${fields.join(", ")} WHERE id = ?`
    ).bind(...values).run();
    return jsonResponse({ message: "Client updated" });
  } catch (e) {
    console.error("Update client error:", e);
    return errorResponse("Failed to update client", 500);
  }
}
async function handleDeleteClient(id, env) {
  try {
    await env.DB.prepare("DELETE FROM sessions WHERE client_id = ?").bind(id).run();
    await env.DB.prepare("DELETE FROM clients WHERE id = ?").bind(id).run();
    return jsonResponse({ message: "Client deleted" });
  } catch (e) {
    console.error("Delete client error:", e);
    return errorResponse("Failed to delete client", 500);
  }
}
async function handleExportClients(env) {
  try {
    const clients = await env.DB.prepare(
      `SELECT c.*,
       (SELECT COUNT(*) FROM sessions WHERE client_id = c.id) as session_count,
       (SELECT COALESCE(SUM(amount), 0) FROM sessions WHERE client_id = c.id AND paid = 1) as total_paid,
       (SELECT COALESCE(SUM(amount), 0) FROM sessions WHERE client_id = c.id AND paid = 0) as total_unpaid
       FROM clients c ORDER BY c.full_name`
    ).all();
    let csv = "\u05E9\u05DD \u05DE\u05DC\u05D0,\u05D0\u05D9\u05DE\u05D9\u05D9\u05DC,\u05D8\u05DC\u05E4\u05D5\u05DF,\u05E1\u05D8\u05D8\u05D5\u05E1,\u05E1\u05D5\u05D2 \u05D8\u05D9\u05E4\u05D5\u05DC,\u05D4\u05E1\u05DB\u05DE\u05D4 \u05D7\u05EA\u05D5\u05DE\u05D4,\u05EA\u05D0\u05E8\u05D9\u05DA \u05D4\u05E6\u05D8\u05E8\u05E4\u05D5\u05EA,\u05DE\u05E1\u05E4\u05E8 \u05D8\u05D9\u05E4\u05D5\u05DC\u05D9\u05DD,\u05E9\u05D5\u05DC\u05DD,\u05DC\u05D0 \u05E9\u05D5\u05DC\u05DD\n";
    for (const c of clients.results) {
      csv += `"${c.full_name || ""}","${c.email || ""}","${c.phone || ""}",`;
      csv += `"${c.status || ""}","${c.treatment_type || ""}",`;
      csv += `"${c.consent_signed ? "\u05DB\u05DF" : "\u05DC\u05D0"}","${c.join_date || ""}",`;
      csv += `${c.session_count},${c.total_paid},${c.total_unpaid}
`;
    }
    return csvResponse(csv, "clients-export.csv");
  } catch (e) {
    console.error("Export error:", e);
    return errorResponse("Failed to export", 500);
  }
}

// sessions.js
async function handleGetSessions(url, env) {
  try {
    const clientId = url.searchParams.get("client_id");
    const from = url.searchParams.get("from");
    const to = url.searchParams.get("to");
    const limit = parseInt(url.searchParams.get("limit") || "50");
    let query = `SELECT s.*, c.full_name as client_name
                 FROM sessions s JOIN clients c ON s.client_id = c.id WHERE 1=1`;
    const bindings = [];
    if (clientId) {
      query += " AND s.client_id = ?";
      bindings.push(clientId);
    }
    if (from) {
      query += " AND s.session_date >= ?";
      bindings.push(from);
    }
    if (to) {
      query += " AND s.session_date <= ?";
      bindings.push(to);
    }
    query += " ORDER BY s.session_date DESC LIMIT ?";
    bindings.push(limit);
    const result = await env.DB.prepare(query).bind(...bindings).all();
    return jsonResponse(result.results);
  } catch (e) {
    console.error("Get sessions error:", e);
    return errorResponse("Failed to load sessions", 500);
  }
}
async function handleGetClientSessions(clientId, env) {
  try {
    const result = await env.DB.prepare(
      "SELECT * FROM sessions WHERE client_id = ? ORDER BY session_date DESC"
    ).bind(clientId).all();
    return jsonResponse(result.results);
  } catch (e) {
    console.error("Get client sessions error:", e);
    return errorResponse("Failed to load sessions", 500);
  }
}
async function handleCreateSession(request, env) {
  try {
    const data = await request.json();
    const {
      client_id,
      session_date,
      session_type,
      duration_minutes,
      summary,
      next_session_notes,
      paid,
      amount,
      payment_method,
      invoice_number
    } = data;
    if (!client_id || !session_date) {
      return errorResponse("Client ID and session date are required");
    }
    const client = await env.DB.prepare(
      "SELECT id FROM clients WHERE id = ?"
    ).bind(client_id).first();
    if (!client) return errorResponse("Client not found", 404);
    const result = await env.DB.prepare(
      `INSERT INTO sessions
       (client_id, session_date, session_type, duration_minutes, summary,
        next_session_notes, paid, amount, payment_method, invoice_number)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).bind(
      client_id,
      session_date,
      session_type || null,
      duration_minutes || 50,
      summary || null,
      next_session_notes || null,
      paid ? 1 : 0,
      amount || 0,
      payment_method || null,
      invoice_number || null
    ).run();
    return jsonResponse({ id: result.meta.last_row_id, message: "Session created" }, 201);
  } catch (e) {
    console.error("Create session error:", e);
    return errorResponse("Failed to create session", 500);
  }
}
async function handleUpdateSession(id, request, env) {
  try {
    const data = await request.json();
    const fields = [];
    const values = [];
    const allowed = [
      "session_date",
      "session_type",
      "duration_minutes",
      "summary",
      "next_session_notes",
      "paid",
      "amount",
      "payment_method",
      "invoice_number"
    ];
    for (const field of allowed) {
      if (data[field] !== void 0) {
        fields.push(`${field} = ?`);
        values.push(field === "paid" ? data[field] ? 1 : 0 : data[field]);
      }
    }
    if (fields.length === 0) return errorResponse("No fields to update");
    fields.push("updated_at = datetime('now')");
    values.push(id);
    await env.DB.prepare(
      `UPDATE sessions SET ${fields.join(", ")} WHERE id = ?`
    ).bind(...values).run();
    return jsonResponse({ message: "Session updated" });
  } catch (e) {
    console.error("Update session error:", e);
    return errorResponse("Failed to update session", 500);
  }
}
async function handleDeleteSession(id, env) {
  try {
    await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(id).run();
    return jsonResponse({ message: "Session deleted" });
  } catch (e) {
    console.error("Delete session error:", e);
    return errorResponse("Failed to delete session", 500);
  }
}

// dashboard.js
async function handleStats(env) {
  try {
    const totalClients = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM clients"
    ).first();
    const activeClients = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM clients WHERE status = 'active'"
    ).first();
    const consentSigned = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM clients WHERE consent_signed = 1"
    ).first();
    const totalSessions = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM sessions"
    ).first();
    const thisMonth = (/* @__PURE__ */ new Date()).toISOString().slice(0, 7);
    const monthSessions = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM sessions WHERE session_date LIKE ?"
    ).bind(thisMonth + "%").first();
    const monthRevenue = await env.DB.prepare(
      "SELECT COALESCE(SUM(amount), 0) as total FROM sessions WHERE session_date LIKE ? AND paid = 1"
    ).bind(thisMonth + "%").first();
    const unpaid = await env.DB.prepare(
      "SELECT COALESCE(SUM(amount), 0) as total FROM sessions WHERE paid = 0 AND amount > 0"
    ).first();
    const recentClients = await env.DB.prepare(
      "SELECT id, full_name, email, join_date, consent_signed FROM clients ORDER BY created_at DESC LIMIT 5"
    ).all();
    const newContacts = await env.DB.prepare(
      "SELECT COUNT(*) as count FROM contacts WHERE status = 'new'"
    ).first();
    const recentContacts = await env.DB.prepare(
      "SELECT id, full_name, phone, email, message, status, created_at FROM contacts ORDER BY created_at DESC LIMIT 5"
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
      recentContacts: recentContacts.results
    });
  } catch (e) {
    console.error("Stats error:", e);
    return errorResponse("Failed to load stats", 500);
  }
}

// users.js
async function getAuthUser(request, env) {
  const authHeader = request.headers.get("Authorization");
  if (!authHeader || !authHeader.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  return await verifyJWT(token, env.JWT_SECRET);
}
function requireAdmin(payload) {
  if (!payload || payload.role !== "admin") {
    return errorResponse("\u05D0\u05D9\u05DF \u05D4\u05E8\u05E9\u05D0\u05D4 \u2014 \u05E0\u05D3\u05E8\u05E9 \u05EA\u05E4\u05E7\u05D9\u05D3 \u05DE\u05E0\u05D4\u05DC", 403);
  }
  return null;
}
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
function validatePassword(password) {
  if (password.length < 8) return "\u05D4\u05E1\u05D9\u05E1\u05DE\u05D4 \u05D7\u05D9\u05D9\u05D1\u05EA \u05DC\u05D4\u05DB\u05D9\u05DC \u05DC\u05E4\u05D7\u05D5\u05EA 8 \u05EA\u05D5\u05D5\u05D9\u05DD";
  if (!/[A-Z]/.test(password)) return "\u05D4\u05E1\u05D9\u05E1\u05DE\u05D4 \u05D7\u05D9\u05D9\u05D1\u05EA \u05DC\u05D4\u05DB\u05D9\u05DC \u05D0\u05D5\u05EA \u05D2\u05D3\u05D5\u05DC\u05D4";
  if (!/[a-z]/.test(password)) return "\u05D4\u05E1\u05D9\u05E1\u05DE\u05D4 \u05D7\u05D9\u05D9\u05D1\u05EA \u05DC\u05D4\u05DB\u05D9\u05DC \u05D0\u05D5\u05EA \u05E7\u05D8\u05E0\u05D4";
  if (!/[0-9]/.test(password)) return "\u05D4\u05E1\u05D9\u05E1\u05DE\u05D4 \u05D7\u05D9\u05D9\u05D1\u05EA \u05DC\u05D4\u05DB\u05D9\u05DC \u05DE\u05E1\u05E4\u05E8";
  return null;
}
var VALID_ROLES = ["admin", "therapist", "viewer"];
async function handleGetUsers(request, env) {
  const payload = await getAuthUser(request, env);
  const denied = requireAdmin(payload);
  if (denied) return denied;
  try {
    const { results } = await env.DB.prepare(
      "SELECT id, name, email, role, active, created_at, updated_at FROM users ORDER BY id"
    ).all();
    return jsonResponse(results || []);
  } catch (e) {
    console.error("Get users error:", e);
    return errorResponse("\u05E9\u05D2\u05D9\u05D0\u05D4 \u05D1\u05D8\u05E2\u05D9\u05E0\u05EA \u05DE\u05E9\u05EA\u05DE\u05E9\u05D9\u05DD", 500);
  }
}
async function handleCreateUser(request, env) {
  const payload = await getAuthUser(request, env);
  const denied = requireAdmin(payload);
  if (denied) return denied;
  try {
    const { name, email, password, role } = await request.json();
    if (!name || name.trim().length < 2) {
      return errorResponse("\u05E9\u05DD \u05D7\u05D9\u05D9\u05D1 \u05DC\u05D4\u05DB\u05D9\u05DC \u05DC\u05E4\u05D7\u05D5\u05EA 2 \u05EA\u05D5\u05D5\u05D9\u05DD", 400);
    }
    if (!email || !validateEmail(email)) {
      return errorResponse("\u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05DC\u05D0 \u05EA\u05E7\u05D9\u05DF", 400);
    }
    if (!password) {
      return errorResponse("\u05E0\u05D3\u05E8\u05E9\u05EA \u05E1\u05D9\u05E1\u05DE\u05D4", 400);
    }
    const passErr = validatePassword(password);
    if (passErr) return errorResponse(passErr, 400);
    if (!role || !VALID_ROLES.includes(role)) {
      return errorResponse("\u05EA\u05E4\u05E7\u05D9\u05D3 \u05DC\u05D0 \u05EA\u05E7\u05D9\u05DF \u2014 admin/therapist/viewer", 400);
    }
    const existing = await env.DB.prepare(
      "SELECT id FROM users WHERE email = ?"
    ).bind(email.toLowerCase().trim()).first();
    if (existing) {
      return errorResponse("\u05DB\u05D1\u05E8 \u05E7\u05D9\u05D9\u05DD \u05DE\u05E9\u05EA\u05DE\u05E9 \u05E2\u05DD \u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05D6\u05D4", 409);
    }
    const passwordHash = await hashPassword(password);
    const result = await env.DB.prepare(
      `INSERT INTO users (name, email, role, password_hash, active, created_at, updated_at)
       VALUES (?, ?, ?, ?, 1, datetime('now'), datetime('now'))`
    ).bind(name.trim(), email.toLowerCase().trim(), role, passwordHash).run();
    return jsonResponse({
      id: result.meta.last_row_id,
      name: name.trim(),
      email: email.toLowerCase().trim(),
      role,
      active: 1
    }, 201);
  } catch (e) {
    console.error("Create user error:", e);
    return errorResponse("\u05E9\u05D2\u05D9\u05D0\u05D4 \u05D1\u05D9\u05E6\u05D9\u05E8\u05EA \u05DE\u05E9\u05EA\u05DE\u05E9", 500);
  }
}
async function handleUpdateUser(request, env, userId) {
  const payload = await getAuthUser(request, env);
  const denied = requireAdmin(payload);
  if (denied) return denied;
  try {
    const { name, email, role, active } = await request.json();
    const user = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?").bind(userId).first();
    if (!user) return errorResponse("\u05DE\u05E9\u05EA\u05DE\u05E9 \u05DC\u05D0 \u05E0\u05DE\u05E6\u05D0", 404);
    if (name !== void 0 && name.trim().length < 2) {
      return errorResponse("\u05E9\u05DD \u05D7\u05D9\u05D9\u05D1 \u05DC\u05D4\u05DB\u05D9\u05DC \u05DC\u05E4\u05D7\u05D5\u05EA 2 \u05EA\u05D5\u05D5\u05D9\u05DD", 400);
    }
    if (email !== void 0 && !validateEmail(email)) {
      return errorResponse("\u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05DC\u05D0 \u05EA\u05E7\u05D9\u05DF", 400);
    }
    if (role !== void 0 && !VALID_ROLES.includes(role)) {
      return errorResponse("\u05EA\u05E4\u05E7\u05D9\u05D3 \u05DC\u05D0 \u05EA\u05E7\u05D9\u05DF \u2014 admin/therapist/viewer", 400);
    }
    if (email !== void 0) {
      const existing = await env.DB.prepare(
        "SELECT id FROM users WHERE email = ? AND id != ?"
      ).bind(email.toLowerCase().trim(), userId).first();
      if (existing) {
        return errorResponse("\u05DB\u05D1\u05E8 \u05E7\u05D9\u05D9\u05DD \u05DE\u05E9\u05EA\u05DE\u05E9 \u05E2\u05DD \u05D0\u05D9\u05DE\u05D9\u05D9\u05DC \u05D6\u05D4", 409);
      }
    }
    if (role !== void 0 && role !== "admin" || active !== void 0 && !active) {
      if (user.role === "admin") {
        const adminCount = await env.DB.prepare(
          "SELECT COUNT(*) as cnt FROM users WHERE role = 'admin' AND active = 1 AND id != ?"
        ).bind(userId).first();
        if (adminCount.cnt === 0) {
          return errorResponse("\u05DC\u05D0 \u05E0\u05D9\u05EA\u05DF \u05DC\u05D4\u05E1\u05D9\u05E8 \u05D0\u05EA \u05D4\u05DE\u05E0\u05D4\u05DC \u05D4\u05D0\u05D7\u05E8\u05D5\u05DF", 403);
        }
      }
    }
    const fields = [];
    const values = [];
    if (name !== void 0) {
      fields.push("name = ?");
      values.push(name.trim());
    }
    if (email !== void 0) {
      fields.push("email = ?");
      values.push(email.toLowerCase().trim());
    }
    if (role !== void 0) {
      fields.push("role = ?");
      values.push(role);
    }
    if (active !== void 0) {
      fields.push("active = ?");
      values.push(active ? 1 : 0);
    }
    fields.push("updated_at = datetime('now')");
    if (fields.length === 1) {
      return errorResponse("\u05D0\u05D9\u05DF \u05E9\u05D3\u05D5\u05EA \u05DC\u05E2\u05D3\u05DB\u05D5\u05DF", 400);
    }
    values.push(userId);
    await env.DB.prepare(
      `UPDATE users SET ${fields.join(", ")} WHERE id = ?`
    ).bind(...values).run();
    const updated = await env.DB.prepare(
      "SELECT id, name, email, role, active, created_at, updated_at FROM users WHERE id = ?"
    ).bind(userId).first();
    return jsonResponse(updated);
  } catch (e) {
    console.error("Update user error:", e);
    return errorResponse("\u05E9\u05D2\u05D9\u05D0\u05D4 \u05D1\u05E2\u05D3\u05DB\u05D5\u05DF \u05DE\u05E9\u05EA\u05DE\u05E9", 500);
  }
}
async function handleDeleteUser(request, env, userId) {
  const payload = await getAuthUser(request, env);
  const denied = requireAdmin(payload);
  if (denied) return denied;
  try {
    if (parseInt(userId) === payload.userId) {
      return errorResponse("\u05DC\u05D0 \u05E0\u05D9\u05EA\u05DF \u05DC\u05DE\u05D7\u05D5\u05E7 \u05D0\u05EA \u05E2\u05E6\u05DE\u05DA", 403);
    }
    const user = await env.DB.prepare("SELECT id, role FROM users WHERE id = ?").bind(userId).first();
    if (!user) return errorResponse("\u05DE\u05E9\u05EA\u05DE\u05E9 \u05DC\u05D0 \u05E0\u05DE\u05E6\u05D0", 404);
    if (user.role === "admin") {
      const adminCount = await env.DB.prepare(
        "SELECT COUNT(*) as cnt FROM users WHERE role = 'admin' AND id != ?"
      ).bind(userId).first();
      if (adminCount.cnt === 0) {
        return errorResponse("\u05DC\u05D0 \u05E0\u05D9\u05EA\u05DF \u05DC\u05DE\u05D7\u05D5\u05E7 \u05D0\u05EA \u05D4\u05DE\u05E0\u05D4\u05DC \u05D4\u05D0\u05D7\u05E8\u05D5\u05DF", 403);
      }
    }
    await env.DB.prepare("DELETE FROM users WHERE id = ?").bind(userId).run();
    return jsonResponse({ message: "\u05D4\u05DE\u05E9\u05EA\u05DE\u05E9 \u05E0\u05DE\u05D7\u05E7 \u05D1\u05D4\u05E6\u05DC\u05D7\u05D4" });
  } catch (e) {
    console.error("Delete user error:", e);
    return errorResponse("\u05E9\u05D2\u05D9\u05D0\u05D4 \u05D1\u05DE\u05D7\u05D9\u05E7\u05EA \u05DE\u05E9\u05EA\u05DE\u05E9", 500);
  }
}
async function handleAdminResetPassword(request, env, userId) {
  const payload = await getAuthUser(request, env);
  const denied = requireAdmin(payload);
  if (denied) return denied;
  try {
    const { newPassword } = await request.json();
    if (!newPassword) return errorResponse("\u05E0\u05D3\u05E8\u05E9\u05EA \u05E1\u05D9\u05E1\u05DE\u05D4 \u05D7\u05D3\u05E9\u05D4", 400);
    const passErr = validatePassword(newPassword);
    if (passErr) return errorResponse(passErr, 400);
    const user = await env.DB.prepare("SELECT id FROM users WHERE id = ?").bind(userId).first();
    if (!user) return errorResponse("\u05DE\u05E9\u05EA\u05DE\u05E9 \u05DC\u05D0 \u05E0\u05DE\u05E6\u05D0", 404);
    const passwordHash = await hashPassword(newPassword);
    await env.DB.prepare(
      "UPDATE users SET password_hash = ?, updated_at = datetime('now') WHERE id = ?"
    ).bind(passwordHash, userId).run();
    return jsonResponse({ message: "\u05D4\u05E1\u05D9\u05E1\u05DE\u05D4 \u05E2\u05D5\u05D3\u05DB\u05E0\u05D4 \u05D1\u05D4\u05E6\u05DC\u05D7\u05D4" });
  } catch (e) {
    console.error("Admin reset password error:", e);
    return errorResponse("\u05E9\u05D2\u05D9\u05D0\u05D4 \u05D1\u05D0\u05D9\u05E4\u05D5\u05E1 \u05E1\u05D9\u05E1\u05DE\u05D4", 500);
  }
}

// index.js
async function runMigrations(env) {
  try {
    const cols = await env.DB.prepare("PRAGMA table_info(users)").all();
    const hasActive = cols.results.some((c) => c.name === "active");
    if (!hasActive) {
      await env.DB.prepare("ALTER TABLE users ADD COLUMN active BOOLEAN DEFAULT 1").run();
      await env.DB.prepare("UPDATE users SET active = 1 WHERE active IS NULL").run();
    }
  } catch (e) {
    console.error("Migration error:", e);
  }
}
var index_default = {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: { ...CORS_HEADERS, ...SECURITY_HEADERS }
      });
    }
    if (!env._migrated) {
      await runMigrations(env);
      env._migrated = true;
    }
    if (path === "/api/consent" && method === "POST") {
      return handleConsentSubmission(request, env);
    }
    if (path === "/api/contact" && method === "POST") {
      return handleContactSubmission(request, env);
    }
    if (path === "/api/login" && method === "POST") {
      return handleLogin(request, env);
    }
    if (path === "/api/reset-request" && method === "POST") {
      return handleRequestReset(request, env);
    }
    if (path === "/api/reset-execute" && method === "POST") {
      return handleExecuteReset(request, env);
    }
    if (path.startsWith("/api/")) {
      if (!await isAuthorized(request, env)) {
        return errorResponse("Unauthorized", 401);
      }
    }
    if (path === "/api/verify" && method === "GET") {
      return handleVerify(request, env);
    }
    if (path === "/api/change-password" && method === "POST") {
      return handleChangePassword(request, env);
    }
    if (path === "/api/stats" && method === "GET") {
      return handleStats(env);
    }
    if (path === "/api/clients" && method === "GET") {
      return handleGetClients(url, env);
    }
    if (path === "/api/clients" && method === "POST") {
      return handleCreateClient(request, env);
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === "GET") {
      return handleGetClient(path.split("/").pop(), env);
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === "PUT") {
      return handleUpdateClient(path.split("/").pop(), request, env);
    }
    if (path.match(/^\/api\/clients\/\d+$/) && method === "DELETE") {
      return handleDeleteClient(path.split("/").pop(), env);
    }
    if (path === "/api/sessions" && method === "GET") {
      return handleGetSessions(url, env);
    }
    if (path === "/api/sessions" && method === "POST") {
      return handleCreateSession(request, env);
    }
    if (path.match(/^\/api\/sessions\/\d+$/) && method === "PUT") {
      return handleUpdateSession(path.split("/").pop(), request, env);
    }
    if (path.match(/^\/api\/sessions\/\d+$/) && method === "DELETE") {
      return handleDeleteSession(path.split("/").pop(), env);
    }
    if (path.match(/^\/api\/clients\/\d+\/sessions$/) && method === "GET") {
      return handleGetClientSessions(path.split("/")[3], env);
    }
    if (path === "/api/contacts" && method === "GET") {
      return handleGetContacts(url, env);
    }
    if (path.match(/^\/api\/contacts\/\d+$/) && method === "PUT") {
      return handleUpdateContact(path.split("/").pop(), request, env);
    }
    if (path.match(/^\/api\/contacts\/\d+$/) && method === "DELETE") {
      return handleDeleteContact(path.split("/").pop(), env);
    }
    if (path === "/api/export/clients" && method === "GET") {
      return handleExportClients(env);
    }
    if (path === "/api/users" && method === "GET") {
      return handleGetUsers(request, env);
    }
    if (path === "/api/users" && method === "POST") {
      return handleCreateUser(request, env);
    }
    if (path.match(/^\/api\/users\/\d+$/) && method === "PUT") {
      return handleUpdateUser(request, env, path.split("/").pop());
    }
    if (path.match(/^\/api\/users\/\d+$/) && method === "DELETE") {
      return handleDeleteUser(request, env, path.split("/").pop());
    }
    if (path.match(/^\/api\/users\/\d+\/reset-password$/) && method === "POST") {
      const parts = path.split("/");
      return handleAdminResetPassword(request, env, parts[3]);
    }
    return errorResponse("Not found", 404);
  }
};
export {
  index_default as default
};
