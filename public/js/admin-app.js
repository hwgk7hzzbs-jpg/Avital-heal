/**
 * @file admin-app.js
 * @description Core app: auth, navigation, API helper, initialization.
 * @module AdminApp
 */

const API_BASE = 'https://avital-heal-crm.tgthf7frmp.workers.dev';
let authToken = null;
let currentUser = null;
let allClients = [];
let allContacts = [];

// ─── API helper ───

async function api(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${authToken}`,
      ...(options.headers || {}),
    },
  });
  if (res.status === 401) { logout(); return null; }
  return res.json();
}

// ─── Login (email + password) ───

async function login() {
  const email = document.getElementById('loginEmail').value.trim();
  const password = document.getElementById('loginPassword').value;
  const errEl = document.getElementById('loginError');
  errEl.style.display = 'none';

  if (!email || !password) {
    errEl.textContent = 'נא למלא אימייל וסיסמה';
    errEl.style.display = 'block';
    return;
  }

  try {
    const res = await fetch(`${API_BASE}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });
    const data = await res.json();
    if (data.token) {
      authToken = data.token;
      currentUser = data.user;
      sessionStorage.setItem('crm_token', authToken);
      showApp();
    } else {
      errEl.textContent = data.error || 'אימייל או סיסמה שגויים';
      errEl.style.display = 'block';
    }
  } catch (e) {
    errEl.textContent = 'שגיאת חיבור לשרת';
    errEl.style.display = 'block';
  }
}

function logout() {
  authToken = null;
  currentUser = null;
  sessionStorage.removeItem('crm_token');
  document.getElementById('loginScreen').classList.remove('hidden');
  document.getElementById('resetScreen').classList.add('hidden');
  document.getElementById('app').classList.remove('active');
  document.getElementById('loginEmail').value = '';
  document.getElementById('loginPassword').value = '';
}

async function showApp() {
  document.getElementById('loginScreen').classList.add('hidden');
  document.getElementById('resetScreen').classList.add('hidden');
  document.getElementById('app').classList.add('active');
  if (currentUser) {
    const ui = document.getElementById('userInfo');
    if (ui) ui.textContent = currentUser.name || currentUser.email;
  }
  loadDashboard();
  loadContacts();
  loadClients();
  loadSessions();
}

// ─── Password reset request ───

function showResetForm() {
  document.getElementById('loginScreen').classList.add('hidden');
  document.getElementById('resetScreen').classList.remove('hidden');
}

function showLoginForm() {
  document.getElementById('resetScreen').classList.add('hidden');
  document.getElementById('loginScreen').classList.remove('hidden');
}

async function requestReset() {
  const email = document.getElementById('resetEmail').value.trim();
  const msgEl = document.getElementById('resetMsg');
  if (!email) {
    msgEl.textContent = 'נא למלא אימייל';
    msgEl.className = 'reset-msg error';
    return;
  }
  try {
    const res = await fetch(`${API_BASE}/api/reset-request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    msgEl.textContent = data.message || 'הבקשה נשלחה';
    msgEl.className = 'reset-msg success';
  } catch (e) {
    msgEl.textContent = 'שגיאה בשליחת הבקשה';
    msgEl.className = 'reset-msg error';
  }
}

// ─── Password reset execution (from URL token) ───

async function executeReset() {
  const params = new URLSearchParams(window.location.search);
  const token = params.get('reset');
  const newPass = document.getElementById('newPassword').value;
  const confirmPass = document.getElementById('confirmPassword').value;
  const msgEl = document.getElementById('resetExecMsg');

  if (!newPass || newPass.length < 8) {
    msgEl.textContent = 'הסיסמה חייבת להכיל לפחות 8 תווים';
    msgEl.className = 'reset-msg error';
    return;
  }
  if (newPass !== confirmPass) {
    msgEl.textContent = 'הסיסמאות אינן תואמות';
    msgEl.className = 'reset-msg error';
    return;
  }
  try {
    const res = await fetch(`${API_BASE}/api/reset-execute`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token, newPassword: newPass }),
    });
    const data = await res.json();
    if (res.ok) {
      msgEl.textContent = 'הסיסמה עודכנה! מעביר לכניסה...';
      msgEl.className = 'reset-msg success';
      setTimeout(() => {
        window.location.href = '/admin';
      }, 2000);
    } else {
      msgEl.textContent = data.error || 'שגיאה באיפוס';
      msgEl.className = 'reset-msg error';
    }
  } catch (e) {
    msgEl.textContent = 'שגיאה באיפוס סיסמה';
    msgEl.className = 'reset-msg error';
  }
}

// ─── Change password (in-app) ───

async function changePassword() {
  const cur = document.getElementById('cp_current').value;
  const nw = document.getElementById('cp_new').value;
  const conf = document.getElementById('cp_confirm').value;
  if (!cur || !nw) { alert('נא למלא את כל השדות'); return; }
  if (nw.length < 8) { alert('הסיסמה חייבת להכיל לפחות 8 תווים'); return; }
  if (nw !== conf) { alert('הסיסמאות אינן תואמות'); return; }

  const data = await api('/api/change-password', {
    method: 'POST',
    body: JSON.stringify({ currentPassword: cur, newPassword: nw }),
  });
  if (data && data.message) {
    alert('הסיסמה שונתה בהצלחה!');
    closeModal('changePasswordModal');
  }
}

// ─── Navigation ───

function showPage(name) {
  document.querySelectorAll('.page').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById(`page-${name}`).classList.add('active');
  const pages = ['dashboard', 'contacts', 'clients', 'sessions'];
  document.querySelectorAll('.nav-tab')[pages.indexOf(name)].classList.add('active');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('active');
}

// ─── Init ───

document.addEventListener('DOMContentLoaded', async () => {
  const params = new URLSearchParams(window.location.search);

  // Check for password reset token in URL
  if (params.get('reset')) {
    document.getElementById('loginScreen').classList.add('hidden');
    document.getElementById('resetExecScreen').classList.remove('hidden');
    return;
  }

  // Check for existing session
  const token = sessionStorage.getItem('crm_token');
  if (token) {
    try {
      const res = await fetch(`${API_BASE}/api/verify`, {
        headers: { 'Authorization': `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        authToken = token;
        currentUser = data.user;
        showApp();
      }
    } catch (e) { /* stay on login */ }
  }

  // Enter key handlers
  document.getElementById('loginPassword')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') login();
  });
  document.getElementById('loginEmail')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.getElementById('loginPassword').focus();
  });
});
