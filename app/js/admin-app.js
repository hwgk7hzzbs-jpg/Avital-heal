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

// ─── Password toggle ───

function togglePasswordVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  const eyeOn = btn.querySelector('.eye-icon');
  const eyeOff = btn.querySelector('.eye-off-icon');
  if (input.type === 'password') {
    input.type = 'text';
    eyeOn.classList.add('hidden');
    eyeOff.classList.remove('hidden');
  } else {
    input.type = 'password';
    eyeOn.classList.remove('hidden');
    eyeOff.classList.add('hidden');
  }
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
  // Show/hide users tab based on role
  const usersTab = document.getElementById('usersTab');
  if (usersTab) {
    usersTab.style.display = (currentUser && currentUser.role === 'admin') ? '' : 'none';
  }
  switchTab('dashboard');
  loadDashboard();
  loadContacts();
  loadClients();
  loadSessions();
  // Load users for admins
  if (currentUser && currentUser.role === 'admin' && typeof loadUsers === 'function') {
    loadUsers();
  }
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
        window.location.href = '/';
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

function switchTab(name) {
  document.querySelectorAll('.page').forEach(p => {
    p.classList.add('hidden');
    p.classList.remove('active');
  });
  document.querySelectorAll('.tab-btn').forEach(t => t.classList.remove('active'));
  const page = document.getElementById(`page-${name}`);
  if (page) { page.classList.remove('hidden'); page.classList.add('active'); }

  // Handle tab button activation
  if (name === 'users') {
    const usersTab = document.getElementById('usersTab');
    if (usersTab) usersTab.classList.add('active');
  } else {
    const pages = ['dashboard', 'contacts', 'clients', 'sessions'];
    const idx = pages.indexOf(name);
    const tabs = document.querySelectorAll('.tab-btn');
    if (tabs[idx]) tabs[idx].classList.add('active');
  }
}

// Alias for backward compatibility
function showPage(name) { switchTab(name); }

// ─── Modal helpers ───
function openModal(id) {
  document.getElementById(id).classList.remove('hidden');
}
function closeModal(id) {
  document.getElementById(id).classList.add('hidden');
}
function showClientFormModal(clientData) {
  if (clientData) {
    document.getElementById('cf_id').value = clientData.id || '';
    document.getElementById('cf_fullName').value = clientData.full_name || '';
    document.getElementById('cf_email').value = clientData.email || '';
    document.getElementById('cf_phone').value = clientData.phone || '';
    document.getElementById('cf_dob').value = clientData.date_of_birth || '';
    document.getElementById('cf_serviceType').value = clientData.service_type || '';
    document.getElementById('cf_status').value = clientData.status || 'active';
    document.getElementById('cf_address').value = clientData.address || '';
    document.getElementById('cf_notes').value = clientData.notes || '';
  } else {
    document.getElementById('cf_id').value = '';
    document.getElementById('cf_fullName').value = '';
    document.getElementById('cf_email').value = '';
    document.getElementById('cf_phone').value = '';
    document.getElementById('cf_dob').value = '';
    document.getElementById('cf_serviceType').value = '';
    document.getElementById('cf_status').value = 'active';
    document.getElementById('cf_address').value = '';
    document.getElementById('cf_notes').value = '';
  }
  openModal('clientFormModal');
}
function closeClientFormModal() { closeModal('clientFormModal'); }
function showSessionFormModal(sessionData) {
  if (sessionData) {
    document.getElementById('sf_id').value = sessionData.id || '';
    document.getElementById('sf_clientId').value = sessionData.client_id || '';
    document.getElementById('sf_date').value = sessionData.session_date ? sessionData.session_date.slice(0,16) : '';
    document.getElementById('sf_serviceType').value = sessionData.service_type || '';
    document.getElementById('sf_duration').value = sessionData.duration_minutes || '';
    document.getElementById('sf_amount').value = sessionData.amount || '';
    document.getElementById('sf_paid').checked = !!sessionData.paid;
    document.getElementById('sf_paymentMethod').value = sessionData.payment_method || '';
    document.getElementById('sf_summary').value = sessionData.summary || '';
    document.getElementById('sf_nextNotes').value = sessionData.next_session_notes || '';
  } else {
    document.getElementById('sf_id').value = '';
    document.getElementById('sf_date').value = '';
    document.getElementById('sf_serviceType').value = '';
    document.getElementById('sf_duration').value = '';
    document.getElementById('sf_amount').value = '500';
    document.getElementById('sf_paid').checked = false;
    document.getElementById('sf_paymentMethod').value = '';
    document.getElementById('sf_summary').value = '';
    document.getElementById('sf_nextNotes').value = '';
  }
  openModal('sessionFormModal');
}
function closeSessionFormModal() { closeModal('sessionFormModal'); }
function showClientDetailModal(client) {
  document.getElementById('clientDetailName').textContent = client.full_name || 'פרטי לקוח';
  const content = document.getElementById('clientDetailContent');
  content.innerHTML = `
    <p><strong>אימייל:</strong> ${client.email || '—'}</p>
    <p><strong>טלפון:</strong> ${client.phone || '—'}</p>
    <p><strong>סוג טיפול:</strong> ${client.service_type || '—'}</p>
    <p><strong>סטטוס:</strong> ${client.status || '—'}</p>
    <p><strong>כתובת:</strong> ${client.address || '—'}</p>
    <p><strong>הערות:</strong> ${client.notes || '—'}</p>
  `;
  openModal('clientDetailModal');
}
function closeClientDetailModal() { closeModal('clientDetailModal'); }
function showChangePasswordModal() { openModal('changePasswordModal'); }
function closeChangePasswordModal() { closeModal('changePasswordModal'); }

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
