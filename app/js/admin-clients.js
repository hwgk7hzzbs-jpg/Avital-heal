/**
 * @file admin-clients.js
 * @description Client management: list, detail, create, edit, delete.
 * @module AdminClients
 */

let currentClientId = null;

async function loadClients() {
  const clients = await api('/api/clients');
  if (!clients) return;
  allClients = clients;
  renderClients(clients);
}

function renderClients(clients) {
  const tbody = document.getElementById('clientsTable');
  if (!clients.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-light);">אין לקוחות</td></tr>';
    return;
  }
  tbody.innerHTML = clients.map(c => `
    <tr class="clickable-row" onclick="openClientDetail(${c.id})">
      <td><strong>${escapeHtml(c.full_name)}</strong></td>
      <td>${escapeHtml(c.phone) || '—'}</td>
      <td>${escapeHtml(c.treatment_type) || '—'}</td>
      <td>${c.session_count || 0}</td>
      <td>${c.consent_signed ? '<span class="badge badge-green">חתום</span>' : '<span class="badge badge-gray">לא</span>'}</td>
      <td>${c.status === 'active' ? '<span class="badge badge-green">פעיל</span>' : c.status === 'completed' ? '<span class="badge badge-blue">הסתיים</span>' : '<span class="badge badge-gray">לא פעיל</span>'}</td>
    </tr>
  `).join('');
}

function searchClients() {
  const q = document.getElementById('clientSearch').value.toLowerCase();
  const filtered = allClients.filter(c =>
    (c.full_name || '').toLowerCase().includes(q) ||
    (c.email || '').toLowerCase().includes(q) ||
    (c.phone || '').includes(q)
  );
  renderClients(filtered);
}

async function openClientDetail(id) {
  currentClientId = id;
  const data = await api(`/api/clients/${id}`);
  if (!data) return;

  document.getElementById('clientDetailName').textContent = data.full_name;
  document.getElementById('clientDetailContent').innerHTML = `
    <div class="form-row" style="margin-bottom:12px;">
      <div><strong>אימייל:</strong> ${escapeHtml(data.email) || '—'}</div>
      <div><strong>טלפון:</strong> ${escapeHtml(data.phone) || '—'}</div>
    </div>
    <div class="form-row" style="margin-bottom:12px;">
      <div><strong>סוג טיפול:</strong> ${escapeHtml(data.treatment_type) || '—'}</div>
      <div><strong>סטטוס:</strong> ${escapeHtml(data.status) || '—'}</div>
    </div>
    <div class="form-row" style="margin-bottom:12px;">
      <div><strong>תאריך הצטרפות:</strong> ${escapeHtml(data.join_date) || '—'}</div>
      <div><strong>הסכמה:</strong> ${data.consent_signed ? '✅ חתום (' + escapeHtml(data.consent_date || '') + ')' : '❌ לא חתום'}</div>
    </div>
    ${data.notes ? '<div style="margin-bottom:12px;"><strong>הערות:</strong> ' + escapeHtml(data.notes) + '</div>' : ''}
  `;

  const stbody = document.getElementById('clientSessionsTable');
  if (data.sessions && data.sessions.length) {
    stbody.innerHTML = data.sessions.map(s => `
      <tr>
        <td>${escapeHtml(s.session_date)}</td>
        <td>${escapeHtml(s.session_type) || '—'}</td>
        <td>${s.duration_minutes} דק׳</td>
        <td>₪${s.amount || 0}</td>
        <td>${s.paid ? '<span class="badge badge-green">שולם</span>' : '<span class="badge badge-red">לא שולם</span>'}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(s.summary) || '—'}</td>
      </tr>
    `).join('');
  } else {
    stbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-light);">אין טיפולים</td></tr>';
  }

  openModal('clientDetailModal');
  loadClientConsents(id);
}

const CONSENT_TYPE_LABELS = { treatment: 'הסכם טיפול', workshop: 'הסכם סדנה' };

async function loadClientConsents(clientId) {
  const el = document.getElementById('clientConsentHistory');
  if (!el) return;
  el.innerHTML = '<p style="color:var(--text-light);">טוען...</p>';
  const consents = await api(`/api/clients/${clientId}/consents`);
  if (!consents || !consents.length) {
    el.innerHTML = '<p style="color:var(--text-light);">אין רישומי הסכמה</p>';
    return;
  }
  el.innerHTML = consents.map(c => `
    <div style="display:flex;justify-content:space-between;align-items:center;padding:6px 0;border-bottom:1px solid var(--border);font-size:0.85rem;">
      <div>
        <strong>${escapeHtml(CONSENT_TYPE_LABELS[c.consent_type] || c.consent_type)}</strong>
        &nbsp;גרסה ${escapeHtml(c.consent_version)}
        &nbsp;·&nbsp;${escapeHtml(c.signed_at)}
        ${c.status === 'revoked' ? '<span class="badge badge-red" style="margin-right:6px;">בוטל</span>' : '<span class="badge badge-green" style="margin-right:6px;">בתוקף</span>'}
      </div>
      ${c.status === 'active' && currentUser && currentUser.role === 'admin'
        ? `<button onclick="revokeConsent(${c.id}, ${clientId})" class="btn btn-sm" style="background:var(--danger);color:white;">בטל הסכמה</button>`
        : ''}
    </div>
  `).join('');
}

async function revokeConsent(consentId, clientId) {
  if (!confirm('לבטל את ההסכמה הזו? הפעולה מתועדת ואינה הפיכה.')) return;
  const res = await api(`/api/consents/${consentId}/revoke`, { method: 'POST' });
  if (res && res.message) loadClientConsents(clientId);
}

function openNewClientModal() {
  document.getElementById('clientFormTitle').textContent = 'לקוח חדש';
  document.getElementById('cf_id').value = '';
  ['cf_fullName', 'cf_email', 'cf_phone', 'cf_dob', 'cf_address', 'cf_notes'].forEach(id =>
    document.getElementById(id).value = ''
  );
  document.getElementById('cf_serviceType').value = '';
  document.getElementById('cf_status').value = 'active';
  openModal('clientFormModal');
}

function openEditClientModal() {
  const c = allClients.find(x => x.id === currentClientId);
  if (!c) return;
  closeModal('clientDetailModal');
  document.getElementById('clientFormTitle').textContent = 'עריכת לקוח';
  document.getElementById('cf_id').value = c.id;
  document.getElementById('cf_fullName').value = c.full_name || '';
  document.getElementById('cf_email').value = c.email || '';
  document.getElementById('cf_phone').value = c.phone || '';
  document.getElementById('cf_dob').value = c.birth_date || '';
  document.getElementById('cf_serviceType').value = c.treatment_type || '';
  document.getElementById('cf_status').value = c.status || 'active';
  document.getElementById('cf_address').value = c.address || '';
  document.getElementById('cf_notes').value = c.notes || '';
  openModal('clientFormModal');
}

async function saveClient() {
  const id = document.getElementById('cf_id').value;
  const body = {
    full_name: document.getElementById('cf_fullName').value,
    email: document.getElementById('cf_email').value,
    phone: document.getElementById('cf_phone').value,
    birth_date: document.getElementById('cf_dob').value,
    treatment_type: document.getElementById('cf_serviceType').value,
    status: document.getElementById('cf_status').value,
    address: document.getElementById('cf_address').value,
    notes: document.getElementById('cf_notes').value,
  };
  if (!body.full_name) { alert('שם מלא הוא שדה חובה'); return; }

  if (id) {
    await api(`/api/clients/${id}`, { method: 'PUT', body: JSON.stringify(body) });
  } else {
    await api('/api/clients', { method: 'POST', body: JSON.stringify(body) });
  }
  closeModal('clientFormModal');
  loadClients();
  loadDashboard();
}

async function deleteCurrentClient() {
  if (!confirm('למחוק את הלקוח? כל הטיפולים שלו יימחקו גם.')) return;
  await api(`/api/clients/${currentClientId}`, { method: 'DELETE' });
  closeModal('clientDetailModal');
  loadClients();
  loadDashboard();
}
