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
      <td><strong>${c.full_name}</strong></td>
      <td>${c.phone || '—'}</td>
      <td>${c.treatment_type || '—'}</td>
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
      <div><strong>אימייל:</strong> ${data.email || '—'}</div>
      <div><strong>טלפון:</strong> ${data.phone || '—'}</div>
    </div>
    <div class="form-row" style="margin-bottom:12px;">
      <div><strong>סוג טיפול:</strong> ${data.treatment_type || '—'}</div>
      <div><strong>סטטוס:</strong> ${data.status || '—'}</div>
    </div>
    <div class="form-row" style="margin-bottom:12px;">
      <div><strong>תאריך הצטרפות:</strong> ${data.join_date || '—'}</div>
      <div><strong>הסכמה:</strong> ${data.consent_signed ? '✅ חתום (' + (data.consent_date || '') + ')' : '❌ לא חתום'}</div>
    </div>
    ${data.notes ? '<div style="margin-bottom:12px;"><strong>הערות:</strong> ' + data.notes + '</div>' : ''}
  `;

  const stbody = document.getElementById('clientSessionsTable');
  if (data.sessions && data.sessions.length) {
    stbody.innerHTML = data.sessions.map(s => `
      <tr>
        <td>${s.session_date}</td>
        <td>${s.session_type || '—'}</td>
        <td>${s.duration_minutes} דק׳</td>
        <td>₪${s.amount || 0}</td>
        <td>${s.paid ? '<span class="badge badge-green">שולם</span>' : '<span class="badge badge-red">לא שולם</span>'}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${s.summary || '—'}</td>
      </tr>
    `).join('');
  } else {
    stbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-light);">אין טיפולים</td></tr>';
  }

  document.getElementById('clientDetailModal').classList.add('active');
}

function openNewClientModal() {
  document.getElementById('clientFormTitle').textContent = 'לקוח חדש';
  document.getElementById('clientFormId').value = '';
  ['cf_name', 'cf_email', 'cf_phone', 'cf_birth', 'cf_address', 'cf_notes'].forEach(id =>
    document.getElementById(id).value = ''
  );
  document.getElementById('cf_type').value = '';
  document.getElementById('cf_status').value = 'active';
  document.getElementById('clientFormModal').classList.add('active');
}

function openEditClientModal() {
  const c = allClients.find(x => x.id === currentClientId);
  if (!c) return;
  closeModal('clientDetailModal');
  document.getElementById('clientFormTitle').textContent = 'עריכת לקוח';
  document.getElementById('clientFormId').value = c.id;
  document.getElementById('cf_name').value = c.full_name || '';
  document.getElementById('cf_email').value = c.email || '';
  document.getElementById('cf_phone').value = c.phone || '';
  document.getElementById('cf_birth').value = c.birth_date || '';
  document.getElementById('cf_type').value = c.treatment_type || '';
  document.getElementById('cf_status').value = c.status || 'active';
  document.getElementById('cf_address').value = c.address || '';
  document.getElementById('cf_notes').value = c.notes || '';
  document.getElementById('clientFormModal').classList.add('active');
}

async function saveClient() {
  const id = document.getElementById('clientFormId').value;
  const body = {
    full_name: document.getElementById('cf_name').value,
    email: document.getElementById('cf_email').value,
    phone: document.getElementById('cf_phone').value,
    birth_date: document.getElementById('cf_birth').value,
    treatment_type: document.getElementById('cf_type').value,
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
