/**
 * @file admin-sessions.js
 * @description Session management: list, create, edit, delete.
 * @module AdminSessions
 */

let allSessions = [];

async function loadSessions() {
  const sessions = await api('/api/sessions');
  if (!sessions) return;
  allSessions = sessions;
  renderSessions(sessions);
}

function renderSessions(sessions) {
  const tbody = document.getElementById('sessionsTable');
  if (!sessions.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-light);">אין טיפולים</td></tr>';
    return;
  }
  tbody.innerHTML = sessions.map(s => `
    <tr>
      <td>${escapeHtml(s.session_date)}</td>
      <td>${escapeHtml(s.client_name) || '—'}</td>
      <td>${escapeHtml(s.session_type) || '—'}</td>
      <td>${s.duration_minutes} דק׳</td>
      <td>₪${s.amount || 0}</td>
      <td>${s.paid ? '<span class="badge badge-green">שולם</span>' : '<span class="badge badge-red">לא שולם</span>'}</td>
      <td class="actions-cell">
        <button onclick="editSession(${s.id})" class="btn btn-sm btn-outline" title="עריכה">✏️</button>
        <button onclick="deleteSession(${s.id})" class="btn btn-sm btn-outline btn-danger-outline" title="מחיקה">🗑️</button>
      </td>
    </tr>
  `).join('');
}

function editSession(id) {
  const s = allSessions.find(x => x.id === id);
  if (s) showSessionFormModal(s);
}

async function saveSession() {
  const id = document.getElementById('sf_id').value;
  const body = {
    client_id: parseInt(document.getElementById('sf_clientId').value),
    session_date: document.getElementById('sf_date').value,
    session_type: document.getElementById('sf_serviceType').value,
    duration_minutes: parseInt(document.getElementById('sf_duration').value) || 50,
    amount: parseFloat(document.getElementById('sf_amount').value) || 0,
    paid: document.getElementById('sf_paid').checked,
    payment_method: document.getElementById('sf_paymentMethod').value,
    summary: document.getElementById('sf_summary').value,
    next_session_notes: document.getElementById('sf_nextNotes').value,
  };
  if (!body.client_id) { alert('יש לבחור לקוח'); return; }
  if (!body.session_date) { alert('יש לבחור תאריך'); return; }

  if (id) {
    await api(`/api/sessions/${id}`, { method: 'PUT', body: JSON.stringify(body) });
  } else {
    await api('/api/sessions', { method: 'POST', body: JSON.stringify(body) });
  }
  closeModal('sessionFormModal');
  loadSessions();
  loadDashboard();
}

// ─── Soft-delete session ───

async function deleteSession(id) {
  if (!confirm('להעביר את הטיפול לסל המיחזור?')) return;
  const data = await api(`/api/sessions/${id}`, { method: 'DELETE' });
  if (data && !data.error) {
    loadSessions();
    loadDashboard();
  } else {
    alert(data?.error || 'שגיאה במחיקת טיפול');
  }
}

// ─── Export ───

async function exportCSV() {
  try {
    const res = await fetch(`${API_BASE}/api/export/clients`, {
      headers: { 'Authorization': `Bearer ${authToken}` },
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'clients-export.csv';
    a.click();
    URL.revokeObjectURL(url);
  } catch (e) {
    alert('שגיאה בייצוא');
  }
}
