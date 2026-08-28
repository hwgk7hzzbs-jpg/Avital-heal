/**
 * @file admin-sessions.js
 * @description Session management: list, create, edit.
 * @module AdminSessions
 */

async function loadSessions() {
  const sessions = await api('/api/sessions');
  if (!sessions) return;
  const tbody = document.getElementById('sessionsTable');
  if (!sessions.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-light);">אין טיפולים</td></tr>';
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
    </tr>
  `).join('');
}

function openNewSessionModal() {
  document.getElementById('sessionFormTitle').textContent = 'טיפול חדש';
  document.getElementById('sf_id').value = '';
  document.getElementById('sf_date').value = new Date().toISOString().slice(0, 10);
  document.getElementById('sf_type').value = '';
  document.getElementById('sf_duration').value = '50';
  document.getElementById('sf_amount').value = '0';
  document.getElementById('sf_paid').value = '0';
  document.getElementById('sf_payment_method').value = '';
  document.getElementById('sf_summary').value = '';
  document.getElementById('sf_next_notes').value = '';

  const sel = document.getElementById('sf_client');
  sel.innerHTML = '<option value="">— בחירת לקוח —</option>' +
    allClients.map(c => `<option value="${c.id}">${escapeHtml(c.full_name)}</option>`).join('');

  document.getElementById('sessionFormModal').classList.add('active');
}

function openNewSessionForClient() {
  closeModal('clientDetailModal');
  openNewSessionModal();
  document.getElementById('sf_client').value = currentClientId;
}

async function saveSession() {
  const id = document.getElementById('sf_id').value;
  const body = {
    client_id: parseInt(document.getElementById('sf_client').value),
    session_date: document.getElementById('sf_date').value,
    session_type: document.getElementById('sf_type').value,
    duration_minutes: parseInt(document.getElementById('sf_duration').value) || 50,
    amount: parseFloat(document.getElementById('sf_amount').value) || 0,
    paid: document.getElementById('sf_paid').value === '1',
    payment_method: document.getElementById('sf_payment_method').value,
    summary: document.getElementById('sf_summary').value,
    next_session_notes: document.getElementById('sf_next_notes').value,
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

// ─── Export ───

async function exportClients() {
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
