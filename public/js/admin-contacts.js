/**
 * @file admin-contacts.js
 * @description Contact inquiry management: list, filter, update status.
 * @module AdminContacts
 */

async function loadContacts() {
  const contacts = await api('/api/contacts');
  if (!contacts) return;
  allContacts = contacts;
  renderContacts(contacts);
}

function renderContacts(contacts) {
  const tbody = document.getElementById('contactsTable');
  if (!contacts.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-light);">אין פניות</td></tr>';
    return;
  }
  tbody.innerHTML = contacts.map(c => `
    <tr>
      <td><strong>${c.full_name}</strong></td>
      <td>${c.phone ? '<a href="tel:' + c.phone + '">' + c.phone + '</a>' : '—'}</td>
      <td>${c.email || '—'}</td>
      <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${c.message || '—'}</td>
      <td>${c.created_at ? new Date(c.created_at).toLocaleDateString('he-IL') : '—'}</td>
      <td>${contactStatusBadge(c.status)}</td>
      <td>
        <select onchange="updateContactStatus(${c.id}, this.value)" style="padding:4px 8px;border:1px solid var(--border);border-radius:6px;font-family:inherit;font-size:0.8rem;">
          <option value="new" ${c.status === 'new' ? 'selected' : ''}>חדש</option>
          <option value="contacted" ${c.status === 'contacted' ? 'selected' : ''}>נוצר קשר</option>
          <option value="converted" ${c.status === 'converted' ? 'selected' : ''}>הפך ללקוח</option>
          <option value="closed" ${c.status === 'closed' ? 'selected' : ''}>סגור</option>
        </select>
      </td>
    </tr>
  `).join('');
}

function filterContacts() {
  const status = document.getElementById('contactStatusFilter').value;
  if (!status) {
    renderContacts(allContacts);
  } else {
    renderContacts(allContacts.filter(c => c.status === status));
  }
}

async function updateContactStatus(id, status) {
  await api(`/api/contacts/${id}`, { method: 'PUT', body: JSON.stringify({ status }) });
  loadContacts();
  loadDashboard();
}
