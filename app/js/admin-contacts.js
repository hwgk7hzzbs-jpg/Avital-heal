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
    <tr style="cursor:pointer;" onclick="openContactDetail(${c.id})" title="לחצי לצפייה בפרטים">
      <td><strong>${escapeHtml(c.full_name)}</strong></td>
      <td onclick="event.stopPropagation()">${c.phone ? '<a href="tel:' + escapeHtml(c.phone) + '">' + escapeHtml(c.phone) + '</a>' : '—'}</td>
      <td onclick="event.stopPropagation()">${c.email ? '<a href="mailto:' + escapeHtml(c.email) + '">' + escapeHtml(c.email) + '</a>' : '—'}</td>
      <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${escapeHtml(c.message || '—')}</td>
      <td>${c.created_at ? new Date(c.created_at).toLocaleDateString('he-IL') : '—'}</td>
      <td>${contactStatusBadge(c.status)}</td>
      <td onclick="event.stopPropagation()">
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

let currentContactId = null;

const CONTACT_STATUS_LABELS = {
  new: 'חדש',
  contacted: 'נוצר קשר',
  converted: 'הפך ללקוח',
  closed: 'סגור',
  rejected: 'דחוי',
};

function openContactDetail(id) {
  const c = (allContacts || []).find(x => x.id === id);
  if (!c) return;
  currentContactId = id;

  document.getElementById('contactDetailName').textContent = c.full_name || 'פרטי פנייה';

  const created = c.created_at
    ? new Date(c.created_at).toLocaleString('he-IL', { dateStyle: 'short', timeStyle: 'short' })
    : '—';

  document.getElementById('contactDetailContent').innerHTML = `
    <div class="form-row" style="margin-bottom:10px;">
      <div><strong>טלפון:</strong> ${c.phone ? '<a href="tel:' + escapeHtml(c.phone) + '">' + escapeHtml(c.phone) + '</a>' : '—'}</div>
      <div><strong>אימייל:</strong> ${c.email ? '<a href="mailto:' + escapeHtml(c.email) + '">' + escapeHtml(c.email) + '</a>' : '—'}</div>
    </div>
    <div class="form-row" style="margin-bottom:10px;">
      <div><strong>תאריך:</strong> ${created}</div>
      <div><strong>סטטוס:</strong> ${contactStatusBadge(c.status)}</div>
    </div>
    <div style="margin-top:12px;">
      <strong>הודעה:</strong>
      <div style="background:var(--bg,#f5f7fa); border:1px solid var(--border,#e2e8f0); border-radius:8px; padding:12px; margin-top:6px; white-space:pre-wrap; word-break:break-word; line-height:1.6;">${escapeHtml(c.message || '—')}</div>
    </div>
    ${c.source ? '<div style="margin-top:10px;color:var(--text-light);font-size:0.85rem;">מקור: ' + escapeHtml(c.source) + '</div>' : ''}
    ${c.notes ? '<div style="margin-top:10px;"><strong>הערות פנימיות:</strong> ' + escapeHtml(c.notes) + '</div>' : ''}
  `;

  const waBtn = document.getElementById('contactDetailWhatsApp');
  const phoneBtn = document.getElementById('contactDetailPhone');
  const emailBtn = document.getElementById('contactDetailEmail');

  if (c.phone) {
    const digits = String(c.phone).replace(/\D/g, '').replace(/^0/, '972');
    waBtn.href = 'https://wa.me/' + digits;
    waBtn.style.display = '';
    phoneBtn.href = 'tel:' + c.phone;
    phoneBtn.style.display = '';
  } else {
    waBtn.style.display = 'none';
    phoneBtn.style.display = 'none';
  }
  if (c.email) {
    emailBtn.href = 'mailto:' + c.email;
    emailBtn.style.display = '';
  } else {
    emailBtn.style.display = 'none';
  }

  openModal('contactDetailModal');
}

function closeContactDetailModal() {
  closeModal('contactDetailModal');
  currentContactId = null;
}

async function deleteContact() {
  if (!currentContactId) return;
  if (!confirm('להעביר את הפנייה לסל המיחזור?')) return;
  const data = await api(`/api/contacts/${currentContactId}`, { method: 'DELETE' });
  if (data && !data.error) {
    closeContactDetailModal();
    loadContacts();
    loadDashboard();
  } else {
    alert(data?.error || 'שגיאה במחיקת פנייה');
  }
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
