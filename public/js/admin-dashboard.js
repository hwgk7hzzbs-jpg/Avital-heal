/**
 * @file admin-dashboard.js
 * @description Dashboard stats loading and rendering.
 * @module AdminDashboard
 */

function contactStatusBadge(status) {
  const map = {
    'new': '<span class="badge badge-red">חדש</span>',
    'contacted': '<span class="badge badge-blue">נוצר קשר</span>',
    'converted': '<span class="badge badge-green">הפך ללקוח</span>',
    'closed': '<span class="badge badge-gray">סגור</span>',
  };
  return map[status] || '<span class="badge badge-gray">' + (status || '—') + '</span>';
}

async function loadDashboard() {
  const stats = await api('/api/stats');
  if (!stats) return;

  document.getElementById('stat-total').textContent = stats.totalClients;
  document.getElementById('stat-active').textContent = stats.activeClients;
  document.getElementById('stat-month-sessions').textContent = stats.monthSessions;
  document.getElementById('stat-month-revenue').textContent = '₪' + (stats.monthRevenue || 0).toLocaleString();
  document.getElementById('stat-unpaid').textContent = '₪' + (stats.unpaidTotal || 0).toLocaleString();
  document.getElementById('stat-consent').textContent = stats.consentSigned;
  document.getElementById('stat-new-contacts').textContent = stats.newContacts || 0;

  // Update contacts badge
  const badge = document.getElementById('contactsBadge');
  if (stats.newContacts > 0) {
    badge.textContent = stats.newContacts;
    badge.style.display = 'inline-block';
  } else {
    badge.style.display = 'none';
  }

  // Recent contacts
  const ctbody = document.getElementById('recentContactsTable');
  if (stats.recentContacts && stats.recentContacts.length) {
    ctbody.innerHTML = stats.recentContacts.map(c => `
      <tr>
        <td><strong>${c.full_name}</strong></td>
        <td>${c.phone || '—'}</td>
        <td>${c.email || '—'}</td>
        <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">${c.message || '—'}</td>
        <td>${c.created_at ? new Date(c.created_at).toLocaleDateString('he-IL') : '—'}</td>
        <td>${contactStatusBadge(c.status)}</td>
      </tr>
    `).join('');
  } else {
    ctbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-light);">אין פניות</td></tr>';
  }

  // Recent clients
  const tbody = document.getElementById('recentClientsTable');
  if (stats.recentClients && stats.recentClients.length) {
    tbody.innerHTML = stats.recentClients.map(c => `
      <tr class="clickable-row" onclick="openClientDetail(${c.id})">
        <td>${c.full_name}</td>
        <td>${c.email || '—'}</td>
        <td>${c.join_date || '—'}</td>
        <td>${c.consent_signed ? '<span class="badge badge-green">חתום</span>' : '<span class="badge badge-gray">לא</span>'}</td>
      </tr>
    `).join('');
  } else {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-light);">אין לקוחות עדיין</td></tr>';
  }
}
