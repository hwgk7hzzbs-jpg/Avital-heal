/**
 * @file admin-recyclebin.js
 * @description Recycle bin UI (admin only) — view, restore, and permanently
 *              delete soft-deleted clients/sessions/contacts/workshop
 *              registrations.
 * @module AdminRecycleBin
 */

const RECYCLE_BIN_TYPES = {
  clients: {
    listPath: '/api/clients/deleted',
    restorePath: id => `/api/clients/${id}/restore`,
    permanentPath: id => `/api/clients/${id}/permanent`,
    describe: c => `${escapeHtml(c.full_name)}${c.email ? ' · ' + escapeHtml(c.email) : ''}`,
  },
  sessions: {
    listPath: '/api/sessions/deleted',
    restorePath: id => `/api/sessions/${id}/restore`,
    permanentPath: id => `/api/sessions/${id}/permanent`,
    describe: s => `${escapeHtml(s.client_name) || ('לקוח #' + s.client_id)} · ${escapeHtml(s.session_date)}`,
  },
  contacts: {
    listPath: '/api/contacts/deleted',
    restorePath: id => `/api/contacts/${id}/restore`,
    permanentPath: id => `/api/contacts/${id}/permanent`,
    describe: c => `${escapeHtml(c.full_name)}${c.phone ? ' · ' + escapeHtml(c.phone) : ''}`,
  },
  'workshop-registrations': {
    listPath: '/api/workshop-registrations/deleted',
    restorePath: id => `/api/workshop-registrations/${id}/restore`,
    permanentPath: id => `/api/workshop-registrations/${id}/permanent`,
    describe: r => `${escapeHtml(r.full_name)} · ${escapeHtml(r.workshop_name) || escapeHtml(r.workshop_id)}`,
  },
};

let currentRecycleBinType = 'clients';
let recycleBinItems = [];

async function loadRecycleBin() {
  const sel = document.getElementById('recycleBinType');
  currentRecycleBinType = sel ? sel.value : 'clients';
  const tbody = document.getElementById('recycleBinTable');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-light);">טוען...</td></tr>';

  const cfg = RECYCLE_BIN_TYPES[currentRecycleBinType];
  const data = await api(cfg.listPath);
  recycleBinItems = Array.isArray(data) ? data : [];
  renderRecycleBin();
}

function renderRecycleBin() {
  const cfg = RECYCLE_BIN_TYPES[currentRecycleBinType];
  const tbody = document.getElementById('recycleBinTable');
  if (!recycleBinItems.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text-light);">סל המיחזור ריק</td></tr>';
    return;
  }
  tbody.innerHTML = recycleBinItems.map(item => `
    <tr>
      <td>${cfg.describe(item)}</td>
      <td>${item.deleted_at ? new Date(item.deleted_at).toLocaleString('he-IL') : '—'}</td>
      <td>${escapeHtml(item.deleted_by_name) || '—'}</td>
      <td class="actions-cell">
        <button onclick="restoreRecycleBinItem(${item.id})" class="btn btn-sm btn-outline">שחזר</button>
        <button onclick="permanentDeleteRecycleBinItem(${item.id})" class="btn btn-sm btn-outline btn-danger-outline">מחק לצמיתות</button>
      </td>
    </tr>
  `).join('');
}

async function restoreRecycleBinItem(id) {
  if (!confirm('לשחזר את הרשומה?')) return;
  const cfg = RECYCLE_BIN_TYPES[currentRecycleBinType];
  const data = await api(cfg.restorePath(id), { method: 'POST' });
  if (data && !data.error) {
    loadRecycleBin();
    loadDashboard();
  } else {
    alert(data?.error || 'שגיאה בשחזור');
  }
}

async function permanentDeleteRecycleBinItem(id) {
  if (!confirm('פעולה זו תמחק את הרשומה לצמיתות ולא ניתן יהיה לשחזר אותה.')) return;
  if (!confirm('אישור אחרון — למחוק לצמיתות?')) return;
  const cfg = RECYCLE_BIN_TYPES[currentRecycleBinType];
  const data = await api(cfg.permanentPath(id), { method: 'DELETE', body: JSON.stringify({ confirm: true }) });
  if (data && !data.error) {
    loadRecycleBin();
  } else {
    alert(data?.error || 'שגיאה במחיקה סופית');
  }
}
