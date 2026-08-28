/**
 * @file admin-auditlog.js
 * @description Audit log viewer (admin only) — filterable, paginated.
 * @module AdminAuditLog
 */

const AUDIT_ACTION_LABELS = {
  login: 'כניסה', create: 'יצירה', update: 'עדכון', view: 'צפייה', delete: 'מחיקה',
  restore: 'שחזור', permanent_delete: 'מחיקה סופית', export: 'ייצוא', revoke: 'ביטול הסכמה',
  password_change: 'שינוי סיסמה', password_reset: 'איפוס סיסמה',
};

const AUDIT_ENTITY_LABELS = {
  client: 'לקוח', session: 'טיפול', contact: 'פנייה', workshop_registration: 'הרשמה לסדנה',
  user: 'משתמש', consent: 'הסכמה',
};

const AUDIT_LOG_PAGE_SIZE = 50;
let auditLogOffset = 0;
let auditLogHasMore = false;

async function loadAuditLog(resetPage) {
  if (resetPage) auditLogOffset = 0;

  const entityType = document.getElementById('auditLogEntityFilter')?.value || '';
  const action = document.getElementById('auditLogActionFilter')?.value || '';
  const params = new URLSearchParams({ limit: String(AUDIT_LOG_PAGE_SIZE + 1), offset: String(auditLogOffset) });
  if (entityType) params.set('entity_type', entityType);
  if (action) params.set('action', action);

  const tbody = document.getElementById('auditLogTable');
  if (!tbody) return;
  tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-light);">טוען...</td></tr>';

  const data = await api(`/api/audit-log?${params.toString()}`);
  const rows = Array.isArray(data) ? data : [];
  auditLogHasMore = rows.length > AUDIT_LOG_PAGE_SIZE;
  renderAuditLog(rows.slice(0, AUDIT_LOG_PAGE_SIZE));
}

function renderAuditLog(rows) {
  const tbody = document.getElementById('auditLogTable');
  if (!rows.length) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-light);">אין רשומות</td></tr>';
  } else {
    tbody.innerHTML = rows.map(r => `
      <tr>
        <td>${r.created_at ? new Date(r.created_at).toLocaleString('he-IL') : '—'}</td>
        <td>${escapeHtml(r.user_email) || '—'}</td>
        <td>${escapeHtml(AUDIT_ACTION_LABELS[r.action] || r.action)}</td>
        <td>${escapeHtml(AUDIT_ENTITY_LABELS[r.entity_type] || r.entity_type)}${r.entity_id ? ' #' + escapeHtml(r.entity_id) : ''}</td>
        <td>${r.result === 'success' ? '<span class="badge badge-green">הצלחה</span>' : '<span class="badge badge-red">כשל</span>'}</td>
        <td style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--text-light);font-size:0.8rem;" title="${escapeHtml(formatAuditMetadata(r.metadata))}">${escapeHtml(formatAuditMetadata(r.metadata))}</td>
      </tr>
    `).join('');
  }
  const pageLabel = document.getElementById('auditLogPageLabel');
  if (pageLabel) pageLabel.textContent = `עמוד ${Math.floor(auditLogOffset / AUDIT_LOG_PAGE_SIZE) + 1}`;
}

function formatAuditMetadata(metadata) {
  if (!metadata) return '';
  try {
    const obj = typeof metadata === 'string' ? JSON.parse(metadata) : metadata;
    return Object.entries(obj).map(([k, v]) => `${k}: ${Array.isArray(v) ? v.join(', ') : v}`).join(' · ');
  } catch (e) {
    return '';
  }
}

function changeAuditLogPage(direction) {
  if (direction < 0 && auditLogOffset === 0) return;
  if (direction > 0 && !auditLogHasMore) return;
  auditLogOffset = Math.max(0, auditLogOffset + direction * AUDIT_LOG_PAGE_SIZE);
  loadAuditLog();
}
