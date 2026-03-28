/**
 * @file admin-users.js
 * @description User management UI — admin only.
 * @module AdminUsers
 */

let allUsers = [];

// ─── Role labels ───
const ROLE_LABELS = {
  admin: 'מנהל',
  therapist: 'מטפל',
  viewer: 'צופה',
};

const ROLE_BADGES = {
  admin: '<span class="badge badge-purple">מנהל</span>',
  therapist: '<span class="badge badge-blue">מטפל</span>',
  viewer: '<span class="badge badge-gray">צופה</span>',
};

// ─── Load users table ───

async function loadUsers() {
  const data = await api('/api/users');
  if (!data) return;
  allUsers = Array.isArray(data) ? data : [];
  renderUsersTable();
}

function renderUsersTable() {
  const tbody = document.getElementById('usersTable');
  if (!tbody) return;

  if (allUsers.length === 0) {
    tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--text-light);">אין משתמשים</td></tr>';
    return;
  }

  tbody.innerHTML = allUsers.map(u => `
    <tr>
      <td><strong>${escapeHtml(u.name)}</strong></td>
      <td>${escapeHtml(u.email)}</td>
      <td>${ROLE_BADGES[u.role] || u.role}</td>
      <td>${u.active ? '<span class="badge badge-green">פעיל</span>' : '<span class="badge badge-red">לא פעיל</span>'}</td>
      <td>${u.created_at ? new Date(u.created_at).toLocaleDateString('he-IL') : '—'}</td>
      <td class="actions-cell">
        <button onclick="editUser(${u.id})" class="btn btn-sm btn-outline" title="עריכה">✏️</button>
        <button onclick="resetUserPassword(${u.id})" class="btn btn-sm btn-outline" title="איפוס סיסמה">🔑</button>
        ${u.id !== currentUser?.id ? `<button onclick="deleteUser(${u.id})" class="btn btn-sm btn-outline btn-danger-outline" title="מחיקה">🗑️</button>` : ''}
      </td>
    </tr>
  `).join('');
}

// ─── Escape HTML ───

function escapeHtml(str) {
  if (!str) return '';
  return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ─── Show user form modal ───

function showUserFormModal(userData) {
  if (userData) {
    document.getElementById('uf_id').value = userData.id || '';
    document.getElementById('uf_name').value = userData.name || '';
    document.getElementById('uf_email').value = userData.email || '';
    document.getElementById('uf_password').value = '';
    document.getElementById('uf_password').placeholder = 'השאר ריק לשמירת הקיימת';
    document.getElementById('uf_role').value = userData.role || 'therapist';
    document.getElementById('uf_active').checked = userData.active !== 0;
    document.getElementById('userFormTitle').textContent = 'עריכת משתמש';
  } else {
    document.getElementById('uf_id').value = '';
    document.getElementById('uf_name').value = '';
    document.getElementById('uf_email').value = '';
    document.getElementById('uf_password').value = '';
    document.getElementById('uf_password').placeholder = 'סיסמה (לפחות 8 תווים, אות גדולה+קטנה+מספר)';
    document.getElementById('uf_role').value = 'therapist';
    document.getElementById('uf_active').checked = true;
    document.getElementById('userFormTitle').textContent = 'משתמש חדש';
  }
  openModal('userFormModal');
}

function closeUserFormModal() {
  closeModal('userFormModal');
}

// ─── Edit user ───

function editUser(id) {
  const user = allUsers.find(u => u.id === id);
  if (user) showUserFormModal(user);
}

// ─── Save user (create or update) ───

async function saveUser() {
  const id = document.getElementById('uf_id').value;
  const name = document.getElementById('uf_name').value.trim();
  const email = document.getElementById('uf_email').value.trim();
  const password = document.getElementById('uf_password').value;
  const role = document.getElementById('uf_role').value;
  const active = document.getElementById('uf_active').checked;

  if (!name || name.length < 2) {
    alert('שם חייב להכיל לפחות 2 תווים');
    return;
  }
  if (!email) {
    alert('נדרש אימייל');
    return;
  }

  if (id) {
    // Update existing user
    const body = { name, email, role, active };
    const data = await api(`/api/users/${id}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
    if (data && !data.error) {
      closeUserFormModal();
      loadUsers();
    } else {
      alert(data?.error || 'שגיאה בעדכון משתמש');
    }
  } else {
    // Create new user
    if (!password) {
      alert('נדרשת סיסמה למשתמש חדש');
      return;
    }
    const data = await api('/api/users', {
      method: 'POST',
      body: JSON.stringify({ name, email, password, role }),
    });
    if (data && !data.error) {
      closeUserFormModal();
      loadUsers();
    } else {
      alert(data?.error || 'שגיאה ביצירת משתמש');
    }
  }
}

// ─── Delete user ───

async function deleteUser(id) {
  const user = allUsers.find(u => u.id === id);
  if (!user) return;

  if (!confirm(`למחוק את המשתמש "${user.name}"?`)) return;

  const data = await api(`/api/users/${id}`, { method: 'DELETE' });
  if (data && !data.error) {
    loadUsers();
  } else {
    alert(data?.error || 'שגיאה במחיקת משתמש');
  }
}

// ─── Reset user password ───

async function resetUserPassword(id) {
  const user = allUsers.find(u => u.id === id);
  if (!user) return;

  const newPassword = prompt(`הזן סיסמה חדשה עבור "${user.name}":\n(לפחות 8 תווים, אות גדולה, אות קטנה, מספר)`);
  if (!newPassword) return;

  const data = await api(`/api/users/${id}/reset-password`, {
    method: 'POST',
    body: JSON.stringify({ newPassword }),
  });
  if (data && !data.error) {
    alert('הסיסמה עודכנה בהצלחה');
  } else {
    alert(data?.error || 'שגיאה באיפוס סיסמה');
  }
}
