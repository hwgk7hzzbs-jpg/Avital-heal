/**
 * @file admin-workshops.js
 * @description Workshops management: list workshops and view registrations.
 * @module AdminWorkshops
 */

let allWorkshops = [];
let currentWorkshop = null;

async function loadWorkshops() {
  const workshops = await api('/api/workshops');
  if (!workshops) return;
  allWorkshops = workshops;
  renderWorkshops(workshops);
}

function renderWorkshops(workshops) {
  const container = document.getElementById('workshopsList');
  if (!workshops || !workshops.length) {
    container.innerHTML = '<p style="color:var(--text-light);text-align:center;padding:20px;">אין סדנאות</p>';
    return;
  }
  container.innerHTML = workshops.map(w => {
    let dates = [];
    try { dates = JSON.parse(w.dates || '[]'); } catch (_) {}
    const datesHtml = dates.map(d => `<span class="badge badge-blue" style="margin-left:6px;">${escapeHtml(d.label)}</span>`).join('');
    return `
      <div class="card" style="margin-bottom:12px;">
        <div class="card-body" style="display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap;">
          <div style="flex:1;min-width:260px;">
            <h3 style="margin:0 0 6px 0;">${escapeHtml(w.name)}</h3>
            <p style="color:var(--text-light);margin:0 0 8px 0;font-size:0.9rem;">${escapeHtml(w.description) || ''}</p>
            <div style="margin-bottom:6px;">${datesHtml}</div>
            <div style="font-size:0.85rem;color:var(--text-light);">
              ${w.sessions_count || ''} מפגשים · ${w.duration_minutes ? (w.duration_minutes / 60) + ' שעות כל מפגש' : ''} · ₪${w.price || 0}
            </div>
          </div>
          <div style="text-align:center;">
            <div style="font-size:1.8rem;font-weight:700;color:var(--primary-dark);">${w.registration_count || 0}</div>
            <div style="font-size:0.85rem;color:var(--text-light);">נרשמים</div>
          </div>
          <button onclick="openWorkshopDetails('${escapeHtml(w.id)}')" class="btn btn-primary">צפה בנרשמים</button>
        </div>
      </div>
    `;
  }).join('');
}

async function openWorkshopDetails(workshopId) {
  const workshop = await api(`/api/workshops/${workshopId}`);
  if (!workshop) return;
  currentWorkshop = workshop;

  document.getElementById('workshopsList').style.display = 'none';
  document.getElementById('workshopDetails').style.display = '';
  document.getElementById('workshopDetailsTitle').textContent = workshop.name;

  const dates = workshop.dates || [];
  const datesHtml = dates.map(d => `<span class="badge badge-blue" style="margin-left:6px;">${escapeHtml(d.label)}</span>`).join('');

  document.getElementById('workshopDetailsInfo').innerHTML = `
    <p style="color:var(--text-light);margin-bottom:8px;">${escapeHtml(workshop.description) || ''}</p>
    <div style="margin-bottom:8px;"><strong>מועדים זמינים:</strong> ${datesHtml}</div>
    <div style="font-size:0.9rem;color:var(--text-light);">
      ${workshop.sessions_count} מפגשים · ${workshop.duration_minutes / 60} שעות · ₪${workshop.price} · ${escapeHtml(workshop.location) || ''}
    </div>
  `;

  renderWorkshopRegistrations(workshop.registrations || [], dates);
}

function renderWorkshopRegistrations(regs, dates) {
  const tbody = document.getElementById('workshopRegistrationsTable');
  if (!regs.length) {
    tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--text-light);">אין נרשמים עדיין</td></tr>';
    return;
  }
  const dateLabel = (id) => {
    const d = dates.find(x => x.id === id);
    return d ? d.label : (id || '—');
  };
  const statusBadge = (s) => {
    const map = {
      'new': { cls: 'badge-blue', text: 'חדש' },
      'contacted': { cls: 'badge-gray', text: 'יצור קשר' },
      'confirmed': { cls: 'badge-green', text: 'אושר' },
      'cancelled': { cls: 'badge-red', text: 'בוטל' },
    };
    const m = map[s] || map['new'];
    return `<span class="badge ${m.cls}">${m.text}</span>`;
  };
  tbody.innerHTML = regs.map(r => `
    <tr>
      <td><strong>${escapeHtml(r.full_name)}</strong> ${r.consent_agreed ? '<span class="badge badge-green" title="אישרה הסכם סדנה ב-' + escapeHtml(r.consent_date || '') + '">📝✓</span>' : '<span class="badge badge-gray" title="לא אישרה הסכם">⚠</span>'}</td>
      <td>${r.phone ? `<a href="tel:${encodeURIComponent(r.phone)}">${escapeHtml(r.phone)}</a>` : '—'}</td>
      <td>${r.email ? `<a href="mailto:${encodeURIComponent(r.email)}">${escapeHtml(r.email)}</a>` : '—'}</td>
      <td>${escapeHtml(dateLabel(r.date_option))}</td>
      <td>${new Date(r.created_at).toLocaleDateString('he-IL')}</td>
      <td>${statusBadge(r.status)}</td>
      <td>
        <select onchange="updateRegistrationStatus(${r.id}, this.value)" class="input-field" style="width:auto;padding:6px;margin:0;">
          <option value="new" ${r.status === 'new' ? 'selected' : ''}>חדש</option>
          <option value="contacted" ${r.status === 'contacted' ? 'selected' : ''}>יצור קשר</option>
          <option value="confirmed" ${r.status === 'confirmed' ? 'selected' : ''}>אושר</option>
          <option value="cancelled" ${r.status === 'cancelled' ? 'selected' : ''}>בוטל</option>
        </select>
        <button onclick="deleteRegistration(${r.id})" class="btn btn-sm" style="background:var(--danger);color:white;">מחק</button>
      </td>
    </tr>
  `).join('');
}

async function updateRegistrationStatus(regId, status) {
  const res = await api(`/api/workshop-registrations/${regId}`, {
    method: 'PUT',
    body: JSON.stringify({ status }),
  });
  if (res && res.message) {
    if (currentWorkshop) openWorkshopDetails(currentWorkshop.id);
    loadWorkshops();
  }
}

async function deleteRegistration(regId) {
  if (!confirm('למחוק הרשמה זו?')) return;
  const res = await api(`/api/workshop-registrations/${regId}`, { method: 'DELETE' });
  if (res && res.message) {
    if (currentWorkshop) openWorkshopDetails(currentWorkshop.id);
    loadWorkshops();
  }
}

function closeWorkshopDetails() {
  document.getElementById('workshopDetails').style.display = 'none';
  document.getElementById('workshopsList').style.display = '';
  currentWorkshop = null;
}
