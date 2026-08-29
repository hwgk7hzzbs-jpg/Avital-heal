/**
 * @file admin-mfa.js
 * @description Self-service MFA (TOTP) enrollment and disable for the
 *              logged-in user's own account.
 * @module AdminMfa
 */

function showMfaModal() {
  openModal('mfaModal');
  renderMfaModal();
}

function closeMfaModal() {
  closeModal('mfaModal');
}

function renderMfaModal() {
  const body = document.getElementById('mfaModalBody');
  if (currentUser && currentUser.mfaEnabled) {
    renderMfaEnabledState(body);
  } else {
    renderMfaEnrollStart(body);
  }
}

function renderMfaEnabledState(body) {
  body.innerHTML = `
    <p style="color:var(--success,#48bb78); font-weight:600;">✅ אימות דו-שלבי פעיל בחשבון שלך</p>
    <p style="color:var(--text-light); font-size:0.85rem; margin-bottom:16px;">כדי לבטל, יש להזין את הסיסמה הנוכחית שלך לאימות.</p>
    <input type="password" id="mfaDisablePassword" placeholder="סיסמה נוכחית" class="input-field">
    <div id="mfaDisableMsg" class="reset-msg"></div>
    <button onclick="disableMfa()" class="btn" style="background:var(--danger); color:#fff; border-color:var(--danger);">בטל אימות דו-שלבי</button>
  `;
}

function renderMfaEnrollStart(body) {
  body.innerHTML = `
    <p style="color:var(--text-light); font-size:0.9rem; margin-bottom:16px;">
      אימות דו-שלבי מוסיף שכבת הגנה נוספת: בכל כניסה תידרש גם קוד מאפליקציית אימות (כגון Google Authenticator או Authy), בנוסף לסיסמה.
    </p>
    <button onclick="startMfaSetup()" class="btn btn-primary">הפעל אימות דו-שלבי</button>
  `;
}

async function startMfaSetup() {
  const data = await api('/api/mfa/setup/start', { method: 'POST' });
  if (!data || data.error) {
    alert(data?.error || 'שגיאה בהפעלת אימות דו-שלבי');
    return;
  }
  const body = document.getElementById('mfaModalBody');
  body.innerHTML = `
    <p style="color:var(--text-light); font-size:0.9rem; margin-bottom:10px;">
      הוסיפי מפתח זה באפליקציית האימות שלך (הזנה ידנית — "Enter a setup key"), ולאחר מכן הזיני את הקוד בן 6 הספרות שמופיע כדי לאשר.
    </p>
    <div style="background:var(--bg,#f5f7fa); border:1px solid var(--border,#e2e8f0); border-radius:8px; padding:12px; margin-bottom:14px; text-align:center;">
      <div style="font-family:monospace; font-size:1.1rem; letter-spacing:2px; word-break:break-all;">${escapeHtml(data.secret)}</div>
    </div>
    <input type="text" id="mfaSetupCode" placeholder="קוד בן 6 ספרות" class="input-field" inputmode="numeric">
    <div id="mfaSetupMsg" class="reset-msg"></div>
    <button onclick="verifyMfaSetup()" class="btn btn-primary">אשר והפעל</button>
  `;
}

async function verifyMfaSetup() {
  const code = document.getElementById('mfaSetupCode').value.trim();
  const msgEl = document.getElementById('mfaSetupMsg');
  if (!code) { msgEl.textContent = 'נא להזין קוד'; msgEl.className = 'reset-msg error'; return; }

  const data = await api('/api/mfa/setup/verify', { method: 'POST', body: JSON.stringify({ code }) });
  if (!data || data.error) {
    msgEl.textContent = data?.error || 'קוד שגוי';
    msgEl.className = 'reset-msg error';
    return;
  }
  currentUser.mfaEnabled = true;
  renderMfaBackupCodes(data.backupCodes);
}

function renderMfaBackupCodes(codes) {
  const body = document.getElementById('mfaModalBody');
  body.innerHTML = `
    <p style="color:var(--success,#48bb78); font-weight:600; margin-bottom:10px;">✅ אימות דו-שלבי הופעל בהצלחה</p>
    <p style="color:var(--danger,#f56565); font-size:0.85rem; margin-bottom:10px; font-weight:600;">
      שמרי את קודי הגיבוי האלה במקום בטוח — כל קוד ניתן לשימוש חד-פעמי, למקרה שתאבדי גישה לאפליקציית האימות. הם לא יוצגו שוב.
    </p>
    <div style="background:var(--bg,#f5f7fa); border:1px solid var(--border,#e2e8f0); border-radius:8px; padding:12px; margin-bottom:14px; font-family:monospace; font-size:0.95rem; line-height:1.8; text-align:center;">
      ${codes.map(c => escapeHtml(c)).join('<br>')}
    </div>
    <button onclick="closeMfaModal()" class="btn btn-primary">סיימתי, שמרתי את הקודים</button>
  `;
}

async function disableMfa() {
  const password = document.getElementById('mfaDisablePassword').value;
  const msgEl = document.getElementById('mfaDisableMsg');
  if (!password) { msgEl.textContent = 'נדרשת סיסמה נוכחית'; msgEl.className = 'reset-msg error'; return; }
  if (!confirm('לבטל את האימות הדו-שלבי בחשבון שלך?')) return;

  const data = await api('/api/mfa/disable', { method: 'POST', body: JSON.stringify({ currentPassword: password }) });
  if (!data || data.error) {
    msgEl.textContent = data?.error || 'שגיאה בביטול';
    msgEl.className = 'reset-msg error';
    return;
  }
  currentUser.mfaEnabled = false;
  closeMfaModal();
  alert('אימות דו-שלבי בוטל');
}
