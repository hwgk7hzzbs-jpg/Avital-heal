/**
 * @file contact-modal.js
 * @description Reusable contact modal. Injects a modal into the page and
 *   intercepts clicks on any <a href="mailto:..."> link to open it instead.
 *   Submits to /api/contact on the CRM Worker, identical to the workshop modal.
 * @usage <script src="contact-modal.js?v=1" defer></script>
 */
(function () {
  'use strict';

  const API_URL = 'https://avital-heal-crm.tgthf7frmp.workers.dev';
  const TURNSTILE_SITEKEY = '0x4AAAAAACxQXQewOnLqH3uM';

  const CSS = `
    .ah-modal-overlay {
      position: fixed; inset: 0;
      background: rgba(10,5,20,0.78);
      backdrop-filter: blur(6px); -webkit-backdrop-filter: blur(6px);
      display: none; align-items: center; justify-content: center;
      z-index: 9999; padding: 20px;
      font-family: 'Rubik', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    .ah-modal-overlay.open { display: flex; animation: ahFadeIn 0.2s ease; }
    @keyframes ahFadeIn { from { opacity: 0; } to { opacity: 1; } }
    .ah-modal-box {
      background: #ffffff;
      border-radius: 18px;
      padding: 28px 24px;
      max-width: 440px; width: 100%;
      max-height: 90vh; overflow-y: auto;
      position: relative;
      box-shadow: 0 30px 80px rgba(0,0,0,0.3);
      direction: rtl;
    }
    .ah-modal-close {
      position: absolute; top: 10px; left: 14px;
      background: none; border: none;
      color: #666; font-size: 26px; cursor: pointer;
      line-height: 1; padding: 4px 8px; border-radius: 6px;
      transition: background 0.15s, color 0.15s;
    }
    .ah-modal-close:hover { background: rgba(0,0,0,0.06); color: #000; }
    .ah-modal-title {
      font-size: 22px; font-weight: 700;
      color: #4A4A4A; text-align: center; margin-bottom: 6px;
    }
    .ah-modal-sub {
      font-size: 14px; color: #777;
      text-align: center; margin-bottom: 20px;
    }
    .ah-field { margin-bottom: 12px; }
    .ah-field input, .ah-field textarea {
      width: 100%; box-sizing: border-box;
      padding: 12px 14px;
      font-family: inherit; font-size: 15px;
      border: 1px solid #d5d5d5; border-radius: 10px;
      background: #fff; color: #222;
      transition: border-color 0.15s;
    }
    .ah-field input:focus, .ah-field textarea:focus {
      outline: none; border-color: #9DC8B0;
    }
    .ah-field textarea { min-height: 100px; resize: vertical; }
    .ah-turnstile { display: flex; justify-content: center; margin: 10px 0; }
    .ah-submit {
      width: 100%; padding: 13px 18px;
      background: #9DC8B0; color: #fff;
      border: none; border-radius: 12px;
      font-family: inherit; font-size: 16px; font-weight: 600;
      cursor: pointer; transition: background 0.15s;
    }
    .ah-submit:hover:not(:disabled) { background: #7ab094; }
    .ah-submit:disabled { opacity: 0.6; cursor: not-allowed; }
    .ah-msg { margin-top: 12px; text-align: center; font-size: 14px; min-height: 20px; }
    .ah-msg.success { color: #2d8a5a; }
    .ah-msg.error { color: #c94545; }
  `;

  const HTML = `
    <div id="ah-contact-modal" class="ah-modal-overlay" role="dialog" aria-modal="true" aria-labelledby="ah-modal-title">
      <div class="ah-modal-box">
        <button type="button" class="ah-modal-close" aria-label="סגור">&times;</button>
        <div class="ah-modal-title" id="ah-modal-title">יצירת קשר</div>
        <div class="ah-modal-sub">מלאי את פרטייך ואחזור אלייך בהקדם</div>
        <form id="ah-contact-form" novalidate>
          <div class="ah-field"><input type="text" name="fullName" placeholder="שם מלא" required></div>
          <div class="ah-field"><input type="tel" name="phone" placeholder="טלפון"></div>
          <div class="ah-field"><input type="email" name="email" placeholder="אימייל" dir="ltr"></div>
          <div class="ah-field"><textarea name="message" placeholder="איך אוכל לעזור? (שאלות / בקשות)" required></textarea></div>
          <div class="ah-turnstile"><div class="cf-turnstile" data-sitekey="${TURNSTILE_SITEKEY}"></div></div>
          <button type="submit" class="ah-submit">שליחה</button>
          <div class="ah-msg" role="status" aria-live="polite"></div>
        </form>
      </div>
    </div>
  `;

  function injectOnce() {
    if (document.getElementById('ah-contact-modal')) return;

    const style = document.createElement('style');
    style.textContent = CSS;
    document.head.appendChild(style);

    const tpl = document.createElement('template');
    tpl.innerHTML = HTML.trim();
    document.body.appendChild(tpl.content.firstChild);

    if (!document.querySelector('script[src*="challenges.cloudflare.com/turnstile"]')) {
      const ts = document.createElement('script');
      ts.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
      ts.async = true;
      ts.defer = true;
      document.head.appendChild(ts);
    }

    const modal = document.getElementById('ah-contact-modal');
    const form = document.getElementById('ah-contact-form');
    const msgEl = form.querySelector('.ah-msg');
    const btnEl = form.querySelector('.ah-submit');

    modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
    modal.querySelector('.ah-modal-close').addEventListener('click', close);
    document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      msgEl.className = 'ah-msg';
      msgEl.textContent = '';

      const tsField = modal.querySelector('[name="cf-turnstile-response"]');
      const turnstileToken = tsField ? tsField.value : '';
      if (!turnstileToken) {
        msgEl.className = 'ah-msg error';
        msgEl.textContent = 'יש להשלים את אימות ה-CAPTCHA';
        return;
      }

      const data = Object.fromEntries(new FormData(form).entries());
      if (!data.fullName || !data.message) {
        msgEl.className = 'ah-msg error';
        msgEl.textContent = 'שם והודעה הם שדות חובה';
        return;
      }

      btnEl.disabled = true;
      btnEl.textContent = 'שולח...';

      try {
        const res = await fetch(API_URL + '/api/contact', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            fullName: data.fullName,
            phone: data.phone || '',
            email: data.email || '',
            message: data.message,
            turnstileToken,
          }),
        });
        const body = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(body.error || 'שגיאה בשליחה');
        msgEl.className = 'ah-msg success';
        msgEl.textContent = '✓ ' + (body.message || 'הפנייה נקלטה בהצלחה! אחזור אלייך בהקדם');
        form.reset();
        if (window.turnstile) window.turnstile.reset();
        setTimeout(close, 2500);
      } catch (err) {
        msgEl.className = 'ah-msg error';
        msgEl.textContent = err.message || 'שגיאה בשליחה, נסי שוב';
      } finally {
        btnEl.disabled = false;
        btnEl.textContent = 'שליחה';
      }
    });
  }

  function open() {
    injectOnce();
    const modal = document.getElementById('ah-contact-modal');
    const msgEl = modal.querySelector('.ah-msg');
    msgEl.className = 'ah-msg';
    msgEl.textContent = '';
    modal.classList.add('open');
    document.body.style.overflow = 'hidden';
    const firstInput = modal.querySelector('input[name="fullName"]');
    if (firstInput) setTimeout(() => firstInput.focus(), 50);
  }

  function close() {
    const modal = document.getElementById('ah-contact-modal');
    if (!modal) return;
    modal.classList.remove('open');
    document.body.style.overflow = '';
  }

  window.openContactModal = open;
  window.closeContactModal = close;

  document.addEventListener('click', (e) => {
    const link = e.target.closest('a[href^="mailto:"]');
    if (!link) return;
    if (link.dataset.noModal === '1') return;
    e.preventDefault();
    open();
  });
})();
