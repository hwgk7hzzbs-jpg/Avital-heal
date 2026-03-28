/**
 * @file info-form.js
 * @description Contact form handler for client info page.
 */

async function handleSubmit(e) {
  e.preventDefault();
  var btn = document.getElementById('submitBtn');
  var msg = document.getElementById('formMsg');
  var form = document.getElementById('contactForm');

  btn.disabled = true;
  btn.textContent = 'שולח...';
  msg.className = 'form-msg';
  msg.style.display = 'none';

  var turnstileEl = document.querySelector('[name="cf-turnstile-response"]');
  var turnstileToken = turnstileEl ? turnstileEl.value : '';

  var data = {
    fullName: document.getElementById('fullName').value.trim(),
    phone: document.getElementById('phone').value.trim(),
    email: document.getElementById('email').value.trim(),
    message: document.getElementById('message').value.trim(),
    turnstileToken: turnstileToken
  };

  try {
    var res = await fetch('https://avital-heal-crm.tgthf7frmp.workers.dev/api/contact', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(data)
    });
    var result = await res.json();

    if (res.ok) {
      msg.textContent = '\u2713 \u05d4\u05e4\u05e0\u05d9\u05d9\u05d4 \u05e0\u05e9\u05dc\u05d7\u05d4 \u05d1\u05d4\u05e6\u05dc\u05d7\u05d4! \u05d0\u05d7\u05d6\u05d5\u05e8 \u05d0\u05dc\u05d9\u05da \u05d1\u05d4\u05e7\u05d3\u05dd.';
      msg.className = 'form-msg success';
      form.reset();
      if (typeof turnstile !== 'undefined') turnstile.reset();
    } else {
      msg.textContent = result.error || '\u05e9\u05d2\u05d9\u05d0\u05d4 \u05d1\u05e9\u05dc\u05d9\u05d7\u05d4, \u05e0\u05e1\u05d5 \u05e9\u05d5\u05d1.';
      msg.className = 'form-msg error';
    }
  } catch (err) {
    msg.textContent = '\u05e9\u05d2\u05d9\u05d0\u05ea \u05ea\u05e7\u05e9\u05d5\u05e8\u05ea, \u05e0\u05e1\u05d5 \u05e9\u05d5\u05d1 \u05de\u05d0\u05d5\u05d7\u05e8 \u05d9\u05d5\u05ea\u05e8.';
    msg.className = 'form-msg error';
  }

  btn.disabled = false;
  btn.textContent = '\u05e9\u05dc\u05d9\u05d7\u05ea \u05e4\u05e0\u05d9\u05d9\u05d4';
  return false;
}
