/* =========================
   script.js (Clean version)
   - Smooth scrolling for anchor links
   - Mobile menu toggle (if navLinks exists)
   - Lightbox modal (if imageModal/img01 exist)
   - FAQ accordion (if .faq-q exists)
========================= */

/* Smooth scrolling for anchor links */
document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
  anchor.addEventListener('click', function (e) {
    const targetId = this.getAttribute('href');

    // ignore empty / invalid anchors
    if (!targetId || targetId === "#") return;

    const targetEl = document.querySelector(targetId);
    if (!targetEl) return;

    e.preventDefault();
    targetEl.scrollIntoView({ behavior: 'smooth' });
  });
});

/* Mobile menu toggle (expects: <div id="navLinks">...) */
function toggleMenu() {
  const nav = document.getElementById('navLinks');
  if (!nav) return;
  nav.classList.toggle('active');
}

/* Lightbox (expects: #imageModal and #img01 in HTML) */
function openModal(src) {
  const modal = document.getElementById('imageModal');
  const img = document.getElementById('img01');
  if (!modal || !img) return;

  modal.style.display = 'flex';
  img.src = src;
}

function closeModal() {
  const modal = document.getElementById('imageModal');
  if (!modal) return;
  modal.style.display = 'none';
}

/* Close modal when clicking outside the image */
window.addEventListener('click', function (event) {
  const modal = document.getElementById('imageModal');
  if (!modal) return;

  if (event.target === modal) {
    modal.style.display = 'none';
  }
});

/* FAQ Accordion (expects: .faq-q button + next sibling .faq-a) */
document.querySelectorAll('.faq-q').forEach((btn) => {
  btn.addEventListener('click', () => {
    const expanded = btn.getAttribute('aria-expanded') === 'true';
    const answer = btn.nextElementSibling;
    const icon = btn.querySelector('.faq-icon');

    btn.setAttribute('aria-expanded', String(!expanded));
    if (answer) answer.hidden = expanded;
    if (icon) icon.textContent = expanded ? '+' : '–';
  });
});
