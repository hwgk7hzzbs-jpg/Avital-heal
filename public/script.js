/* =========================
   script.js (FINAL - matches your HTML)
   ✅ Smooth scroll for #anchors
   ✅ Mobile nav toggle (.nav-toggle + .nav-links)
   ✅ Close mobile nav on link click
   ✅ Lightbox modal (optional)
   ✅ FAQ accordion (robust, works with your .faq-item structure)
========================= */

document.addEventListener("DOMContentLoaded", () => {
  /* -----------------------
     Smooth scrolling for anchor links
  ----------------------- */
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener("click", function (e) {
      const targetId = this.getAttribute("href");
      if (!targetId || targetId === "#") return;

      const targetEl = document.querySelector(targetId);
      if (!targetEl) return;

      e.preventDefault();
      targetEl.scrollIntoView({ behavior: "smooth" });
    });
  });

  /* -----------------------
     Mobile menu toggle (matches your HTML)
     .nav-toggle + .nav-links
  ----------------------- */
  const toggleBtn = document.querySelector(".nav-toggle");
  const navLinks = document.querySelector(".nav-links");

  if (toggleBtn && navLinks) {
    toggleBtn.addEventListener("click", () => {
      const isOpen = navLinks.classList.toggle("active");
      toggleBtn.setAttribute("aria-expanded", String(isOpen));
    });

    // Close mobile nav after clicking a link
    navLinks.querySelectorAll("a").forEach((a) => {
      a.addEventListener("click", () => {
        navLinks.classList.remove("active");
        toggleBtn.setAttribute("aria-expanded", "false");
      });
    });
  }

  /* -----------------------
     Lightbox (optional)
  ----------------------- */
  const modal = document.getElementById("imageModal");
  const modalImg = document.getElementById("img01");

  window.openModal = function (src) {
    if (!modal || !modalImg) return;
    modal.style.display = "flex";
    modalImg.src = src;
  };

  window.closeModal = function () {
    if (!modal) return;
    modal.style.display = "none";
  };

  if (modal) {
    window.addEventListener("click", (event) => {
      if (event.target === modal) modal.style.display = "none";
    });
  }

  /* -----------------------
     FAQ Accordion (robust)
     expects:
     .faq-item
       button.faq-q
       div.faq-a (hidden)
  ----------------------- */
  document.querySelectorAll(".faq-q").forEach((btn) => {
    btn.addEventListener("click", () => {
      const item = btn.closest(".faq-item");
      if (!item) return;

      const answer = item.querySelector(".faq-a");
      const icon = btn.querySelector(".faq-icon");

      const expanded = btn.getAttribute("aria-expanded") === "true";
      const nextExpanded = !expanded;

      btn.setAttribute("aria-expanded", String(nextExpanded));
      if (answer) answer.hidden = !nextExpanded;
      if (icon) icon.textContent = nextExpanded ? "−" : "+";
    });
  });
});
