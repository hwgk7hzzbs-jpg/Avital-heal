/* =========================
   script.js
   ✅ Smooth scroll for #anchors
   ✅ Mobile nav toggle (.nav-toggle + .nav-links)
   ✅ Close mobile nav on link click
   ✅ FAQ accordion (robust, works with your .faq-item structure)
   ✅ Analytics tracking via data-track attributes
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

  /* -----------------------
     Analytics tracking (data-track attributes)
     Replaces inline onclick handlers for better CSP compliance
  ----------------------- */
  document.querySelectorAll("[data-track]").forEach((el) => {
    el.addEventListener("click", () => {
      const trackId = el.getAttribute("data-track");
      if (typeof gtag === "function") {
        switch (trackId) {
          case "click_phone":
            gtag("event", "click_phone", { event_category: "contact" });
            break;
          case "click_whatsapp_big":
            gtag("event", "click_whatsapp", { event_label: "big_button" });
            break;
          case "click_whatsapp_float":
            gtag("event", "click_whatsapp", { event_label: "floating_button" });
            break;
        }
      }
    });
  });

  /* -----------------------
     Back-to-top button visibility
  ----------------------- */
  const backToTop = document.querySelector(".back-to-top");
  if (backToTop) {
    window.addEventListener("scroll", () => {
      if (window.scrollY > 600) {
        backToTop.classList.add("visible");
      } else {
        backToTop.classList.remove("visible");
      }
    });
  }
});
