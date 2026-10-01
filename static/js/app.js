// Kept in a separate file so the Content-Security-Policy can block inline scripts.

// Ask before submitting any form marked with data-confirm.
document.querySelectorAll("form[data-confirm]").forEach(function (form) {
  form.addEventListener("submit", function (e) {
    if (!confirm(form.dataset.confirm)) e.preventDefault();
  });
});
