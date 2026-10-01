// Kept in a separate file so the Content-Security-Policy can block inline scripts.

// Ask before submitting any form marked with data-confirm.
document.querySelectorAll("form[data-confirm]").forEach(function (form) {
  form.addEventListener("submit", function (e) {
    if (!confirm(form.dataset.confirm)) e.preventDefault();
  });
});

// Key generation: check the passphrases match and show progress.
var keygen = document.getElementById("keygen-form");
if (keygen) {
  keygen.addEventListener("submit", function (e) {
    var p1 = keygen.querySelector("[name=passphrase]").value;
    var p2 = document.getElementById("confirm").value;
    if (p1 !== p2) { e.preventDefault(); alert("Passphrases do not match."); return; }
    var btn = document.getElementById("gen-btn");
    btn.textContent = "Generating… (this may take a moment)";
    btn.disabled = true;
  });
}
