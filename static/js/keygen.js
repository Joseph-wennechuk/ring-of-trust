// Key setup: generates the member's keypair in this browser with OpenPGP.js.
// Only the public key and a signature over the server's one-time challenge are
// submitted; the private key and passphrase never leave the page.
(function () {
  var root = document.getElementById("keygen");
  if (!root) return;
  function $(id) { return document.getElementById(id); }

  var TWO_YEARS = 2 * 365 * 24 * 60 * 60;
  var generated = null;

  async function generate(passphrase) {
    var result = await openpgp.generateKey({
      type: "ecc", curve: "curve25519Legacy",   // Ed25519 + Curve25519, v4: GnuPG-compatible
      userIDs: [{ name: root.dataset.name, email: root.dataset.email }],
      passphrase: passphrase,
      keyExpirationTime: TWO_YEARS,
      format: "armored",
    });
    var unlocked = await openpgp.decryptKey({
      privateKey: await openpgp.readPrivateKey({ armoredKey: result.privateKey }),
      passphrase: passphrase,
    });
    var proof = await openpgp.sign({
      message: await openpgp.createCleartextMessage({ text: root.dataset.challenge }),
      signingKeys: unlocked,
    });
    return {
      privateKey: result.privateKey,              // still passphrase-protected
      publicKey: result.publicKey,
      revocationCertificate: result.revocationCertificate,
      fingerprint: unlocked.getFingerprint().toUpperCase(),
      proof: proof,
    };
  }
  window.GhettoPassKeygen = { generate: generate };   // used by the test harness

  function saveFile(filename, text) {
    var url = URL.createObjectURL(new Blob([text], { type: "application/pgp-keys" }));
    var link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
  }

  $("kg-generate").addEventListener("click", async function () {
    var pass = $("kg-passphrase").value, confirm = $("kg-confirm").value;
    if (pass.length < 12) { $("kg-status").textContent = "Passphrase must be at least 12 characters."; return; }
    if (pass !== confirm) { $("kg-status").textContent = "Passphrases do not match."; return; }
    this.disabled = true;
    $("kg-status").textContent = "Generating… this can take a few seconds.";
    try {
      generated = await generate(pass);
    } catch (err) {
      this.disabled = false;
      $("kg-status").textContent = "Key generation failed: " + err.message;
      return;
    }
    $("kg-passphrase").value = $("kg-confirm").value = "";
    $("kg-fingerprint").textContent = generated.fingerprint;
    $("kg-public-key").value = generated.publicKey;
    $("kg-signed-proof").value = generated.proof;
    $("keygen-step1").hidden = true;
    $("keygen-step2").hidden = false;
  });

  $("kg-save-private").addEventListener("click", function () {
    saveFile(root.dataset.name + "_private_key.asc", generated.privateKey);
  });
  $("kg-save-revocation").addEventListener("click", function () {
    saveFile(root.dataset.name + "_revocation_certificate.asc", generated.revocationCertificate);
  });
  // Drawn here in the browser: the private key never goes to the server.
  $("kg-show-qr").addEventListener("click", function () {
    var img = $("kg-private-qr");
    if (img.hidden) {
      var qr = qrcode(0, "L");   // smallest version that fits; L holds the most data
      qr.addData(generated.privateKey);
      qr.make();
      img.src = qr.createDataURL(4, 4);
      img.hidden = false;
      this.textContent = "Hide private key QR";
    } else {
      img.hidden = true;
      img.removeAttribute("src");
      this.textContent = "Show private key QR";
    }
  });

  $("kg-saved").addEventListener("change", function () {
    $("kg-register").disabled = !this.checked;
  });
})();
