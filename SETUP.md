# Ghetto-PASS — Windows Setup Guide

## Step 1: Install Prerequisites

### Python 3.11+
Download: https://www.python.org/downloads/
During install: CHECK "Add Python to PATH"
Verify: python --version

### Gpg4win
Download: https://gpg4win.org/download.html
Install with default options.
Verify: gpg --version

If gpg is not found after install, add this to your PATH:
  C:\Program Files (x86)\Gpg4win\bin

### Adding to PATH on Windows 10/11
  Start → "Edit the system environment variables"
  → Environment Variables → Path → Edit → New → paste path → OK

---

## Step 2: Set Up the Project

Open Command Prompt or PowerShell in the project folder:

  cd path\to\ring_of_trust

Create and activate a virtual environment:
  python -m venv venv
  venv\Scripts\activate

If PowerShell blocks activation:
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

Install dependencies:
  pip install -r requirements.txt

---

## Step 3: Run

  python app.py

Open: http://127.0.0.1:5000

The first run creates an `admin` account and prints its random password
once in the console. Save it; it is not shown again. To choose the password
yourself instead, set ADMIN_PASSWORD before the first run.

An older database whose admin still uses the old default password
(changeme123!) is forced to set a new one at the next login.

---

## Step 4: Change a Password

Log in and use the **Password** link in the navigation bar.
Changing a password logs out that account's other sessions.

---

## Step 5: Set Up Your Key

After logging in, members set up their PGP key. Either:

  - generate a new key in the browser. The private key and the passphrase
    never leave the browser; members download the private key and a
    revocation certificate and keep them offline. Or:
  - register an existing key: paste the public key and clear-sign the
    one-time challenge shown on the page with it.

The server only ever stores public keys. Gpg4win (Step 1) is still needed:
the server uses gpg to check submitted keys and signatures.

---

## How Key Status Works

  active    — key is in good standing
  inactive  — creditor or admin has marked debtor as not making efforts on a
              confirmed debt
              → debtor can dispute the marking once; an admin keeps or clears it
              → key reactivates when the marking is lifted or the debt is settled
  revoked   — admin has manually revoked the key (irreversible unless admin reinstates)

Debts: only the creditor records a debt, and it has no effect until the
debtor (or an admin) confirms it. Only the creditor or an admin records
payments.

Security flags (opsec) are INFORMATIONAL ONLY.
They never affect key status. They exist so members can signal
operational security concerns (e.g. law enforcement contact)
to the rest of the network.

---

## Project Structure

  app.py                   Main Flask application
  requirements.txt         Python dependencies
  instance/
    rot.db                 SQLite database (auto-created)
  templates/
    index.html             Landing page (login/register only, no graphics)
    base.html              Nav + layout shell
    login.html
    register.html
    generate_keys.html     Key setup: in-browser generation or bring your own
    change_password.html
    dashboard.html
    key_directory.html     Main social page
    add_debt.html
    admin.html
    admin_flags.html       Opsec flag review + revocation panel
  static/css/style.css     All styles
  static/js/app.js         Confirmation prompts
  static/js/keygen.js      In-browser key generation
  static/vendor/openpgp/   OpenPGP.js 6.3.2 (LGPL-3.0), see SOURCE.txt
  static/vendor/qrcode-generator/  QR codes drawn in the browser (MIT), see SOURCE.txt

---

## Environment Variables (optional)

  SECRET_KEY       Flask secret key. Required in production; `python app.py`
                   generates a temporary one (everyone is logged out on restart)
  ADMIN_PASSWORD   Password for the admin account created on first run
  FLASK_DEBUG      Set to 1 to enable the debugger with `python app.py`.
                   Never in production: it can run arbitrary code.
  HOST             Address `python app.py` listens on (default 127.0.0.1, this
                   computer only). HOST=0.0.0.0 lets other devices on your network
                   connect, over plain HTTP: only on a network you trust. Refused
                   while FLASK_DEBUG=1.
  PORT             Port for `python app.py` (default 5000)
  FLAG_THRESHOLD   How many opsec flags trigger the visual warning (default: 3)

Set in PowerShell before running:
  $env:FLAG_THRESHOLD = "5"
  python app.py
