# Ring of Trust — Windows Setup Guide

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

Default admin login: admin / changeme123!
CHANGE THIS IMMEDIATELY (see below).

---

## Step 4: Change Admin Password

  python
  >>> from app import app, db, User
  >>> from werkzeug.security import generate_password_hash
  >>> with app.app_context():
  ...     u = User.query.filter_by(username='admin').first()
  ...     u.password = generate_password_hash('your-new-password')
  ...     db.session.commit()
  >>> exit()

---

## How Key Status Works

  active    — key is in good standing
  inactive  — creditor or admin has marked debtor as not making efforts on a debt
              → debtor can dispute this publicly (visible on their key card)
              → key reactivates when creditor confirms efforts resume or debt is settled
  revoked   — admin has manually revoked the key (irreversible unless admin reinstates)

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
    gnupg/                 Server-side GPG keyring (public keys only)
  templates/
    index.html             Landing page (login/register only, no graphics)
    base.html              Nav + layout shell
    login.html
    register.html
    generate_keys.html
    show_keys.html         QR display + download
    dashboard.html
    key_directory.html     Main social page
    add_debt.html
    admin.html
    admin_flags.html       Opsec flag review + revocation panel
  static/css/style.css     All styles

---

## Environment Variables (optional)

  SECRET_KEY       Flask secret key (auto-generated if not set)
  FLAG_THRESHOLD   How many opsec flags trigger the visual warning (default: 3)

Set in PowerShell before running:
  $env:FLAG_THRESHOLD = "5"
  python app.py
