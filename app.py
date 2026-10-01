import os
import io
import re
import hmac
import math
import time
import base64
import secrets
import tempfile
from collections import defaultdict, deque
from datetime import datetime, timedelta
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, abort, g)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import gnupg
import qrcode

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

# `python app.py` runs the local development server. Anything else (gunicorn,
# waitress, ...) is treated as production and gets the strict settings.
RUNNING_DEV_SERVER = __name__ == "__main__"

app = Flask(__name__)

secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    if not RUNNING_DEV_SERVER:
        raise RuntimeError("SECRET_KEY must be set when running in production.")
    secret_key = secrets.token_hex(32)
app.secret_key = secret_key

app.config.update(
    SQLALCHEMY_DATABASE_URI="sqlite:///rot.db",
    SQLALCHEMY_TRACK_MODIFICATIONS=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Browsers only send Secure cookies over HTTPS, so the dev server needs it off.
    SESSION_COOKIE_SECURE=not RUNNING_DEV_SERVER,
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=64 * 1024,
)

FLAG_THRESHOLD = int(os.environ.get("FLAG_THRESHOLD", 3))

# Only used to spot the old hard-coded admin password and force a change.
LEGACY_DEFAULT_PASSWORD = "changeme123!"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024
USERNAME_RE = re.compile(r"[A-Za-z0-9_.-]{3,32}")
EMAIL_RE    = re.compile(r"[^@\s]+@[^@\s]+\.[^@\s]+")

db = SQLAlchemy(app)

# Members create their keys themselves (in the browser, or with their own
# GnuPG). The server only ever sees public keys, checked with a throwaway
# keyring per submission, so it holds no keyring of its own.

class KeyCheckError(Exception):
    pass


def key_challenge_text(username, nonce):
    # Plain characters only, so it survives `echo ... | gpg --clearsign` on any shell.
    return f"Ghetto-PASS key ownership proof for {username}: {nonce}"


def check_submitted_key(armored_public_key, signed_proof, challenge):
    """Validate a member's public key and their signature over `challenge`.

    Returns (fingerprint, armored public key stripped of third-party
    signatures). Raises KeyCheckError with a message fit to show the member.
    """
    if "PRIVATE KEY BLOCK" in armored_public_key:
        raise KeyCheckError("That is a PRIVATE key. Never paste it anywhere; "
                            "paste the PUBLIC key block instead.")
    if "BEGIN PGP PUBLIC KEY BLOCK" not in armored_public_key:
        raise KeyCheckError("Paste an ASCII-armored public key "
                            "(it starts with -----BEGIN PGP PUBLIC KEY BLOCK-----).")
    if "BEGIN PGP SIGNED MESSAGE" not in signed_proof:
        raise KeyCheckError("The proof must be a clear-signed message "
                            "(it starts with -----BEGIN PGP SIGNED MESSAGE-----).")

    with tempfile.TemporaryDirectory() as home:
        keyring = gnupg.GPG(gnupghome=home)
        # Signature notations can hold raw binary (OpenPGP.js adds a random
        # salt to every signature), which GnuPG echoes on its status output.
        # Latin-1 decodes any byte; everything checked here is ASCII.
        keyring.encoding = "latin-1"
        imported = keyring.import_keys(armored_public_key)
        fingerprints = set(imported.fingerprints)
        if len(fingerprints) != 1:
            raise KeyCheckError("Paste exactly one public key.")
        fingerprint = fingerprints.pop()
        if keyring.list_keys(secret=True):
            raise KeyCheckError("Paste only the public key.")

        info = keyring.list_keys(keys=[fingerprint])[0]
        if info["trust"] == "r":
            raise KeyCheckError("This key has been revoked.")
        if info["trust"] == "e" or (info["expires"] and int(info["expires"]) <= time.time()):
            raise KeyCheckError("This key has expired.")
        algo, length = info["algo"], int(info["length"] or 0)
        if algo == "1" and length < 3072:   # RSA
            raise KeyCheckError("RSA keys must be at least 3072 bits.")
        if algo not in ("1", "19", "22"):   # RSA, ECDSA, EdDSA
            raise KeyCheckError("Unsupported key type. Use Ed25519 or RSA 3072+.")

        verified = keyring.decrypt(signed_proof)
        if not verified.valid or verified.pubkey_fingerprint != fingerprint:
            raise KeyCheckError("The proof was not signed by this key.")
        if verified.data.decode("utf-8", "replace").strip() != challenge:
            raise KeyCheckError("The signed text doesn't match the challenge shown on this page.")

        cleaned = keyring.export_keys(fingerprint, minimal=True)
        if not cleaned:
            raise KeyCheckError("Could not read this key.")
        return fingerprint, cleaned


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(db.Model):
    id           = db.Column(db.Integer, primary_key=True)
    username     = db.Column(db.String(80),  unique=True, nullable=False)
    email        = db.Column(db.String(120), unique=True, nullable=False)
    password     = db.Column(db.String(200), nullable=False)
    approved     = db.Column(db.Boolean, default=False)
    is_admin     = db.Column(db.Boolean, default=False)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow)
    has_keys     = db.Column(db.Boolean, default=False)
    fingerprint  = db.Column(db.String(40), unique=True, nullable=True)
    public_key   = db.Column(db.Text, nullable=True)
    # Key status: 'active' | 'inactive' | 'revoked'
    # 'inactive' = creditor/admin flagged debtor as not making efforts
    key_status   = db.Column(db.String(16), default="active")
    # Debt dispute: debtor can dispute an inactive status
    debt_disputed = db.Column(db.Boolean, default=False)
    dispute_note  = db.Column(db.Text, nullable=True)
    revoked_at    = db.Column(db.DateTime, nullable=True)
    revoke_note   = db.Column(db.Text, nullable=True)

    debts          = db.relationship("Debt", foreign_keys="Debt.debtor_id",   back_populates="debtor")
    credits        = db.relationship("Debt", foreign_keys="Debt.creditor_id", back_populates="creditor")
    annotations    = db.relationship("Annotation", back_populates="author",   foreign_keys="Annotation.author_id")
    flags_received = db.relationship("CompromiseFlag", foreign_keys="CompromiseFlag.target_id",  back_populates="target")
    flags_made     = db.relationship("CompromiseFlag", foreign_keys="CompromiseFlag.flagger_id", back_populates="flagger")


class KeySignature(db.Model):
    id        = db.Column(db.Integer, primary_key=True)
    signer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    target_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    note      = db.Column(db.String(300), nullable=True)
    signed_at = db.Column(db.DateTime, default=datetime.utcnow)
    signer    = db.relationship("User", foreign_keys=[signer_id])
    target    = db.relationship("User", foreign_keys=[target_id])


class Annotation(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    target_id  = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    author_id  = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body       = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    target     = db.relationship("User", foreign_keys=[target_id])
    author     = db.relationship("User", back_populates="annotations", foreign_keys=[author_id])


class Debt(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    debtor_id   = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    creditor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    description = db.Column(db.String(300), nullable=False)
    amount      = db.Column(db.Float, nullable=False)
    currency    = db.Column(db.String(10), default="USD")
    active      = db.Column(db.Boolean, default=True)
    # Recorded by the creditor; has no effect until the debtor (or an admin) confirms it
    confirmed    = db.Column(db.Boolean, default=False)
    confirmed_at = db.Column(db.DateTime, nullable=True)
    # Creditor/admin can mark debtor as not making efforts on this debt
    efforts_ok  = db.Column(db.Boolean, default=True)
    efforts_note = db.Column(db.Text, nullable=True)
    efforts_updated_at = db.Column(db.DateTime, nullable=True)
    # Debtor's dispute of a no-efforts marking: None | 'open' (awaiting an admin)
    # | 'upheld' (admin kept the marking). An admin clearing it resets to None.
    dispute_status = db.Column(db.String(16), nullable=True)
    dispute_note   = db.Column(db.Text, nullable=True)
    disputed_at    = db.Column(db.DateTime, nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at  = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    debtor      = db.relationship("User", foreign_keys=[debtor_id],  back_populates="debts")
    creditor    = db.relationship("User", foreign_keys=[creditor_id], back_populates="credits")


FLAG_REASONS = [
    "Known law enforcement contact",
    "Device or communications believed seized",
    "Key material believed compromised",
    "Unusual network or communication patterns",
    "Identity verification failure",
    "Reported by trusted third party",
    "Other — see notes",
]


class CompromiseFlag(db.Model):
    id          = db.Column(db.Integer, primary_key=True)
    target_id   = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    flagger_id  = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    reason      = db.Column(db.String(100), nullable=False)
    notes       = db.Column(db.Text, nullable=True)
    created_at  = db.Column(db.DateTime, default=datetime.utcnow)
    # None = pending, True = upheld, False = dismissed
    upheld      = db.Column(db.Boolean, nullable=True)
    reviewed_at = db.Column(db.DateTime, nullable=True)
    reviewer_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    target   = db.relationship("User", foreign_keys=[target_id],  back_populates="flags_received")
    flagger  = db.relationship("User", foreign_keys=[flagger_id], back_populates="flags_made")
    reviewer = db.relationship("User", foreign_keys=[reviewer_id])


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def password_marker(user):
    """Ties a session to the password it was created with, so changing the
    password logs out every other session."""
    return user.password[-16:]


def current_user():
    """The logged-in user, re-checked against the database on every request."""
    if "user" not in g:
        user = None
        user_id = session.get("user_id")
        if user_id is not None:
            user = db.session.get(User, user_id)
            if (not user or not user.approved
                    or session.get("pw_marker") != password_marker(user)):
                session.clear()
                user = None
        g.user = user
    return g.user


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user():
            return redirect(url_for("login"))
        if (session.get("must_change_password")
                and request.endpoint not in ("change_password", "logout")):
            return redirect(url_for("change_password"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if not current_user().is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


@app.before_request
def check_csrf():
    if request.method == "POST":
        sent     = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400, "Missing or invalid form token. Reload the page and try again.")


CONTENT_SECURITY_POLICY = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "form-action 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "object-src 'none'",
])


@app.after_request
def set_security_headers(response):
    response.headers["Content-Security-Policy"] = CONTENT_SECURITY_POLICY
    response.headers["X-Content-Type-Options"]  = "nosniff"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["Referrer-Policy"]         = "no-referrer"
    if request.endpoint != "static":
        # Pages show private data, so keep them out of browser and proxy caches.
        response.headers["Cache-Control"] = "no-store"
    if app.config["SESSION_COOKIE_SECURE"]:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.context_processor
def inject_globals():
    return dict(current_user=current_user(), FLAG_THRESHOLD=FLAG_THRESHOLD,
                csrf_token=csrf_token)


# Failed logins per client address and per username. Kept in memory, so it is
# per-process and resets on restart; run a single worker or move this to Redis.
LOGIN_MAX_FAILURES = 5
LOGIN_WINDOW       = 15 * 60
_login_failures    = defaultdict(deque)
# Checked when the username doesn't exist, so both cases take the same time.
_DUMMY_HASH        = generate_password_hash(secrets.token_hex(16))


def _login_keys(username):
    return (f"ip:{request.remote_addr}", f"user:{username.lower()}")


def login_blocked(username):
    now = time.monotonic()
    blocked = False
    for key in _login_keys(username):
        failures = _login_failures.get(key)
        if not failures:
            continue
        while failures and now - failures[0] > LOGIN_WINDOW:
            failures.popleft()
        if not failures:
            del _login_failures[key]
        elif len(failures) >= LOGIN_MAX_FAILURES:
            blocked = True
    return blocked


def record_login_failure(username):
    now = time.monotonic()
    for key in _login_keys(username):
        _login_failures[key].append(now)


def clear_login_failures(username):
    for key in _login_keys(username):
        _login_failures.pop(key, None)


def parse_amount(raw):
    """A positive, finite money amount, or None."""
    try:
        amount = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(amount) or amount <= 0 or amount > 1e12:
        return None
    return round(amount, 2)


def make_qr_b64(data: str):
    """PNG QR code as base64, or None if the data is too big for a QR code
    (e.g. a large RSA public key)."""
    try:
        img = qrcode.make(data, error_correction=qrcode.constants.ERROR_CORRECT_L)
    except (qrcode.exceptions.DataOverflowError, ValueError):
        # Too much data: qrcode raises ValueError ("Invalid version") rather
        # than DataOverflowError when no QR version is big enough.
        return None
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def recheck_debt_status(debtor: User):
    """
    Key goes inactive if ANY confirmed, active debt on this user has efforts_ok=False.
    Key returns to active only when all of them have efforts_ok=True.
    Revoked status is untouched by this function, but the dispute summary on
    the user (shown next to their key) is always refreshed.
    """
    open_dispute = (Debt.query
                    .filter_by(debtor_id=debtor.id, active=True, confirmed=True,
                               dispute_status="open")
                    .order_by(Debt.disputed_at.desc()).first())
    debtor.debt_disputed = open_dispute is not None
    debtor.dispute_note  = open_dispute.dispute_note if open_dispute else None
    if debtor.key_status != "revoked":
        bad_debts = Debt.query.filter_by(
            debtor_id=debtor.id, active=True, confirmed=True, efforts_ok=False
        ).count()
        if bad_debts > 0:
            debtor.key_status = "inactive"
        elif debtor.key_status == "inactive":
            debtor.key_status = "active"
    db.session.commit()


# ---------------------------------------------------------------------------
# Routes – auth
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("index.html")


def password_problem(password):
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return "Password is too long."
    if password == LEGACY_DEFAULT_PASSWORD:
        return "That password is public. Choose another."
    return None


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        if not USERNAME_RE.fullmatch(username):
            flash("Username must be 3–32 characters: letters, digits, dot, dash or underscore.", "error")
            return render_template("register.html")
        if len(email) > 120 or not EMAIL_RE.fullmatch(email):
            flash("Enter a valid email address.", "error")
            return render_template("register.html")
        problem = password_problem(password)
        if problem:
            flash(problem, "error")
            return render_template("register.html")
        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "error")
            return render_template("register.html")
        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "error")
            return render_template("register.html")
        db.session.add(User(username=username, email=email,
                            password=generate_password_hash(password)))
        db.session.commit()
        flash("Registration received. You will be notified once approved.", "info")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()[:80]
        password = request.form.get("password", "")[:MAX_PASSWORD_LENGTH]
        if login_blocked(username):
            flash("Too many failed attempts. Try again in 15 minutes.", "error")
            return render_template("login.html"), 429
        user = User.query.filter_by(username=username).first()
        valid = check_password_hash(user.password if user else _DUMMY_HASH, password)
        if not user or not valid:
            record_login_failure(username)
            flash("Invalid credentials.", "error")
            return render_template("login.html")
        clear_login_failures(username)
        if not user.approved:
            flash("Your account is pending approval.", "info")
            return render_template("login.html")
        session.clear()   # fresh session, fresh CSRF token
        session.permanent    = True
        session["user_id"]   = user.id
        session["pw_marker"] = password_marker(user)
        if password == LEGACY_DEFAULT_PASSWORD:
            session["must_change_password"] = True
            flash("This account still uses the default password. Set a new one now.", "warning")
            return redirect(url_for("change_password"))
        return redirect(url_for("generate_keys") if not user.has_keys else url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("index"))


@app.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    user = current_user()
    if request.method == "POST":
        current = request.form.get("current_password", "")[:MAX_PASSWORD_LENGTH]
        new     = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        if not check_password_hash(user.password, current):
            flash("Current password is incorrect.", "error")
            return render_template("change_password.html")
        problem = password_problem(new)
        if problem:
            flash(problem, "error")
            return render_template("change_password.html")
        if new != confirm:
            flash("New passwords do not match.", "error")
            return render_template("change_password.html")
        if new == current:
            flash("New password must be different from the current one.", "error")
            return render_template("change_password.html")
        user.password = generate_password_hash(new)
        db.session.commit()
        # Other sessions now fail the marker check; keep this one alive.
        session.pop("must_change_password", None)
        session["pw_marker"] = password_marker(user)
        flash("Password changed. Other sessions have been logged out.", "success")
        return redirect(url_for("generate_keys") if not user.has_keys else url_for("dashboard"))
    return render_template("change_password.html")


# ---------------------------------------------------------------------------
# Routes – key generation
# ---------------------------------------------------------------------------

@app.route("/generate-keys", methods=["GET", "POST"])
@login_required
def generate_keys():
    """Register the member's public key. The private key is created on their
    own device; they prove they hold it by signing a one-time challenge."""
    user = current_user()
    if user.has_keys:
        return redirect(url_for("dashboard"))

    if "key_nonce" not in session:
        session["key_nonce"] = secrets.token_urlsafe(18)
    challenge = key_challenge_text(user.username, session["key_nonce"])

    if request.method == "POST":
        public_key   = request.form.get("public_key", "").strip()
        signed_proof = request.form.get("signed_proof", "").strip()
        try:
            fingerprint, public_key = check_submitted_key(public_key, signed_proof, challenge)
        except KeyCheckError as e:
            flash(str(e), "error")
            return render_template("generate_keys.html", challenge=challenge)
        if User.query.filter(User.fingerprint == fingerprint, User.id != user.id).first():
            flash("That key is already registered to another member.", "error")
            return render_template("generate_keys.html", challenge=challenge)

        user.fingerprint = fingerprint
        user.public_key  = public_key
        user.has_keys    = True
        user.key_status  = "active"
        db.session.commit()
        session.pop("key_nonce", None)   # single use
        flash("Your public key is registered.", "success")
        return redirect(url_for("dashboard"))

    return render_template("generate_keys.html", challenge=challenge)


# ---------------------------------------------------------------------------
# Routes – dashboard & key directory
# ---------------------------------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():
    user = current_user()
    if not user.has_keys:
        return redirect(url_for("generate_keys"))
    pending_count     = User.query.filter_by(approved=False).count() if user.is_admin else 0
    flag_review_count = CompromiseFlag.query.filter_by(upheld=None).count() if user.is_admin else 0
    dispute_count     = (Debt.query.filter_by(active=True, dispute_status="open").count()
                         if user.is_admin else 0)
    # Debts where I am creditor and have marked no-efforts
    my_inactive_credits = Debt.query.filter_by(creditor_id=user.id, active=True,
                                               confirmed=True, efforts_ok=False).count()
    # My own key status info
    my_bad_debts = Debt.query.filter_by(debtor_id=user.id, active=True,
                                        confirmed=True, efforts_ok=False).count()
    # Debts recorded against me that I haven't confirmed or rejected yet
    my_pending_debts = Debt.query.filter_by(debtor_id=user.id, active=True,
                                            confirmed=False).count()
    return render_template("dashboard.html",
        fingerprint_qr=make_qr_b64(user.fingerprint) if user.fingerprint else None,
        public_key_qr=make_qr_b64(user.public_key) if user.public_key else None,
        pending_count=pending_count,
        flag_review_count=flag_review_count,
        dispute_count=dispute_count,
        my_bad_debts=my_bad_debts,
        my_inactive_credits=my_inactive_credits,
        my_pending_debts=my_pending_debts,
    )


@app.route("/keys")
@login_required
def key_directory():
    user  = current_user()
    users = User.query.filter_by(approved=True, has_keys=True).all()
    data  = []
    for u in users:
        sigs    = KeySignature.query.filter_by(target_id=u.id).all()
        annots  = Annotation.query.filter_by(target_id=u.id).order_by(Annotation.created_at.desc()).all()
        debts   = Debt.query.filter_by(debtor_id=u.id, active=True).all()
        flags   = CompromiseFlag.query.filter_by(target_id=u.id).order_by(CompromiseFlag.created_at.desc()).all()
        already_signed  = any(s.signer_id == user.id for s in sigs)
        already_flagged = any(f.flagger_id == user.id and f.upheld is None for f in flags)
        # Can this user mark efforts on any of u's debts?
        can_mark_efforts = any(
            d.creditor_id == user.id or user.is_admin for d in debts
        )
        data.append(dict(
            user=u, sigs=sigs, annots=annots, debts=debts, flags=flags,
            already_signed=already_signed,
            already_flagged=already_flagged,
            open_flag_count=sum(1 for f in flags if f.upheld is None),
            can_sign=(u.id != user.id and not already_signed and u.key_status != "revoked"),
            can_flag=(u.id != user.id and not already_flagged and u.key_status != "revoked"),
            can_mark_efforts=can_mark_efforts,
            is_own=(u.id == user.id),
        ))
    return render_template("key_directory.html", data=data, me=user,
                           flag_reasons=FLAG_REASONS)


@app.route("/sign-key/<int:target_id>", methods=["POST"])
@login_required
def sign_key(target_id):
    user   = current_user()
    target = db.get_or_404(User, target_id)
    if target.id == user.id:
        flash("You cannot sign your own key.", "error")
        return redirect(url_for("key_directory"))
    if target.key_status == "revoked":
        flash("Cannot sign a revoked key.", "error")
        return redirect(url_for("key_directory"))
    if KeySignature.query.filter_by(signer_id=user.id, target_id=target_id).first():
        flash("You have already signed this key.", "info")
        return redirect(url_for("key_directory"))
    note = request.form.get("note", "").strip()[:300]
    db.session.add(KeySignature(signer_id=user.id, target_id=target_id, note=note or None))
    db.session.commit()
    flash(f"You have signed {target.username}'s key.", "success")
    return redirect(url_for("key_directory"))


@app.route("/annotate/<int:target_id>", methods=["POST"])
@login_required
def annotate(target_id):
    db.get_or_404(User, target_id)
    body = request.form.get("body", "").strip()
    if not body:
        flash("Annotation cannot be empty.", "error")
        return redirect(url_for("key_directory"))
    db.session.add(Annotation(target_id=target_id,
                              author_id=session["user_id"], body=body[:1000]))
    db.session.commit()
    flash("Annotation added.", "success")
    return redirect(url_for("key_directory"))


# ---------------------------------------------------------------------------
# Routes – debt tracking
# ---------------------------------------------------------------------------

@app.route("/debt/add", methods=["GET", "POST"])
@login_required
def add_debt():
    """The creditor records a debt owed to them; it counts once the debtor confirms."""
    user  = current_user()
    peers = User.query.filter(User.approved.is_(True), User.has_keys.is_(True),
                              User.id != user.id).all()
    if request.method == "POST":
        peer_ids    = {p.id for p in peers}
        debtor_id   = request.form.get("debtor_id", type=int)
        description = request.form.get("description", "").strip()[:300]
        amount      = parse_amount(request.form.get("amount"))
        currency    = request.form.get("currency", "USD").strip().upper()[:10]
        if debtor_id not in peer_ids:
            flash("Pick the member who owes you from the list.", "error")
            return render_template("add_debt.html", peers=peers, me=user)
        if not description:
            flash("Description is required.", "error")
            return render_template("add_debt.html", peers=peers, me=user)
        if amount is None:
            flash("Amount must be a positive number.", "error")
            return render_template("add_debt.html", peers=peers, me=user)
        if not currency.isalnum():
            flash("Currency must be letters or digits, e.g. USD.", "error")
            return render_template("add_debt.html", peers=peers, me=user)
        db.session.add(Debt(debtor_id=debtor_id, creditor_id=user.id,
                            description=description, amount=amount, currency=currency))
        db.session.commit()
        flash("Debt recorded. It takes effect once the debtor confirms it.", "success")
        return redirect(url_for("key_directory"))
    return render_template("add_debt.html", peers=peers, me=user)


@app.route("/debt/confirm/<int:debt_id>", methods=["POST"])
@login_required
def confirm_debt(debt_id):
    """The debtor (or an admin) accepts a pending debt."""
    debt = db.get_or_404(Debt, debt_id)
    user = current_user()
    if user.id != debt.debtor_id and not user.is_admin:
        flash("Only the debtor or an admin can confirm this debt.", "error")
        return redirect(url_for("key_directory"))
    if debt.confirmed or not debt.active:
        flash("This debt is not awaiting confirmation.", "info")
        return redirect(url_for("key_directory"))
    debt.confirmed    = True
    debt.confirmed_at = datetime.utcnow()
    db.session.commit()
    recheck_debt_status(debt.debtor)
    flash("Debt confirmed.", "success")
    return redirect(url_for("key_directory"))


@app.route("/debt/withdraw/<int:debt_id>", methods=["POST"])
@login_required
def withdraw_debt(debt_id):
    """A pending debt can be rejected by the debtor or cancelled by the creditor."""
    debt = db.get_or_404(Debt, debt_id)
    user = current_user()
    if user.id not in (debt.debtor_id, debt.creditor_id) and not user.is_admin:
        flash("Not authorised.", "error")
        return redirect(url_for("key_directory"))
    if debt.confirmed:
        flash("A confirmed debt can only be reduced or settled by the creditor.", "error")
        return redirect(url_for("key_directory"))
    db.session.delete(debt)
    db.session.commit()
    flash("Pending debt removed.", "info")
    return redirect(url_for("key_directory"))


@app.route("/debt/reduce/<int:debt_id>", methods=["POST"])
@login_required
def reduce_debt(debt_id):
    """Only the creditor (or an admin) records payments against a confirmed debt."""
    debt = db.get_or_404(Debt, debt_id)
    user = current_user()
    if user.id != debt.creditor_id and not user.is_admin:
        flash("Only the creditor or an admin can reduce a debt.", "error")
        return redirect(url_for("key_directory"))
    if not debt.confirmed or not debt.active:
        flash("Only confirmed, outstanding debts can be reduced.", "error")
        return redirect(url_for("key_directory"))
    amount = parse_amount(request.form.get("amount"))
    if amount is None:
        flash("Amount must be a positive number.", "error")
        return redirect(url_for("key_directory"))
    debt.amount = max(0.0, round(debt.amount - amount, 2))
    if debt.amount == 0:
        debt.active         = False
        debt.efforts_ok     = True   # settled — clear any no-efforts flag
        debt.dispute_status = None
    debt.updated_at = datetime.utcnow()
    db.session.commit()
    recheck_debt_status(debt.debtor)
    flash("Debt settled." if not debt.active else "Debt updated.", "success")
    return redirect(url_for("key_directory"))


@app.route("/debt/set-efforts/<int:debt_id>", methods=["POST"])
@login_required
def set_efforts(debt_id):
    """Creditor or admin marks whether debtor is making efforts on this debt."""
    debt = db.get_or_404(Debt, debt_id)
    user = current_user()
    if user.id != debt.creditor_id and not user.is_admin:
        flash("Only the creditor or an admin can update effort status.", "error")
        return redirect(url_for("key_directory"))
    if not debt.confirmed or not debt.active:
        flash("Effort status only applies to confirmed, outstanding debts.", "error")
        return redirect(url_for("key_directory"))
    efforts_ok   = request.form.get("efforts_ok") == "1"
    efforts_note = request.form.get("efforts_note", "").strip()[:500]
    if efforts_ok or debt.efforts_ok:
        # Lifting a marking, or making a new one: any earlier dispute is moot.
        debt.dispute_status = None
        debt.dispute_note   = None
        debt.disputed_at    = None
    debt.efforts_ok          = efforts_ok
    debt.efforts_note        = efforts_note or None
    debt.efforts_updated_at  = datetime.utcnow()
    db.session.commit()
    recheck_debt_status(debt.debtor)
    status = "making efforts" if efforts_ok else "NOT making efforts"
    flash(f"Debt effort status updated: debtor is {status}.", "info")
    return redirect(url_for("key_directory"))


@app.route("/debt/dispute/<int:debt_id>", methods=["POST"])
@login_required
def dispute_debt(debt_id):
    """Debtor disputes a no-efforts marking; an admin then keeps or clears it."""
    debt = db.get_or_404(Debt, debt_id)
    user = current_user()
    if user.id != debt.debtor_id:
        flash("Only the debtor can dispute this.", "error")
        return redirect(url_for("key_directory"))
    if not debt.confirmed or not debt.active or debt.efforts_ok:
        flash("This debt is not currently marked as no-efforts.", "info")
        return redirect(url_for("key_directory"))
    if debt.dispute_status == "open":
        flash("Your dispute is already waiting for an admin.", "info")
        return redirect(url_for("key_directory"))
    if debt.dispute_status == "upheld":
        flash("An admin has already reviewed this marking.", "info")
        return redirect(url_for("key_directory"))
    note = request.form.get("dispute_note", "").strip()[:1000]
    debt.dispute_status = "open"
    debt.dispute_note   = note or "Debtor disputes the no-efforts marking."
    debt.disputed_at    = datetime.utcnow()
    db.session.commit()
    recheck_debt_status(debt.debtor)
    flash("Dispute submitted. An admin will review it; your key stays inactive until then.", "info")
    return redirect(url_for("key_directory"))


# ---------------------------------------------------------------------------
# Routes – opsec / compromise flags (informational only, no key status effect)
# ---------------------------------------------------------------------------

@app.route("/flag/<int:target_id>", methods=["POST"])
@login_required
def flag_key(target_id):
    user   = current_user()
    target = db.get_or_404(User, target_id)
    if target.id == user.id:
        flash("You cannot flag your own key.", "error")
        return redirect(url_for("key_directory"))
    if target.key_status == "revoked":
        flash("Key is already revoked.", "info")
        return redirect(url_for("key_directory"))
    if CompromiseFlag.query.filter_by(flagger_id=user.id,
                                       target_id=target_id, upheld=None).first():
        flash("You already have an open security flag for this key.", "info")
        return redirect(url_for("key_directory"))
    reason = request.form.get("reason", "").strip()
    notes  = request.form.get("notes",  "").strip()[:2000]
    if reason not in FLAG_REASONS:
        flash("Invalid reason selected.", "error")
        return redirect(url_for("key_directory"))
    db.session.add(CompromiseFlag(target_id=target_id, flagger_id=user.id,
                                   reason=reason, notes=notes or None))
    db.session.commit()
    flash(f"Security flag submitted for {target.username}. An admin will review.", "info")
    return redirect(url_for("key_directory"))


# ---------------------------------------------------------------------------
# Routes – admin
# ---------------------------------------------------------------------------

@app.route("/admin")
@admin_required
def admin_panel():
    pending    = User.query.filter_by(approved=False).all()
    all_users  = User.query.order_by(User.created_at.desc()).all()
    flag_count = CompromiseFlag.query.filter_by(upheld=None).count()
    return render_template("admin.html", pending=pending,
                           all_users=all_users, flag_count=flag_count)


@app.route("/admin/approve/<int:user_id>", methods=["POST"])
@admin_required
def approve_user(user_id):
    user = db.get_or_404(User, user_id)
    user.approved = True
    db.session.commit()
    flash(f"{user.username} approved.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/reject/<int:user_id>", methods=["POST"])
@admin_required
def reject_user(user_id):
    user = db.get_or_404(User, user_id)
    if user.approved:
        flash("Only pending registrations can be rejected.", "error")
        return redirect(url_for("admin_panel"))
    db.session.delete(user)
    db.session.commit()
    flash("User rejected and removed.", "info")
    return redirect(url_for("admin_panel"))


@app.route("/admin/toggle-admin/<int:user_id>", methods=["POST"])
@admin_required
def toggle_admin(user_id):
    user = db.get_or_404(User, user_id)
    if user.id == current_user().id:
        flash("You cannot change your own admin status.", "error")
        return redirect(url_for("admin_panel"))
    user.is_admin = not user.is_admin
    db.session.commit()
    flash(f"Admin status toggled for {user.username}.", "info")
    return redirect(url_for("admin_panel"))


@app.route("/admin/flags")
@admin_required
def admin_flags():
    pending  = CompromiseFlag.query.filter_by(upheld=None).order_by(
                   CompromiseFlag.created_at.asc()).all()
    reviewed = CompromiseFlag.query.filter(
                   CompromiseFlag.upheld.isnot(None)
               ).order_by(CompromiseFlag.reviewed_at.desc()).limit(50).all()
    inactive_users = User.query.filter_by(key_status="inactive").all()
    revoked_users  = User.query.filter_by(key_status="revoked").all()
    open_disputes  = Debt.query.filter_by(active=True, dispute_status="open").order_by(
                         Debt.disputed_at.asc()).all()
    return render_template("admin_flags.html", pending=pending, reviewed=reviewed,
                           inactive_users=inactive_users, revoked_users=revoked_users,
                           open_disputes=open_disputes)


@app.route("/admin/debt/<int:debt_id>/dispute/<decision>", methods=["POST"])
@admin_required
def resolve_dispute(debt_id, decision):
    """Admin keeps the creditor's no-efforts marking ('uphold') or lifts it ('clear')."""
    if decision not in ("uphold", "clear"):
        abort(404)
    debt = db.get_or_404(Debt, debt_id)
    if debt.dispute_status != "open" or not debt.active:
        flash("This dispute is no longer open.", "info")
        return redirect(url_for("admin_flags"))
    if decision == "uphold":
        debt.dispute_status = "upheld"
        flash(f"Marking kept; {debt.debtor.username}'s key stays inactive.", "warning")
    else:
        debt.dispute_status     = None
        debt.efforts_ok         = True
        debt.efforts_note       = "Cleared by an admin after the debtor's dispute."
        debt.efforts_updated_at = datetime.utcnow()
        flash(f"Marking cleared for {debt.debtor.username}.", "success")
    db.session.commit()
    recheck_debt_status(debt.debtor)
    return redirect(url_for("admin_flags"))


@app.route("/admin/flags/<int:flag_id>/uphold", methods=["POST"])
@admin_required
def uphold_flag(flag_id):
    flag = db.get_or_404(CompromiseFlag, flag_id)
    flag.upheld = True
    flag.reviewed_at = datetime.utcnow()
    flag.reviewer_id = session["user_id"]
    db.session.commit()
    flash("Flag upheld.", "warning")
    return redirect(url_for("admin_flags"))


@app.route("/admin/flags/<int:flag_id>/dismiss", methods=["POST"])
@admin_required
def dismiss_flag(flag_id):
    flag = db.get_or_404(CompromiseFlag, flag_id)
    flag.upheld = False
    flag.reviewed_at = datetime.utcnow()
    flag.reviewer_id = session["user_id"]
    db.session.commit()
    flash("Flag dismissed.", "info")
    return redirect(url_for("admin_flags"))


@app.route("/admin/revoke/<int:user_id>", methods=["POST"])
@admin_required
def revoke_key(user_id):
    target = db.get_or_404(User, user_id)
    note   = request.form.get("note", "").strip()[:500]
    target.key_status  = "revoked"
    target.revoked_at  = datetime.utcnow()
    target.revoke_note = note or "Revoked by administrator."
    db.session.commit()
    flash(f"{target.username}'s key revoked.", "warning")
    return redirect(url_for("admin_flags"))


@app.route("/admin/reinstate/<int:user_id>", methods=["POST"])
@admin_required
def reinstate_key(user_id):
    target = db.get_or_404(User, user_id)
    if target.key_status != "revoked":
        flash(f"{target.username}'s key is not revoked.", "info")
        return redirect(url_for("admin_flags"))
    # Start from active; recheck_debt_status moves it to inactive if debts say so.
    target.key_status  = "active"
    target.revoked_at  = None
    target.revoke_note = None
    db.session.commit()
    recheck_debt_status(target)   # re-evaluate based on debts
    flash(f"{target.username}'s key reinstated.", "success")
    return redirect(url_for("admin_flags"))


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def add_missing_columns():
    """create_all() never alters existing tables, so add columns introduced
    after a database was created. Stopgap until the app uses real migrations."""
    new_columns = {
        "debt": {
            "confirmed":      "BOOLEAN DEFAULT 0",
            "confirmed_at":   "DATETIME",
            "dispute_status": "VARCHAR(16)",
            "dispute_note":   "TEXT",
            "disputed_at":    "DATETIME",
        },
    }
    inspector = db.inspect(db.engine)
    for table, columns in new_columns.items():
        existing = {c["name"] for c in inspector.get_columns(table)}
        for name, ddl in columns.items():
            if name not in existing:
                db.session.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
    db.session.commit()


def create_tables():
    with app.app_context():
        db.create_all()
        add_missing_columns()
        if not User.query.filter_by(is_admin=True).first():
            password = os.environ.get("ADMIN_PASSWORD") or secrets.token_urlsafe(18)
            db.session.add(User(
                username="admin", email="admin@localhost",
                password=generate_password_hash(password),
                approved=True, is_admin=True, has_keys=False,
            ))
            db.session.commit()
            if "ADMIN_PASSWORD" in os.environ:
                print("Admin account created: admin (password from ADMIN_PASSWORD)")
            else:
                # Shown once; it is not stored anywhere in readable form.
                print(f"Admin account created: admin / {password}")
                print("Save this password now. It will not be shown again.")


if __name__ == "__main__":
    create_tables()
    # The Werkzeug debugger can run arbitrary code, so it is opt-in.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1", host="127.0.0.1", port=5000)
