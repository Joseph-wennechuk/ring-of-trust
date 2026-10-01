import os
import io
import json
import base64
import secrets
import zipfile
from datetime import datetime
from functools import wraps

from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, send_file)
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import gnupg
import qrcode
from mnemonic import Mnemonic

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///rot.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

FLAG_THRESHOLD = int(os.environ.get("FLAG_THRESHOLD", 3))

db = SQLAlchemy(app)

GPG_HOME  = os.path.join(os.path.dirname(__file__), "instance", "gnupg")
KEYS_TEMP = os.path.join(os.path.dirname(__file__), "instance", "keytemp")
os.makedirs(GPG_HOME,  exist_ok=True)
os.makedirs(KEYS_TEMP, exist_ok=True)
gpg = gnupg.GPG(gnupghome=GPG_HOME, options=["--pinentry-mode", "loopback"])
gpg.encoding = "utf-8"


def save_key_temp(user_id, data):
    path = os.path.join(KEYS_TEMP, f"{user_id}.json")
    with open(path, "w") as f:
        json.dump(data, f)


def load_key_temp(user_id):
    path = os.path.join(KEYS_TEMP, f"{user_id}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        return json.load(f)


def delete_key_temp(user_id):
    path = os.path.join(KEYS_TEMP, f"{user_id}.json")
    if os.path.exists(path):
        os.remove(path)

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
    # Creditor/admin can mark debtor as not making efforts on this debt
    efforts_ok  = db.Column(db.Boolean, default=True)
    efforts_note = db.Column(db.Text, nullable=True)
    efforts_updated_at = db.Column(db.DateTime, nullable=True)
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

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        user = db.session.get(User, session["user_id"])
        if not user or not user.is_admin:
            flash("Admin access required.", "error")
            return redirect(url_for("dashboard"))
        return f(*args, **kwargs)
    return decorated


def current_user():
    if "user_id" in session:
        return db.session.get(User, session["user_id"])
    return None


@app.context_processor
def inject_globals():
    return dict(current_user=current_user(), FLAG_THRESHOLD=FLAG_THRESHOLD)


def make_qr_b64(data: str) -> str:
    img = qrcode.make(data)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


def generate_mnemonic() -> str:
    return Mnemonic("english").generate(strength=256)


def recheck_debt_status(debtor: User):
    """
    Key goes inactive if ANY active debt on this user has efforts_ok=False.
    Key returns to active only when all active debts have efforts_ok=True.
    Revoked status is untouched by this function.
    """
    if debtor.key_status == "revoked":
        return
    bad_debts = Debt.query.filter_by(
        debtor_id=debtor.id, active=True, efforts_ok=False
    ).count()
    if bad_debts > 0:
        debtor.key_status = "inactive"
    else:
        if debtor.key_status == "inactive":
            debtor.key_status = "active"
            debtor.debt_disputed = False
            debtor.dispute_note  = None
    db.session.commit()


# ---------------------------------------------------------------------------
# Routes – auth
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email    = request.form["email"].strip().lower()
        password = request.form["password"]
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
        username = request.form["username"].strip()
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password, password):
            flash("Invalid credentials.", "error")
            return render_template("login.html")
        if not user.approved:
            flash("Your account is pending approval.", "info")
            return render_template("login.html")
        session["user_id"] = user.id
        return redirect(url_for("generate_keys") if not user.has_keys else url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------------------------------------------------------------------
# Routes – key generation
# ---------------------------------------------------------------------------

@app.route("/generate-keys", methods=["GET", "POST"])
@login_required
def generate_keys():
    user = current_user()
    if user.has_keys:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        passphrase = request.form.get("passphrase", "").strip()
        if len(passphrase) < 12:
            flash("Passphrase must be at least 12 characters.", "error")
            return render_template("generate_keys.html")

        input_data = gpg.gen_key_input(
            key_type="EDDSA", key_curve="Ed25519", key_usage="sign",
            subkey_type="ECDH", subkey_curve="Curve25519", subkey_usage="encrypt",
            name_real=user.username, name_email=user.email,
            passphrase=passphrase, expire_date="2y",
        )
        key         = gpg.gen_key(input_data)
        fingerprint = str(key.fingerprint)

        if not fingerprint:
            app.logger.error("Key generation failed: %s", key.stderr)
            flash("Key generation failed — check server logs.", "error")
            return render_template("generate_keys.html")

        pub_key  = gpg.export_keys(fingerprint)
        priv_key = gpg.export_keys(
            fingerprint, secret=True, passphrase=passphrase,
            expect_passphrase=True,
        )

        if not pub_key or not priv_key:
            app.logger.error("Key export failed. pub=%r priv=%r", bool(pub_key), bool(priv_key))
            flash("Key export failed — check server logs.", "error")
            return render_template("generate_keys.html")

        mnemonic = generate_mnemonic()

        user.fingerprint = fingerprint
        user.public_key  = pub_key
        user.has_keys    = True
        user.key_status  = "active"
        db.session.commit()

        # Store on disk — too large for a session cookie
        save_key_temp(user.id, {
            "priv_key":    priv_key,
            "mnemonic":    mnemonic,
            "pub_qr":      make_qr_b64(pub_key),
            "priv_qr":     make_qr_b64(priv_key),
            "mnem_qr":     make_qr_b64(mnemonic),
            "fingerprint": fingerprint,
        })
        return redirect(url_for("show_keys"))

    return render_template("generate_keys.html")


@app.route("/show-keys")
@login_required
def show_keys():
    user = current_user()
    data = load_key_temp(user.id)
    if not data:
        return redirect(url_for("dashboard"))
    return render_template("show_keys.html",
        pub_qr=data["pub_qr"], priv_qr=data["priv_qr"],
        mnem_qr=data["mnem_qr"], fingerprint=data["fingerprint"])


@app.route("/download-keys")
@login_required
def download_keys():
    user = current_user()
    data = load_key_temp(user.id)
    if not data:
        flash("Nothing to download — keys may already have been downloaded.", "error")
        return redirect(url_for("dashboard"))
    priv_key = data["priv_key"]
    mnemonic = data["mnemonic"]
    delete_key_temp(user.id)
    user = current_user()
    buf  = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(f"{user.username}_private_key.asc",       priv_key)
        zf.writestr(f"{user.username}_public_key.asc",        user.public_key)
        zf.writestr(f"{user.username}_recovery_mnemonic.txt", mnemonic)
        zf.writestr("README.txt",
            "KEEP THESE FILES SECURE AND OFFLINE.\n\n"
            f"Private key  : {user.username}_private_key.asc\n"
            f"Public key   : {user.username}_public_key.asc\n"
            f"Recovery seed: {user.username}_recovery_mnemonic.txt\n\n"
            "The recovery mnemonic allows a sysop to help reconstruct\n"
            "your key material if the private key is lost.\n"
            "Do NOT share your private key or mnemonic with anyone.\n")
    buf.seek(0)
    return send_file(buf, as_attachment=True,
                     download_name=f"{user.username}_ghetto-pass_keys.zip",
                     mimetype="application/zip")


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
    # Debts where I am creditor and have marked no-efforts
    my_inactive_credits = Debt.query.filter_by(creditor_id=user.id, active=True, efforts_ok=False).count()
    # My own key status info
    my_bad_debts = Debt.query.filter_by(debtor_id=user.id, active=True, efforts_ok=False).count()
    return render_template("dashboard.html",
        pending_count=pending_count,
        flag_review_count=flag_review_count,
        my_bad_debts=my_bad_debts,
        my_inactive_credits=my_inactive_credits,
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
    user  = current_user()
    peers = User.query.filter_by(approved=True, has_keys=True).all()
    if request.method == "POST":
        debtor_id   = int(request.form["debtor_id"])
        creditor_id = int(request.form["creditor_id"])
        description = request.form["description"].strip()
        amount      = float(request.form["amount"])
        currency    = request.form.get("currency", "USD").strip().upper()[:10]
        if debtor_id == creditor_id:
            flash("Debtor and creditor cannot be the same person.", "error")
            return render_template("add_debt.html", peers=peers, me=user)
        db.session.add(Debt(debtor_id=debtor_id, creditor_id=creditor_id,
                            description=description, amount=amount, currency=currency))
        db.session.commit()
        flash("Debt recorded.", "success")
        return redirect(url_for("key_directory"))
    return render_template("add_debt.html", peers=peers, me=user)


@app.route("/debt/reduce/<int:debt_id>", methods=["POST"])
@login_required
def reduce_debt(debt_id):
    debt = db.get_or_404(Debt, debt_id)
    user = current_user()
    if user.id not in (debt.debtor_id, debt.creditor_id) and not user.is_admin:
        flash("Not authorised.", "error")
        return redirect(url_for("key_directory"))
    amount = float(request.form.get("amount", 0))
    debt.amount = max(0.0, debt.amount - amount)
    if debt.amount == 0:
        debt.active     = False
        debt.efforts_ok = True   # settled — clear any no-efforts flag
    debt.updated_at = datetime.utcnow()
    db.session.commit()
    recheck_debt_status(debt.debtor)
    flash("Debt updated.", "success")
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
    efforts_ok   = request.form.get("efforts_ok") == "1"
    efforts_note = request.form.get("efforts_note", "").strip()[:500]
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
    """Debtor disputes an inactive/no-efforts marking on their key."""
    debt = db.get_or_404(Debt, debt_id)
    user = current_user()
    if user.id != debt.debtor_id:
        flash("Only the debtor can dispute this.", "error")
        return redirect(url_for("key_directory"))
    if debt.efforts_ok:
        flash("This debt is not currently marked as no-efforts.", "info")
        return redirect(url_for("key_directory"))
    note = request.form.get("dispute_note", "").strip()[:1000]
    debt.debtor.debt_disputed = True
    debt.debtor.dispute_note  = note or "Debtor disputes the no-efforts marking."
    db.session.commit()
    flash("Dispute recorded. It is now visible on your key.", "info")
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


@app.route("/admin/approve/<int:user_id>")
@admin_required
def approve_user(user_id):
    user = db.get_or_404(User, user_id)
    user.approved = True
    db.session.commit()
    flash(f"{user.username} approved.", "success")
    return redirect(url_for("admin_panel"))


@app.route("/admin/reject/<int:user_id>")
@admin_required
def reject_user(user_id):
    db.session.delete(db.get_or_404(User, user_id))
    db.session.commit()
    flash("User rejected and removed.", "info")
    return redirect(url_for("admin_panel"))


@app.route("/admin/toggle-admin/<int:user_id>")
@admin_required
def toggle_admin(user_id):
    user = db.get_or_404(User, user_id)
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
    return render_template("admin_flags.html", pending=pending, reviewed=reviewed,
                           inactive_users=inactive_users, revoked_users=revoked_users)


@app.route("/admin/flags/<int:flag_id>/uphold")
@admin_required
def uphold_flag(flag_id):
    flag = db.get_or_404(CompromiseFlag, flag_id)
    flag.upheld = True
    flag.reviewed_at = datetime.utcnow()
    flag.reviewer_id = session["user_id"]
    db.session.commit()
    flash("Flag upheld.", "warning")
    return redirect(url_for("admin_flags"))


@app.route("/admin/flags/<int:flag_id>/dismiss")
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
    target.revoked_at  = None
    target.revoke_note = None
    db.session.commit()
    recheck_debt_status(target)   # re-evaluate based on debts
    flash(f"{target.username}'s key reinstated.", "success")
    return redirect(url_for("admin_flags"))


# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

def create_tables():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(is_admin=True).first():
            db.session.add(User(
                username="admin", email="admin@localhost",
                password=generate_password_hash("changeme123!"),
                approved=True, is_admin=True, has_keys=False,
            ))
            db.session.commit()
            print("Default admin created: admin / changeme123!")
            print("CHANGE THIS PASSWORD IMMEDIATELY.")


if __name__ == "__main__":
    create_tables()
    app.run(debug=True, host="127.0.0.1", port=5000)
