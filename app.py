"""
Secure Login System (Flask)

Security features
  * Passwords hashed with Argon2id (argon2-cffi) - never stored in plain text
  * SQL injection protection: every query is parameterised (?) - no string building
  * Input validation: username / email / password-strength rules, server side
  * Session management: signed HttpOnly cookie, 15 min expiry, session reset on login
    (prevents session fixation), logout via POST
  * CSRF tokens on every POST form
  * Brute-force protection: account locked for 5 minutes after 5 failed logins
  * Generic error messages + dummy hash check (no username enumeration / timing leak)
  * Optional Two-Factor Authentication (TOTP, works with Google/Microsoft Authenticator)
  * Security headers (CSP, X-Frame-Options, nosniff, no-store cache)
"""
import io
import os
import re
import secrets
import sqlite3
import time
from datetime import timedelta
from functools import wraps

import pyotp
import qrcode
import qrcode.image.svg
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import (Flask, abort, flash, g, redirect, render_template, request,
                   session, url_for)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ph = PasswordHasher()
DUMMY_HASH = ph.hash("dummy-password-for-timing")

MAX_FAILED = 5
LOCK_SECONDS = 300
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until REAL NOT NULL DEFAULT 0,
    totp_secret TEXT,
    totp_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


def load_secret_key():
    """SECRET_KEY env var, else a random key saved in .secret_key (git-ignored)."""
    if os.environ.get("SECRET_KEY"):
        return os.environ["SECRET_KEY"]
    path = os.path.join(BASE_DIR, ".secret_key")
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


def validate_password(pw):
    errors = []
    if len(pw) < 8:
        errors.append("at least 8 characters")
    if len(pw) > 128:
        errors.append("at most 128 characters")
    if not re.search(r"[a-z]", pw):
        errors.append("a lowercase letter")
    if not re.search(r"[A-Z]", pw):
        errors.append("an uppercase letter")
    if not re.search(r"\d", pw):
        errors.append("a digit")
    if not re.search(r"[^A-Za-z0-9]", pw):
        errors.append("a special character")
    return errors


def qr_svg(uri):
    img = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode()


def create_app(db_path=None):
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=load_secret_key(),
        DB_PATH=db_path or os.environ.get("DB_PATH", os.path.join(BASE_DIR, "users.db")),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        # Set SESSION_COOKIE_SECURE=1 when serving over HTTPS (production)
        SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE") == "1",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=15),
    )

    # ------------------------------------------------------------ database
    def get_db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close_db(_exc):
        db = g.pop("db", None)
        if db is not None:
            db.close()

    with sqlite3.connect(app.config["DB_PATH"]) as conn:
        conn.executescript(SCHEMA)

    # ------------------------------------------------------------ CSRF + headers
    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_hex(16)
        return session["csrf"]

    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.before_request
    def check_csrf():
        if request.method == "POST":
            sent = request.form.get("csrf_token", "")
            if not sent or not secrets.compare_digest(sent, session.get("csrf", "")):
                abort(400, "Invalid or missing CSRF token")

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cache-Control"] = "no-store"
        return resp

    # ------------------------------------------------------------ helpers
    def current_user():
        uid = session.get("user_id")
        if not uid:
            return None
        return get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()

    def login_required(view):
        @wraps(view)
        def wrapper(*a, **kw):
            if current_user() is None:
                flash("Please log in first.", "error")
                return redirect(url_for("login"))
            return view(*a, **kw)
        return wrapper

    def start_session(user):
        session.clear()                      # new session -> prevents session fixation
        session["user_id"] = user["id"]
        session.permanent = True             # expires after PERMANENT_SESSION_LIFETIME

    # ------------------------------------------------------------ routes
    @app.route("/")
    def index():
        return redirect(url_for("dashboard" if current_user() else "login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            email = request.form.get("email", "").strip().lower()
            password = request.form.get("password", "")
            confirm = request.form.get("confirm", "")

            errors = []
            if not USERNAME_RE.match(username):
                errors.append("Username must be 3-20 characters: letters, digits, underscore.")
            if not EMAIL_RE.match(email) or len(email) > 120:
                errors.append("Enter a valid email address.")
            pw_errors = validate_password(password)
            if pw_errors:
                errors.append("Password needs: " + ", ".join(pw_errors) + ".")
            if password != confirm:
                errors.append("Passwords do not match.")

            if not errors:
                try:
                    db = get_db()
                    db.execute(
                        "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
                        (username, email, ph.hash(password)))
                    db.commit()
                    flash("Account created. Please log in.", "success")
                    return redirect(url_for("login"))
                except sqlite3.IntegrityError:
                    errors.append("Username or email is already registered.")
            for e in errors:
                flash(e, "error")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            db = get_db()
            user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
            now = time.time()

            if user is None:
                try:                         # same work as a real check -> no timing leak
                    ph.verify(DUMMY_HASH, password)
                except (VerifyMismatchError, InvalidHashError):
                    pass
                flash("Invalid username or password.", "error")
                return render_template("login.html")

            if user["locked_until"] > now:
                flash("Too many failed attempts. Try again in a few minutes.", "error")
                return render_template("login.html")

            try:
                ph.verify(user["password_hash"], password)
            except (VerifyMismatchError, InvalidHashError):
                attempts = user["failed_attempts"] + 1
                locked = now + LOCK_SECONDS if attempts >= MAX_FAILED else 0
                db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
                           (0 if locked else attempts, locked, user["id"]))
                db.commit()
                flash("Invalid username or password.", "error")
                return render_template("login.html")

            db.execute("UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE id = ?", (user["id"],))
            if ph.check_needs_rehash(user["password_hash"]):
                db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (ph.hash(password), user["id"]))
            db.commit()

            if user["totp_enabled"]:
                session.clear()
                session["pending_2fa"] = user["id"]
                session["pending_at"] = now
                session["pending_tries"] = 0
                return redirect(url_for("login_2fa"))
            start_session(user)
            return redirect(url_for("dashboard"))
        return render_template("login.html")

    @app.route("/login/2fa", methods=["GET", "POST"])
    def login_2fa():
        uid = session.get("pending_2fa")
        if not uid or time.time() - session.get("pending_at", 0) > 300:
            session.clear()
            flash("Please log in again.", "error")
            return redirect(url_for("login"))
        if request.method == "POST":
            user = get_db().execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
            code = request.form.get("code", "").strip()
            if user and pyotp.TOTP(user["totp_secret"]).verify(code, valid_window=1):
                start_session(user)
                return redirect(url_for("dashboard"))
            session["pending_tries"] = session.get("pending_tries", 0) + 1
            if session["pending_tries"] >= MAX_FAILED:
                session.clear()
                flash("Too many invalid codes. Please log in again.", "error")
                return redirect(url_for("login"))
            flash("Invalid authentication code.", "error")
        return render_template("login_2fa.html")

    @app.route("/dashboard")
    @login_required
    def dashboard():
        return render_template("dashboard.html", user=current_user())

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        flash("You have been logged out.", "success")
        return redirect(url_for("login"))

    @app.route("/2fa/setup", methods=["GET", "POST"])
    @login_required
    def setup_2fa():
        db = get_db()
        user = current_user()
        if user["totp_enabled"]:
            flash("Two-factor authentication is already enabled.", "success")
            return redirect(url_for("dashboard"))
        secret = user["totp_secret"]
        if not secret:
            secret = pyotp.random_base32()
            db.execute("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user["id"]))
            db.commit()
        if request.method == "POST":
            if pyotp.TOTP(secret).verify(request.form.get("code", "").strip(), valid_window=1):
                db.execute("UPDATE users SET totp_enabled = 1 WHERE id = ?", (user["id"],))
                db.commit()
                flash("Two-factor authentication enabled.", "success")
                return redirect(url_for("dashboard"))
            flash("That code was not correct. Try again.", "error")
        uri = pyotp.TOTP(secret).provisioning_uri(name=user["email"], issuer_name="SecureLoginDemo")
        return render_template("setup_2fa.html", secret=secret, qr=qr_svg(uri))

    @app.route("/2fa/disable", methods=["POST"])
    @login_required
    def disable_2fa():
        user = current_user()
        try:
            ph.verify(user["password_hash"], request.form.get("password", ""))
        except (VerifyMismatchError, InvalidHashError):
            flash("Wrong password. 2FA was not disabled.", "error")
            return redirect(url_for("dashboard"))
        db = get_db()
        db.execute("UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?", (user["id"],))
        db.commit()
        flash("Two-factor authentication disabled.", "success")
        return redirect(url_for("dashboard"))

    return app


if __name__ == "__main__":
    create_app().run(debug=False)
