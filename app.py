"""
Simple secure Flask app with Sign Up, Login, and Dashboard pages.
Uses SQLite for storage and Werkzeug for password hashing.
Includes Prometheus metrics export for Kubernetes monitoring.
"""

import os
import sqlite3
import re
from datetime import timedelta

from flask import Flask, request, redirect, url_for, session, render_template_string, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from prometheus_flask_exporter import PrometheusMetrics

# --------------------------------------------------------------------------
# App configuration
# --------------------------------------------------------------------------
app = Flask(__name__)
metrics = PrometheusMetrics(app) # Enables /metrics endpoint for Prometheus

app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY", os.urandom(32)),
    SESSION_COOKIE_HTTPONLY=True,      # JS can't read the cookie
    SESSION_COOKIE_SAMESITE="Lax",     # basic CSRF mitigation
    PERMANENT_SESSION_LIFETIME=timedelta(hours=2),
)

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "users.db")


# --------------------------------------------------------------------------
# Database helpers
# --------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = sqlite3.connect(DATABASE)
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()
    db.close()

# Ensure the database and tables are created automatically on app load
with app.app_context():
    init_db()


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------
USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,20}$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_signup(username, email, password, confirm):
    if not USERNAME_RE.match(username or ""):
        return "Username must be 3-20 characters (letters, numbers, underscore only)."
    if not EMAIL_RE.match(email or ""):
        return "Please enter a valid email address."
    if not password or len(password) < 8:
        return "Password must be at least 8 characters long."
    if password != confirm:
        return "Passwords do not match."
    return None


def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "error")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


# --------------------------------------------------------------------------
# Shared page layout
# --------------------------------------------------------------------------
BASE_HTML = """
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{{ title }}</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0; min-height: 100vh; display: flex; align-items: center; justify-content: center;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #1e293b, #0f172a); color: #e2e8f0;
    }
    .card {
      background: #1e293bcc; border: 1px solid #334155; border-radius: 12px;
      padding: 2.5rem; width: 100%; max-width: 400px; box-shadow: 0 10px 30px rgba(0,0,0,.4);
    }
    h1 { margin-top: 0; font-size: 1.5rem; color: #f1f5f9; }
    label { display: block; margin: 1rem 0 .35rem; font-size: .85rem; color: #94a3b8; }
    input {
      width: 100%; padding: .65rem .8rem; border-radius: 8px; border: 1px solid #334155;
      background: #0f172a; color: #f1f5f9; font-size: 1rem;
    }
    input:focus { outline: none; border-color: #6366f1; }
    button {
      margin-top: 1.5rem; width: 100%; padding: .75rem; border: none; border-radius: 8px;
      background: #6366f1; color: white; font-size: 1rem; font-weight: 600; cursor: pointer;
    }
    button:hover { background: #4f46e5; }
    .flash { padding: .6rem .8rem; border-radius: 8px; margin-bottom: 1rem; font-size: .9rem; }
    .flash.error { background: #7f1d1d55; border: 1px solid #b91c1c; color: #fecaca; }
    .flash.success { background: #14532d55; border: 1px solid #16a34a; color: #bbf7d0; }
    .muted { color: #94a3b8; font-size: .9rem; margin-top: 1.2rem; text-align: center; }
    a { color: #818cf8; text-decoration: none; }
    a:hover { text-decoration: underline; }
    .dash { max-width: 640px; }
    .row { display: flex; justify-content: space-between; align-items: center; }
    .badge {
      display: inline-block; background: #6366f133; color: #a5b4fc; padding: .2rem .6rem;
      border-radius: 999px; font-size: .75rem; margin-left: .5rem;
    }
    .logout-btn { background: #334155; margin-top: 2rem; }
    .logout-btn:hover { background: #475569; }
  </style>
</head>
<body>
  <div class="card {{ 'dash' if dash else '' }}">
    {% with messages = get_flashed_messages(with_categories=true) %}
      {% for category, message in messages %}
        <div class="flash {{ category }}">{{ message }}</div>
      {% endfor %}
    {% endwith %}
    {{ body|safe }}
  </div>
</body>
</html>
"""

SIGNUP_BODY = """
<h1>Create an account</h1>
<form method="post">
  <label>Username</label>
  <input type="text" name="username" value="{{ username or '' }}" required>
  <label>Email</label>
  <input type="email" name="email" value="{{ email or '' }}" required>
  <label>Password</label>
  <input type="password" name="password" required>
  <label>Confirm password</label>
  <input type="password" name="confirm" required>
  <button type="submit">Sign Up</button>
</form>
<p class="muted">Already have an account? <a href="{{ url_for('login') }}">Log in</a></p>
"""

LOGIN_BODY = """
<h1>Welcome back</h1>
<form method="post">
  <label>Username or email</label>
  <input type="text" name="identifier" value="{{ identifier or '' }}" required>
  <label>Password</label>
  <input type="password" name="password" required>
  <button type="submit">Log In</button>
</form>
<p class="muted">Don't have an account? <a href="{{ url_for('signup') }}">Sign up</a></p>
"""

DASHBOARD_BODY = """
<div class="row">
  <h1>Dashboard <span class="badge">secure</span></h1>
</div>
<p>Welcome, <strong>{{ username }}</strong>. You're logged in as <strong>{{ email }}</strong>.</p>
<p class="muted">This page is only visible to authenticated users.</p>
<form method="post" action="{{ url_for('logout') }}">
  <button class="logout-btn" type="submit">Log Out</button>
</form>
"""


def render(body_template, title, dash=False, **ctx):
    body = render_template_string(body_template, **ctx)
    return render_template_string(BASE_HTML, title=title, body=body, dash=dash)


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------
@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/signup", methods=["GET", "POST"])
def signup():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")

        error = validate_signup(username, email, password, confirm)
        if error:
            flash(error, "error")
            return render(SIGNUP_BODY, "Sign Up", username=username, email=email)

        db = get_db()
        existing = db.execute(
            "SELECT id FROM users WHERE username = ? OR email = ?", (username, email)
        ).fetchone()
        if existing:
            flash("Username or email is already taken.", "error")
            return render(SIGNUP_BODY, "Sign Up", username=username, email=email)

        password_hash = generate_password_hash(password)
        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            (username, email, password_hash),
        )
        db.commit()

        flash("Account created successfully. Please log in.", "success")
        return redirect(url_for("login"))

    return render(SIGNUP_BODY, "Sign Up")


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        identifier = request.form.get("identifier", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (identifier, identifier.lower()),
        ).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            flash("Invalid username/email or password.", "error")
            return render(LOGIN_BODY, "Log In", identifier=identifier)

        session.clear()
        session.permanent = True
        session["user_id"] = user["id"]
        session["username"] = user["username"]
        return redirect(url_for("dashboard"))

    return render(LOGIN_BODY, "Log In")


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    if user is None:
        session.clear()
        return redirect(url_for("login"))
    return render(DASHBOARD_BODY, "Dashboard", dash=True, username=user["username"], email=user["email"])


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000)