from flask import Flask, render_template, request, redirect, url_for, session, g, flash
from werkzeug.security import generate_password_hash, check_password_hash
import re
import sqlite3
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))

# ❗ Add this: send no-cache headers for every non-static response
@app.after_request
def add_no_cache_headers(response):
    # keep static files cacheable
    if request.path.startswith("/static/"):
        return response
    # strongest combination for browsers & proxies
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0, private"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

DATABASE = "LoginData.db"

# ---------- DB helpers ----------
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

def ensure_schema():
    db = get_db()
    db.execute("""
    CREATE TABLE IF NOT EXISTS USERS(
        first_name TEXT NOT NULL,
        last_name  TEXT NOT NULL,
        email      TEXT PRIMARY KEY,
        password   TEXT NOT NULL,
        mobile     TEXT,
        address    TEXT
    )
    """)
    db.commit()

# ---------- Validators ----------
name_re = re.compile(r"^[A-Za-z][A-Za-z\s]{1,49}$")      # 2–50 chars, letters/spaces
mobile_re = re.compile(r"^\d{10}$")                      # 10 digits
email_re = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")     # simple email check
pwd_re = re.compile(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,}$")

def split_name(full):
    parts = full.strip().split()
    if not parts:
        return "", ""
    if len(parts) == 1:
        return parts[0], ""
    return parts[0], " ".join(parts[1:])

# ---------- Routes ----------
@app.route("/")
def login():
    ensure_schema()
    if session.get("user"):
        return redirect(url_for("home"))
    return render_template("login.html")

@app.route("/login_validation", methods=["POST"])
def login_validation():
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""

    db = get_db()
    user = db.execute(
        "SELECT first_name, last_name, email, password FROM USERS WHERE email=?",
        (email,)
    ).fetchone()

    if user and check_password_hash(user["password"], password):
        session["user"] = {
            "fname": user["first_name"],
            "lname": user["last_name"],
            "email": user["email"]
        }
        return redirect(url_for("home"))

    flash("Invalid email or password.")
    return redirect(url_for("login"))

@app.route("/signUp")
def signUp():
    return render_template("signUp.html")

@app.route("/add_user", methods=["POST"])
def add_user():
    full_name = (request.form.get("name") or "").strip()
    mobile = (request.form.get("mobile") or "").strip()
    email = (request.form.get("email") or "").strip().lower()
    address = (request.form.get("address") or "").strip()
    password = request.form.get("password") or ""
    confirm = request.form.get("confirm_password") or ""

    # server-side validation
    errors = []
    if not name_re.match(full_name):
        errors.append("Enter a valid Name (letters/spaces, 2–50 chars).")
    if not mobile_re.match(mobile):
        errors.append("Enter a valid 10-digit mobile number.")
    if not email_re.match(email):
        errors.append("Enter a valid email address.")
    if not pwd_re.match(password):
        errors.append("Password must be 8+ chars with upper, lower, digit, and special.")
    if password != confirm:
        errors.append("Passwords do not match.")

    if errors:
        for e in errors:
            flash(e)
        return redirect(url_for("signUp"))

    db = get_db()
    exists = db.execute("SELECT 1 FROM USERS WHERE email=?", (email,)).fetchone()
    if exists:
        flash("Email already registered. Please log in.")
        return redirect(url_for("login"))

    fname, lname = split_name(full_name)
    db.execute(
        "INSERT INTO USERS(first_name, last_name, email, password, mobile, address) VALUES (?, ?, ?, ?, ?, ?)",
        (fname, lname, email, generate_password_hash(password), mobile, address)
    )
    db.commit()
    flash("Account created. Please log in.")
    return redirect(url_for("login"))

@app.route("/home")
def home():
    user = session.get("user")
    if not user:
        return redirect(url_for("login"))
    return render_template("home.html", **user)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ---------- Forgot password ----------
@app.route("/forgot", methods=["GET"])
def forgot_get():
    return render_template("forgot.html")

@app.route("/forgot", methods=["POST"])
def forgot_post():
    email = (request.form.get("email") or "").strip().lower()
    mobile = (request.form.get("mobile") or "").strip()
    new_password = request.form.get("new_password") or ""
    confirm = request.form.get("confirm_password") or ""

    errors = []
    if not email_re.match(email):
        errors.append("Enter a valid email.")
    if not mobile_re.match(mobile):
        errors.append("Enter a valid 10-digit mobile number.")
    if not pwd_re.match(new_password):
        errors.append("Password must be 8+ chars with upper, lower, digit, and special.")
    if new_password != confirm:
        errors.append("Passwords do not match.")

    if errors:
        for e in errors:
            flash(e)
        return redirect(url_for("forgot_get"))

    db = get_db()
    user = db.execute("SELECT email FROM USERS WHERE email=? AND mobile=?", (email, mobile)).fetchone()
    if not user:
        flash("Account not found for the given email and mobile.")
        return redirect(url_for("forgot_get"))

    db.execute("UPDATE USERS SET password=? WHERE email=?", (generate_password_hash(new_password), email))
    db.commit()
    flash("Password updated. Please log in.")
    return redirect(url_for("login"))

if __name__ == "__main__":
    # optional: run ensure_schema at startup
    with app.app_context():
        ensure_schema()
    app.run(debug=True)
