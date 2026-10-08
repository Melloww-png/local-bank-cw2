import time
import re
import secrets
import sqlite3
from contextlib import closing
from pathlib import Path

from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "bank.db"
SECRET_FILE = BASE_DIR / ".env.secret"

if not SECRET_FILE.exists():
    SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")

app.config["SECRET_KEY"] = SECRET_FILE.read_text(encoding="utf-8").strip()
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
IDLE_TIMEOUT_SECONDS = 5 * 60


@app.before_request
def check_session_timeout():
    if request.endpoint == "static" or "user_id" not in session:
        return

    now = time.time()
    last_activity = session.get("last_activity", 0)

    if now - last_activity >= IDLE_TIMEOUT_SECONDS:
        session.clear()
    else:
        session["last_activity"] = now


def get_db_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db():
    with closing(get_db_connection()) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'customer',
                balance_cents INTEGER NOT NULL DEFAULT 100000,
                credit_score INTEGER NOT NULL DEFAULT 600
            )
        """)
        db.commit()


@app.get("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    username = ""
    email = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
            error = "Username must contain 3–32 letters, numbers, or underscores."
        elif len(email) > 254 or not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+", email
        ):
            error = "Enter a valid email address."
        elif not 8 <= len(password) <= 128:
            error = "Password must contain 8–128 characters."
        elif password != confirm_password:
            error = "The passwords do not match."

        if error is None:
            password_hash = generate_password_hash(password, method="scrypt")

            try:
                with closing(get_db_connection()) as db:
                    db.execute(
                        """
                        INSERT INTO users (username, email, password_hash)
                        VALUES (?, ?, ?)
                        """,
                        (username, email, password_hash)
                    )
                    db.commit()
            except sqlite3.IntegrityError:
                error = "That username or email is already registered."
            else:
                return redirect(url_for("home"), code=303)

    return render_template(
        "register.html",
        error=error,
        username=username,
        email=email
    ), 400 if error else 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))

    error = None
    username = ""

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = None

        if re.fullmatch(r"[A-Za-z0-9_]{3,32}", username) and (
            8 <= len(password) <= 128
        ):
            with closing(get_db_connection()) as db:
                user = db.execute(
                    "SELECT id, password_hash FROM users WHERE username = ?",
                    (username,)
                ).fetchone()

        if user is not None and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session.permanent = False
            session["user_id"] = user["id"]
            session["last_activity"] = time.time()
            return redirect(url_for("dashboard"), code=303)

        error = "Incorrect username or password."

    return render_template(
        "login.html",
        error=error,
        username=username
    ), 401 if error else 200


@app.get("/dashboard")
def dashboard():
    user_id = session.get("user_id")

    if user_id is None:
        return redirect(url_for("login"))

    with closing(get_db_connection()) as db:
        user = db.execute(
            """
            SELECT id, username, email, role, balance_cents, credit_score
            FROM users WHERE id = ?
            """,
            (user_id,)
        ).fetchone()

    if user is None:
        session.clear()
        return redirect(url_for("login"))

    return render_template("dashboard.html", user=user)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"), code=303)


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)   