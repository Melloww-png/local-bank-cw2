import re
import sqlite3
from contextlib import closing
from pathlib import Path

from flask import Flask, redirect, render_template, request, url_for
from werkzeug.security import generate_password_hash

app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "bank.db"


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
    with closing(get_db_connection()) as db:
        account_count = db.execute(
            "SELECT COUNT(*) FROM users"
        ).fetchone()[0]

    return render_template("index.html", account_count=account_count)


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


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)