import sqlite3
from contextlib import closing
from pathlib import Path

from flask import Flask, render_template

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


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)