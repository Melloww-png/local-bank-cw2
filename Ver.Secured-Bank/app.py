import os
import re
import secrets
import ssl
import sqlite3
import time
from contextlib import closing
from datetime import timedelta
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect, render_template,
    request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.exceptions import HTTPException, SecurityError
from flask_wtf.csrf import CSRFError, CSRFProtect


app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("BANK_INSTANCE_DIR", BASE_DIR / "instance"))
DATA_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
DATABASE = DATA_DIR / "bank.db"
SECRET_FILE = DATA_DIR / ".env.secret"

IDLE_TIMEOUT_SECONDS = 300
ADMIN_USERNAME = "admin1"


def load_secret():
    supplied = os.environ.get("BANK_SECRET_KEY")
    if supplied:
        if len(supplied) < 32:
            raise RuntimeError("BANK_SECRET_KEY must contain at least 32 characters.")
        return supplied
    try:
        descriptor = os.open(SECRET_FILE, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        with os.fdopen(descriptor, "w", encoding="utf-8") as secret:
            secret.write(secrets.token_hex(32))
    value = SECRET_FILE.read_text(encoding="utf-8").strip()
    if len(value) < 32:
        raise RuntimeError("The local session secret is invalid.")
    return value

app.config.update(
    SECRET_KEY=load_secret(),
    DATABASE=DATABASE,
    SESSION_COOKIE_NAME="cw2_secure_session",
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(minutes=5),
    MAX_CONTENT_LENGTH=16 * 1024,
    MAX_FORM_MEMORY_SIZE=16 * 1024,
    MAX_FORM_PARTS=40,
    TRUSTED_HOSTS=["127.0.0.1", "localhost"],
)


def get_db_connection():
    db = sqlite3.connect(app.config["DATABASE"], timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys = ON")
    return db


def ensure_demo_card(db, user_id):
    """Create a fictional card once; keep its number/CVV on later starts."""
    existing = db.execute(
        "SELECT * FROM demo_cards WHERE user_id = ?", (user_id,)
    ).fetchone()
    if existing is not None:
        return existing

    for _ in range(20):
        # 0000 is a demo prefix. Deliberately fail the Luhn checksum so this
        # number cannot be mistaken for a usable payment card.
        stem = "0000" + "".join(str(secrets.randbelow(10)) for _ in range(11))
        total = 0
        for index, character in enumerate(stem):
            digit = int(character)
            if index % 2 == 0:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        invalid_check_digit = ((-total) % 10 + 1) % 10
        number = stem + str(invalid_check_digit)
        cvv = f"{secrets.randbelow(1000):03d}"
        cursor = db.execute(
            """INSERT INTO demo_cards (user_id, card_number, cvv)
               VALUES (?, ?, ?) ON CONFLICT(card_number) DO NOTHING""",
            (user_id, number, cvv),
        )
        if cursor.rowcount == 1:
            return db.execute(
                "SELECT * FROM demo_cards WHERE user_id = ?", (user_id,)
            ).fetchone()
    raise RuntimeError("Could not allocate a unique demo card.")


def init_db():
    with closing(get_db_connection()) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                full_name TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'customer' CHECK (role IN ('customer', 'admin')),
                balance_cents INTEGER NOT NULL DEFAULT 100000 CHECK (balance_cents >= 0),
                credit_score INTEGER NOT NULL DEFAULT 600 CHECK (credit_score BETWEEN 300 AND 850)
            );

            CREATE TABLE IF NOT EXISTS account_extras (
                user_id INTEGER PRIMARY KEY REFERENCES users(id),
                debt_cents INTEGER NOT NULL DEFAULT 25000 CHECK (debt_cents >= 0),
                is_vip INTEGER NOT NULL DEFAULT 0 CHECK (is_vip IN (0, 1)),
                loan_limit_override_cents INTEGER CHECK (loan_limit_override_cents >= 0),
                cruise_eligible INTEGER NOT NULL DEFAULT 0 CHECK (cruise_eligible IN (0, 1)),
                cruise_claimed INTEGER NOT NULL DEFAULT 0 CHECK (cruise_claimed IN (0, 1)),
                ticket_code TEXT,
                CHECK (cruise_claimed = 0 OR (cruise_eligible = 1 AND ticket_code IS NOT NULL))
            );

            CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL REFERENCES users(id),
                recipient_id INTEGER NOT NULL REFERENCES users(id),
                amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                CHECK (sender_id <> recipient_id)
            );

            CREATE TABLE IF NOT EXISTS support_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS demo_cards (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                card_number TEXT NOT NULL UNIQUE CHECK (
                    length(card_number) = 16 AND
                    substr(card_number, 1, 4) = '0000' AND
                    card_number NOT GLOB '*[^0-9]*'
                ),
                cvv TEXT NOT NULL CHECK (
                    length(cvv) = 3 AND cvv NOT GLOB '*[^0-9]*'
                ),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

        """)

        # Add new fields without replacing existing customer records.
        user_columns = {
            column["name"]
            for column in db.execute("PRAGMA table_info(users)")
        }

        if "full_name" not in user_columns:
            db.execute(
                "ALTER TABLE users ADD COLUMN full_name TEXT NOT NULL DEFAULT ''"
            )

        extra_columns = {
            column["name"]
            for column in db.execute("PRAGMA table_info(account_extras)")
        }

        if "is_vip" not in extra_columns:
            db.execute(
                "ALTER TABLE account_extras ADD COLUMN is_vip INTEGER NOT NULL DEFAULT 0"
            )

        if "loan_limit_override_cents" not in extra_columns:
            db.execute(
                "ALTER TABLE account_extras ADD COLUMN loan_limit_override_cents INTEGER"
            )

        # Administrators are created explicitly by setup_admin.py.
        # Starting the app must never restore the old shared admin password.

        db.execute("""
            INSERT OR IGNORE INTO account_extras (user_id)
            SELECT id FROM users WHERE role = 'customer'
        """)

        # Backfill old customers without resetting their accounts or cards.
        missing_cards = db.execute("""
            SELECT u.id FROM users u
            LEFT JOIN demo_cards c ON c.user_id = u.id
            WHERE u.role = 'customer' AND c.user_id IS NULL
        """).fetchall()
        for customer in missing_cards:
            ensure_demo_card(db, customer["id"])

        db.commit()


@app.before_request
def require_https():
    # V8 fixed: refuse plaintext WSGI requests, including POSTs.
    # Do not trust user-supplied X-Forwarded-Proto headers.
    if not request.is_secure:
        abort(400, description="Open https://127.0.0.1:5001 for the secured bank.")


@app.before_request
def load_user():
    g.user = None

    if request.endpoint == "static" or "user_id" not in session:
        return

    now = time.time()

    if now - session.get("last_activity", 0) >= IDLE_TIMEOUT_SECONDS:
        session.clear()
        return

    with closing(get_db_connection()) as db:
        g.user = db.execute(
            "SELECT * FROM users WHERE id = ?",
            (session["user_id"],),
        ).fetchone()

    if g.user is None:
        session.clear()
    else:
        session["last_activity"] = now


csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def csrf_error(error):
    return render_template("error.html", code=400, message=error.description), 400


@app.errorhandler(HTTPException)
def http_error(error):
    if isinstance(error, SecurityError):
        # Host validation can fail before Flask has a URL adapter for templates.
        return "Request blocked (400). Untrusted host.", 400, {"Content-Type": "text/plain; charset=utf-8"}
    return render_template("error.html", code=error.code, message=error.description), error.code


@app.after_request
def security_headers(response):
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'none'; style-src 'self'; "
        "img-src 'self'; font-src 'self'; connect-src 'self'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    # HSTS is deliberately omitted on this loopback lab: it applies to every
    # port on a hostname and would interfere with the separate HTTP demo.
    return response


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def customer_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "customer":
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def check_form_fields(*allowed):
    allowed = set(allowed) | {"csrf_token"}
    if any(key not in allowed or len(request.form.getlist(key)) != 1 for key in request.form):
        abort(400, description="This form contains unexpected or repeated fields.")


@app.template_filter("money")
def money(cents):
    return f"SGD {cents / 100:,.2f}"


def parse_amount(text):
    text = text.strip()
    if len(text) > 40 or not re.fullmatch(r"-?[0-9]+(?:\.[0-9]{1,2})?", text):
        raise ValueError("Enter an amount such as 10 or 10.25, using at most two decimal places.")

    try:
        amount = Decimal(text)

        if not amount.is_finite() or abs(amount) > 1000000:
            raise ValueError("Invalid amount.")

        cents = amount * 100

        if cents != cents.to_integral_value():
            raise ValueError("Use at most two decimal places.")

        return int(cents)

    except InvalidOperation:
        raise ValueError("Enter a valid amount.") from None


def loan_limit(score):
    if score >= 750:
        return 500000

    if score >= 650:
        return 250000

    return 100000


def effective_loan_limit(score, extras):
    override = extras["loan_limit_override_cents"]
    return loan_limit(score) if override is None else override


def valid_full_name(name):
    return 1 <= len(name) <= 120 and name.isprintable()


@app.get("/")
def home():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        check_form_fields("username", "full_name", "email", "password", "confirm_password")
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")

        error = None

        if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
            error = "Use 3–32 letters, numbers, or underscores for your username."
        elif username.lower() in (ADMIN_USERNAME.lower(), "lab_admin"):
            error = "That username is reserved."
        elif not valid_full_name(full_name):
            error = "Enter a full name containing 1–120 printable characters."
        elif len(email) > 254 or not re.fullmatch(
            r"[^@\s]+@[^@\s]+\.[^@\s]+", email
        ):
            error = "Enter a valid email address."
        elif not 8 <= len(password) <= 128:
            error = "Use a password containing 8–128 characters."
        elif password != confirmation:
            error = "The passwords do not match."

        if error is None:
            try:
                with closing(get_db_connection()) as db:
                    cursor = db.execute(
                        """INSERT INTO users
                           (username, full_name, email, password_hash)
                           VALUES (?, ?, ?, ?)""",
                        (
                            username,
                            full_name,
                            email,
                            generate_password_hash(
                                password, method="scrypt"
                            ),
                        ),
                    )

                    db.execute(
                        "INSERT INTO account_extras (user_id) VALUES (?)",
                        (cursor.lastrowid,),
                    )

                    ensure_demo_card(db, cursor.lastrowid)
                    db.commit()

            except sqlite3.IntegrityError:
                error = "That username or email is already registered."
            else:
                flash("Account created. You can now sign in.")
                return redirect(url_for("login"), code=303)

        flash(error)
        return render_template("register.html"), 400

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.user is not None:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = None

        if len(username) <= 32 and len(password) <= 128:
            with closing(get_db_connection()) as db:
                user = db.execute(
                    "SELECT * FROM users WHERE username = ?",
                    (username,),
                ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session.permanent = False
            session["user_id"] = user["id"]
            session["last_activity"] = time.time()

            return redirect(url_for("dashboard"), code=303)

        flash("Incorrect username or password.")
        return render_template("login.html"), 401

    return render_template("login.html")


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"), code=303)


@app.get("/dashboard")
@login_required
def dashboard():
    if g.user["role"] == "admin":
        return redirect(url_for("admin"))

    with closing(get_db_connection()) as db:
        extras = db.execute(
            "SELECT * FROM account_extras WHERE user_id = ?",
            (g.user["id"],),
        ).fetchone()

        card = db.execute(
            "SELECT * FROM demo_cards WHERE user_id = ?",
            (g.user["id"],),
        ).fetchone()

        history = db.execute("""
            SELECT t.*, s.username AS sender, r.username AS recipient
            FROM transfers t
            JOIN users s ON s.id = t.sender_id
            JOIN users r ON r.id = t.recipient_id
            WHERE t.sender_id = ? OR t.recipient_id = ?
            ORDER BY t.id DESC LIMIT 20
        """, (g.user["id"], g.user["id"])).fetchall()

    limit = effective_loan_limit(g.user["credit_score"], extras)

    return render_template(
        "dashboard.html",
        extras=extras,
        history=history,
        limit=limit,
        remaining=max(0, limit - extras["debt_cents"]),
        card=card,
    )


# V1 and V7 fixed: parameterized, admin-only search with a minimal column list.
@app.get("/search")
@admin_required
def search():
    query = request.args.get("q", "").strip()
    if len(query) > 120:
        abort(400, description="Use at most 120 characters for a search.")
    rows = []

    if query:
        # Escape LIKE wildcards as well: a literal underscore stays literal.
        pattern = "%" + query.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        with closing(get_db_connection()) as db:
            rows = db.execute(
                """SELECT id, username, full_name, email FROM users
                   WHERE role = 'customer' AND username LIKE ? ESCAPE '\\'
                   ORDER BY username LIMIT 50""", (pattern,)
            ).fetchall()
    return render_template("search.html", rows=rows, query=query)


@app.route("/transfer", methods=["GET", "POST"])
@customer_required
def transfer():
    if request.method == "POST":
        recipient_name = request.form.get("recipient", "").strip()

        try:
            amount = parse_amount(request.form.get("amount", ""))

            # V3 fixed: validate on the server before opening a transaction.
            if amount <= 0:
                raise ValueError("Transfer an amount greater than zero.")

            with closing(get_db_connection()) as db:
                db.execute("BEGIN IMMEDIATE")

                recipient = db.execute(
                    """SELECT id FROM users
                       WHERE username = ? AND role = 'customer'""",
                    (recipient_name,),
                ).fetchone()

                sender = db.execute(
                    "SELECT balance_cents FROM users WHERE id = ?",
                    (g.user["id"],),
                ).fetchone()

                if recipient is None or recipient["id"] == g.user["id"]:
                    raise ValueError("Choose another existing customer.")

                if amount > sender["balance_cents"]:
                    raise ValueError("You do not have enough money.")

                deducted = db.execute(
                    """UPDATE users SET balance_cents = balance_cents - ?
                       WHERE id = ? AND role = 'customer' AND balance_cents >= ?""",
                    (amount, g.user["id"], amount),
                )
                if deducted.rowcount != 1:
                    raise ValueError("You do not have enough money.")

                db.execute(
                    "UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                    (amount, recipient["id"]),
                )

                db.execute(
                    """INSERT INTO transfers
                       (sender_id, recipient_id, amount_cents)
                       VALUES (?, ?, ?)""",
                    (g.user["id"], recipient["id"], amount),
                )

                db.commit()

            flash("Transfer recorded.")
            return redirect(url_for("dashboard"), code=303)

        except ValueError as error:
            flash(str(error))
            return render_template("transfer.html"), 400

    return render_template("transfer.html")


@app.post("/loans")
@login_required
def borrow():
    if g.user["role"] != "customer":
        abort(403)

    try:
        amount = parse_amount(request.form.get("amount", ""))

        if amount <= 0:
            raise ValueError("Borrow a positive amount.")

        with closing(get_db_connection()) as db:
            db.execute("BEGIN IMMEDIATE")

            user = db.execute(
                "SELECT * FROM users WHERE id = ?",
                (g.user["id"],),
            ).fetchone()

            extras = db.execute(
                "SELECT * FROM account_extras WHERE user_id = ?",
                (g.user["id"],),
            ).fetchone()

            if extras["debt_cents"] + amount > effective_loan_limit(
                user["credit_score"], extras
            ):
                raise ValueError(
                    "That loan exceeds your current borrowing limit."
                )

            db.execute(
                "UPDATE users SET balance_cents = balance_cents + ? WHERE id = ?",
                (amount, g.user["id"]),
            )

            db.execute(
                """UPDATE account_extras
                   SET debt_cents = debt_cents + ? WHERE user_id = ?""",
                (amount, g.user["id"]),
            )

            db.commit()

        flash("Loan added to your balance and outstanding debt.")

    except ValueError as error:
        flash(str(error))

    return redirect(url_for("dashboard"), code=303)


# V2 fixed: the administrator role is checked on the actual write endpoint.
@app.post("/admin/debt/<int:user_id>/delete")
@admin_required
def delete_debt(user_id):
    with closing(get_db_connection()) as db:
        cursor = db.execute(
            "UPDATE account_extras SET debt_cents = 0 WHERE user_id = ?",
            (user_id,),
        )

        if cursor.rowcount == 0:
            abort(404)

        db.commit()

    flash("Outstanding debt cleared.")

    return redirect(url_for("admin"), code=303)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        # V4 fixed: only these public profile fields can be changed here.
        editable_fields = ("username", "full_name", "email")
        check_form_fields(*editable_fields)

        updates = {
            key: request.form[key].strip()
            for key in editable_fields
            if key in request.form
        }

        error = None

        if "username" in updates:
            username_pattern = (
                r"[A-Za-z0-9_ ]{3,32}"
                if g.user["role"] == "admin"
                else r"[A-Za-z0-9_]{3,32}"
            )

            if not re.fullmatch(username_pattern, updates["username"]):
                error = "Enter a valid username."
            elif (
                updates["username"].lower()
                in (ADMIN_USERNAME.lower(), "lab_admin")
                and g.user["role"] != "admin"
            ):
                error = "That username is reserved."

        if "full_name" in updates and not valid_full_name(updates["full_name"]):
            error = "Enter a full name containing 1–120 printable characters."

        if "email" in updates:
            updates["email"] = updates["email"].lower()

            if len(updates["email"]) > 254 or not re.fullmatch(
                r"[^@\s]+@[^@\s]+\.[^@\s]+", updates["email"]
            ):
                error = "Enter a valid email address."

        if error:
            flash(error)
        else:
            try:
                with closing(get_db_connection()) as db:
                    db.execute(
                        """UPDATE users SET username = ?, full_name = ?, email = ?
                           WHERE id = ?""",
                        (updates.get("username", g.user["username"]),
                         updates.get("full_name", g.user["full_name"]),
                         updates.get("email", g.user["email"]), g.user["id"]),
                    )

                    db.commit()

                flash("Profile updated.")

            except sqlite3.IntegrityError:
                flash("That username or email is already registered.")

        return redirect(url_for("profile"), code=303)

    return render_template("profile.html")


@app.route("/support", methods=["GET", "POST"])
@login_required
def support():
    if request.method == "POST":
        body = request.form.get("body", "").strip()

        if not 1 <= len(body) <= 2000:
            flash("Write a message containing 1–2,000 characters.")
        else:
            with closing(get_db_connection()) as db:
                db.execute(
                    "INSERT INTO support_messages (user_id, body) VALUES (?, ?)",
                    (g.user["id"], body),
                )
                db.commit()

            flash("Message sent to the administrator.")

        return redirect(url_for("support"), code=303)

    with closing(get_db_connection()) as db:
        messages = db.execute(
            """SELECT * FROM support_messages
               WHERE user_id = ? ORDER BY id DESC""",
            (g.user["id"],),
        ).fetchall()

    return render_template("support.html", messages=messages)


@app.route("/giveaway", methods=["GET", "POST"])
@login_required
def giveaway():
    if g.user["role"] != "customer":
        return redirect(url_for("admin"))

    if request.method == "POST":
        # V6 fixed: ignore every client-supplied eligibility flag. The database
        # authorizes the claim and prevents repeat claims in the same write.
        code = "CRUISE-" + secrets.token_hex(16).upper()
        with closing(get_db_connection()) as db:
            cursor = db.execute("""
                UPDATE account_extras
                SET cruise_claimed = 1, ticket_code = ?
                WHERE user_id = ? AND cruise_eligible = 1 AND cruise_claimed = 0
            """, (code, g.user["id"]))
            existing = db.execute(
                "SELECT * FROM account_extras WHERE user_id = ?", (g.user["id"],)
            ).fetchone()
            if existing is None:
                abort(404)
            if not existing["cruise_eligible"]:
                abort(403, description="You have not been selected as a winner.")
            db.commit()
        flash("Ticket claimed." if cursor.rowcount else "You already claimed your ticket.")

        return redirect(url_for("giveaway"), code=303)

    with closing(get_db_connection()) as db:
        extras = db.execute(
            "SELECT * FROM account_extras WHERE user_id = ?",
            (g.user["id"],),
        ).fetchone()

    return render_template("giveaway.html", extras=extras)


@app.get("/admin")
@admin_required
def admin():
    with closing(get_db_connection()) as db:
        customer_rows = db.execute("""
            SELECT u.id, u.username, u.full_name, u.email,
                   u.balance_cents, u.credit_score, e.*
            FROM users u
            JOIN account_extras e ON e.user_id = u.id
            WHERE u.role = 'customer'
            ORDER BY u.id
        """).fetchall()

        messages = db.execute("""
            SELECT m.*, u.username
            FROM support_messages m
            JOIN users u ON u.id = m.user_id
            ORDER BY m.id DESC
        """).fetchall()

    customers = []

    for row in customer_rows:
        customer = dict(row)

        customer["borrowing_limit"] = effective_loan_limit(
            row["credit_score"], row
        )

        customer["remaining"] = max(
            0, customer["borrowing_limit"] - row["debt_cents"]
        )

        customers.append(customer)

    return render_template(
        "admin.html",
        customers=customers,
        messages=messages,
    )


@app.post("/admin/customers/<int:user_id>/update")
@admin_required
def update_customer(user_id):
    # Protected financial fields are changed only through this admin endpoint.
    with closing(get_db_connection()) as db:
        db.execute("BEGIN IMMEDIATE")

        customer = db.execute(
            "SELECT id FROM users WHERE id = ? AND role = 'customer'",
            (user_id,),
        ).fetchone()

        if customer is None:
            abort(404)

        try:
            vip_text = request.form.get("is_vip", "")

            if vip_text not in ("0", "1"):
                raise ValueError(
                    "Choose Standard or VIP for the account type."
                )

            score_text = request.form.get("credit_score", "").strip()

            if not re.fullmatch(r"[0-9]{3}", score_text):
                raise ValueError(
                    "Enter a credit score between 300 and 850."
                )

            score = int(score_text)

            if not 300 <= score <= 850:
                raise ValueError(
                    "Credit score must be between 300 and 850."
                )

            debt = parse_amount(request.form.get("debt", "").strip())

            if debt < 0:
                raise ValueError("Outstanding debt cannot be negative.")

            limit_text = request.form.get("borrowing_limit", "").strip()
            override = parse_amount(limit_text) if limit_text else None

            if override is not None and override < 0:
                raise ValueError("Borrowing limit cannot be negative.")

        except ValueError as error:
            flash(str(error))

            return redirect(
                url_for("admin") + f"#customer-{user_id}",
                code=303,
            )

        db.execute(
            "UPDATE users SET credit_score = ? WHERE id = ?",
            (score, user_id),
        )

        db.execute("""
            UPDATE account_extras
            SET is_vip = ?,
                debt_cents = ?,
                loan_limit_override_cents = ?
            WHERE user_id = ?
        """, (int(vip_text), debt, override, user_id))

        db.commit()

    flash("Customer account updated.")

    return redirect(
        url_for("admin") + f"#customer-{user_id}",
        code=303,
    )


@app.post("/admin/giveaway/<int:user_id>/winner")
@admin_required
def select_winner(user_id):
    with closing(get_db_connection()) as db:
        cursor = db.execute(
            """UPDATE account_extras
               SET cruise_eligible = 1 WHERE user_id = ?""",
            (user_id,),
        )

        if cursor.rowcount == 0:
            abort(404)

        db.commit()

    flash("Customer selected as a giveaway winner.")
    return redirect(url_for("admin"), code=303)


def create_tls_context():
    from setup_tls import create_certificate
    certificate, private_key = create_certificate(DATA_DIR / "certs")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(str(certificate), str(private_key))
    return context


if __name__ == "__main__":
    init_db()
    with closing(get_db_connection()) as db:
        has_admin = db.execute("SELECT 1 FROM users WHERE role = 'admin'").fetchone()
    if not has_admin:
        raise SystemExit("First run: python setup_admin.py, then python app.py")
    app.run(host="127.0.0.1", port=5001, debug=False,
            use_reloader=False, ssl_context=create_tls_context())
