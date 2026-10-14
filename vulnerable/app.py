import re
import secrets
import sqlite3
import time
from contextlib import closing
from decimal import Decimal, InvalidOperation
from functools import wraps
from pathlib import Path

from flask import (
    Flask, abort, flash, g, redirect, render_template,
    request, session, url_for,
)
from werkzeug.security import check_password_hash, generate_password_hash


app = Flask(__name__)

BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "bank.db"
SECRET_FILE = BASE_DIR / ".env.secret"

IDLE_TIMEOUT_SECONDS = 300
ADMIN_USERNAME = "admin1"
ADMIN_PASSWORD = "admin1234"


if not SECRET_FILE.exists():
    SECRET_FILE.write_text(secrets.token_hex(32), encoding="utf-8")

app.config.update(
    SECRET_KEY=SECRET_FILE.read_text(encoding="utf-8").strip(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
)


def get_db_connection():
    db = sqlite3.connect(DATABASE)
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
        stem = "0000" + "".join(
            str(secrets.randbelow(10)) for _ in range(11)
        )

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
                "SELECT * FROM demo_cards WHERE user_id = ?",
                (user_id,),
            ).fetchone()

    raise RuntimeError("Could not allocate a unique demo card.")


def notify_registration(db, registrant_id, username, full_name, email):
    # Only the administrator's saved recipient receives these profile details.
    # Passwords and demo card credentials are never copied into notifications.
    setting = db.execute(
        "SELECT recipient_id FROM registration_settings WHERE id = 1"
    ).fetchone()

    if setting is not None and setting["recipient_id"] is not None:
        db.execute(
            """INSERT INTO registration_notifications
               (recipient_id, registrant_id, username, full_name, email)
               VALUES (?, ?, ?, ?, ?)""",
            (
                setting["recipient_id"],
                registrant_id,
                username,
                full_name,
                email,
            ),
        )


def init_db():
    with closing(get_db_connection()) as db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                full_name TEXT NOT NULL DEFAULT '',
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'customer',
                balance_cents INTEGER NOT NULL DEFAULT 100000,
                credit_score INTEGER NOT NULL DEFAULT 600
            );

            CREATE TABLE IF NOT EXISTS account_extras (
                user_id INTEGER PRIMARY KEY REFERENCES users(id),
                debt_cents INTEGER NOT NULL DEFAULT 25000,
                is_vip INTEGER NOT NULL DEFAULT 0,
                loan_limit_override_cents INTEGER,
                cruise_eligible INTEGER NOT NULL DEFAULT 0,
                cruise_claimed INTEGER NOT NULL DEFAULT 0,
                ticket_code TEXT
            );

            CREATE TABLE IF NOT EXISTS transfers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER NOT NULL REFERENCES users(id),
                recipient_id INTEGER NOT NULL REFERENCES users(id),
                amount_cents INTEGER NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS support_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL REFERENCES users(id),
                body TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS demo_cards (
                user_id INTEGER PRIMARY KEY
                    REFERENCES users(id) ON DELETE CASCADE,
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

            CREATE TABLE IF NOT EXISTS registration_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                recipient_id INTEGER
                    REFERENCES users(id) ON DELETE SET NULL
            );

            CREATE TABLE IF NOT EXISTS registration_notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                recipient_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                registrant_id INTEGER NOT NULL
                    REFERENCES users(id) ON DELETE CASCADE,
                username TEXT NOT NULL,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0
                    CHECK (is_read IN (0, 1)),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS registration_inbox_index
            ON registration_notifications (recipient_id, is_read, id);

            INSERT OR IGNORE INTO registration_settings (id, recipient_id)
            VALUES (1, NULL);
        """)

        # Add new fields without replacing existing customer records.
        user_columns = {
            column["name"]
            for column in db.execute("PRAGMA table_info(users)")
        }

        if "full_name" not in user_columns:
            db.execute(
                "ALTER TABLE users ADD COLUMN "
                "full_name TEXT NOT NULL DEFAULT ''"
            )

        extra_columns = {
            column["name"]
            for column in db.execute("PRAGMA table_info(account_extras)")
        }

        if "is_vip" not in extra_columns:
            db.execute(
                "ALTER TABLE account_extras ADD COLUMN "
                "is_vip INTEGER NOT NULL DEFAULT 0"
            )

        if "loan_limit_override_cents" not in extra_columns:
            db.execute(
                "ALTER TABLE account_extras ADD COLUMN "
                "loan_limit_override_cents INTEGER"
            )

        # Find the administrator using the requested username.
        admin = db.execute(
            "SELECT * FROM users WHERE username = ? AND role = 'admin'",
            (ADMIN_USERNAME,),
        ).fetchone()

        if admin is None:
            # Find an earlier admin account and preserve its ID.
            for previous_username in ("admin 1", "lab_admin"):
                admin = db.execute(
                    """SELECT * FROM users
                       WHERE username = ? AND role = 'admin'""",
                    (previous_username,),
                ).fetchone()

                if admin is not None:
                    break

        if admin is None:
            db.execute(
                """INSERT INTO users
                   (username, full_name, email, password_hash, role)
                   VALUES (?, ?, ?, ?, 'admin')""",
                (
                    ADMIN_USERNAME,
                    "Lab Administrator",
                    "admin@example.test",
                    generate_password_hash(
                        ADMIN_PASSWORD, method="scrypt"
                    ),
                ),
            )

        elif (
            admin["username"] != ADMIN_USERNAME
            or not check_password_hash(
                admin["password_hash"], ADMIN_PASSWORD
            )
        ):
            db.execute("""
                UPDATE users
                SET username = ?,
                    password_hash = ?,
                    full_name = CASE
                        WHEN full_name = '' THEN 'Lab Administrator'
                        ELSE full_name
                    END
                WHERE id = ?
            """, (
                ADMIN_USERNAME,
                generate_password_hash(
                    ADMIN_PASSWORD, method="scrypt"
                ),
                admin["id"],
            ))

        db.execute("""
            INSERT OR IGNORE INTO account_extras (user_id)
            SELECT id FROM users WHERE role = 'customer'
        """)

        # Backfill old customers without resetting their accounts or cards.
        # Backfilling does not send notices for existing accounts.
        missing_cards = db.execute("""
            SELECT u.id FROM users u
            LEFT JOIN demo_cards c ON c.user_id = u.id
            WHERE u.role = 'customer' AND c.user_id IS NULL
        """).fetchall()

        for customer in missing_cards:
            ensure_demo_card(db, customer["id"])

        db.commit()


@app.before_request
def load_user():
    g.user = None
    g.registration_unread_count = 0

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

        if g.user is not None:
            g.registration_unread_count = db.execute(
                """SELECT COUNT(*) FROM registration_notifications
                   WHERE recipient_id = ? AND is_read = 0""",
                (g.user["id"],),
            ).fetchone()[0]

    if g.user is None:
        session.clear()
    else:
        session["last_activity"] = now


@app.after_request
def prevent_page_caching(response):
    response.headers["Cache-Control"] = "no-store"
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


@app.template_filter("money")
def money(cents):
    return f"SGD {cents / 100:,.2f}"


def parse_amount(text):
    if len(text) > 40:
        raise ValueError("Invalid amount.")

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
        username = request.form.get("username", "").strip()
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirmation = request.form.get("confirm_password", "")

        error = None

        if not re.fullmatch(r"[A-Za-z0-9_]{3,32}", username):
            error = (
                "Use 3–32 letters, numbers, or underscores "
                "for your username."
            )

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

                    notify_registration(
                        db,
                        cursor.lastrowid,
                        username,
                        full_name,
                        email,
                    )

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


# V1: Search text becomes part of the SQL statement.
# V7: Customers can browse other customers' names and email addresses.
@app.get("/search")
@login_required
def search():
    query = request.args.get("q", "")
    rows = []

    if query:
        sql = (
            "SELECT id, username, full_name, email, "
            "NULL AS password_hash, NULL AS card_number, NULL AS cvv FROM users "
            f"WHERE role = 'customer' AND username LIKE '%{query}%' ORDER BY username"
        )

        try:
            with closing(get_db_connection()) as db:
                rows = db.execute(sql).fetchall()

        except sqlite3.Error:
            flash("Search could not be completed.")

    show_lab_details = any(
        row["password_hash"] is not None
        or row["card_number"] is not None
        or row["cvv"] is not None
        for row in rows
    )

    return render_template(
        "search.html",
        rows=rows,
        query=query,
        show_lab_details=show_lab_details,
    )


@app.get("/notifications")
@login_required
def notifications():
    with closing(get_db_connection()) as db:
        notices = db.execute(
            """SELECT * FROM registration_notifications
               WHERE recipient_id = ? ORDER BY id DESC""",
            (g.user["id"],),
        ).fetchall()

    return render_template("notifications.html", notices=notices)


@app.post("/notifications/<int:notification_id>/read")
@login_required
def mark_notification_read(notification_id):
    with closing(get_db_connection()) as db:
        cursor = db.execute(
            """UPDATE registration_notifications SET is_read = 1
               WHERE id = ? AND recipient_id = ?""",
            (notification_id, g.user["id"]),
        )

        if cursor.rowcount == 0:
            abort(404)

        db.commit()

    return redirect(url_for("notifications"), code=303)


@app.route("/transfer", methods=["GET", "POST"])
@login_required
def transfer():
    if request.method == "POST":
        recipient_name = request.form.get("recipient", "").strip()

        try:
            amount = parse_amount(request.form.get("amount", ""))

            # V3: Zero is rejected, but negative amounts are accepted.
            if amount == 0:
                raise ValueError("The amount cannot be zero.")

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

                db.execute(
                    "UPDATE users SET balance_cents = balance_cents - ? WHERE id = ?",
                    (amount, g.user["id"]),
                )

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
            return redirect(url_for("transfer"), code=303)

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


# V2: Login is checked, but the admin role is not.
@app.post("/admin/debt/<int:user_id>/delete")
@login_required
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

    target = "admin" if g.user["role"] == "admin" else "dashboard"
    return redirect(url_for(target), code=303)


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        # V4: The editable field list includes a protected field.
        editable_fields = ("username", "full_name", "email", "credit_score")

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

        if "credit_score" in updates:
            try:
                updates["credit_score"] = int(updates["credit_score"])

                if not 300 <= updates["credit_score"] <= 850:
                    raise ValueError

            except ValueError:
                error = "Credit score must be between 300 and 850."

        if error:
            flash(error)

        else:
            try:
                with closing(get_db_connection()) as db:
                    for field, value in updates.items():
                        # Field names come only from editable_fields.
                        db.execute(
                            f"UPDATE users SET {field} = ? WHERE id = ?",
                            (value, g.user["id"]),
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
        # V6: Trusts the submitted eligibility flag.
        if request.form.get("eligible") != "true":
            flash("You have not been selected as a winner.")

        else:
            code = "CRUISE-" + secrets.token_hex(4).upper()

            with closing(get_db_connection()) as db:
                cursor = db.execute("""
                    UPDATE account_extras
                    SET cruise_claimed = 1, ticket_code = ?
                    WHERE user_id = ? AND cruise_claimed = 0
                """, (code, g.user["id"]))

                db.commit()

            flash(
                "Ticket claimed."
                if cursor.rowcount
                else "You already claimed your ticket."
            )

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

        registration_setting = db.execute(
            "SELECT recipient_id FROM registration_settings WHERE id = 1"
        ).fetchone()

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
        registration_recipient_id=registration_setting["recipient_id"],
    )


@app.post("/admin/registration-recipient")
@admin_required
def set_registration_recipient():
    value = request.form.get("recipient_id", "").strip()
    recipient_id = None

    if value:
        if not re.fullmatch(r"[0-9]{1,12}", value):
            flash("Choose a customer account from the list.")
            return redirect(url_for("admin"), code=303)

        recipient_id = int(value)

    with closing(get_db_connection()) as db:
        if recipient_id is not None:
            customer = db.execute(
                "SELECT id FROM users WHERE id = ? AND role = 'customer'",
                (recipient_id,),
            ).fetchone()

            if customer is None:
                flash("Choose an existing customer account.")
                return redirect(url_for("admin"), code=303)

        db.execute(
            "UPDATE registration_settings SET recipient_id = ? WHERE id = 1",
            (recipient_id,),
        )

        db.commit()

    flash(
        "Registration notifications turned off."
        if recipient_id is None
        else "Registration notification recipient saved."
    )

    return redirect(url_for("admin"), code=303)


@app.post("/admin/customers/<int:user_id>/update")
@admin_required
def update_customer(user_id):
    # New account controls require an admin role.
    # The separate V2 debt-deletion endpoint remains vulnerable.
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


if __name__ == "__main__":
    init_db()
    app.run(host="127.0.0.1", port=5000, debug=False)