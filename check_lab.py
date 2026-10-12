import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash
from vulnerable import app as bank
from reset_database import reset_database

bank.app.config["TESTING"] = True


def check(condition, description):
    assert condition, description
    print("PASS:", description)


with tempfile.TemporaryDirectory() as directory:
    bank.DATABASE = Path(directory) / "vulnerable" / "bank.db"
    bank.DATABASE.parent.mkdir()
    bank.SECRET_FILE = bank.DATABASE.parent / ".env.secret"
    bank.SECRET_FILE.write_text(
        bank.app.config["SECRET_KEY"], encoding="utf-8"
    )

    old_hash = generate_password_hash("user1234", method="scrypt")

    with closing(sqlite3.connect(bank.DATABASE)) as db:
        db.execute("""CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE COLLATE NOCASE,
            email TEXT NOT NULL UNIQUE COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'customer',
            balance_cents INTEGER NOT NULL DEFAULT 100000,
            credit_score INTEGER NOT NULL DEFAULT 600
        )""")
        db.execute(
            "INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)",
            ("user1", "user@gmail.com", old_hash),
        )
        db.execute("""CREATE TABLE account_extras (
            user_id INTEGER PRIMARY KEY REFERENCES users(id),
            debt_cents INTEGER NOT NULL DEFAULT 25000,
            cruise_eligible INTEGER NOT NULL DEFAULT 0,
            cruise_claimed INTEGER NOT NULL DEFAULT 0,
            ticket_code TEXT
        )""")
        db.execute("INSERT INTO account_extras (user_id) VALUES (1)")
        db.commit()

    bank.init_db()

    def row(sql, args=()):
        with closing(bank.get_db_connection()) as db:
            return db.execute(sql, args).fetchone()

    def customer(username):
        return row(
            "SELECT * FROM users WHERE username = ?", (username,)
        )

    user1 = customer("user1")
    check(
        user1["password_hash"] == old_hash
        and user1["balance_cents"] == 100000,
        "Existing account/password/balance preserved",
    )
    check(
        user1["full_name"] == ""
        and row("SELECT debt_cents FROM account_extras")[0] == 25000,
        "Migration adds full-name field without inventing a name or resetting debt",
    )
    check(
        row("SELECT is_vip, loan_limit_override_cents FROM account_extras")[0] == 0,
        "Existing account defaults to Standard with automatic borrowing limit",
    )

    user_id = user1["id"]
    customer_client = bank.app.test_client()
    admin_client = bank.app.test_client()
    anonymous = bank.app.test_client()

    check(
        customer_client.post(
            "/login",
            data={"username": "user1", "password": "wrong"},
        ).status_code == 401,
        "Wrong password rejected",
    )
    check(
        customer_client.post(
            "/login",
            data={"username": "user1", "password": "user1234"},
        ).status_code == 303,
        "Existing account signs in",
    )
    check(
        customer_client.post("/register", data={
            "username": "user2",
            "email": "user2@example.test",
            "full_name": "Alex O'Neil",
            "password": "user1234",
            "confirm_password": "user1234",
            "role": "admin",
            "credit_score": "850",
            "is_vip": "1",
            "borrowing_limit": "9000",
        }).status_code == 303,
        "Second customer created",
    )
    check(
        customer("user2")["role"] == "customer"
        and customer("user2")["credit_score"] == 600,
        "Registration ignores protected fields",
    )
    check(
        check_password_hash(
            customer("user2")["password_hash"], "user1234"
        ),
        "New password stored as a hash",
    )
    check(
        customer("user2")["full_name"] == "Alex O'Neil",
        "Registration stores full name",
    )

    second_id = customer("user2")["id"]
    check(
        row(
            "SELECT is_vip FROM account_extras WHERE user_id = ?",
            (second_id,),
        )[0] == 0,
        "Registration cannot set VIP status",
    )

    missing_name = {
        "username": "user3",
        "email": "user3@example.test",
        "password": "user1234",
        "confirm_password": "user1234",
    }
    check(
        anonymous.post(
            "/register", data=missing_name
        ).status_code == 400,
        "Registration requires full name on the server",
    )
    check(
        anonymous.post("/register", data={
            **missing_name,
            "full_name": "Alex\x00Smith",
        }).status_code == 400,
        "Control characters in full names rejected",
    )

    customer_client.post(
        "/profile", data={"full_name": "Jamie García"}
    )
    check(
        customer("user1")["full_name"] == "Jamie García",
        "Existing account can add a Unicode full name",
    )
    check(
        admin_client.post("/login", data={
            "username": "lab_admin",
            "password": "AdminDemo123!",
        }).status_code == 303,
        "Admin demo account signs in",
    )

    for path in (
        "/", "/login", "/register", "/dashboard", "/search",
        "/transfer", "/profile", "/support", "/giveaway",
    ):
        check(
            customer_client.get(
                path, follow_redirects=True
            ).status_code == 200,
            f"Page renders: {path}",
        )

    check(
        admin_client.get("/admin").status_code == 200,
        "Admin page renders",
    )
    check(
        customer_client.get("/admin").status_code == 403,
        "Customer cannot open admin page",
    )
    check(
        anonymous.get("/dashboard").status_code == 302,
        "Anonymous customer page blocked",
    )
    check(
        customer_client.get(
            "/search", query_string={"q": "user2"}
        ).status_code == 200,
        "Ordinary search works",
    )

    ordinary = customer_client.get(
        "/search", query_string={"q": "user2"}
    ).get_data(as_text=True)
    check(
        "Alex O&#39;Neil" in ordinary
        and "user2@example.test" in ordinary,
        "V7: Ordinary customer search reveals another customer's name and email",
    )
    check(
        "Lab Administrator" not in customer_client.get(
            "/search", query_string={"q": "lab_admin"}
        ).get_data(as_text=True),
        "Ordinary search excludes the admin account",
    )

    injection = (
        "' AND 1=0 UNION SELECT "
        "id, username, full_name, password_hash FROM users -- "
    )
    result = customer_client.get(
        "/search", query_string={"q": injection}
    ).get_data(as_text=True)
    check(
        old_hash in result
        and "Jamie García" in result
        and "Lab Administrator" in result,
        "V1: SQL injection exposes full names and password hashes, including the admin",
    )

    check(
        customer_client.post("/transfer", data={
            "recipient": "user2", "amount": "100",
        }).status_code == 303,
        "Ordinary transfer accepted",
    )
    check(
        customer("user1")["balance_cents"] == 90000
        and customer("user2")["balance_cents"] == 110000,
        "Ordinary transfer updates both balances",
    )

    customer_client.post("/transfer", data={
        "recipient": "user2", "amount": "-100",
    })
    check(
        customer("user1")["balance_cents"] == 100000
        and customer("user2")["balance_cents"] == 100000,
        "V3: Negative transfer increases sender balance and decreases recipient balance",
    )

    before = customer("user1")["balance_cents"]
    customer_client.post("/transfer", data={
        "recipient": "missing", "amount": "10",
    })
    customer_client.post("/transfer", data={
        "recipient": "user2", "amount": "NaN",
    })
    check(
        customer("user1")["balance_cents"] == before,
        "Invalid transfers do not change balance",
    )

    customer_client.post("/loans", data={"amount": "2000"})
    check(
        customer("user1")["balance_cents"] == before,
        "Large loan rejected at original credit score",
    )

    customer_client.post("/profile", data={
        "username": "user1",
        "email": "user@gmail.com",
        "credit_score": "850",
        "role": "admin",
        "is_vip": "1",
        "loan_limit_override_cents": "999999",
    })
    check(
        customer("user1")["credit_score"] == 850
        and customer("user1")["role"] == "customer",
        "V4: Extra profile field changes credit score, not role",
    )

    unchanged_extras = row(
        "SELECT * FROM account_extras WHERE user_id = ?",
        (user_id,),
    )
    check(
        unchanged_extras["is_vip"] == 0
        and unchanged_extras["loan_limit_override_cents"] is None,
        "Profile cannot change the new protected VIP/limit fields",
    )

    customer_client.post("/loans", data={"amount": "2000"})
    check(
        customer("user1")["balance_cents"] == before + 200000,
        "Changed score permits larger loan",
    )
    check(
        customer_client.post(
            f"/admin/debt/{user_id}/delete"
        ).status_code == 303,
        "V2: Customer can call admin debt action",
    )
    check(
        row(
            "SELECT debt_cents FROM account_extras WHERE user_id = ?",
            (user_id,),
        )[0] == 0,
        "Debt cleared in database",
    )

    payload = '<script>alert("CW2 stored XSS")</script>'
    customer_client.post("/support", data={"body": payload})
    check(
        "&lt;script&gt;" in customer_client.get(
            "/support"
        ).get_data(as_text=True),
        "Customer message history escapes HTML",
    )
    check(
        payload in admin_client.get(
            "/admin"
        ).get_data(as_text=True),
        "V5: Stored script rendered unescaped in admin inbox (browser execution requires manual check)",
    )

    customer_client.post("/giveaway", data={"eligible": "false"})
    check(
        row(
            "SELECT cruise_claimed FROM account_extras WHERE user_id = ?",
            (user_id,),
        )[0] == 0,
        "Ordinary non-winner claim rejected",
    )
    check(
        customer_client.post(
            f"/admin/giveaway/{user_id}/winner"
        ).status_code == 403,
        "Winner selection requires admin",
    )

    customer_client.post("/giveaway", data={"eligible": "true"})
    extras = row(
        "SELECT * FROM account_extras WHERE user_id = ?",
        (user_id,),
    )
    check(
        extras["cruise_eligible"] == 0
        and extras["cruise_claimed"] == 1
        and extras["ticket_code"],
        "V6: Forged eligibility claims ticket without winning",
    )

    ticket = extras["ticket_code"]
    customer_client.post("/giveaway", data={"eligible": "true"})
    check(
        row(
            "SELECT ticket_code FROM account_extras WHERE user_id = ?",
            (user_id,),
        )[0] == ticket,
        "Repeat claim does not replace ticket",
    )

    admin_client.post(
        f'/admin/giveaway/{customer("user2")["id"]}/winner'
    )
    second = bank.app.test_client()
    second.post("/login", data={
        "username": "user2", "password": "user1234",
    })
    second.post("/giveaway", data={"eligible": "true"})
    check(
        row(
            "SELECT cruise_claimed FROM account_extras WHERE user_id = ?",
            (customer("user2")["id"],),
        )[0] == 1,
        "Legitimate winner can claim",
    )

    bank.init_db()
    check(
        row(
            "SELECT debt_cents FROM account_extras WHERE user_id = ?",
            (user_id,),
        )[0] == 0,
        "Restart does not recreate cleared debt",
    )
    check(
        row(
            "SELECT ticket_code FROM account_extras WHERE user_id = ?",
            (user_id,),
        )[0] == ticket,
        "Restart preserves ticket",
    )

    edit_path = f"/admin/customers/{user_id}/update"
    edit = {
        "is_vip": "1",
        "credit_score": "720",
        "debt": "800.00",
        "borrowing_limit": "750.00",
    }
    check(
        customer_client.post(
            edit_path, data=edit
        ).status_code == 403,
        "Customer cannot call the new admin account-update endpoint",
    )
    check(
        anonymous.post(edit_path, data=edit).status_code == 302,
        "Anonymous account updates require login",
    )
    check(
        customer("user1")["credit_score"] == 850,
        "Blocked updates leave customer data unchanged",
    )
    check(
        admin_client.post(
            "/admin/customers/999999/update", data=edit
        ).status_code == 404,
        "Admin cannot update a nonexistent customer",
    )
    check(
        admin_client.post(
            f'/admin/customers/{customer("lab_admin")["id"]}/update',
            data=edit,
        ).status_code == 404,
        "Customer controls cannot alter the admin account",
    )

    for field, value in (
        ("is_vip", "2"),
        ("credit_score", "900"),
        ("credit_score", "abc"),
        ("debt", "-1"),
        ("debt", "NaN"),
        ("debt", "1.001"),
        ("borrowing_limit", "-10"),
        ("borrowing_limit", "1000000.01"),
    ):
        admin_client.post(
            edit_path, data={**edit, field: value}
        )
        saved = row(
            "SELECT * FROM account_extras WHERE user_id = ?",
            (user_id,),
        )
        check(
            saved["is_vip"] == 0
            and saved["debt_cents"] == 0
            and saved["loan_limit_override_cents"] is None
            and customer("user1")["credit_score"] == 850,
            f"Invalid admin {field}={value} rejected without partial updates",
        )

    check(
        admin_client.post(
            edit_path, data=edit
        ).status_code == 303,
        "Admin can save VIP, credit score, debt, and a custom borrowing limit",
    )
    saved = row(
        "SELECT * FROM account_extras WHERE user_id = ?",
        (user_id,),
    )
    check(
        saved["is_vip"] == 1
        and saved["debt_cents"] == 80000
        and saved["loan_limit_override_cents"] == 75000,
        "Admin values stored in the correct units",
    )

    page = customer_client.get(
        "/dashboard"
    ).get_data(as_text=True)
    check(
        "VIP" in page
        and "SGD 750.00" in page
        and "SGD 0.00" in page,
        "Customer dashboard reflects VIP status and admin-set limit",
    )

    before_loan = customer("user1")["balance_cents"]
    customer_client.post("/loans", data={"amount": "1"})
    check(
        customer("user1")["balance_cents"] == before_loan,
        "Debt above a reduced borrowing limit blocks new loans",
    )

    admin_client.post(
        edit_path, data={**edit, "debt": "500.00"}
    )
    customer_client.post("/loans", data={"amount": "250.00"})
    check(
        row(
            "SELECT debt_cents FROM account_extras WHERE user_id = ?",
            (user_id,),
        )[0] == 75000,
        "Loan at the exact custom borrowing limit accepted",
    )

    before_loan = customer("user1")["balance_cents"]
    customer_client.post("/loans", data={"amount": "0.01"})
    check(
        customer("user1")["balance_cents"] == before_loan,
        "Loan one cent beyond custom limit rejected",
    )

    admin_client.post(edit_path, data={
        **edit,
        "debt": "750.00",
        "borrowing_limit": "1000.00",
    })
    customer_client.post("/loans", data={"amount": "100.00"})
    check(
        row(
            "SELECT debt_cents FROM account_extras WHERE user_id = ?",
            (user_id,),
        )[0] == 85000,
        "Increasing custom limit permits further borrowing",
    )

    admin_client.post(edit_path, data={
        **edit,
        "debt": "850.00",
        "borrowing_limit": "0",
    })
    saved = row(
        "SELECT * FROM account_extras WHERE user_id = ?",
        (user_id,),
    )
    check(
        bank.effective_loan_limit(720, saved) == 0,
        "An explicit zero borrowing limit stays zero",
    )

    before_loan = customer("user1")["balance_cents"]
    customer_client.post("/loans", data={"amount": "1"})
    check(
        customer("user1")["balance_cents"] == before_loan,
        "Zero borrowing limit blocks new loans",
    )

    admin_client.post(edit_path, data={
        **edit,
        "debt": "100.00",
        "borrowing_limit": "",
    })
    saved = row(
        "SELECT * FROM account_extras WHERE user_id = ?",
        (user_id,),
    )
    check(
        saved["loan_limit_override_cents"] is None
        and bank.effective_loan_limit(720, saved) == 250000,
        "Blank custom limit restores credit-score-based borrowing",
    )

    customer_client.post(
        "/profile", data={"credit_score": "850"}
    )
    check(
        "SGD 5,000.00" in customer_client.get(
            "/dashboard"
        ).get_data(as_text=True),
        "V4 remains demonstrable when the custom limit is blank",
    )

    bank.init_db()
    saved = row(
        "SELECT * FROM account_extras WHERE user_id = ?",
        (user_id,),
    )
    check(
        saved["is_vip"] == 1 and saved["debt_cents"] == 10000,
        "Restart preserves admin edits without recreating initial debt",
    )

    with customer_client.session_transaction() as session:
        session["last_activity"] -= 301

    check(
        customer_client.get(
            "/dashboard"
        ).location.endswith("/login"),
        "Idle session expires",
    )

    customer_client.post("/login", data={
        "username": "user1", "password": "user1234",
    })
    customer_client.post("/logout")
    check(
        customer_client.get(
            "/dashboard"
        ).location.endswith("/login"),
        "Logout blocks dashboard",
    )

    customer_client.post("/login", data={
        "username": "user1", "password": "user1234",
    })
    old_secret = bank.app.config["SECRET_KEY"]
    backup = reset_database()

    check(
        backup is not None and backup.exists(),
        "Reset makes a recoverable database backup",
    )

    with closing(sqlite3.connect(backup)) as backup_db:
        check(
            backup_db.execute(
                "SELECT full_name FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()[0] == "Jamie García",
            "Reset backup retains original customer records",
        )
        check(
            backup_db.execute(
                "SELECT debt_cents FROM account_extras WHERE user_id = ?",
                (user_id,),
            ).fetchone()[0] == 10000,
            "Reset backup retains latest debt edits",
        )

    check(
        row("SELECT COUNT(*) FROM users")[0] == 1
        and customer("lab_admin")["role"] == "admin",
        "Fresh database contains only the lab admin, no old or seeded customers",
    )
    check(
        row("SELECT COUNT(*) FROM account_extras")[0] == 0
        and row("SELECT COUNT(*) FROM transfers")[0] == 0
        and row("SELECT COUNT(*) FROM support_messages")[0] == 0,
        "Reset removes old debts, tickets, transfers, and support messages",
    )
    check(
        bank.app.config["SECRET_KEY"] != old_secret
        and customer_client.get(
            "/dashboard"
        ).location.endswith("/login"),
        "Reset invalidates old browser sessions",
    )
    check(
        admin_client.post("/login", data={
            "username": "lab_admin",
            "password": "AdminDemo123!",
        }).status_code == 303,
        "Fresh admin account signs in after reset",
    )

print("All integration checks passed.")