"""Regression tests for the eight CW2 findings; CSRF stays enabled throughout."""
import http.client
import io
import os
import re
import sqlite3
import ssl
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, redirect_stdout
from html.parser import HTMLParser
from pathlib import Path
from unittest.mock import patch

from markupsafe import escape
from werkzeug.datastructures import MultiDict
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.serving import make_server

_import_directory = tempfile.TemporaryDirectory(prefix="cw2-secure-import-")
_previous_instance = os.environ.get("BANK_INSTANCE_DIR")
os.environ["BANK_INSTANCE_DIR"] = _import_directory.name
import app as bank
if _previous_instance is None:
    os.environ.pop("BANK_INSTANCE_DIR", None)
else:
    os.environ["BANK_INSTANCE_DIR"] = _previous_instance

HTTPS = "https://127.0.0.1"
TEST_PASSWORD = "Fictional-test-password-123"


class BankSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = generate_password_hash(TEST_PASSWORD, method="scrypt")

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="cw2-secure-test-")
        self.addCleanup(self.directory.cleanup)
        bank.app.config.update(
            TESTING=True, DATABASE=Path(self.directory.name) / "test.db",
            SECRET_KEY="isolated-test-secret-which-is-never-used-by-the-bank",
            WTF_CSRF_ENABLED=True, WTF_CSRF_SSL_STRICT=True,
        )
        bank.init_db()
        with closing(bank.get_db_connection()) as db:
            for user_id, username, role in [(1, "admin1", "admin"), (2, "user1", "customer"), (3, "user2", "customer")]:
                db.execute(
                    """INSERT INTO users (id, username, full_name, email, password_hash, role)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (user_id, username, f"Fictional {username}", f"{username}@example.test", self.password_hash, role),
                )
                if role == "customer":
                    db.execute("INSERT INTO account_extras (user_id) VALUES (?)", (user_id,))
                    bank.ensure_demo_card(db, user_id)
            db.commit()
        self.client = bank.app.test_client()

    def read(self, sql, values=()):
        with closing(bank.get_db_connection()) as db:
            return [dict(row) for row in db.execute(sql, values).fetchall()]

    def write(self, sql, values=()):
        with closing(bank.get_db_connection()) as db:
            db.execute(sql, values)
            db.commit()

    def get(self, path, client=None, **kwargs):
        return (client or self.client).get(path, base_url=HTTPS, **kwargs)

    def token(self, path="/profile", client=None):
        response = self.get(path, client)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        match = re.search(r'name="csrf_token" value="([^"]+)"', response.get_data(as_text=True))
        self.assertIsNotNone(match, f"No CSRF form token on {path}")
        return match.group(1)

    def post(self, path, data=None, client=None, token_path="/profile"):
        client = client or self.client
        data = MultiDict(data or {})
        data["csrf_token"] = self.token(token_path, client)
        return client.post(path, data=data, base_url=HTTPS, headers={"Referer": HTTPS + token_path})

    def login(self, username="user1", client=None):
        response = self.post("/login", {"username": username, "password": TEST_PASSWORD}, client, "/login")
        self.assertEqual(response.status_code, 303)
        return response

    def balances(self):
        return self.read("SELECT id, balance_cents FROM users ORDER BY id")

    def test_v1_admin_sql_injection_is_literal_search_text(self):
        self.login("admin1")
        payloads = [
            "%' OR 1=1 --",
            "%' UNION SELECT id, username, password_hash, email FROM users --",
            "%' UNION SELECT id, username, full_name, email, password_hash, NULL, NULL FROM users --",
        ]
        for payload in payloads:
            with self.subTest(payload=payload):
                response = self.get("/search", query_string={"q": payload})
                self.assertEqual(response.status_code, 200)
                html = response.get_data(as_text=True)
                self.assertIn("No matching accounts.", html)
                self.assertNotIn(self.password_hash, html)
                self.assertNotIn("user2@example.test", html)

    def test_v1_legitimate_admin_search_omits_hashes_and_cards(self):
        self.login("admin1")
        response = self.get("/search?q=user1")
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("user1@example.test", html)
        self.assertNotIn(self.password_hash, html)
        card = self.read("SELECT card_number FROM demo_cards WHERE user_id = 2")[0]
        self.assertNotIn(card["card_number"], html)
        self.assertNotIn("Demo CVV", html)

    def test_v7_customer_search_is_forbidden_and_absent_from_navigation(self):
        self.login()
        response = self.get("/search?q=user2")
        self.assertEqual(response.status_code, 403)
        self.assertNotIn("user2@example.test", response.get_data(as_text=True))
        self.assertNotIn('href="/search"', self.get("/dashboard").get_data(as_text=True))

    def test_v2_customer_cannot_clear_own_or_another_customers_debt(self):
        self.login()
        before = self.read("SELECT * FROM account_extras ORDER BY user_id")
        for target in (2, 3):
            self.assertEqual(self.post(f"/admin/debt/{target}/delete").status_code, 403)
        self.assertEqual(before, self.read("SELECT * FROM account_extras ORDER BY user_id"))

    def test_v2_admin_can_clear_debt(self):
        self.login("admin1")
        self.assertEqual(self.post("/admin/debt/2/delete").status_code, 303)
        self.assertEqual(self.read("SELECT debt_cents FROM account_extras WHERE user_id=2")[0]["debt_cents"], 0)
        self.assertEqual(self.read("SELECT debt_cents FROM account_extras WHERE user_id=3")[0]["debt_cents"], 25000)

    def test_all_admin_routes_check_the_role_on_the_server(self):
        self.login()
        self.assertEqual(self.get("/admin").status_code, 403)
        for path in ("/admin/giveaway/2/winner", "/admin/customers/2/update"):
            self.assertEqual(self.post(path, {"credit_score": "850"}).status_code, 403)

    def test_admin_role_is_reloaded_from_database(self):
        self.login("admin1")
        self.write("UPDATE users SET role='customer' WHERE id=1")
        self.assertEqual(self.post("/admin/giveaway/2/winner").status_code, 403)

    def test_v3_bad_amounts_cannot_change_balances_or_the_ledger(self):
        self.login()
        before = self.balances()
        for amount in ("-100", "0", "-0.00", "NaN", "Infinity", "0.001", "1000000.01", "1e309", "1e99999999", ""):
            with self.subTest(amount=amount):
                response = self.post("/transfer", {"recipient": "user2", "amount": amount})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(self.balances(), before)
                self.assertEqual(self.read("SELECT * FROM transfers"), [])

    def test_v3_positive_transfer_moves_the_exact_amount_once(self):
        self.login()
        self.assertEqual(self.post("/transfer", {"recipient": "user2", "amount": "10.25"}).status_code, 303)
        rows = self.read("SELECT balance_cents FROM users WHERE role='customer' ORDER BY id")
        self.assertEqual([r["balance_cents"] for r in rows], [98975, 101025])
        self.assertEqual(self.read("SELECT amount_cents FROM transfers"), [{"amount_cents": 1025}])

    def test_transfer_rejects_overspending_self_and_missing_recipients(self):
        self.login()
        before = self.balances()
        for recipient, amount in [("user2", "1000.01"), ("user1", "10"), ("missing", "10"), ("admin1", "10")]:
            self.assertEqual(self.post("/transfer", {"recipient": recipient, "amount": amount}).status_code, 400)
        self.assertEqual(before, self.balances())

    def test_transfer_rolls_back_both_balances_when_ledger_insert_fails(self):
        self.login()
        before = self.balances()
        self.write("""CREATE TRIGGER reject_ledger BEFORE INSERT ON transfers
                      BEGIN SELECT RAISE(ABORT, 'test rollback'); END""")
        with self.assertRaises(sqlite3.IntegrityError):
            self.post("/transfer", {"recipient": "user2", "amount": "10"})
        self.assertEqual(before, self.balances())
        self.assertEqual([], self.read("SELECT * FROM transfers"))

    def test_concurrent_transfers_cannot_spend_the_same_balance_twice(self):
        clients = [bank.app.test_client(), bank.app.test_client()]
        for client in clients:
            self.login(client=client)
        tokens = [self.token(client=c) for c in clients]
        def send(index):
            return clients[index].post("/transfer", base_url=HTTPS,
                data={"recipient": "user2", "amount": "600", "csrf_token": tokens[index]},
                headers={"Referer": HTTPS + "/profile"}).status_code
        with ThreadPoolExecutor(max_workers=2) as pool:
            statuses = list(pool.map(send, range(2)))
        self.assertEqual(sorted(statuses), [303, 400])
        self.assertEqual(self.read("SELECT balance_cents FROM users WHERE id=2")[0]["balance_cents"], 40000)
        self.assertEqual(len(self.read("SELECT * FROM transfers")), 1)

    def test_v4_profile_rejects_all_protected_fields(self):
        self.login()
        before = self.read("SELECT * FROM users WHERE id=2")
        extras = self.read("SELECT * FROM account_extras WHERE user_id=2")
        for field, value in [("credit_score", "850"), ("role", "admin"), ("balance_cents", "999999"),
                             ("debt_cents", "0"), ("is_vip", "1"), ("cruise_eligible", "1"),
                             ("loan_limit_override_cents", "999999")]:
            with self.subTest(field=field):
                self.assertEqual(self.post("/profile", {field: value}).status_code, 400)
                self.assertEqual(before, self.read("SELECT * FROM users WHERE id=2"))
                self.assertEqual(extras, self.read("SELECT * FROM account_extras WHERE user_id=2"))

    def test_v4_legitimate_profile_edits_work_without_changing_credit(self):
        self.login()
        self.assertEqual(self.post("/profile", {"full_name": "Updated fictional name", "email": "updated@example.test"}).status_code, 303)
        row = self.read("SELECT full_name, email, credit_score FROM users WHERE id=2")[0]
        self.assertEqual(row, {"full_name": "Updated fictional name", "email": "updated@example.test", "credit_score": 600})

    def test_profile_rejects_duplicate_parameters(self):
        self.login()
        data = MultiDict([("full_name", "First"), ("full_name", "Second")])
        self.assertEqual(self.post("/profile", data).status_code, 400)

    def test_v4_only_admin_changes_can_raise_the_borrowing_limit(self):
        self.login()
        self.assertEqual(self.post("/profile", {"credit_score": "850"}).status_code, 400)
        self.post("/loans", {"amount": "1000"})
        self.assertEqual(self.read("SELECT debt_cents FROM account_extras WHERE user_id=2")[0]["debt_cents"], 25000)
        admin = bank.app.test_client()
        self.login("admin1", admin)
        update = {"credit_score": "850", "is_vip": "1", "debt": "250", "borrowing_limit": ""}
        self.assertEqual(self.post("/admin/customers/2/update", update, admin).status_code, 303)
        self.post("/loans", {"amount": "1000"})
        self.assertEqual(self.read("SELECT debt_cents FROM account_extras WHERE user_id=2")[0]["debt_cents"], 125000)

    def test_v5_support_messages_are_escaped_in_the_admin_inbox(self):
        self.login()
        payload = "<script>alert('CW2')</script><img src=x onerror=alert(1)>"
        self.assertEqual(self.post("/support", {"body": payload}).status_code, 303)
        admin = bank.app.test_client()
        self.login("admin1", admin)
        response = self.get("/admin", admin)
        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn(str(escape(payload)), html)
        self.assertNotIn("<script>", html)
        self.assertNotIn("<img src=x", html)
        self.assertIn("script-src 'none'", response.headers["Content-Security-Policy"])
        self.assertEqual(self.read("SELECT body FROM support_messages")[0]["body"], payload)

    def test_v5_preexisting_stored_html_is_also_escaped(self):
        payload = '<svg onload="alert(1)"></svg>'
        self.write("INSERT INTO support_messages (user_id, body) VALUES (2, ?)", (payload,))
        self.login("admin1")
        html = self.get("/admin").get_data(as_text=True)
        self.assertIn(str(escape(payload)), html)
        self.assertNotIn("<svg", html)

    def test_v6_fake_eligibility_cannot_claim_a_ticket(self):
        self.login()
        self.assertEqual(self.post("/giveaway", {"eligible": "true"}).status_code, 403)
        extras = self.read("SELECT cruise_eligible, cruise_claimed, ticket_code FROM account_extras WHERE user_id=2")[0]
        self.assertEqual(extras, {"cruise_eligible": 0, "cruise_claimed": 0, "ticket_code": None})
        self.assertNotIn('action="/giveaway"', self.get("/giveaway").get_data(as_text=True))

    def test_v6_selected_winner_can_claim_only_one_ticket(self):
        self.login("admin1")
        self.assertEqual(self.post("/admin/giveaway/2/winner").status_code, 303)
        customer = bank.app.test_client()
        self.login("user1", customer)
        self.assertEqual(self.post("/giveaway", {"eligible": "false"}, customer).status_code, 303)
        first = self.read("SELECT ticket_code FROM account_extras WHERE user_id=2")[0]["ticket_code"]
        self.assertTrue(first.startswith("CRUISE-"))
        self.post("/giveaway", {"eligible": "true"}, customer)
        self.assertEqual(first, self.read("SELECT ticket_code FROM account_extras WHERE user_id=2")[0]["ticket_code"])

    def test_v7_customer_cannot_read_another_customers_card_or_support(self):
        self.write("INSERT INTO support_messages (user_id, body) VALUES (3, 'Other account private note')")
        self.login()
        card = self.read("SELECT card_number FROM demo_cards WHERE user_id=3")[0]["card_number"]
        self.assertNotIn(card, self.get("/dashboard").get_data(as_text=True))
        self.assertNotIn("Other account private note", self.get("/support").get_data(as_text=True))

    def test_v8_plain_http_and_spoofed_forwarded_header_are_rejected(self):
        for method, path in [("GET", "/login"), ("POST", "/login")]:
            response = self.client.open(path, method=method, base_url="http://127.0.0.1",
                headers={"X-Forwarded-Proto": "https"})
            self.assertEqual(response.status_code, 400)
        self.assertIsNone(self.client.get_cookie("cw2_secure_session"))

    def test_v8_session_cookie_has_secure_httponly_and_samesite(self):
        response = self.login()
        cookie = response.headers["Set-Cookie"]
        for attribute in ("Secure", "HttpOnly", "SameSite=Strict"):
            self.assertIn(attribute, cookie)

    def test_v8_real_https_login_uses_a_verified_local_certificate(self):
        with patch.object(bank, "DATA_DIR", Path(self.directory.name)):
            server_context = bank.create_tls_context()
        cert = Path(self.directory.name) / "certs" / "localhost.crt"
        self.assertGreaterEqual(server_context.minimum_version, ssl.TLSVersion.TLSv1_2)
        server = make_server("127.0.0.1", 0, bank.app, ssl_context=server_context)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            origin = f"https://127.0.0.1:{server.server_port}"
            client_context = ssl.create_default_context(cafile=str(cert))
            connection = http.client.HTTPSConnection("127.0.0.1", server.server_port, context=client_context, timeout=5)
            connection.request("GET", "/login")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            cookie = response.getheader("Set-Cookie").split(";", 1)[0]
            token = re.search(r'name="csrf_token" value="([^"]+)"', response.read().decode()).group(1)
            connection.close()
            from urllib.parse import urlencode
            connection = http.client.HTTPSConnection("127.0.0.1", server.server_port, context=client_context, timeout=5)
            connection.connect()
            self.assertIn(connection.sock.version(), ("TLSv1.2", "TLSv1.3"))
            connection.request("POST", "/login", urlencode({"username": "user1", "password": TEST_PASSWORD, "csrf_token": token}),
                {"Cookie": cookie, "Referer": origin + "/login", "Content-Type": "application/x-www-form-urlencoded"})
            response = connection.getresponse()
            self.assertEqual(response.status, 303)
            self.assertEqual(response.getheader("Location"), "/dashboard")
            response.read()
            connection.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

    def test_csrf_missing_invalid_and_other_sessions_tokens_are_rejected(self):
        self.login()
        before = self.balances()
        other = bank.app.test_client()
        other_token = self.token("/login", other)
        for token in (None, "invalid", other_token):
            data = {"recipient": "user2", "amount": "10"}
            if token is not None:
                data["csrf_token"] = token
            response = self.client.post("/transfer", data=data, base_url=HTTPS, headers={"Referer": HTTPS + "/transfer"})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(before, self.balances())

    def test_registration_hashes_password_and_refuses_role_injection(self):
        data = {"username": "newuser", "full_name": "New fictional user", "email": "new@example.test",
                "password": TEST_PASSWORD, "confirm_password": TEST_PASSWORD, "role": "admin"}
        self.assertEqual(self.post("/register", data, token_path="/register").status_code, 400)
        self.assertEqual([], self.read("SELECT id FROM users WHERE username='newuser'"))
        data.pop("role")
        self.assertEqual(self.post("/register", data, token_path="/register").status_code, 303)
        row = self.read("SELECT password_hash, role FROM users WHERE username='newuser'")[0]
        self.assertNotEqual(row["password_hash"], TEST_PASSWORD)
        self.assertTrue(check_password_hash(row["password_hash"], TEST_PASSWORD))
        self.assertEqual(row["role"], "customer")

    def test_login_does_not_accept_sql_injection_or_the_old_admin_password(self):
        for username, password in [("admin1' --", "anything"), ("admin1", "admin1234")]:
            response = self.post("/login", {"username": username, "password": password}, token_path="/login")
            self.assertEqual(response.status_code, 401)

    def test_initialization_does_not_reset_the_admin_password(self):
        before = self.read("SELECT password_hash FROM users WHERE id=1")
        bank.init_db()
        self.assertEqual(before, self.read("SELECT password_hash FROM users WHERE id=1"))

    def test_first_run_admin_setup_creates_one_admin_without_a_shared_password(self):
        import setup_admin
        bank.app.config["DATABASE"] = Path(self.directory.name) / "fresh-admin.db"
        with patch.object(setup_admin, "getpass", side_effect=[TEST_PASSWORD, TEST_PASSWORD]), redirect_stdout(io.StringIO()):
            setup_admin.main()
        admins = self.read("SELECT username, password_hash FROM users WHERE role='admin'")
        self.assertEqual(len(admins), 1)
        self.assertEqual(admins[0]["username"], "admin1")
        self.assertTrue(check_password_hash(admins[0]["password_hash"], TEST_PASSWORD))
        with patch.object(setup_admin, "getpass") as prompt, redirect_stdout(io.StringIO()):
            setup_admin.main()
            prompt.assert_not_called()
        self.assertEqual(admins, self.read("SELECT username, password_hash FROM users WHERE role='admin'"))

    def test_every_rendered_post_form_contains_a_csrf_token(self):
        class Forms(HTMLParser):
            def __init__(self):
                super().__init__()
                self.current = None
                self.forms = []
            def handle_starttag(self, tag, attributes):
                attributes = dict(attributes)
                if tag == "form":
                    self.current = [attributes.get("method", "GET").upper(), False]
                if tag == "input" and self.current is not None:
                    if attributes.get("name") == "csrf_token" and attributes.get("value"):
                        self.current[1] = True
            def handle_endtag(self, tag):
                if tag == "form" and self.current is not None:
                    self.forms.append(self.current)
                    self.current = None
        def check(path, client):
            parsed = Forms()
            parsed.feed(self.get(path, client).get_data(as_text=True))
            for method, has_token in parsed.forms:
                if method == "POST":
                    self.assertTrue(has_token, f"Missing CSRF token in a form on {path}")
        for path in ("/login", "/register"):
            check(path, self.client)
        self.login()
        self.write("UPDATE account_extras SET cruise_eligible=1 WHERE user_id=2")
        for path in ("/dashboard", "/transfer", "/profile", "/support", "/giveaway"):
            check(path, self.client)
        admin = bank.app.test_client()
        self.login("admin1", admin)
        check("/admin", admin)

    def test_expired_session_requires_login(self):
        self.login()
        with self.client.session_transaction(base_url=HTTPS) as state:
            state["last_activity"] = time.time() - 301
        response = self.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.headers["Location"], "/login")

    def test_untrusted_hosts_are_rejected(self):
        self.assertEqual(self.client.get("/login", base_url="https://untrusted.example").status_code, 400)

    def test_all_current_pages_render_for_their_authorized_roles(self):
        for path in ("/", "/login", "/register", "/static/style.css"):
            with self.get(path) as response:
                self.assertEqual(response.status_code, 200)
        self.login()
        for path in ("/dashboard", "/profile", "/support", "/giveaway", "/transfer"):
            self.assertEqual(self.get(path).status_code, 200)
        admin = bank.app.test_client()
        self.login("admin1", admin)
        self.assertEqual(self.get("/admin", admin).status_code, 200)
        self.assertEqual(self.get("/search?q=user", admin).status_code, 200)
        self.assertEqual(self.post("/logout").status_code, 303)
        self.assertEqual(self.get("/dashboard").status_code, 302)


if __name__ == "__main__":
    unittest.main(verbosity=2)
