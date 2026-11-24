"""Run with:  python -m unittest discover -v"""
import os
import re
import sqlite3
import sys
import tempfile
import unittest

import pyotp

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app  # noqa: E402

GOOD_PW = "Str0ng!Passw0rd"


class SecureLoginTests(unittest.TestCase):
    def setUp(self):
        fd, self.db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self.app = create_app(self.db_path)
        self.app.config["TESTING"] = True
        self.c = self.app.test_client()

    def tearDown(self):
        os.unlink(self.db_path)

    # helpers
    def token(self, url):
        html = self.c.get(url).get_data(as_text=True)
        return re.search(r'name="csrf_token" value="([^"]+)"', html).group(1)

    def post(self, url, data, form_page=None):
        data = dict(data, csrf_token=self.token(form_page or url))
        return self.c.post(url, data=data, follow_redirects=True)

    def register(self, user="alice", pw=GOOD_PW, email="alice@example.com"):
        return self.post("/register", {"username": user, "email": email, "password": pw, "confirm": pw})

    def login(self, user="alice", pw=GOOD_PW):
        return self.post("/login", {"username": user, "password": pw})

    # tests
    def test_password_is_hashed_with_argon2(self):
        self.register()
        row = sqlite3.connect(self.db_path).execute("SELECT password_hash FROM users").fetchone()
        self.assertTrue(row[0].startswith("$argon2id$"))
        self.assertNotIn(GOOD_PW, row[0])

    def test_weak_password_rejected(self):
        r = self.register(pw="password")
        self.assertIn("Password needs", r.get_data(as_text=True))
        self.assertEqual(sqlite3.connect(self.db_path).execute("SELECT COUNT(*) FROM users").fetchone()[0], 0)

    def test_invalid_username_rejected(self):
        r = self.register(user="bad name'; DROP TABLE users;--")
        self.assertIn("Username must be", r.get_data(as_text=True))

    def test_duplicate_user_rejected(self):
        self.register()
        r = self.register()
        self.assertIn("already registered", r.get_data(as_text=True))

    def test_login_dashboard_logout(self):
        self.register()
        r = self.login()
        self.assertIn("Welcome, alice", r.get_data(as_text=True))
        r = self.post("/logout", {}, form_page="/dashboard")
        self.assertIn("logged out", r.get_data(as_text=True))
        r = self.c.get("/dashboard", follow_redirects=True)
        self.assertIn("Please log in first", r.get_data(as_text=True))

    def test_sql_injection_login_fails(self):
        self.register()
        for payload in ["admin' OR '1'='1' --", "alice' --", "' OR 1=1 --", "x'; DROP TABLE users; --"]:
            r = self.login(user=payload, pw="anything")
            self.assertIn("Invalid username or password", r.get_data(as_text=True))
            self.assertNotIn("Welcome", r.get_data(as_text=True))
        # table still exists and still holds our user
        self.assertEqual(sqlite3.connect(self.db_path).execute("SELECT COUNT(*) FROM users").fetchone()[0], 1)

    def test_lockout_after_failed_attempts(self):
        self.register()
        for _ in range(5):
            self.login(pw="WrongPass1!")
        r = self.login(pw=GOOD_PW)  # correct password, but account is locked
        self.assertIn("Too many failed attempts", r.get_data(as_text=True))

    def test_csrf_required(self):
        r = self.c.post("/login", data={"username": "a", "password": "b"})
        self.assertEqual(r.status_code, 400)

    def test_dashboard_requires_login(self):
        r = self.c.get("/dashboard")
        self.assertEqual(r.status_code, 302)

    def test_two_factor_flow(self):
        self.register()
        self.login()
        html = self.c.get("/2fa/setup").get_data(as_text=True)
        secret = re.search(r'<code id="secret">([A-Z2-7]+)</code>', html).group(1)
        r = self.post("/2fa/setup", {"code": pyotp.TOTP(secret).now()})
        self.assertIn("enabled", r.get_data(as_text=True))
        self.post("/logout", {}, form_page="/dashboard")

        r = self.login()                                  # password OK -> needs 2FA code
        self.assertIn("Two-factor authentication", r.get_data(as_text=True))
        self.assertEqual(self.c.get("/dashboard").status_code, 302)   # not logged in yet
        r = self.post("/login/2fa", {"code": "000000"})
        self.assertIn("Invalid authentication code", r.get_data(as_text=True))
        r = self.post("/login/2fa", {"code": pyotp.TOTP(secret).now()})
        self.assertIn("Welcome, alice", r.get_data(as_text=True))

    def test_security_headers_and_cookie_flags(self):
        r = self.c.get("/login")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)


if __name__ == "__main__":
    unittest.main()
