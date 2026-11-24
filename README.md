# Secure Login System

A secure login web app built with **Python Flask**, **SQLite** and **Argon2**, created for the
Thiranex Cybersecurity Internship.

## Features (task requirements)
| Requirement | How it is done |
|---|---|
| User registration and login with hashed passwords | Argon2id via `argon2-cffi`; only the hash is stored |
| Basic input validation | Username/email/password rules checked on the server (`validate_password`, regexes) |
| Protection from SQL injection | Every query is parameterised (`?` placeholders), never string-built |
| Session management with logout | Signed HttpOnly cookie, 15-minute expiry, session reset on login, POST logout |
| Optional: Two-Factor Authentication | TOTP (Google/Microsoft Authenticator) with QR-code setup |

## Extra protections
- CSRF token on every POST form
- Account lock for 5 minutes after 5 failed logins (brute-force protection)
- Generic "Invalid username or password" message + dummy hash check (no user enumeration)
- Security headers: CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, no-store
- Jinja2 auto-escaping (XSS protection)
- Secret key from `SECRET_KEY` env var or an auto-generated, git-ignored file

## Run
```bash
pip install -r requirements.txt
python app.py
```
Open http://127.0.0.1:5000 -> Register -> Log in -> (optional) Enable 2FA.

## Test
```bash
python -m unittest discover -v
```
11 automated tests cover hashing, validation, SQL-injection attempts
(`admin' OR '1'='1' --`, `'; DROP TABLE users; --`), lockout, CSRF, logout, 2FA and headers.

## Project structure
```
app.py            Flask app (routes + security logic)
templates/        HTML pages (Jinja2)
static/style.css  Styling
tests/            Automated security tests
```

## Notes for deployment
Run behind HTTPS and set `SESSION_COOKIE_SECURE=1`, set a strong `SECRET_KEY`, and use a
production server (e.g. gunicorn) instead of Flask's built-in one. This is a learning project.
