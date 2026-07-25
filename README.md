# MFA Vault

A minimal, from-scratch two-factor authentication system: password + TOTP
(the same standard behind Google Authenticator), backup codes, and
short-lived JWT sessions. Built to be small enough to fully explain, not to
impress with scale.

## Run it

```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000` — the backend serves the frontend directly,
so there's nothing else to start. A `mfa.db` SQLite file is created
automatically on first run.

## How the flow works

1. **Register** — username + password. Password is hashed with bcrypt
   before it's stored. A TOTP secret is generated and shown as a QR code;
   8 backup codes are generated and shown once.
2. **Confirm MFA** — user enters the code their authenticator app produced,
   proving the QR scan actually worked, before MFA is marked active.
3. **Login step 1** — password checked. On success, a short-lived
   (2 minute) "pending" JWT is issued — it cannot reach protected routes.
4. **Login step 2** — the 6-digit TOTP code (or a backup code) is checked
   against the pending token. Only on success is a real access token issued.
5. **Dashboard** — a protected route that only accepts a token with
   `mfa_pending: false`.

## What's deliberately included, and why — for interview walkthroughs

| Decision | Reasoning |
|---|---|
| TOTP over SMS OTP | No telecom dependency, works offline, immune to SIM-swap attacks |
| Two-token model (pending → access) | The password-verified state and the fully-authenticated state are never the same token — a stolen "pending" token alone can't reach protected data |
| Backup codes are hashed, single-use | Same principle as passwords: if the DB leaks, codes can't be replayed |
| Generic "invalid username or password" | Doesn't reveal whether a username exists (username enumeration) |
| Lockout after 5 failed MFA attempts | Slows down brute-forcing a 6-digit code (only 1,000,000 combinations) |
| `valid_window=1` on TOTP check | Tolerates ~30s of clock drift between phone and server without weakening the window much |

## What's a known simplification, and what you'd change for production

- **Lockout state is in-memory** (`_failed_attempts` dict) — it resets on
  server restart and won't work across multiple server instances. Real
  fix: move it to Redis with a TTL.
- **JWT secret is hardcoded** in `security.py` for demo clarity — in
  production this comes from an environment variable or a secret manager,
  and should be rotated.
- **No HTTPS enforced** — this runs on plain HTTP locally. In production,
  tokens and codes must never travel over unencrypted connections.
- **No email verification / password reset flow** — out of scope for a
  focused MFA demo, but the obvious next feature.

## Project structure

```
backend/
  main.py        # HTTP routes only
  security.py     # hashing, JWT, TOTP, backup codes
  database.py     # SQLite schema + queries
  requirements.txt
frontend/
  index.html      # landing / explainer
  register.html   # step 1: create account
  setup.html      # step 2: scan QR, save backup codes, confirm
  login.html      # login step 1: password
  verify.html     # login step 2: TOTP or backup code
  dashboard.html  # protected page
  style.css
  script.js
```
