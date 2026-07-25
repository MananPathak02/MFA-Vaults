"""
main.py
-------
HTTP layer only. Every route does three things: validate input (pydantic),
call into security.py / database.py, return a response. No hashing, no
token logic, no SQL lives in this file — keeps the request flow readable
top to bottom.

Auth flow implemented here:

  1. POST /api/register     -> create account, return QR code + backup codes (shown once)
  2. POST /api/mfa/confirm  -> user proves they scanned the QR (first real code), activates MFA
  3. POST /api/login        -> check password -> return a short-lived "pending" token
  4. POST /api/mfa/verify   -> check TOTP or backup code -> return full access token
  5. GET  /api/dashboard    -> protected route, requires a valid access token

Brute-force protection: a naive in-memory counter locks an account for
5 minutes after 5 failed MFA attempts. In-memory is a deliberate demo
simplification — call it out as the first thing you'd swap for Redis
in a real deployment (state needs to survive a restart / work across
multiple server instances).
"""

import time

from fastapi import FastAPI, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import database as db
import security as sec

app = FastAPI(title="MFA Vault")

db.init_db()

# username -> {"count": int, "locked_until": float}
_failed_attempts: dict[str, dict] = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


# ---------- request/response schemas ----------

class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8)


class LoginRequest(BaseModel):
    username: str
    password: str


class MFAConfirmRequest(BaseModel):
    username: str
    code: str


class MFAVerifyRequest(BaseModel):
    pending_token: str
    code: str


# ---------- helpers ----------

def _is_locked(username: str) -> bool:
    entry = _failed_attempts.get(username)
    return bool(entry and entry["locked_until"] > time.time())


def _register_failure(username: str):
    entry = _failed_attempts.setdefault(username, {"count": 0, "locked_until": 0})
    entry["count"] += 1
    if entry["count"] >= MAX_ATTEMPTS:
        entry["locked_until"] = time.time() + LOCKOUT_SECONDS
        entry["count"] = 0


def _clear_failures(username: str):
    _failed_attempts.pop(username, None)


def _require_access_token(authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    payload = sec.decode_token(authorization.removeprefix("Bearer "))
    if not payload or payload.get("mfa_pending") is not False:
        raise HTTPException(status_code=401, detail="Invalid or unverified session")
    return payload


# ---------- routes ----------

@app.post("/api/register")
def register(req: RegisterRequest):
    if db.get_user_by_username(req.username):
        raise HTTPException(status_code=409, detail="Username already taken")

    secret = sec.generate_totp_secret()
    user_id = db.create_user(req.username, sec.hash_password(req.password), secret)

    backup_codes = sec.generate_backup_codes()
    db.save_backup_codes(user_id, [sec.hash_backup_code(c) for c in backup_codes])

    uri = sec.get_totp_uri(secret, req.username)
    qr_base64 = sec.generate_qr_code_base64(uri)

    return {
        "username": req.username,
        "qr_code_base64": qr_base64,
        "manual_key": secret,
        "backup_codes": backup_codes,  # shown once — frontend must tell the user to save these
    }


@app.post("/api/mfa/confirm")
def confirm_mfa(req: MFAConfirmRequest):
    """Proves the user actually scanned the QR into a real authenticator
    app before we treat MFA as active on the account."""
    user = db.get_user_by_username(req.username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    if not sec.verify_totp_code(user["totp_secret"], req.code):
        raise HTTPException(status_code=401, detail="Incorrect code")
    db.mark_mfa_confirmed(user["id"])
    return {"status": "mfa_activated"}


@app.post("/api/login")
def login(req: LoginRequest):
    user = db.get_user_by_username(req.username)
    # Same error message whether the username or password was wrong —
    # avoids leaking which usernames exist (a real, common vulnerability).
    if not user or not sec.verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    if not user["mfa_confirmed"]:
        raise HTTPException(status_code=428, detail="MFA setup not completed")

    return {"pending_token": sec.create_pending_token(req.username)}


@app.post("/api/mfa/verify")
def verify_mfa(req: MFAVerifyRequest):
    payload = sec.decode_token(req.pending_token)
    if not payload or payload.get("mfa_pending") is not True:
        raise HTTPException(status_code=401, detail="Invalid or expired login session")

    username = payload["sub"]
    if _is_locked(username):
        raise HTTPException(status_code=429, detail="Too many failed attempts. Try again later.")

    user = db.get_user_by_username(username)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # 1. try TOTP first
    if sec.verify_totp_code(user["totp_secret"], req.code):
        _clear_failures(username)
        return {"access_token": sec.create_access_token(username)}

    # 2. fall back to a single-use backup code
    for row in db.get_unused_backup_codes(user["id"]):
        if sec.verify_backup_code(req.code, row["code_hash"]):
            db.mark_backup_code_used(row["id"])
            _clear_failures(username)
            return {"access_token": sec.create_access_token(username), "used_backup_code": True}

    _register_failure(username)
    raise HTTPException(status_code=401, detail="Incorrect code")


@app.get("/api/dashboard")
def dashboard(authorization: str | None = Header(default=None)):
    payload = _require_access_token(authorization)
    user = db.get_user_by_username(payload["sub"])
    remaining_backup = len(db.get_unused_backup_codes(user["id"]))
    return {
        "username": user["username"],
        "mfa_confirmed": bool(user["mfa_confirmed"]),
        "backup_codes_remaining": remaining_backup,
        "member_since": user["created_at"],
    }


# ---------- serve the frontend ----------
# Mounted last so /api/* routes above take priority.
app.mount("/", StaticFiles(directory="../frontend", html=True), name="frontend")
