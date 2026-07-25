"""
main.py
-------
HTTP layer for the MFA Vault application.

Production-ready changes:
- Uses config.py for environment configuration.
- CORS configured from settings.ALLOWED_ORIGIN.
- Same authentication flow and API endpoints.
"""

import os
import time

from fastapi import FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

import database as db
import security as sec
from config import settings

app = FastAPI(title="MFA Vault")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.ALLOWED_ORIGIN],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

db.init_db()

_failed_attempts: dict[str, dict] = {}
MAX_ATTEMPTS = 5
LOCKOUT_SECONDS = 300


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


def _is_locked(username: str) -> bool:
    entry = _failed_attempts.get(username)
    return bool(entry and entry["locked_until"] > time.time())


def _register_failure(username: str):
    entry = _failed_attempts.setdefault(
        username,
        {"count": 0, "locked_until": 0},
    )
    entry["count"] += 1
    if entry["count"] >= MAX_ATTEMPTS:
        entry["locked_until"] = time.time() + LOCKOUT_SECONDS
        entry["count"] = 0


def _clear_failures(username: str):
    _failed_attempts.pop(username, None)


def _require_access_token(authorization: str | None) -> dict:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")

    payload = sec.decode_token(
        authorization.removeprefix("Bearer ")
    )

    if not payload or payload.get("mfa_pending") is not False:
        raise HTTPException(
            status_code=401,
            detail="Invalid or unverified session",
        )

    return payload


@app.post("/api/register")
def register(req: RegisterRequest):
    existing = db.get_user_by_username(req.username)

    if existing:
        if existing["mfa_confirmed"]:
            raise HTTPException(
                status_code=409,
                detail="Username already taken",
            )

        db.delete_unconfirmed_user(existing["id"])

    secret = sec.generate_totp_secret()

    user_id = db.create_user(
        req.username,
        sec.hash_password(req.password),
        secret,
    )

    backup_codes = sec.generate_backup_codes()

    db.save_backup_codes(
        user_id,
        [sec.hash_backup_code(code) for code in backup_codes],
    )

    uri = sec.get_totp_uri(secret, req.username)
    qr_base64 = sec.generate_qr_code_base64(uri)

    return {
        "username": req.username,
        "qr_code_base64": qr_base64,
        "manual_key": secret,
        "backup_codes": backup_codes,
    }


@app.post("/api/mfa/confirm")
def confirm_mfa(req: MFAConfirmRequest):
    user = db.get_user_by_username(req.username)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    matched_step = sec.verify_totp_code(
        user["totp_secret"],
        req.code,
        user["last_totp_step"],
    )

    if matched_step is None:
        raise HTTPException(status_code=401, detail="Incorrect code")

    db.update_last_totp_step(user["id"], matched_step)
    db.mark_mfa_confirmed(user["id"])

    return {"status": "mfa_activated"}


@app.post("/api/login")
def login(req: LoginRequest):
    user = db.get_user_by_username(req.username)

    if not user or not sec.verify_password(
        req.password,
        user["password_hash"],
    ):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
        )

    if not user["mfa_confirmed"]:
        raise HTTPException(
            status_code=428,
            detail="MFA setup not completed",
        )

    return {
        "pending_token": sec.create_pending_token(req.username)
    }


@app.post("/api/mfa/verify")
def verify_mfa(req: MFAVerifyRequest):
    payload = sec.decode_token(req.pending_token)

    if not payload or payload.get("mfa_pending") is not True:
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired login session",
        )

    username = payload["sub"]

    if _is_locked(username):
        raise HTTPException(
            status_code=429,
            detail="Too many failed attempts. Try again later.",
        )

    user = db.get_user_by_username(username)

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    matched_step = sec.verify_totp_code(
        user["totp_secret"],
        req.code,
        user["last_totp_step"],
    )

    if matched_step is not None:
        db.update_last_totp_step(user["id"], matched_step)
        _clear_failures(username)
        return {
            "access_token": sec.create_access_token(username)
        }

    for row in db.get_unused_backup_codes(user["id"]):
        if sec.verify_backup_code(req.code, row["code_hash"]):
            db.mark_backup_code_used(row["id"])
            _clear_failures(username)
            return {
                "access_token": sec.create_access_token(username),
                "used_backup_code": True,
            }

    _register_failure(username)
    raise HTTPException(status_code=401, detail="Incorrect code")


@app.get("/api/dashboard")
def dashboard(authorization: str | None = Header(default=None)):
    payload = _require_access_token(authorization)
    user = db.get_user_by_username(payload["sub"])

    return {
        "username": user["username"],
        "mfa_confirmed": bool(user["mfa_confirmed"]),
        "backup_codes_remaining": len(
            db.get_unused_backup_codes(user["id"])
        ),
        "member_since": user["created_at"],
    }


_frontend_dir = "../frontend"

if os.path.isdir(_frontend_dir):
    app.mount(
        "/",
        StaticFiles(directory=_frontend_dir, html=True),
        name="frontend",
    )
