"""
security.py
------------
Every cryptographic / auth-adjacent operation lives here, separated from
the HTTP layer in main.py. This split is what you point to in an
interview when someone asks "how is this organized?" — routes don't
touch secrets directly, they call into this module.

Covers three layers of the system:
  1. Password hashing         (bcrypt via passlib)
  2. Session tokens           (JWT, short-lived "pending" vs full "access")
  3. Second factor            (TOTP - RFC 6238 - + single-use backup codes)
"""

import base64
import io
import secrets
import time

import pyotp
import qrcode
from jose import jwt, JWTError
from passlib.context import CryptContext

# ---- config (demo values — in production these come from env vars / a secret manager) ----
JWT_SECRET = "dev-secret-change-me"          # signing key for JWTs
JWT_ALGORITHM = "HS256"
PENDING_TOKEN_TTL_SECONDS = 120              # window to complete MFA after password step
ACCESS_TOKEN_TTL_SECONDS = 1800              # session length after MFA succeeds
ISSUER_NAME = "MFAVault"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------- 1. passwords ----------

def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    return pwd_context.verify(password, password_hash)


# ---------- 2. JWTs ----------

def _create_token(payload: dict, ttl_seconds: int) -> str:
    to_encode = payload.copy()
    to_encode["exp"] = int(time.time()) + ttl_seconds
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)


def create_pending_token(username: str) -> str:
    """Issued after password check succeeds, before MFA is verified.
    Deliberately short-lived and scoped with mfa_pending=True so it
    cannot be used to reach protected routes on its own."""
    return _create_token({"sub": username, "mfa_pending": True}, PENDING_TOKEN_TTL_SECONDS)


def create_access_token(username: str) -> str:
    """Issued only after MFA succeeds. This is the token protected
    routes accept."""
    return _create_token({"sub": username, "mfa_pending": False}, ACCESS_TOKEN_TTL_SECONDS)


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except JWTError:
        return None


# ---------- 3. TOTP (RFC 6238) ----------

def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    return pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=ISSUER_NAME)


def generate_qr_code_base64(uri: str) -> str:
    """Turns the otpauth:// URI into a PNG, base64-encoded so the
    frontend can drop it straight into an <img src="data:..."> tag
    with no extra file storage on the server."""
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format="PNG")
    return base64.b64encode(buffer.getvalue()).decode()


def verify_totp_code(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    # valid_window=1 tolerates ~30s of clock drift between server and phone
    return totp.verify(code, valid_window=1)


# ---------- 3b. backup codes ----------

def generate_backup_codes(count: int = 8) -> list[str]:
    """Plaintext codes shown to the user ONCE at setup time. Only the
    hash is ever stored — same principle as passwords."""
    return [secrets.token_hex(4) for _ in range(count)]  # e.g. "a91f3c02"


def hash_backup_code(code: str) -> str:
    return pwd_context.hash(code)


def verify_backup_code(code: str, code_hash: str) -> bool:
    return pwd_context.verify(code, code_hash)
