"""
security.py
------------
Every cryptographic / auth-adjacent operation lives here, separated from
the HTTP layer in main.py.

Production-ready version:
  • Configuration comes from config.py
  • No hardcoded secrets
  • Same authentication flow and behavior
"""

import base64
import io
import secrets
import time

import pyotp
import qrcode
from jose import JWTError, jwt
from passlib.context import CryptContext

from config import settings

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

    return jwt.encode(
        to_encode,
        settings.JWT_SECRET,
        algorithm=settings.JWT_ALGORITHM,
    )


def create_pending_token(username: str) -> str:
    return _create_token(
        {
            "sub": username,
            "mfa_pending": True,
        },
        settings.PENDING_TOKEN_TTL_SECONDS,
    )


def create_access_token(username: str) -> str:
    return _create_token(
        {
            "sub": username,
            "mfa_pending": False,
        },
        settings.ACCESS_TOKEN_TTL_SECONDS,
    )


def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM],
        )
    except JWTError:
        return None


# ---------- 3. TOTP ----------

def generate_totp_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(
        name=username,
        issuer_name=settings.ISSUER_NAME,
    )


def generate_qr_code_base64(uri: str) -> str:
    img = qrcode.make(uri)

    buffer = io.BytesIO()
    img.save(buffer, format="PNG")

    return base64.b64encode(buffer.getvalue()).decode()


def verify_totp_code(
    secret: str,
    code: str,
    last_used_step: int = 0,
) -> int | None:

    totp = pyotp.TOTP(secret)
    current_step = int(time.time() // 30)

    for offset in (-1, 0, 1):
        step = current_step + offset

        if totp.at(step * 30) == code:
            if step <= last_used_step:
                return None

            return step

    return None


# ---------- 4. Backup Codes ----------

def generate_backup_codes(count: int = 8) -> list[str]:
    return [secrets.token_hex(4) for _ in range(count)]


def hash_backup_code(code: str) -> str:
    return pwd_context.hash(code)


def verify_backup_code(code: str, code_hash: str) -> bool:
    return pwd_context.verify(code, code_hash)
