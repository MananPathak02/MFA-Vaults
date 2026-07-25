"""
config.py
---------
Centralized application configuration.

Every configurable value comes from environment variables.
This keeps secrets out of the source code and allows the same
codebase to run locally (SQLite) and in production (PostgreSQL)
without any code changes.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # ---------------- Database ----------------
    DATABASE_URL: str = "sqlite:///mfa.db"

    # ---------------- JWT ----------------
    JWT_SECRET: str
    JWT_ALGORITHM: str = "HS256"

    PENDING_TOKEN_TTL_SECONDS: int = 120
    ACCESS_TOKEN_TTL_SECONDS: int = 1800

    # ---------------- MFA ----------------
    ISSUER_NAME: str = "MFAVault"

    # ---------------- Frontend ----------------
    ALLOWED_ORIGIN: str = "http://127.0.0.1:8000"

    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
    )


settings = Settings()