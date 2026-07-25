"""
database.py
-----------
Database layer using SQLAlchemy Core.

Supports:
- SQLite for local development
- PostgreSQL for production

Database selection is handled entirely through config.py.
"""

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    delete,
    func,
    insert,
    select,
    update,
)

from config import settings

DATABASE_URL = settings.DATABASE_URL

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
)

metadata = MetaData()

users = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("username", String(64), unique=True, nullable=False),
    Column("password_hash", String(255), nullable=False),
    Column("totp_secret", String(64), nullable=False),
    Column("mfa_confirmed", Boolean, nullable=False, server_default="0"),
    Column("last_totp_step", Integer, nullable=False, server_default="0"),
    Column("created_at", DateTime, nullable=False, server_default=func.now()),
)

backup_codes = Table(
    "backup_codes",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("user_id", Integer, ForeignKey("users.id"), nullable=False),
    Column("code_hash", String(255), nullable=False),
    Column("used", Boolean, nullable=False, server_default="0"),
)


def init_db():
    metadata.create_all(engine)


def _row_to_dict(row):
    return dict(row._mapping) if row else None


def create_user(username: str, password_hash: str, totp_secret: str) -> int:
    with engine.begin() as conn:
        result = conn.execute(
            insert(users).values(
                username=username,
                password_hash=password_hash,
                totp_secret=totp_secret,
            )
        )
        return result.inserted_primary_key[0]


def get_user_by_username(username: str):
    with engine.begin() as conn:
        row = conn.execute(
            select(users).where(users.c.username == username)
        ).fetchone()
        return _row_to_dict(row)


def get_user_by_id(user_id: int):
    with engine.begin() as conn:
        row = conn.execute(
            select(users).where(users.c.id == user_id)
        ).fetchone()
        return _row_to_dict(row)


def mark_mfa_confirmed(user_id: int):
    with engine.begin() as conn:
        conn.execute(
            update(users)
            .where(users.c.id == user_id)
            .values(mfa_confirmed=True)
        )


def update_last_totp_step(user_id: int, step: int):
    with engine.begin() as conn:
        conn.execute(
            update(users)
            .where(users.c.id == user_id)
            .values(last_totp_step=step)
        )


def delete_unconfirmed_user(user_id: int):
    with engine.begin() as conn:
        conn.execute(
            delete(backup_codes).where(
                backup_codes.c.user_id == user_id
            )
        )
        conn.execute(
            delete(users).where(users.c.id == user_id)
        )


def save_backup_codes(user_id: int, code_hashes: list[str]):
    with engine.begin() as conn:
        conn.execute(
            insert(backup_codes),
            [
                {
                    "user_id": user_id,
                    "code_hash": code_hash,
                }
                for code_hash in code_hashes
            ],
        )


def get_unused_backup_codes(user_id: int):
    with engine.begin() as conn:
        rows = conn.execute(
            select(backup_codes).where(
                backup_codes.c.user_id == user_id,
                backup_codes.c.used == False,  # noqa: E712
            )
        ).fetchall()

        return [_row_to_dict(row) for row in rows]


def mark_backup_code_used(code_id: int):
    with engine.begin() as conn:
        conn.execute(
            update(backup_codes)
            .where(backup_codes.c.id == code_id)
            .values(used=True)
        )
