"""
database.py
-----------
Tiny wrapper around SQLite. No ORM on purpose — with only two tables,
raw SQL is easier to read and easier to explain line by line.

Tables:
  users        -> login identity + hashed password + TOTP secret
  backup_codes -> one-time recovery codes, each hashed, each single-use
"""

import sqlite3
from contextlib import contextmanager

DB_PATH = "mfa.db"


def init_db():
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                totp_secret TEXT NOT NULL,
                mfa_confirmed INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS backup_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                used INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        conn.commit()


@contextmanager
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


# ---------- users ----------

def create_user(username: str, password_hash: str, totp_secret: str):
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO users (username, password_hash, totp_secret) VALUES (?, ?, ?)",
            (username, password_hash, totp_secret),
        )
        conn.commit()
        return cur.lastrowid


def get_user_by_username(username: str):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id: int):
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None


def mark_mfa_confirmed(user_id: int):
    with get_conn() as conn:
        conn.execute("UPDATE users SET mfa_confirmed = 1 WHERE id = ?", (user_id,))
        conn.commit()


# ---------- backup codes ----------

def save_backup_codes(user_id: int, code_hashes: list[str]):
    with get_conn() as conn:
        conn.executemany(
            "INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)",
            [(user_id, h) for h in code_hashes],
        )
        conn.commit()


def get_unused_backup_codes(user_id: int):
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM backup_codes WHERE user_id = ? AND used = 0", (user_id,)
        ).fetchall()
        return [dict(r) for r in rows]


def mark_backup_code_used(code_id: int):
    with get_conn() as conn:
        conn.execute("UPDATE backup_codes SET used = 1 WHERE id = ?", (code_id,))
        conn.commit()
