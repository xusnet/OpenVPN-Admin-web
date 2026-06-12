"""
OpenVPN Admin — Database Models & Initialization
=================================================
SQLite-backed persistence for users, roles, audit logs, and key records.
"""

import sqlite3
import os
from datetime import datetime, timezone
from contextlib import contextmanager

DB_PATH = os.environ.get("OPENVPN_ADMIN_DB", "/app/data/admin.db")


def get_db() -> sqlite3.Connection:
    """Get a database connection with row_factory enabled."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_session():
    """Context manager for database transactions."""
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db():
    """Create all tables and seed default admin user."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    with db_session() as db:
        db.executescript("""
        -- Users & Roles
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,   -- bcrypt hash
            role        TEXT    NOT NULL DEFAULT 'viewer',  -- admin | operator | viewer
            email       TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            is_active   INTEGER NOT NULL DEFAULT 1
        );

        -- Audit log
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL,
            action      TEXT    NOT NULL,   -- login | logout | create_key | revoke_key |
                                            -- download_key | start_service | stop_service |
                                            -- restart_service | update_config | create_user |
                                            -- delete_user | update_user | view_page
            detail      TEXT    DEFAULT '',
            ip_address  TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username);
        CREATE INDEX IF NOT EXISTS idx_audit_created  ON audit_log(created_at);

        -- Key management records
        CREATE TABLE IF NOT EXISTS key_records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            common_name TEXT    UNIQUE NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'active',  -- active | revoked | expired
            issued_by   TEXT    NOT NULL,
            issued_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            revoked_at  TEXT    DEFAULT NULL,
            revoked_by  TEXT    DEFAULT NULL,
            expiry_date TEXT    DEFAULT '',
            description TEXT    DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_keys_status ON key_records(status);

        -- Server configuration history
        CREATE TABLE IF NOT EXISTS config_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            content     TEXT    NOT NULL,
            changed_by  TEXT    NOT NULL,
            changed_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            comment     TEXT    DEFAULT ''
        );
        """)

        # Seed default admin if no users exist
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            import bcrypt
            admin_pw = bcrypt.hashpw(
                os.environ.get("ADMIN_PASSWORD", "admin123").encode(),
                bcrypt.gensalt()
            ).decode()
            db.execute(
                "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                ("admin", admin_pw, "admin", "admin@openvpn.local")
            )
            print("[DB] Seeded default admin user (username: admin)")
