"""
OpenVPN Admin — Database Models & Initialization
=================================================

SQLite-backed persistence layer for the OpenVPN Admin web application.

Tables:
    users           — Admin accounts with bcrypt-hashed passwords and roles
    audit_log       — Immutable trail of all admin operations
    key_records     — Client certificate lifecycle tracking
    config_history  — Versioned server.conf snapshots

Design Decisions:
    - SQLite over PostgreSQL/MySQL: zero-config, self-contained, runs inside
      the Docker container without a separate database service.
    - WAL journal mode: better concurrent read performance for web workloads.
    - ``sqlite3.Row`` as row factory: enables column access by name
      (``row["username"]``) for cleaner template code.
    - ``db_session()`` context manager: automatic commit/rollback/close,
      preventing connection leaks.

Environment Variables:
    OPENVPN_ADMIN_DB — Path to the SQLite database file (default: /app/data/admin.db)
"""

import sqlite3
import os
from datetime import datetime, timezone
from contextlib import contextmanager


# ── Database Configuration ─────────────────────────────────────────────────

# Default path is inside the Docker container's persistent volume.
# Override for local development: ``export OPENVPN_ADMIN_DB=./admin.db``.
DB_PATH = os.environ.get("OPENVPN_ADMIN_DB", "/app/data/admin.db")


# ═══════════════════════════════════════════════════════════════════════════
#  Connection Management
# ═══════════════════════════════════════════════════════════════════════════

def get_db() -> sqlite3.Connection:
    """
    Create and return a new SQLite database connection.

    Configures:
    - Row factory: columns accessible by name (``row["column"]``)
    - WAL journal mode: allows concurrent reads during writes
    - Foreign key enforcement: ON by default (SQLite disables it)

    Note:
        The caller is responsible for closing the connection.
        For automatic lifecycle management, use the ``db_session()``
        context manager instead.

    Returns:
        sqlite3.Connection: A configured database connection.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


@contextmanager
def db_session():
    """
    Context manager for transactional database operations.

    Provides automatic commit on success and rollback on exception,
    with guaranteed connection cleanup.

    Usage:
        with db_session() as db:
            db.execute("INSERT INTO users ...", (...))

        # Connection is automatically committed and closed here.
        # On exception, the transaction is rolled back before re-raising.

    Yields:
        sqlite3.Connection: A database connection with an active transaction.
    """
    conn = get_db()
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ═══════════════════════════════════════════════════════════════════════════
#  Schema Initialization
# ═══════════════════════════════════════════════════════════════════════════

def init_db() -> None:
    """
    Create all database tables and seed the default admin user.

    This is idempotent — ``CREATE TABLE IF NOT EXISTS`` ensures safe
    re-execution. The default admin user is only created when the
    ``users`` table is completely empty (first run).

    Tables created:
        users           — id, username (UNIQUE), password (bcrypt), role,
                          email, created_at, updated_at, is_active
        audit_log       — id, username, action, detail, ip_address, created_at.
                          Indexed on (username) and (created_at).
        key_records     — id, common_name (UNIQUE), status, issued_by,
                          issued_at, revoked_at, revoked_by, expiry_date,
                          description. Indexed on (status).
        config_history  — id, content, changed_by, changed_at, comment.

    Security:
        The default admin password is read from ADMIN_PASSWORD env var
        (default: "admin123"). CHANGE THIS IMMEDIATELY after first login.
    """
    # Ensure the parent directory exists (critical for first-run in Docker)
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

    with db_session() as db:
        # ── Create all tables in a single script for atomicity ─────────
        db.executescript("""
        -- ── Users & Roles ───────────────────────────────────────────────
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    UNIQUE NOT NULL,
            password    TEXT    NOT NULL,           -- bcrypt hash string
            role        TEXT    NOT NULL DEFAULT 'viewer',
            email       TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            updated_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            is_active   INTEGER NOT NULL DEFAULT 1  -- 0 = disabled
        );

        -- ── Audit Log ──────────────────────────────────────────────────
        -- Immutable log of every admin action. Never truncated or deleted
        -- by application code. For compliance and incident investigation.
        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT    NOT NULL,
            action      TEXT    NOT NULL,
            detail      TEXT    DEFAULT '',
            ip_address  TEXT    DEFAULT '',
            created_at  TEXT    NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_audit_username ON audit_log(username);
        CREATE INDEX IF NOT EXISTS idx_audit_created  ON audit_log(created_at);

        -- ── Key Management Records ─────────────────────────────────────
        -- Tracks the full lifecycle of each client certificate:
        -- issued → active → revoked/expired.
        CREATE TABLE IF NOT EXISTS key_records (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            common_name TEXT    UNIQUE NOT NULL,
            status      TEXT    NOT NULL DEFAULT 'active',
            issued_by   TEXT    NOT NULL,
            issued_at   TEXT    NOT NULL DEFAULT (datetime('now')),
            revoked_at  TEXT    DEFAULT NULL,
            revoked_by  TEXT    DEFAULT NULL,
            expiry_date TEXT    DEFAULT '',
            description TEXT    DEFAULT ''
        );
        CREATE INDEX IF NOT EXISTS idx_keys_status ON key_records(status);

        -- ── Server Configuration History ───────────────────────────────
        -- Full-text snapshots of server.conf on every save.
        -- Enables rollback and audit of configuration changes.
        CREATE TABLE IF NOT EXISTS config_history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            content     TEXT    NOT NULL,
            changed_by  TEXT    NOT NULL,
            changed_at  TEXT    NOT NULL DEFAULT (datetime('now')),
            comment     TEXT    DEFAULT ''
        );
        """)

        # ── Seed default admin user (first run only) ──────────────────
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            import bcrypt

            # Read from env var; fallback is intentionally weak —
            # production deployments MUST set ADMIN_PASSWORD.
            admin_pw = os.environ.get("ADMIN_PASSWORD", "admin123")
            admin_hash = bcrypt.hashpw(
                admin_pw.encode(),
                bcrypt.gensalt()
            ).decode()

            db.execute(
                "INSERT INTO users (username, password, role, email) "
                "VALUES (?, ?, ?, ?)",
                ("admin", admin_hash, "admin", "admin@openvpn.local")
            )
            print("[DB] Seeded default admin user (username: admin)")
