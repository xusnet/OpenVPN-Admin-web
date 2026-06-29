"""
OpenVPN Admin — Authentication & Authorization Module
======================================================

Provides session-based authentication with bcrypt password hashing
and role-based access control (RBAC).

Roles:
    admin     — Full access: users, keys, service, config, logs
    operator  — Service and key management (no users, no config)
    viewer    — Read-only: dashboard and logs only

Architecture:
    This module is a Flask Blueprint registered on the main app.
    It exposes three routes: /login, /logout, /profile.
    Decorators ``login_required`` and ``role_required`` are used
    by routes in app.py to enforce authentication and authorization.

Security:
    - Passwords are hashed with bcrypt (work factor from gensalt())
    - Session data is signed with Flask's SECRET_KEY
    - Session timeout is configurable via SESSION_TIMEOUT env var
    - All auth operations are audit-logged

Environment Variables:
    SESSION_TIMEOUT — Session lifetime in seconds (default: 3600)
"""

import functools
import os
import secrets
from datetime import datetime, timezone

import bcrypt
from flask import (
    Blueprint, request, session, redirect, url_for,
    render_template, flash, g
)

from database import get_db, db_session


# ── Blueprint ──────────────────────────────────────────────────────────────

# ``auth_bp`` is registered on the main Flask app in app.py.
# Routes are prefixed at the root level (no prefix).
auth_bp = Blueprint("auth", __name__)


# ── Session Configuration ─────────────────────────────────────────────────

# Session timeout in seconds. Flask's default session cookie is browser-session
# only (expires on close). For persistent sessions, consider using Flask-Login
# or Redis-backed sessions in production.
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "3600"))


# ═══════════════════════════════════════════════════════════════════════════
#  Decorators
# ═══════════════════════════════════════════════════════════════════════════

def login_required(f):
    """
    Decorator: require an authenticated session to access the route.

    If the user is not logged in (no ``username`` in session), redirects
    to the login page. On success, injects ``g.username`` and ``g.role``
    for use by downstream code and templates.

    Usage:
        @app.route("/dashboard")
        @login_required
        def dashboard():
            ...

    Args:
        f: The view function to wrap.

    Returns:
        Wrapped function that enforces authentication.
    """
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("auth.login_page"))
        # Inject user identity into Flask's request context global
        g.username = session["username"]
        g.role = session.get("role", "viewer")
        return f(*args, **kwargs)
    return wrapper


def role_required(*roles: str):
    """
    Decorator: require one of the specified roles to access the route.

    Checks that the authenticated user's role matches at least one of
    the allowed roles. If not, flashes a permissions error and redirects
    to the dashboard.

    Usage:
        @app.route("/users")
        @login_required
        @role_required("admin")
        def users_list():
            ...

    Args:
        *roles: One or more role names that are allowed (e.g., "admin", "operator").

    Returns:
        Decorator function that enforces role-based access.
    """
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            # Must be logged in first (this also sets g.username and g.role)
            if "username" not in session:
                return redirect(url_for("auth.login_page"))

            # Check if the user's role is in the allowed set
            if session.get("role") not in roles:
                flash("权限不足", "danger")
                return redirect(url_for("dashboard"))

            # Re-inject globals for routes that don't chain @login_required
            g.username = session["username"]
            g.role = session.get("role", "viewer")
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ═══════════════════════════════════════════════════════════════════════════
#  Audit Logging Helper
# ═══════════════════════════════════════════════════════════════════════════

def _audit(action: str, detail: str = "") -> None:
    """
    Write an entry to the audit_log table.

    This is the central audit trail mechanism used by all routes.
    Audit failures are silently ignored — they must never block the
    user's operation.

    Args:
        action: A machine-readable action identifier (e.g., "login",
                "create_key", "update_config"). Use lowercase_with_underscores.
        detail: Optional human-readable context (e.g., "cn=client01",
                "username=alice role=operator").
    """
    try:
        with db_session() as db:
            db.execute(
                "INSERT INTO audit_log (username, action, detail, ip_address) "
                "VALUES (?, ?, ?, ?)",
                (
                    session.get("username", "system"),
                    action,
                    detail,
                    request.remote_addr or ""
                )
            )
    except Exception:
        # Audit failures must never propagate to the user — the operation
        # itself was successful; logging is secondary.
        pass


# ═══════════════════════════════════════════════════════════════════════════
#  Password Hashing Utilities
# ═══════════════════════════════════════════════════════════════════════════

def hash_password(password: str) -> str:
    """
    Hash a plaintext password using bcrypt.

    Uses a randomly generated salt (bcrypt.gensalt()) for each call,
    ensuring that identical passwords produce different hashes.

    Args:
        password: The plaintext password to hash.

    Returns:
        str: The bcrypt hash string (e.g., "$2b$12$...").

    Security:
        bcrypt is intentionally slow (~250ms per hash) to resist
        brute-force attacks. The work factor is determined by gensalt().
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.

    Uses constant-time comparison internally (bcrypt.checkpw).

    Args:
        password: The plaintext password to verify.
        hashed: The stored bcrypt hash string.

    Returns:
        bool: True if the password matches the hash, False otherwise.
    """
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ═══════════════════════════════════════════════════════════════════════════
#  Auth Routes
# ═══════════════════════════════════════════════════════════════════════════

@auth_bp.route("/login", methods=["GET", "POST"])
def login_page():
    """
    Handle user login.

    GET  — Render the login form.
    POST — Authenticate credentials and create a session.

    On successful login:
    - Stores ``username``, ``role``, and ``user_id`` in the session
    - Writes a ``login`` audit entry
    - Redirects to the dashboard

    On failed login:
    - Flashes an error message
    - Writes a ``login_failed`` audit entry
    - Re-renders the login form
    """
    # ── GET: show login form ──────────────────────────────────────────
    if request.method == "GET":
        return render_template("login.html")

    # ── POST: validate credentials ────────────────────────────────────
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    # Basic input validation
    if not username or not password:
        flash("请输入用户名和密码", "warning")
        return render_template("login.html")

    # Look up the user — only active accounts can log in
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ? AND is_active = 1",
        (username,)
    ).fetchone()
    db.close()

    # Constant-time-ish verification via bcrypt.checkpw
    if not user or not verify_password(password, user["password"]):
        flash("用户名或密码错误", "danger")
        _audit("login_failed", f"username={username}")
        return render_template("login.html")

    # ── Create session ────────────────────────────────────────────────
    session["username"] = user["username"]
    session["role"] = user["role"]
    session["user_id"] = user["id"]

    _audit("login", f"role={user['role']}")
    return redirect(url_for("dashboard"))


@auth_bp.route("/logout")
def logout():
    """
    Handle user logout.

    Clears the session entirely, writes a ``logout`` audit entry,
    and redirects to the login page.
    """
    _audit("logout")
    session.clear()
    flash("已退出登录", "info")
    return redirect(url_for("auth.login_page"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """
    Display and handle the user profile (change password) page.

    GET  — Show the profile form (username, role, change password form).
    POST — Validate and change the user's password.

    Security:
    - Requires the current password to change (prevents session hijacking
      from changing credentials)
    - New password must be at least 6 characters
    - New password must be confirmed (entered twice)
    """
    if request.method == "POST":
        # ── Extract form fields ──────────────────────────────────────
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        # ── Client-side input validation ─────────────────────────────
        if not current_pw or not new_pw:
            flash("请填写所有字段", "warning")
            return render_template("profile.html")

        if new_pw != confirm_pw:
            flash("两次输入的新密码不一致", "warning")
            return render_template("profile.html")

        if len(new_pw) < 6:
            flash("新密码长度至少6位", "warning")
            return render_template("profile.html")

        # ── Verify current password ──────────────────────────────────
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?",
            (session["username"],)
        ).fetchone()

        if not verify_password(current_pw, user["password"]):
            flash("当前密码错误", "danger")
            db.close()
            return render_template("profile.html")

        # ── Update password ──────────────────────────────────────────
        new_hash = hash_password(new_pw)
        db.execute(
            "UPDATE users SET password = ?, updated_at = datetime('now') "
            "WHERE username = ?",
            (new_hash, session["username"])
        )
        db.commit()
        db.close()

        _audit("change_password")
        flash("密码修改成功", "success")
        return redirect(url_for("dashboard"))

    # ── GET: show profile page ──────────────────────────────────────
    return render_template("profile.html")
