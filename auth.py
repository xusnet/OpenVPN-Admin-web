"""
OpenVPN Admin — Authentication Module
======================================
Session-based auth with bcrypt password hashing.
Roles: admin (full access), operator (service + keys), viewer (read-only).
"""

import functools
import os
import secrets
from datetime import datetime, timezone

import bcrypt
from flask import Blueprint, request, session, redirect, url_for, render_template, flash, g

from database import get_db, db_session

auth_bp = Blueprint("auth", __name__)

# Simple in-memory session store (production: use Redis or server-side sessions)
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "3600"))  # 1 hour


def login_required(f):
    """Decorator: require authenticated session."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("auth.login_page"))
        g.username = session["username"]
        g.role = session.get("role", "viewer")
        return f(*args, **kwargs)
    return wrapper


def role_required(*roles):
    """Decorator: require specific role(s)."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            if "username" not in session:
                return redirect(url_for("auth.login_page"))
            if session.get("role") not in roles:
                flash("权限不足", "danger")
                return redirect(url_for("dashboard"))
            g.username = session["username"]
            g.role = session.get("role", "viewer")
            return f(*args, **kwargs)
        return wrapper
    return decorator


def _audit(action: str, detail: str = ""):
    """Write an audit log entry."""
    try:
        with db_session() as db:
            db.execute(
                "INSERT INTO audit_log (username, action, detail, ip_address) VALUES (?, ?, ?, ?)",
                (session.get("username", "system"), action, detail, request.remote_addr or "")
            )
    except Exception:
        pass  # Don't let audit failures break the app


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


# ── Routes ──────────────────────────────────────────────────────────────

@auth_bp.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template("login.html")

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    if not username or not password:
        flash("请输入用户名和密码", "warning")
        return render_template("login.html")

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE username = ? AND is_active = 1",
                      (username,)).fetchone()
    db.close()

    if not user or not verify_password(password, user["password"]):
        flash("用户名或密码错误", "danger")
        _audit("login_failed", f"username={username}")
        return render_template("login.html")

    session["username"] = user["username"]
    session["role"] = user["role"]
    session["user_id"] = user["id"]
    _audit("login", f"role={user['role']}")
    return redirect(url_for("dashboard"))


@auth_bp.route("/logout")
def logout():
    _audit("logout")
    session.clear()
    flash("已退出登录", "info")
    return redirect(url_for("auth.login_page"))


@auth_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if request.method == "POST":
        current_pw = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm_pw = request.form.get("confirm_password", "")

        if not current_pw or not new_pw:
            flash("请填写所有字段", "warning")
            return render_template("profile.html")

        if new_pw != confirm_pw:
            flash("两次输入的新密码不一致", "warning")
            return render_template("profile.html")

        if len(new_pw) < 6:
            flash("新密码长度至少6位", "warning")
            return render_template("profile.html")

        db = get_db()
        user = db.execute("SELECT * FROM users WHERE username = ?",
                          (session["username"],)).fetchone()

        if not verify_password(current_pw, user["password"]):
            flash("当前密码错误", "danger")
            db.close()
            return render_template("profile.html")

        new_hash = hash_password(new_pw)
        db.execute("UPDATE users SET password = ?, updated_at = datetime('now') WHERE username = ?",
                   (new_hash, session["username"]))
        db.commit()
        db.close()

        _audit("change_password")
        flash("密码修改成功", "success")
        return redirect(url_for("dashboard"))

    return render_template("profile.html")
