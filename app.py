#!/usr/bin/env python3
"""
OpenVPN Admin — Web Management Backend
=======================================
Flask-based management dashboard for OpenVPN servers.

Features:
  - User & Role management (admin / operator / viewer)
  - Key management (apply, revoke, download .ovpn)
  - Service management (start, stop, restart, status)
  - Online server.conf editor
  - Audit logging (OpenVPN logs + admin operation logs)
"""

import io
import json
import os
import re
from datetime import datetime, timezone

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, g, jsonify, send_file, Response
)

from database import init_db, get_db, db_session
from auth import auth_bp, login_required, role_required, _audit, hash_password, verify_password
from openvpn import OpenVPNManager

# ── App setup ───────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 MB

# Register auth blueprint
app.register_blueprint(auth_bp)

# Lazy init OpenVPN manager
_ovpn: OpenVPNManager | None = None


def get_ovpn() -> OpenVPNManager:
    global _ovpn
    if _ovpn is None:
        _ovpn = OpenVPNManager()
    return _ovpn


# ── Context processor ───────────────────────────────────────────────────
@app.context_processor
def inject_globals():
    return {
        "username": session.get("username", ""),
        "role": session.get("role", "viewer"),
        "now": datetime.now(),
    }


# ── Dashboard ───────────────────────────────────────────────────────────
@app.route("/")
@login_required
def dashboard():
    db = get_db()
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_keys = db.execute("SELECT COUNT(*) FROM key_records WHERE status='active'").fetchone()[0]
    revoked_keys = db.execute("SELECT COUNT(*) FROM key_records WHERE status='revoked'").fetchone()[0]
    recent_audit = db.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    db.close()

    # Try to get OpenVPN status (graceful if unreachable)
    ovpn_status = None
    ovpn_error = None
    try:
        ovpn_status = get_ovpn().get_status()
    except Exception as e:
        ovpn_error = str(e)

    return render_template("dashboard.html",
                           user_count=user_count,
                           active_keys=active_keys,
                           revoked_keys=revoked_keys,
                           recent_audit=recent_audit,
                           ovpn_status=ovpn_status,
                           ovpn_error=ovpn_error)


# ══════════════════════════════════════════════════════════════════════════
#  User Management
# ══════════════════════════════════════════════════════════════════════════

@app.route("/users")
@login_required
@role_required("admin")
def users_list():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    db.close()
    return render_template("users.html", users=users)


@app.route("/users/create", methods=["POST"])
@login_required
@role_required("admin")
def users_create():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "viewer")
    email = request.form.get("email", "").strip()

    if not username or not password:
        flash("用户名和密码不能为空", "warning")
        return redirect(url_for("users_list"))

    if role not in ("admin", "operator", "viewer"):
        flash("无效的角色", "warning")
        return redirect(url_for("users_list"))

    if len(password) < 6:
        flash("密码长度至少6位", "warning")
        return redirect(url_for("users_list"))

    try:
        with db_session() as db:
            db.execute(
                "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                (username, hash_password(password), role, email)
            )
        _audit("create_user", f"username={username} role={role}")
        flash(f"用户 {username} 创建成功", "success")
    except Exception as e:
        flash(f"创建失败: {e}", "danger")

    return redirect(url_for("users_list"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def users_delete(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("用户不存在", "danger")
        db.close()
        return redirect(url_for("users_list"))
    if user["username"] == session["username"]:
        flash("不能删除自己", "danger")
        db.close()
        return redirect(url_for("users_list"))

    db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    db.commit()
    db.close()
    _audit("delete_user", f"username={user['username']}")
    flash(f"用户 {user['username']} 已删除", "success")
    return redirect(url_for("users_list"))


@app.route("/users/<int:user_id>/toggle", methods=["POST"])
@login_required
@role_required("admin")
def users_toggle(user_id):
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("用户不存在", "danger")
        db.close()
        return redirect(url_for("users_list"))
    if user["username"] == session["username"]:
        flash("不能禁用自己", "danger")
        db.close()
        return redirect(url_for("users_list"))

    new_status = 0 if user["is_active"] else 1
    db.execute("UPDATE users SET is_active = ?, updated_at = datetime('now') WHERE id = ?",
               (new_status, user_id))
    db.commit()
    db.close()
    action = "enable_user" if new_status else "disable_user"
    _audit(action, f"username={user['username']}")
    status_text = "启用" if new_status else "禁用"
    flash(f"用户 {user['username']} 已{status_text}", "success")
    return redirect(url_for("users_list"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
@role_required("admin")
def users_reset_password(user_id):
    new_pw = request.form.get("new_password", "").strip()
    if len(new_pw) < 6:
        flash("密码长度至少6位", "warning")
        return redirect(url_for("users_list"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not user:
        flash("用户不存在", "danger")
        db.close()
        return redirect(url_for("users_list"))

    db.execute("UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?",
               (hash_password(new_pw), user_id))
    db.commit()
    db.close()
    _audit("reset_password", f"username={user['username']}")
    flash(f"用户 {user['username']} 密码已重置", "success")
    return redirect(url_for("users_list"))


# ══════════════════════════════════════════════════════════════════════════
#  Key Management
# ══════════════════════════════════════════════════════════════════════════

@app.route("/keys")
@login_required
def keys_list():
    db = get_db()
    records = db.execute("SELECT * FROM key_records ORDER BY issued_at DESC").fetchall()
    db.close()

    # Sync with live server certificates
    try:
        live_certs = get_ovpn().list_certificates()
    except Exception:
        live_certs = []

    return render_template("keys.html", records=records, live_certs=live_certs)


@app.route("/keys/create", methods=["POST"])
@login_required
@role_required("admin", "operator")
def keys_create():
    common_name = request.form.get("common_name", "").strip()
    description = request.form.get("description", "").strip()

    if not common_name:
        flash("请输入客户端名称 (Common Name)", "warning")
        return redirect(url_for("keys_list"))

    if not re.match(r"^[a-zA-Z0-9_\-\.]+$", common_name):
        flash("客户端名称只能包含字母、数字、下划线、连字符和点", "warning")
        return redirect(url_for("keys_list"))

    # Check if already exists in DB
    db = get_db()
    existing = db.execute("SELECT * FROM key_records WHERE common_name = ? AND status = 'active'",
                          (common_name,)).fetchone()
    if existing:
        flash(f"客户端 {common_name} 已存在且处于活跃状态", "warning")
        db.close()
        return redirect(url_for("keys_list"))
    db.close()

    # Create on OpenVPN server
    try:
        result = get_ovpn().create_client(common_name)
    except Exception as e:
        flash(f"连接 OpenVPN 服务器失败: {e}", "danger")
        return redirect(url_for("keys_list"))

    if not result.get("success"):
        flash(f"创建密钥失败: {result.get('error', '未知错误')}", "danger")
        return redirect(url_for("keys_list"))

    # Record in DB
    with db_session() as db:
        db.execute(
            "INSERT INTO key_records (common_name, status, issued_by, description) VALUES (?, 'active', ?, ?)",
            (common_name, session["username"], description)
        )

    _audit("create_key", f"cn={common_name}")
    flash(f"客户端 {common_name} 密钥创建成功", "success")
    return redirect(url_for("keys_list"))


@app.route("/keys/<common_name>/download")
@login_required
def keys_download(common_name):
    try:
        content = get_ovpn().download_client_config(common_name)
    except Exception as e:
        flash(f"下载失败: {e}", "danger")
        return redirect(url_for("keys_list"))

    if content is None:
        flash(f"客户端 {common_name} 的配置文件不存在", "warning")
        return redirect(url_for("keys_list"))

    _audit("download_key", f"cn={common_name}")
    return send_file(
        io.BytesIO(content),
        mimetype="application/x-openvpn-profile",
        as_attachment=True,
        download_name=f"{common_name}.ovpn"
    )


@app.route("/keys/<common_name>/revoke", methods=["POST"])
@login_required
@role_required("admin", "operator")
def keys_revoke(common_name):
    try:
        result = get_ovpn().revoke_client(common_name)
    except Exception as e:
        flash(f"连接 OpenVPN 服务器失败: {e}", "danger")
        return redirect(url_for("keys_list"))

    if not result.get("success"):
        flash(f"吊销失败: {result.get('error', '未知错误')}", "danger")
        return redirect(url_for("keys_list"))

    # Update DB
    with db_session() as db:
        db.execute(
            "UPDATE key_records SET status='revoked', revoked_at=datetime('now'), revoked_by=? WHERE common_name=? AND status='active'",
            (session["username"], common_name)
        )

    _audit("revoke_key", f"cn={common_name}")
    flash(f"客户端 {common_name} 密钥已吊销", "success")
    return redirect(url_for("keys_list"))


# ══════════════════════════════════════════════════════════════════════════
#  Service Management
# ══════════════════════════════════════════════════════════════════════════

@app.route("/service")
@login_required
def service_page():
    try:
        status = get_ovpn().get_status()
        host_info = get_ovpn().get_host_info()
        error = None
    except Exception as e:
        status = None
        host_info = None
        error = str(e)

    return render_template("service.html", status=status, host_info=host_info, error=error)


@app.route("/service/<action>", methods=["POST"])
@login_required
@role_required("admin", "operator")
def service_action(action):
    if action not in ("start", "stop", "restart"):
        flash("无效的操作", "danger")
        return redirect(url_for("service_page"))

    try:
        ovpn = get_ovpn()
        if action == "start":
            result = ovpn.start()
        elif action == "stop":
            result = ovpn.stop()
        else:
            result = ovpn.restart()

        _audit(f"{action}_service", f"success={result.get('success')}")
        if result.get("success"):
            flash(f"OpenVPN 服务{action}成功", "success")
        else:
            flash(f"操作失败: {result.get('output', '未知错误')}", "danger")
    except Exception as e:
        flash(f"操作失败: {e}", "danger")

    return redirect(url_for("service_page"))


# ══════════════════════════════════════════════════════════════════════════
#  Configuration Editor
# ══════════════════════════════════════════════════════════════════════════

@app.route("/config")
@login_required
@role_required("admin")
def config_page():
    try:
        current_config = get_ovpn().get_config()
        error = None
    except Exception as e:
        current_config = ""
        error = str(e)

    # Get config history
    db = get_db()
    history = db.execute(
        "SELECT * FROM config_history ORDER BY changed_at DESC LIMIT 20"
    ).fetchall()
    db.close()

    return render_template("config.html", config=current_config, history=history, error=error)


@app.route("/config/update", methods=["POST"])
@login_required
@role_required("admin")
def config_update():
    new_config = request.form.get("config_content", "")
    comment = request.form.get("comment", "").strip()

    if not new_config.strip():
        flash("配置内容不能为空", "warning")
        return redirect(url_for("config_page"))

    try:
        result = get_ovpn().update_config(new_config)
    except Exception as e:
        flash(f"更新配置失败: {e}", "danger")
        return redirect(url_for("config_page"))

    # Save to history
    with db_session() as db:
        db.execute(
            "INSERT INTO config_history (content, changed_by, comment) VALUES (?, ?, ?)",
            (new_config, session["username"], comment)
        )

    _audit("update_config", f"comment={comment}")
    flash(f"配置已更新 (备份: {result.get('backup', 'N/A')})", "success")
    return redirect(url_for("config_page"))


@app.route("/config/history/<int:history_id>")
@login_required
@role_required("admin")
def config_view_history(history_id):
    db = get_db()
    entry = db.execute("SELECT * FROM config_history WHERE id = ?", (history_id,)).fetchone()
    db.close()
    if not entry:
        flash("历史记录不存在", "danger")
        return redirect(url_for("config_page"))
    return render_template("config_view.html", entry=entry)


# ══════════════════════════════════════════════════════════════════════════
#  Audit Logs
# ══════════════════════════════════════════════════════════════════════════

@app.route("/logs")
@login_required
def logs_page():
    page = request.args.get("page", 1, type=int)
    per_page = 50
    action_filter = request.args.get("action", "").strip()
    user_filter = request.args.get("user", "").strip()

    db = get_db()

    # Build query
    where_clauses = []
    params = []
    if action_filter:
        where_clauses.append("action LIKE ?")
        params.append(f"%{action_filter}%")
    if user_filter:
        where_clauses.append("username LIKE ?")
        params.append(f"%{user_filter}%")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # Count
    total = db.execute(f"SELECT COUNT(*) FROM audit_log {where_sql}", params).fetchone()[0]

    # Page
    offset = (page - 1) * per_page
    logs = db.execute(
        f"SELECT * FROM audit_log {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()

    # Distinct actions for filter dropdown
    actions = db.execute(
        "SELECT DISTINCT action FROM audit_log ORDER BY action"
    ).fetchall()

    db.close()

    total_pages = max(1, (total + per_page - 1) // per_page)

    return render_template("logs.html",
                           logs=logs, page=page, total_pages=total_pages,
                           total=total, action_filter=action_filter,
                           user_filter=user_filter, actions=actions)


@app.route("/logs/openvpn")
@login_required
def logs_openvpn():
    lines = request.args.get("lines", 200, type=int)
    lines = min(max(lines, 10), 1000)

    try:
        ovpn_logs = get_ovpn().get_logs(lines=lines)
        error = None
    except Exception as e:
        ovpn_logs = ""
        error = str(e)

    return render_template("logs_openvpn.html", ovpn_logs=ovpn_logs, lines=lines, error=error)


# ══════════════════════════════════════════════════════════════════════════
#  API endpoints (for AJAX refresh)
# ══════════════════════════════════════════════════════════════════════════

@app.route("/api/status")
@login_required
def api_status():
    try:
        status = get_ovpn().get_status()
        return jsonify({"success": True, "data": status})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ══════════════════════════════════════════════════════════════════════════
#  Error handlers
# ══════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e):
    return render_template("error.html", code=404, message="页面不存在"), 404


@app.errorhandler(500)
def server_error(e):
    return render_template("error.html", code=500, message="服务器内部错误"), 500


# ══════════════════════════════════════════════════════════════════════════
#  Main
# ══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    init_db()
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "false").lower() == "true"
    print(f"[OpenVPN Admin] Starting on {host}:{port}")
    app.run(host=host, port=port, debug=debug)
