"""
OpenVPN Admin — Web Management Backend
=======================================

A Flask-based web dashboard for managing remote OpenVPN servers via SSH.

Architecture:
    Browser → Flask (app.py) → Paramiko SSH → OpenVPN Server
    SQLite stores users, keys, audit logs, and config history.

Features:
    - Dashboard with VPN status, connected clients, and audit trail
    - User & Role-based access control (admin / operator / viewer)
    - Client key lifecycle management (create, revoke, download .ovpn)
    - Service management (start, stop, restart via systemctl)
    - Online server.conf editor with automatic backups and change history
    - Full audit logging with pagination and filtering
    - OpenVPN server log viewer
    - REST API endpoint for AJAX status polling

Routes (15 total):
    GET  /                          Dashboard
    GET  /users                     User list (admin only)
    POST /users/create              Create user (admin only)
    POST /users/<id>/delete         Delete user (admin only)
    POST /users/<id>/toggle         Enable/disable user (admin only)
    POST /users/<id>/reset-password Reset user password (admin only)
    GET  /keys                      Key list
    POST /keys/create               Create client key (admin, operator)
    GET  /keys/<cn>/download        Download .ovpn file
    POST /keys/<cn>/revoke          Revoke client key (admin, operator)
    GET  /service                   Service status page
    POST /service/<action>          Start/stop/restart service (admin, operator)
    GET  /config                    Config editor (admin only)
    POST /config/update             Save config (admin only)
    GET  /config/history/<id>       View config history (admin only)
    GET  /logs                      Audit logs with pagination
    GET  /logs/openvpn              OpenVPN server logs
    GET  /api/status                Service status JSON

Environment Variables:
    See README.md for the full list. Key variables:
    SECRET_KEY, OPENVPN_HOST, OPENVPN_SSH_USER, OPENVPN_SSH_KEY,
    OPENVPN_SSH_PASSWORD, ADMIN_PASSWORD, OPENVPN_SERVICE

Usage:
    python app.py                    # Development server
    gunicorn --bind :5000 app:app   # Production server
"""

# ── Standard library imports ──────────────────────────────────────────────
import io
import os
import re
import sqlite3
import time

# ── Third-party imports ───────────────────────────────────────────────────
from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, jsonify, send_file
)

# ── Environment file loading ──────────────────────────────────────────────
# Load variables from a .env file in the project root before any module
# reads its configuration from os.environ. This makes local development
# easier without hard-coding host paths or secrets in the source code.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:  # pragma: no cover
    # python-dotenv is optional; if absent, rely purely on real env vars.
    pass

# ── Application modules ───────────────────────────────────────────────────
from database import init_db, get_db, db_session
from auth import (
    auth_bp, login_required, role_required, _audit, hash_password,
    get_csrf_token, validate_csrf_token
)
from openvpn import OpenVPNManager


# ═══════════════════════════════════════════════════════════════════════════
#  App Initialization
# ═══════════════════════════════════════════════════════════════════════════

# Create Flask application instance
app = Flask(__name__)

# Session signing key — MUST be set in production via SECRET_KEY env var,
# otherwise a random key is generated per process (invalidating all sessions
# on restart, and breaking multi-worker deployments).
app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24).hex())

# Limit request body to 16 MB (prevents memory exhaustion from large uploads)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

# Register the authentication blueprint (handles /login, /logout, /profile)
app.register_blueprint(auth_bp)

# Initialize database on import — ensures tables exist and default admin
# is seeded when running under gunicorn (Docker) where __main__ is not used.
init_db()


# ═══════════════════════════════════════════════════════════════════════════
#  Jinja2 Filters
# ═══════════════════════════════════════════════════════════════════════════

@app.template_filter("fmt_bytes")
def fmt_bytes(value) -> str:
    """
    Format a raw byte count as a human-readable string (B / KB / MB / GB).

    Accepts int, str (containing an int), or anything ``int()`` can parse.
    Returns ``'-'`` for unparseable input so the template never breaks.
    """
    try:
        n = int(value)
    except (TypeError, ValueError):
        return "-"
    if n < 0:
        return "-"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} {unit}"
        n /= 1024
    return f"{n:.1f} PB"


# ── Lazy initialization of OpenVPN manager ────────────────────────────────
# The OpenVPNManager opens SSH connections to the remote server. We lazy-init
# it so the app can start even if the VPN server is temporarily unreachable
# (e.g. during container startup before the network is ready).
_ovpn: OpenVPNManager | None = None


def get_ovpn() -> OpenVPNManager:
    """
    Return the singleton OpenVPNManager instance, creating it on first call.

    Lazy initialization allows the web app to start without an active SSH
    connection to the VPN server. Any route that needs SSH will trigger
    the connection at that point and surface errors gracefully.

    Returns:
        OpenVPNManager: The application-wide SSH manager singleton.
    """
    global _ovpn
    if _ovpn is None:
        _ovpn = OpenVPNManager()
    return _ovpn


# ═══════════════════════════════════════════════════════════════════════════
#  Context Processor — injects template globals
# ═══════════════════════════════════════════════════════════════════════════

@app.context_processor
def inject_globals() -> dict:
    """
    Inject common variables into all Jinja2 templates.

    Called automatically by Flask before every render_template().
    Makes ``username`` and ``role`` available in every template without
    needing to pass them explicitly in each route.

    Returns:
        dict: Variables accessible as ``{{ username }}`` and ``{{ role }}``
              in all templates.
    """
    return {
        "username": session.get("username", ""),
        "role": session.get("role", "viewer"),
        "csrf_token": get_csrf_token(),
    }


# ── Session timeout enforcement ────────────────────────────────────────────
# Check session age on every request. If the session has been idle longer
# than SESSION_TIMEOUT seconds, clear it and redirect to login.
#
# NOTE: Flask's default session is a client-side cookie that must remain
# JSON-serializable. We store ``_last_activity`` as a Unix timestamp (int)
# rather than a datetime object to keep it serializable.

SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT", "3600"))


@app.before_request
def _security_middleware():
    """
    Global security middleware run before every request.

    Performs two checks:
    1. CSRF token validation for every state-changing request (POST/PUT/
       PATCH/DELETE), including the login form submission.
    2. Session idle timeout enforcement for authenticated users. If the
       session has exceeded SESSION_TIMEOUT seconds since the last activity,
       the session is cleared and the user is redirected to login.

    Static assets are fully exempt. The login page is exempt from timeout
    checks (it handles its own logic), but CSRF is still validated there.
    """
    # Static files are fully exempt.
    if request.endpoint == "static":
        return

    # 1) Validate CSRF token for all state-changing requests (including login).
    # The login form GET sets a token via the context processor, so even an
    # unauthenticated POST can be verified. Safe methods are ignored.
    validate_csrf_token()

    # Login page: no session-timeout check needed here (it is handled by
    # the route itself and session is recreated on success).
    if request.endpoint == "auth.login_page":
        return

    # 2) Session idle timeout — only for authenticated users.
    if "username" not in session:
        return

    last_activity = session.get("_last_activity")
    if last_activity is not None:
        try:
            elapsed = time.time() - float(last_activity)
        except (TypeError, ValueError):
            # Corrupt or non-numeric value (e.g. legacy datetime string
            # from a previous deploy) — refresh it and move on.
            elapsed = 0
        if elapsed > SESSION_TIMEOUT:
            session.clear()
            flash("会话已过期，请重新登录", "info")
            return redirect(url_for("auth.login_page"))

    # Update last activity timestamp (Unix epoch seconds).
    session["_last_activity"] = time.time()


# ═══════════════════════════════════════════════════════════════════════════
#  Dashboard
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/")
@login_required
def dashboard():
    """
    Render the main dashboard with system overview.

    Gathers:
    - User count from the local SQLite database
    - Active and revoked key counts
    - Last 20 audit log entries
    - OpenVPN server status (gracefully degrades if unreachable)

    Returns:
        Rendered ``dashboard.html`` template.
    """
    # ── Gather local DB statistics ────────────────────────────────────
    db = get_db()
    user_count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    active_keys = db.execute(
        "SELECT COUNT(*) FROM key_records WHERE status='active'"
    ).fetchone()[0]
    revoked_keys = db.execute(
        "SELECT COUNT(*) FROM key_records WHERE status='revoked'"
    ).fetchone()[0]
    recent_audit = db.execute(
        "SELECT * FROM audit_log ORDER BY created_at DESC LIMIT 20"
    ).fetchall()
    db.close()

    # ── Attempt to fetch remote VPN server status ─────────────────────
    # Wrap in try/except so the dashboard still renders if the VPN server
    # is unreachable (network issues, server down, SSH key problems).
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


# ═══════════════════════════════════════════════════════════════════════════
#  User Management (admin-only)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/users")
@login_required
@role_required("admin")
def users_list():
    """
    List all users ordered by creation time (newest first).

    Returns:
        Rendered ``users.html`` template with all user records.
    """
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    db.close()
    return render_template("users.html", users=users)


@app.route("/users/create", methods=["POST"])
@login_required
@role_required("admin")
def users_create():
    """
    Create a new user account.

    Validates:
    - Username and password are non-empty
    - Role is one of: admin, operator, viewer
    - Password is at least 6 characters

    The password is bcrypt-hashed before storage.
    Audit log entry is written on success.

    Returns:
        Redirect to user list with flash message.
    """
    # Extract and sanitize form fields
    username = request.form.get("username", "").strip()
    # Do not strip passwords — whitespace can be intentional.
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")
    email = request.form.get("email", "").strip()

    # ── Input validation ──────────────────────────────────────────────
    if not username or not password:
        flash("用户名和密码不能为空", "warning")
        return redirect(url_for("users_list"))

    if role not in ("admin", "operator", "viewer"):
        flash("无效的角色", "warning")
        return redirect(url_for("users_list"))

    if len(password) < 6:
        flash("密码长度至少6位", "warning")
        return redirect(url_for("users_list"))

    if email and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        flash("邮箱格式不正确", "warning")
        return redirect(url_for("users_list"))

    # ── Persist to database ───────────────────────────────────────────
    try:
        with db_session() as db:
            db.execute(
                "INSERT INTO users (username, password, role, email) VALUES (?, ?, ?, ?)",
                (username, hash_password(password), role, email)
            )
        _audit("create_user", f"username={username} role={role}")
        flash(f"用户 {username} 创建成功", "success")
    except sqlite3.IntegrityError:
        # Most likely the username UNIQUE constraint was violated.
        flash(f"用户名 {username} 已存在", "warning")
    except Exception as e:
        flash(f"创建失败: {e}", "danger")

    return redirect(url_for("users_list"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@role_required("admin")
def users_delete(user_id: int):
    """
    Delete a user account permanently.

    Safety guards:
    - Cannot delete a non-existent user
    - Cannot delete yourself (the currently logged-in admin)

    Args:
        user_id: The database ID of the user to delete.

    Returns:
        Redirect to user list with flash message.
    """
    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        flash("用户不存在", "danger")
        db.close()
        return redirect(url_for("users_list"))

    # Prevent self-deletion — critical safety guard
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
def users_toggle(user_id: int):
    """
    Toggle a user's active status (enable ↔ disable).

    Disabling a user prevents login but preserves their data and audit
    trail. The currently logged-in admin cannot disable themselves.

    Args:
        user_id: The database ID of the user to toggle.

    Returns:
        Redirect to user list with flash message.
    """
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

    # Flip the active flag: 0 → 1 (enable) or 1 → 0 (disable)
    new_status = 0 if user["is_active"] else 1
    db.execute(
        "UPDATE users SET is_active = ?, updated_at = datetime('now') WHERE id = ?",
        (new_status, user_id)
    )
    db.commit()
    db.close()

    # Determine audit action name and user-facing status text
    action = "enable_user" if new_status else "disable_user"
    _audit(action, f"username={user['username']}")
    status_text = "启用" if new_status else "禁用"
    flash(f"用户 {user['username']} 已{status_text}", "success")
    return redirect(url_for("users_list"))


@app.route("/users/<int:user_id>/reset-password", methods=["POST"])
@login_required
@role_required("admin")
def users_reset_password(user_id: int):
    """
    Reset a user's password (admin override — no current password required).

    The new password is bcrypt-hashed before storage.

    Args:
        user_id: The database ID of the user whose password to reset.

    Returns:
        Redirect to user list with flash message.
    """
    # Do not strip passwords — whitespace can be intentional.
    new_pw = request.form.get("new_password", "")
    if len(new_pw) < 6:
        flash("密码长度至少6位", "warning")
        return redirect(url_for("users_list"))

    db = get_db()
    user = db.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()

    if not user:
        flash("用户不存在", "danger")
        db.close()
        return redirect(url_for("users_list"))

    db.execute(
        "UPDATE users SET password = ?, updated_at = datetime('now') WHERE id = ?",
        (hash_password(new_pw), user_id)
    )
    db.commit()
    db.close()

    _audit("reset_password", f"username={user['username']}")
    flash(f"用户 {user['username']} 密码已重置", "success")
    return redirect(url_for("users_list"))


# ═══════════════════════════════════════════════════════════════════════════
#  Key Management
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/keys")
@login_required
def keys_list():
    """
    List all client key records with live certificate sync.

    Combines:
    - DB records: key_records table (our authoritative audit trail)
    - Live certs: fetched from the VPN server's EasyRSA PKI index

    Returns:
        Rendered ``keys.html`` template.
    """
    # ── Get local DB records ─────────────────────────────────────────
    db = get_db()
    records = db.execute("SELECT * FROM key_records ORDER BY issued_at DESC").fetchall()
    db.close()

    # ── Sync with live server certificates ────────────────────────────
    # If the VPN server is unreachable, we gracefully fall back to an
    # empty list — the template shows DB records + a warning if needed.
    try:
        live_certs = get_ovpn().list_certificates()
    except Exception:
        live_certs = []

    return render_template("keys.html", records=records, live_certs=live_certs)


@app.route("/keys/create", methods=["POST"])
@login_required
@role_required("admin", "operator")
def keys_create():
    """
    Create a new client certificate and generate an .ovpn config file.

    Flow:
    1. Validate the common name (alphanumeric + hyphens/underscores/dots)
    2. Check no active record exists with the same CN in the database
    3. Execute EasyRSA build-client-full on the VPN server via SSH
    4. Generate the .ovpn bundle (inline certs + keys)
    5. Record the issuance in the key_records table

    Returns:
        Redirect to key list with flash message.
    """
    common_name = request.form.get("common_name", "").strip()
    description = request.form.get("description", "").strip()

    # ── Input validation ──────────────────────────────────────────────
    if not common_name:
        flash("请输入客户端名称 (Common Name)", "warning")
        return redirect(url_for("keys_list"))

    # Restrict CN to safe characters to prevent shell injection and
    # EasyRSA parameter contamination. Cap at 64 chars for parity with
    # the OpenVPN-side validation in OpenVPNManager.
    if not re.match(r"^[a-zA-Z0-9_\-\.]{1,64}$", common_name):
        flash("客户端名称只能包含字母、数字、下划线、连字符和点 (最多64字符)", "warning")
        return redirect(url_for("keys_list"))

    # ── Check for duplicate active key ────────────────────────────────
    db = get_db()
    existing = db.execute(
        "SELECT * FROM key_records WHERE common_name = ? AND status = 'active'",
        (common_name,)
    ).fetchone()
    if existing:
        flash(f"客户端 {common_name} 已存在且处于活跃状态", "warning")
        db.close()
        return redirect(url_for("keys_list"))
    db.close()

    # ── Create certificate on the VPN server ──────────────────────────
    try:
        result = get_ovpn().create_client(common_name)
    except Exception as e:
        flash(f"连接 OpenVPN 服务器失败: {e}", "danger")
        return redirect(url_for("keys_list"))

    if not result.get("success"):
        flash(f"创建密钥失败: {result.get('error', '未知错误')}", "danger")
        return redirect(url_for("keys_list"))

    # ── Record issuance in database ───────────────────────────────────
    try:
        with db_session() as db:
            db.execute(
                "INSERT INTO key_records (common_name, status, issued_by, description) "
                "VALUES (?, 'active', ?, ?)",
                (common_name, session["username"], description)
            )
    except sqlite3.IntegrityError:
        # Race condition: another request inserted the same CN between
        # the existence check above and this insert. The certificate and
        # .ovpn file already exist on the server, but we have no local
        # record. Revoke the freshly-created certificate to keep server
        # and DB state consistent; ignore CRL failures here because the
        # primary problem is the duplicate CN.
        try:
            get_ovpn().revoke_client(common_name)
        except Exception:
            pass
        flash(f"客户端 {common_name} 已被其他管理员创建", "warning")
        return redirect(url_for("keys_list"))

    _audit("create_key", f"cn={common_name}")
    flash(f"客户端 {common_name} 密钥创建成功", "success")
    return redirect(url_for("keys_list"))


@app.route("/keys/<common_name>/download")
@login_required
def keys_download(common_name: str):
    """
    Download a client's .ovpn configuration file.

    Fetches the .ovpn file from the VPN server via SFTP and sends it
    as a file download with the correct MIME type and filename.

    Args:
        common_name: The client's Common Name (matches the .ovpn filename).

    Returns:
        File download response, or redirect with flash error.
    """
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
def keys_revoke(common_name: str):
    """
    Revoke a client certificate and update the Certificate Revocation List.

    Flow:
    1. Execute EasyRSA revoke on the VPN server
    2. Regenerate the CRL
    3. Mark the key as 'revoked' in the database with timestamp and operator

    Args:
        common_name: The client's Common Name to revoke.

    Returns:
        Redirect to key list with flash message.
    """
    # ── Revoke on VPN server ──────────────────────────────────────────
    try:
        result = get_ovpn().revoke_client(common_name)
    except Exception as e:
        flash(f"连接 OpenVPN 服务器失败: {e}", "danger")
        return redirect(url_for("keys_list"))

    if not result.get("success"):
        flash(f"吊销失败: {result.get('error', '未知错误')}", "danger")
        return redirect(url_for("keys_list"))

    # ── Update database record ────────────────────────────────────────
    with db_session() as db:
        db.execute(
            "UPDATE key_records SET status='revoked', revoked_at=datetime('now'), "
            "revoked_by=? WHERE common_name=? AND status='active'",
            (session["username"], common_name)
        )

    _audit("revoke_key", f"cn={common_name}")

    # The cert is revoked on the server, but if the CRL was not regenerated
    # the client can still authenticate. Surface this prominently so the
    # operator knows the revocation may not be enforced yet.
    if not result.get("crl_updated"):
        flash(
            f"客户端 {common_name} 密钥已吊销, 但 CRL 未更新, 客户端暂时仍可连接, "
            "请手动执行: cd /etc/openvpn/easy-rsa && ./easyrsa gen-crl",
            "warning",
        )
    else:
        flash(f"客户端 {common_name} 密钥已吊销", "success")
    return redirect(url_for("keys_list"))


# ═══════════════════════════════════════════════════════════════════════════
#  Service Management
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/service")
@login_required
def service_page():
    """
    Display the OpenVPN service status and host information.

    Fetches service status (systemctl) and host info (disk, memory, ports)
    from the remote VPN server. Gracefully degrades if unreachable.

    Returns:
        Rendered ``service.html`` template.
    """
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
def service_action(action: str):
    """
    Execute a service control action on the remote OpenVPN server.

    Actions:
        start   — systemctl start openvpn@server
        stop    — systemctl stop openvpn@server
        restart — systemctl restart openvpn@server

    Args:
        action: One of 'start', 'stop', 'restart'.

    Returns:
        Redirect to service page with flash message indicating result.
    """
    if action not in ("start", "stop", "restart"):
        flash("无效的操作", "danger")
        return redirect(url_for("service_page"))

    try:
        ovpn = get_ovpn()
        # Dispatch to the appropriate systemctl command
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


# ═══════════════════════════════════════════════════════════════════════════
#  Configuration Editor (admin-only)
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/config")
@login_required
@role_required("admin")
def config_page():
    """
    Display the server.conf online editor with change history.

    Fetches the current config from the VPN server and the last 20
    config history entries from the local database.

    Returns:
        Rendered ``config.html`` template.
    """
    # ── Fetch current config from VPN server ──────────────────────────
    try:
        current_config = get_ovpn().get_config()
        error = None
    except Exception as e:
        current_config = ""
        error = str(e)

    # ── Get config change history from local DB ───────────────────────
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
    """
    Save a new server.conf to the VPN server.

    Safety measures:
    - Creates a timestamped backup before overwriting
    - Writes via SFTP temp file + atomic mv (avoids partial writes)
    - Records the change in config_history with operator and comment

    Returns:
        Redirect to config page with flash message.
    """
    new_config = request.form.get("config_content", "")
    comment = request.form.get("comment", "").strip()

    if not new_config.strip():
        flash("配置内容不能为空", "warning")
        return redirect(url_for("config_page"))

    # ── Write config to VPN server ────────────────────────────────────
    # The update_config method handles backup creation and atomic write
    # via temp file + mv, preventing partial/corrupt config files.
    try:
        result = get_ovpn().update_config(new_config)
    except Exception as e:
        flash(f"更新配置失败: {e}", "danger")
        return redirect(url_for("config_page"))

    # ── Record in local config history ────────────────────────────────
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
def config_view_history(history_id: int):
    """
    View a specific historical config snapshot.

    Args:
        history_id: The database ID of the config_history entry.

    Returns:
        Rendered ``config_view.html`` template, or redirect if not found.
    """
    db = get_db()
    entry = db.execute(
        "SELECT * FROM config_history WHERE id = ?", (history_id,)
    ).fetchone()
    db.close()

    if not entry:
        flash("历史记录不存在", "danger")
        return redirect(url_for("config_page"))
    return render_template("config_view.html", entry=entry)


# ═══════════════════════════════════════════════════════════════════════════
#  Audit Logs
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/logs")
@login_required
def logs_page():
    """
    Display paginated audit logs with optional filtering.

    Query parameters:
        page   — Page number (default: 1)
        action — Filter by action keyword (partial match)
        user   — Filter by username keyword (partial match)

    Returns:
        Rendered ``logs.html`` template with pagination and filters.
    """
    # ── Parse query parameters ────────────────────────────────────────
    page = request.args.get("page", 1, type=int)
    per_page = 50
    action_filter = request.args.get("action", "").strip()
    user_filter = request.args.get("user", "").strip()

    db = get_db()

    # ── Build dynamic WHERE clause from filters ───────────────────────
    where_clauses = []
    params = []
    if action_filter:
        where_clauses.append("action LIKE ?")
        params.append(f"%{action_filter}%")
    if user_filter:
        where_clauses.append("username LIKE ?")
        params.append(f"%{user_filter}%")

    where_sql = ("WHERE " + " AND ".join(where_clauses)) if where_clauses else ""

    # ── Count total matching records ──────────────────────────────────
    total = db.execute(
        f"SELECT COUNT(*) FROM audit_log {where_sql}", params
    ).fetchone()[0]

    # ── Fetch current page ────────────────────────────────────────────
    offset = (page - 1) * per_page
    logs = db.execute(
        f"SELECT * FROM audit_log {where_sql} ORDER BY created_at DESC LIMIT ? OFFSET ?",
        params + [per_page, offset]
    ).fetchall()

    # ── Get distinct actions for filter dropdown ──────────────────────
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
    """
    Display recent OpenVPN server logs.

    Query parameters:
        lines — Number of log lines to fetch (10–1000, default: 200)

    Returns:
        Rendered ``logs_openvpn.html`` template.
    """
    lines = request.args.get("lines", 200, type=int)
    # Clamp to safe range to prevent excessive SSH output
    lines = min(max(lines, 10), 1000)

    try:
        ovpn_logs = get_ovpn().get_logs(lines=lines)
        error = None
    except Exception as e:
        ovpn_logs = ""
        error = str(e)

    return render_template("logs_openvpn.html", ovpn_logs=ovpn_logs, lines=lines, error=error)


# ═══════════════════════════════════════════════════════════════════════════
#  API Endpoints
# ═══════════════════════════════════════════════════════════════════════════

@app.route("/api/status")
@login_required
def api_status():
    """
    Return OpenVPN service status as JSON.

    Used by the frontend JavaScript for AJAX polling (10-second interval)
    to keep the service status indicator up-to-date without full page
    reloads.

    Returns:
        JSON response: ``{"success": true, "data": {...}}`` on success,
        ``{"success": false, "error": "..."}`` on failure.
    """
    try:
        status = get_ovpn().get_status()
        return jsonify({"success": True, "data": status})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


# ═══════════════════════════════════════════════════════════════════════════
#  Error Handlers
# ═══════════════════════════════════════════════════════════════════════════

@app.errorhandler(404)
def not_found(e: Exception) -> tuple:
    """
    Handle 404 Not Found errors with a custom error page.

    Args:
        e: The Werkzeug HTTP exception.

    Returns:
        Rendered ``error.html`` with status code 404.
    """
    return render_template("error.html", code=404, message="页面不存在"), 404


@app.errorhandler(500)
def server_error(e: Exception) -> tuple:
    """
    Handle 500 Internal Server Error with a custom error page.

    Args:
        e: The Werkzeug HTTP exception.

    Returns:
        Rendered ``error.html`` with status code 500.
    """
    return render_template("error.html", code=500, message="服务器内部错误"), 500


# ═══════════════════════════════════════════════════════════════════════════
#  Application Entry Point
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Database is initialized at module import time (line 90) to support
    # both `python app.py` and `gunicorn app:app` (Docker).

    # Read runtime configuration from environment variables
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("DEBUG", "false").lower() == "true"

    print(f"[OpenVPN Admin] Starting on {host}:{port}")
    app.run(host=host, port=port, debug=debug)
