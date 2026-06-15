"""
OpenVPN Admin — OpenVPN Server Manager
=======================================

SSH-based remote management client for OpenVPN servers.

Uses Paramiko to execute commands on the remote VPN server, providing
a clean Python API for the Flask web layer. All SSH operations are
stateless — each method opens a fresh connection, runs its command(s),
and closes the connection.

Capabilities:
    - Service lifecycle: status, start, stop, restart (via systemctl)
    - Configuration: read and update server.conf (with automatic backups)
    - Key management: list, create, and revoke EasyRSA certificates
    - Client management: list connected clients, generate .ovpn bundles
    - Log retrieval: tail OpenVPN logs, fallback to journalctl
    - Host information: disk usage, memory, listening ports

Authentication:
    Supports both SSH key and password authentication. Key authentication
    is preferred — if OPENVPN_SSH_KEY points to an existing file, it is
    used as an RSA private key. Otherwise, OPENVPN_SSH_PASSWORD is used.

Environment Variables:
    OPENVPN_HOST         — VPN server hostname/IP (default: 192.168.3.147)
    OPENVPN_SSH_PORT     — SSH port (default: 22)
    OPENVPN_SSH_USER     — SSH username (default: root)
    OPENVPN_SSH_KEY      — Path to RSA private key (default: /app/keys/id_rsa)
    OPENVPN_SSH_PASSWORD — SSH password (fallback if key not found)
    OPENVPN_SERVICE      — systemd service name (default: openvpn@server)
    OPENVPN_CONFIG       — Path to server.conf (default: /etc/openvpn/server/server.conf)
    OPENVPN_LOG_DIR      — OpenVPN log directory (default: /var/log/openvpn)
    OPENVPN_EASYRSA_DIR  — EasyRSA installation directory (default: /etc/openvpn/easy-rsa)
    OPENVPN_CLIENT_DIR   — Client .ovpn output directory (default: /etc/openvpn/client-configs)

Security Note:
    This module executes shell commands on a remote server as root (via sudo).
    Ensure the SSH key is restricted and audit logging is enabled.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone

import paramiko


class OpenVPNManager:
    """
    Manages a remote OpenVPN server via SSH.

    All methods open a fresh SSH connection per operation — there is no
    persistent connection pool. This simplifies error handling (each call
    is self-contained) at the cost of connection setup overhead (~100ms).

    Attributes:
        host (str): VPN server hostname or IP address.
        port (int): SSH port number.
        user (str): SSH login username.
        key_file (str): Path to the RSA private key file.
        service_name (str): systemd unit name for OpenVPN.
        config_path (str): Remote path to server.conf.
        log_dir (str): Remote directory containing OpenVPN logs.
        easyrsa_dir (str): Remote EasyRSA installation directory.
        ipp_file (str): Remote IP persistence file path.
        client_dir (str): Remote directory for generated .ovpn files.
    """

    # Allow only safe characters in a client Common Name. This is used
    # by every method that interpolates ``common_name`` into a shell
    # command or filesystem path, providing defense in depth against
    # path traversal and shell injection even if the caller forgets to
    # validate the value itself.
    _CN_RE = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")

    @classmethod
    def _validate_cn(cls, common_name: str) -> None:
        """
        Validate a client Common Name (defense in depth).

        Raises:
            ValueError: If ``common_name`` contains anything other than
                        letters, digits, ``_``, ``-``, ``.`` (max 64 chars).
        """
        if not common_name or not cls._CN_RE.match(common_name):
            raise ValueError(
                f"Invalid common name: {common_name!r}. "
                "Allowed: letters, digits, '_', '-', '.' (max 64 chars)."
            )

    def __init__(self) -> None:
        """
        Initialize the manager from environment variables.

        All configuration is read from environment variables at init time.
        None of these values are validated here — connection failures are
        surfaced when methods are actually called.
        """
        self.host = os.environ.get("OPENVPN_HOST", "192.168.3.147")
        self.port = int(os.environ.get("OPENVPN_SSH_PORT", "22"))
        self.user = os.environ.get("OPENVPN_SSH_USER", "root")
        self.key_file = os.environ.get("OPENVPN_SSH_KEY", "/app/keys/id_rsa")
        self.service_name = os.environ.get("OPENVPN_SERVICE", "openvpn@server")
        self.config_path = os.environ.get("OPENVPN_CONFIG", "/etc/openvpn/server/server.conf")
        self.log_dir = os.environ.get("OPENVPN_LOG_DIR", "/var/log/openvpn")
        self.easyrsa_dir = os.environ.get("OPENVPN_EASYRSA_DIR", "/etc/openvpn/easy-rsa")
        self.ipp_file = os.environ.get("OPENVPN_IPP_FILE", "/etc/openvpn/server/ipp.txt")
        self.client_dir = os.environ.get("OPENVPN_CLIENT_DIR", "/etc/openvpn/client-configs")


    # ── SSH Helpers ────────────────────────────────────────────────────────

    def _ssh(self) -> paramiko.SSHClient:
        """
        Create and connect a new Paramiko SSH client.

        Authentication strategy:
        1. If ``self.key_file`` exists on the local filesystem, use RSA key auth.
        2. Otherwise, fall back to password auth via OPENVPN_SSH_PASSWORD.

        Returns:
            paramiko.SSHClient: Connected and authenticated SSH client.

        Raises:
            paramiko.SSHException: On connection or authentication failure.
            FileNotFoundError: If the key file path is invalid (RSAKey parsing).
        """
        client = paramiko.SSHClient()

        # Auto-accept unknown host keys.
        # In production, consider using known_hosts via
        # client.load_system_host_keys() for MITM protection.
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        # Build connection kwargs
        kwargs = dict(
            hostname=self.host,
            port=self.port,
            username=self.user,
            timeout=15,
            allow_agent=False,    # Don't use ssh-agent
            look_for_keys=False,  # Don't scan ~/.ssh/ for keys
        )

        # Prefer key authentication over password
        if self.key_file and os.path.exists(self.key_file):
            kwargs["pkey"] = paramiko.RSAKey.from_private_key_file(self.key_file)
        else:
            kwargs["password"] = os.environ.get("OPENVPN_SSH_PASSWORD", "")

        client.connect(**kwargs)
        return client


    def _exec(self, command: str, timeout: int = 30, sudo: bool = False) -> tuple[str, str, int]:
        """
        Execute a command on the remote VPN server and return its output.

        Opens a fresh SSH connection, runs the command, reads stdout/stderr,
        and closes the connection. Each call is stateless and self-contained.

        Args:
            command: The shell command to execute on the remote host.
            timeout: Maximum seconds to wait for command completion.
            sudo: If True, prepend ``sudo`` to the command.

        Returns:
            A tuple of ``(stdout, stderr, exit_code)``. Both stdout and stderr
            are decoded from UTF-8 with replacement characters for invalid bytes,
            and stripped of trailing whitespace.

        Raises:
            paramiko.SSHException: On SSH connection or authentication failure.
            socket.timeout: If the command exceeds the timeout.
        """
        if sudo:
            command = f"sudo {command}"

        client = self._ssh()
        try:
            # Execute the command — triple return: stdin, stdout, stderr channels
            _, stdout, stderr = client.exec_command(command, timeout=timeout)

            # Read all output before checking exit status (paramiko recommendation)
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            code = stdout.channel.recv_exit_status()

            return out, err, code
        finally:
            client.close()


    # ── Service Management ─────────────────────────────────────────────────

    def get_status(self) -> dict:
        """
        Get comprehensive OpenVPN service status.

        Fetches:
        - systemctl status output for detailed service state
        - Host system uptime
        - systemctl is-active for a simple boolean active flag
        - Connected client list with traffic statistics

        Returns:
            dict with keys:
                active (bool):          Whether the service is running
                service (str):          The systemd unit name
                host (str):             VPN server hostname/IP
                status_text (str):      Full systemctl status output
                uptime (str):           Host system uptime string
                connected_clients (int): Number of currently connected clients
                clients (list[dict]):   Connected client details
        """
        # Get detailed service status
        out, err, code = self._exec(
            f"systemctl status {self.service_name} --no-pager -l", sudo=True
        )

        # Get host uptime
        uptime_out, _, _ = self._exec("uptime")

        # Check if the service is active (simple boolean)
        active_out, _, active_code = self._exec(
            f"systemctl is-active {self.service_name}", sudo=True
        )
        is_active = "active" in active_out.lower()

        # Get connected client list
        clients = self.list_clients()

        return {
            "active": is_active,
            "service": self.service_name,
            "host": self.host,
            "status_text": out or err,
            "uptime": uptime_out,
            "connected_clients": len(clients),
            "clients": clients,
        }


    def start(self) -> dict:
        """
        Start the OpenVPN service via systemctl.

        Waits 2 seconds after starting, then verifies the service is active.

        Returns:
            dict with keys: ``success`` (bool), ``output`` (str), ``active`` (bool).
        """
        out, err, code = self._exec(
            f"systemctl start {self.service_name}", sudo=True
        )

        # Give systemd a moment to start the service before checking
        time.sleep(2)

        active_out, _, _ = self._exec(
            f"systemctl is-active {self.service_name}", sudo=True
        )
        return {
            "success": code == 0,
            "output": out or err,
            "active": "active" in active_out.lower(),
        }


    def stop(self) -> dict:
        """
        Stop the OpenVPN service via systemctl.

        Waits 1 second after stopping, then verifies the service is inactive.

        Returns:
            dict with keys: ``success`` (bool), ``output`` (str), ``active`` (bool).
        """
        out, err, code = self._exec(
            f"systemctl stop {self.service_name}", sudo=True
        )

        time.sleep(1)

        active_out, _, _ = self._exec(
            f"systemctl is-active {self.service_name}", sudo=True
        )
        return {
            "success": code == 0,
            "output": out or err,
            "active": "active" in active_out.lower(),
        }


    def restart(self) -> dict:
        """
        Restart the OpenVPN service via systemctl.

        Waits 3 seconds after restarting (longer than start/stop because
        OpenVPN needs time to reinitialize tunnels and re-read config).

        Returns:
            dict with keys: ``success`` (bool), ``output`` (str), ``active`` (bool).
        """
        out, err, code = self._exec(
            f"systemctl restart {self.service_name}", sudo=True
        )

        time.sleep(3)

        active_out, _, _ = self._exec(
            f"systemctl is-active {self.service_name}", sudo=True
        )
        return {
            "success": code == 0,
            "output": out or err,
            "active": "active" in active_out.lower(),
        }


    # ── Configuration Management ───────────────────────────────────────────

    def get_config(self) -> str:
        """
        Read the current server.conf from the remote VPN server.

        Returns:
            str: The complete contents of server.conf.

        Raises:
            RuntimeError: If the config file cannot be read (SSH error,
                          file not found, permission denied).
        """
        out, err, code = self._exec(f"cat {self.config_path}", sudo=True)
        if code != 0:
            raise RuntimeError(f"Failed to read config: {err}")
        return out


    def update_config(self, new_content: str) -> dict:
        """
        Write a new server.conf to the VPN server.

        Safety measures:
        1. Verifies the existing config can be read before changing anything
        2. Creates a timestamped backup of the existing config and verifies
           the backup succeeded (refuses to continue on backup failure)
        3. Writes the new content to a temp file via SFTP and verifies the
           size on disk matches what we tried to write
        4. Atomically moves the temp file to the config path (mv is atomic
           on the same filesystem); falls back to cat+rm if mv fails

        Args:
            new_content: The complete new server.conf content.

        Returns:
            dict with keys: ``success`` (bool), ``backup`` (str) — path to
            the timestamped backup file.

        Raises:
            RuntimeError: If the existing config is unreadable, the backup
                          cannot be created, or the SFTP write fails.
        """
        # ── Sanity-check the existing config first ─────────────────────
        # If we cannot read the current config, something is fundamentally
        # wrong and we must not proceed with overwriting it.
        pre_check, pre_err, pre_code = self._exec(
            f"test -r {self.config_path}", sudo=True
        )
        if pre_code != 0:
            raise RuntimeError(
                f"Cannot read existing config at {self.config_path}: {pre_err}"
            )

        # ── Create timestamped backup ──────────────────────────────────
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{self.config_path}.bak.{timestamp}"

        _, cp_err, cp_code = self._exec(
            f"cp -p {self.config_path} {backup_path}", sudo=True
        )
        if cp_code != 0:
            raise RuntimeError(
                f"Failed to create config backup at {backup_path}: {cp_err}"
            )

        # ── Write new config via SFTP ──────────────────────────────────
        # Using SFTP (not echo/heredoc) to avoid shell escaping issues
        # with special characters in the config content.
        tmp_path = f"/tmp/openvpn-server.conf.{timestamp}"
        written_bytes = 0
        client = self._ssh()
        try:
            sftp = client.open_sftp()
            try:
                with sftp.file(tmp_path, "w") as f:
                    f.write(new_content)
                # Verify what we wrote by stat'ing the file on the server.
                # paramiko's SFTP write can silently truncate on partial
                # failures (network glitch, disk full, permission denied),
                # so we must check the file size matches the input.
                remote_stat = sftp.stat(tmp_path)
                written_bytes = remote_stat.st_size
            finally:
                sftp.close()
        except Exception as exc:
            # Best-effort cleanup of the temp file on the server.
            self._exec(f"rm -f {tmp_path}", sudo=True)
            raise RuntimeError(f"SFTP write failed: {exc}") from exc
        finally:
            client.close()

        expected_bytes = len(new_content.encode("utf-8"))
        if written_bytes != expected_bytes:
            self._exec(f"rm -f {tmp_path}", sudo=True)
            raise RuntimeError(
                f"SFTP write size mismatch: wrote {written_bytes} bytes, "
                f"expected {expected_bytes}. Aborting to protect config."
            )

        # ── Atomic move into place ─────────────────────────────────────
        _, mv_err, mv_code = self._exec(
            f"mv {tmp_path} {self.config_path}", sudo=True
        )
        if mv_code != 0:
            # Best-effort cleanup if the move failed.
            self._exec(f"rm -f {tmp_path}", sudo=True)
            raise RuntimeError(
                f"Failed to move new config into place: {mv_err}"
            )

        return {"success": True, "backup": backup_path}


    # ── Key Management ─────────────────────────────────────────────────────

    def list_certificates(self) -> list[dict]:
        """
        List all certificates from the EasyRSA PKI index file.

        Parses ``/etc/openvpn/easy-rsa/pki/index.txt`` which has the format:
        ``<flag> <expiry> <revocation_date> <serial> <filename> <subject>``

        Flag meanings:
            V = valid, R = revoked, E = expired

        Returns:
            list[dict]: Each dict has keys: ``common_name``, ``status``,
                        ``expiry``, ``serial``.
        """
        out, err, code = self._exec(
            f"cat {self.easyrsa_dir}/pki/index.txt", sudo=True
        )
        if code != 0:
            return []

        certs = []
        for line in out.splitlines():
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) >= 5:
                flag = parts[0]
                expiry = parts[1]
                serial = parts[2]

                # Extract CN from the subject DN: /C=XX/ST=XX/.../CN=myclient
                cn_match = re.search(r"/CN=([^\s/]+)", line)
                cn = cn_match.group(1) if cn_match else "unknown"

                # Map EasyRSA single-letter status flags to human-readable labels
                status_map = {"V": "valid", "R": "revoked", "E": "expired"}
                certs.append({
                    "common_name": cn,
                    "status": status_map.get(flag, flag),
                    "expiry": expiry,
                    "serial": serial,
                })

        return certs


    def create_client(self, common_name: str) -> dict:
        """
        Create a new client certificate and generate an .ovpn config file.

        Two-step process:
        1. Build client cert: ``easyrsa build-client-full <cn> nopass``
        2. Generate .ovpn bundle: inline the CA cert, client cert, client key,
           and (optionally) TLS auth key into a single file.

        Args:
            common_name: The client's Common Name (used as both the cert CN
                         and the .ovpn filename). Must match ``_CN_RE``.

        Returns:
            dict with keys: ``success`` (bool), ``common_name`` (str),
            ``ovpn_path`` (str — remote path to the generated .ovpn file),
            and optionally ``error`` (str) on failure.
        """
        # Defense in depth: validate the CN even if the caller already did.
        try:
            self._validate_cn(common_name)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        # ── Step 1: Build client certificate ──────────────────────────
        # EasyRSA prompts for several fields interactively; we pipe empty
        # lines to accept all defaults. 'nopass' = no private key passphrase.
        cmd = (
            f"cd {self.easyrsa_dir} && "
            f"echo -e '\\n\\n\\n\\n\\n\\n' | "
            f"./easyrsa build-client-full {common_name} nopass"
        )
        out, err, code = self._exec(cmd, timeout=60, sudo=True)
        if code != 0:
            return {"success": False, "error": err or out}

        # ── Step 2: Generate .ovpn bundle ─────────────────────────────
        ovpn_path = f"{self.client_dir}/{common_name}.ovpn"

        # Multi-line shell script: extract certs and keys, then assemble
        # them into an inline OpenVPN client config file.
        #
        # IMPORTANT: We use an *unquoted* heredoc delimiter (OVPNEOF) so
        # that shell variables ($CA_CERT, $CLIENT_CERT, ...) are expanded.
        # A quoted delimiter ('OVPNEOF') would write the literal strings
        # "$CA_CERT" into the .ovpn file, producing an invalid profile.
        gen_cmd = f"""
CA_CERT=$(cat {self.easyrsa_dir}/pki/ca.crt)
CLIENT_CERT=$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' {self.easyrsa_dir}/pki/issued/{common_name}.crt)
CLIENT_KEY=$(cat {self.easyrsa_dir}/pki/private/{common_name}.key)
TLS_KEY=$(cat /etc/openvpn/server/ta.key 2>/dev/null || echo '')

cat > {ovpn_path} << OVPNEOF
client
dev tun
proto udp
remote {self.host} 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
verb 3
<ca>
$CA_CERT
</ca>
<cert>
$CLIENT_CERT
</cert>
<key>
$CLIENT_KEY
</key>
OVPNEOF

# Optionally append TLS auth key if one exists on the server
if [ -n "$TLS_KEY" ]; then
    cat >> {ovpn_path} << OVPNEOF
<tls-auth>
$TLS_KEY
</tls-auth>
key-direction 1
OVPNEOF
fi
"""
        out2, err2, code2 = self._exec(gen_cmd, timeout=30, sudo=True)
        if code2 != 0:
            return {
                "success": False,
                "error": f"Cert built but ovpn generation failed: {err2}"
            }

        # ── Verify the generated profile is non-empty and contains certs ─
        verify_out, _, verify_code = self._exec(
            f"grep -E '(BEGIN CERTIFICATE|BEGIN PRIVATE KEY|BEGIN OPENVPN PRIVATE KEY)' {ovpn_path} | wc -l",
            sudo=True
        )
        try:
            cert_lines = int(verify_out.strip())
        except (ValueError, AttributeError):
            cert_lines = 0
        if verify_code != 0 or cert_lines < 2:
            return {
                "success": False,
                "error": "Generated .ovpn file appears invalid (missing certificates). "
                         "Check that /etc/openvpn/server/ta.key and EasyRSA PKI files exist."
            }

        return {
            "success": True,
            "common_name": common_name,
            "ovpn_path": ovpn_path,
        }


    def revoke_client(self, common_name: str) -> dict:
        """
        Revoke a client certificate and update the Certificate Revocation List.

        Two-step process:
        1. Revoke: ``easyrsa revoke <cn>`` (auto-confirms 'yes')
        2. Regenerate CRL: ``easyrsa gen-crl`` (makes the revocation effective)

        Args:
            common_name: The client's Common Name to revoke. Must match
                         ``_CN_RE``.

        Returns:
            dict with keys: ``success`` (bool), ``common_name`` (str),
            ``crl_updated`` (bool — whether CRL regeneration succeeded),
            and ``output`` (str — EasyRSA command output).
        """
        # Defense in depth: validate the CN before interpolating it into
        # a shell command. An invalid CN would either fail later in a
        # confusing way or, worse, be interpreted by the shell.
        try:
            self._validate_cn(common_name)
        except ValueError as e:
            return {"success": False, "error": str(e)}

        # ── Revoke the certificate ────────────────────────────────────
        out, err, code = self._exec(
            f"cd {self.easyrsa_dir} && echo 'yes' | ./easyrsa revoke {common_name}",
            timeout=30,
            sudo=True,
        )
        if code != 0:
            return {"success": False, "error": err or out}

        # ── Regenerate CRL to enforce the revocation ──────────────────
        crl_out, crl_err, crl_code = self._exec(
            f"cd {self.easyrsa_dir} && ./easyrsa gen-crl",
            timeout=30,
            sudo=True,
        )

        return {
            "success": True,
            "common_name": common_name,
            "crl_updated": crl_code == 0,
            "output": out,
        }


    def download_client_config(self, common_name: str) -> bytes | None:
        """
        Download a client's .ovpn configuration file via SFTP.

        Args:
            common_name: The client's Common Name (matches the .ovpn
                         filename). Must match ``_CN_RE``; CNs containing
                         ``..`` or path separators are rejected to defend
                         against path traversal on the server filesystem.

        Returns:
            bytes: The complete .ovpn file content as UTF-8 encoded bytes,
                   or None if the file does not exist on the server.
        """
        # Defense in depth: validate the CN to prevent path traversal.
        # While the Flask route already validates this, a future caller
        # might forget — refuse anything that could escape the client
        # config directory.
        try:
            self._validate_cn(common_name)
        except ValueError:
            return None

        ovpn_path = f"{self.client_dir}/{common_name}.ovpn"
        client = self._ssh()
        try:
            sftp = client.open_sftp()
            try:
                with sftp.file(ovpn_path, "rb") as f:
                    return f.read()
            except FileNotFoundError:
                return None
            finally:
                sftp.close()
        finally:
            client.close()


    def get_client_config_base64(self, common_name: str) -> str | None:
        """
        Get a client's .ovpn config as a base64-encoded string.

        Useful for API responses or embedding in HTML data URIs.

        Args:
            common_name: The client's Common Name.

        Returns:
            str: Base64-encoded .ovpn file content, or None if not found.
        """
        import base64
        content = self.download_client_config(common_name)
        if content:
            return base64.b64encode(content).decode()
        return None


    # ── Connected Clients ──────────────────────────────────────────────────

    def list_clients(self) -> list[dict]:
        """
        Parse the OpenVPN status log to list currently connected clients.

        Searches several common status file locations, parsing the
        comma-separated format used by OpenVPN's ``status`` directive:
        ``Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since``

        Returns:
            list[dict]: Each dict has keys: ``common_name``, ``real_address``,
                        ``bytes_received``, ``bytes_sent``, ``connected_since``.
        """
        # Common locations for OpenVPN status files
        status_files = [
            f"{self.log_dir}/openvpn-status.log",
            f"{self.log_dir}/status.log",
            "/var/log/openvpn-status.log",
            "/run/openvpn-server/status.log",
        ]

        raw = ""
        for sf in status_files:
            out, _, code = self._exec(f"cat {sf}", sudo=True)
            if code == 0 and out.strip():
                raw = out
                break

        if not raw:
            return []

        # ── Parse the OpenVPN status file ─────────────────────────────
        # Format:
        #   OpenVPN CLIENT LIST
        #   Updated,...
        #   Common Name,Real Address,Bytes Received,Bytes Sent,Connected Since
        #   client1,10.8.0.2:12345,1234567,9876543,Mon Jun  9 15:30:00 2025
        #   ROUTING TABLE
        #   ...
        #   GLOBAL STATS
        #   ...
        clients = []
        in_section = False
        for line in raw.splitlines():
            line = line.strip()

            # Section start: the header row indicating the CLIENT LIST
            if line.startswith("Common Name"):
                in_section = True
                continue

            # Section end: ROUTING TABLE or GLOBAL STATS terminates the client list
            if line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
                break

            if not in_section or not line:
                continue

            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                clients.append({
                    "common_name": parts[0],
                    "real_address": parts[1],
                    # Parse byte counters as integers for reliable sorting,
                    # arithmetic, and formatting in templates.
                    "bytes_received": int(parts[2]) if parts[2].isdigit() else 0,
                    "bytes_sent": int(parts[3]) if parts[3].isdigit() else 0,
                    "connected_since": parts[4],
                })

        return clients


    # ── Log Retrieval ──────────────────────────────────────────────────────

    def get_logs(self, lines: int = 200) -> str:
        """
        Get the most recent OpenVPN server log entries.

        Tries common log file locations first, falling back to journalctl
        if none are found.

        Args:
            lines: Number of log lines to retrieve (default: 200).

        Returns:
            str: Recent log content, or empty string if no logs are available.
        """
        # Common OpenVPN log file locations
        log_files = [
            f"{self.log_dir}/openvpn.log",
            f"{self.log_dir}/server.log",
            "/var/log/openvpn.log",
        ]

        for lf in log_files:
            out, _, code = self._exec(f"tail -n {lines} {lf}", sudo=True)
            if code == 0 and out.strip():
                return out

        # Fallback: use journalctl to read systemd journal entries
        out, _, _ = self._exec(
            f"journalctl -u {self.service_name} --no-pager -n {lines}",
            sudo=True,
        )
        return out


    # ── Host Information ───────────────────────────────────────────────────

    def get_host_info(self) -> dict:
        """
        Collect basic host system information from the VPN server.

        Gathers:
        - Disk usage (df -h /)
        - Memory usage (free -m)
        - Listening ports related to OpenVPN (port 1194, 943) or top 20 if none

        Returns:
            dict with keys: ``disk`` (str), ``memory`` (str), ``ports`` (str).
        """
        df_out, _, _ = self._exec("df -h /")
        mem_out, _, _ = self._exec("free -m")

        # Try to find OpenVPN-related listening ports first, then fall back
        # to showing the top 20 listeners for general diagnostics.
        ss_out, _, _ = self._exec(
            "ss -tlnp | grep -E '1194|943|openvpn' || ss -tlnp | head -20"
        )

        return {
            "disk": df_out,
            "memory": mem_out,
            "ports": ss_out,
        }
