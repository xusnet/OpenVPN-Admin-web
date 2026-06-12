"""
OpenVPN Admin — OpenVPN Server Manager
=======================================
SSH-based remote management of OpenVPN server.
Supports: status, start, stop, restart, config read/write, key management, log reading.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime, timezone
from typing import Any

import paramiko


class OpenVPNManager:
    """Manages a remote OpenVPN server via SSH."""

    def __init__(self):
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

    # ── SSH helpers ─────────────────────────────────────────────────────

    def _ssh(self) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        kwargs = dict(hostname=self.host, port=self.port, username=self.user, timeout=15,
                      allow_agent=False, look_for_keys=False)
        if self.key_file and os.path.exists(self.key_file):
            kwargs["pkey"] = paramiko.RSAKey.from_private_key_file(self.key_file)
        else:
            kwargs["password"] = os.environ.get("OPENVPN_SSH_PASSWORD", "")
        client.connect(**kwargs)
        return client

    def _exec(self, command: str, timeout: int = 30, sudo: bool = False) -> tuple[str, str, int]:
        if sudo:
            command = f"sudo {command}"
        client = self._ssh()
        try:
            _, stdout, stderr = client.exec_command(command, timeout=timeout)
            out = stdout.read().decode("utf-8", errors="replace").strip()
            err = stderr.read().decode("utf-8", errors="replace").strip()
            code = stdout.channel.recv_exit_status()
            return out, err, code
        finally:
            client.close()

    # ── Service management ──────────────────────────────────────────────

    def get_status(self) -> dict:
        """Get OpenVPN service status."""
        out, err, code = self._exec(f"systemctl status {self.service_name} --no-pager -l", sudo=True)
        uptime_out, _, _ = self._exec("uptime")

        # Check if active
        active_out, _, active_code = self._exec(f"systemctl is-active {self.service_name}", sudo=True)
        is_active = "active" in active_out.lower()

        # Get connected clients
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
        out, err, code = self._exec(f"systemctl start {self.service_name}", sudo=True)
        time.sleep(2)
        active_out, _, _ = self._exec(f"systemctl is-active {self.service_name}", sudo=True)
        return {"success": code == 0, "output": out or err, "active": "active" in active_out.lower()}

    def stop(self) -> dict:
        out, err, code = self._exec(f"systemctl stop {self.service_name}", sudo=True)
        time.sleep(1)
        active_out, _, _ = self._exec(f"systemctl is-active {self.service_name}", sudo=True)
        return {"success": code == 0, "output": out or err, "active": "active" in active_out.lower()}

    def restart(self) -> dict:
        out, err, code = self._exec(f"systemctl restart {self.service_name}", sudo=True)
        time.sleep(3)
        active_out, _, _ = self._exec(f"systemctl is-active {self.service_name}", sudo=True)
        return {"success": code == 0, "output": out or err, "active": "active" in active_out.lower()}

    # ── Configuration ───────────────────────────────────────────────────

    def get_config(self) -> str:
        out, err, code = self._exec(f"cat {self.config_path}", sudo=True)
        if code != 0:
            raise RuntimeError(f"Failed to read config: {err}")
        return out

    def update_config(self, new_content: str) -> dict:
        """Write new server.conf and optionally restart."""
        # Backup first
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = f"{self.config_path}.bak.{timestamp}"
        self._exec(f"cp {self.config_path} {backup_path}", sudo=True)

        # Write new config via a temp file then mv (avoids partial writes)
        tmp_path = f"/tmp/openvpn-server.conf.{timestamp}"
        # Escape the content for echo/heredoc
        sftp_client = None
        client = self._ssh()
        try:
            sftp = client.open_sftp()
            with sftp.file(tmp_path, "w") as f:
                f.write(new_content)
            sftp.chmod(tmp_path, 0o644)
        finally:
            client.close()

        self._exec(f"mv {tmp_path} {self.config_path}", sudo=True)

        return {"success": True, "backup": backup_path}

    # ── Key management ──────────────────────────────────────────────────

    def list_certificates(self) -> list[dict]:
        """List all certificates from EasyRSA PKI index."""
        out, err, code = self._exec(f"cat {self.easyrsa_dir}/pki/index.txt", sudo=True)
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
                cn_match = re.search(r"/CN=([^\s/]+)", line)
                cn = cn_match.group(1) if cn_match else "unknown"
                status_map = {"V": "valid", "R": "revoked", "E": "expired"}
                certs.append({
                    "common_name": cn,
                    "status": status_map.get(flag, flag),
                    "expiry": expiry,
                    "serial": serial,
                })
        return certs

    def create_client(self, common_name: str) -> dict:
        """Create a new client certificate and generate .ovpn file."""
        # Build client cert
        cmd = f"cd {self.easyrsa_dir} && echo -e '\\n\\n\\n\\n\\n\\n' | ./easyrsa build-client-full {common_name} nopass"
        out, err, code = self._exec(cmd, timeout=60, sudo=True)
        if code != 0:
            return {"success": False, "error": err or out}

        # Generate .ovpn file
        ovpn_path = f"{self.client_dir}/{common_name}.ovpn"
        gen_cmd = f"""
CA_CERT=$(cat {self.easyrsa_dir}/pki/ca.crt)
CLIENT_CERT=$(sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' {self.easyrsa_dir}/pki/issued/{common_name}.crt)
CLIENT_KEY=$(cat {self.easyrsa_dir}/pki/private/{common_name}.key)
TLS_KEY=$(cat /etc/openvpn/server/ta.key 2>/dev/null || echo '')

cat > {ovpn_path} << 'OVPNEOF'
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
"""
        out2, err2, code2 = self._exec(gen_cmd, timeout=30, sudo=True)
        if code2 != 0:
            return {"success": False, "error": f"Cert built but ovpn generation failed: {err2}"}

        return {"success": True, "common_name": common_name, "ovpn_path": ovpn_path}

    def revoke_client(self, common_name: str) -> dict:
        """Revoke a client certificate."""
        out, err, code = self._exec(
            f"cd {self.easyrsa_dir} && echo 'yes' | ./easyrsa revoke {common_name}",
            timeout=30, sudo=True
        )
        if code != 0:
            return {"success": False, "error": err or out}

        # Update CRL
        crl_out, crl_err, crl_code = self._exec(
            f"cd {self.easyrsa_dir} && ./easyrsa gen-crl", timeout=30, sudo=True
        )

        return {
            "success": True,
            "common_name": common_name,
            "crl_updated": crl_code == 0,
            "output": out,
        }

    def download_client_config(self, common_name: str) -> bytes | None:
        """Download the .ovpn client config file content."""
        ovpn_path = f"{self.client_dir}/{common_name}.ovpn"
        client = self._ssh()
        try:
            sftp = client.open_sftp()
            try:
                with sftp.file(ovpn_path, "r") as f:
                    return f.read().encode("utf-8")
            except FileNotFoundError:
                return None
        finally:
            client.close()

    def get_client_config_base64(self, common_name: str) -> str | None:
        """Get client config as base64 string."""
        import base64
        content = self.download_client_config(common_name)
        if content:
            return base64.b64encode(content).decode()
        return None

    # ── Clients ─────────────────────────────────────────────────────────

    def list_clients(self) -> list[dict]:
        """Parse OpenVPN status log for connected clients."""
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

        clients = []
        in_section = False
        for line in raw.splitlines():
            line = line.strip()
            if line.startswith("Common Name"):
                in_section = True
                continue
            if line.startswith("ROUTING TABLE") or line.startswith("GLOBAL STATS"):
                break
            if not in_section or not line:
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 5:
                clients.append({
                    "common_name": parts[0],
                    "real_address": parts[1],
                    "bytes_received": parts[2],
                    "bytes_sent": parts[3],
                    "connected_since": parts[4],
                })
        return clients

    # ── Logs ────────────────────────────────────────────────────────────

    def get_logs(self, lines: int = 200) -> str:
        """Get recent OpenVPN server logs."""
        log_files = [
            f"{self.log_dir}/openvpn.log",
            f"{self.log_dir}/server.log",
            "/var/log/openvpn.log",
        ]
        for lf in log_files:
            out, _, code = self._exec(f"tail -n {lines} {lf}", sudo=True)
            if code == 0 and out.strip():
                return out

        # Fallback to journalctl
        out, _, _ = self._exec(f"journalctl -u {self.service_name} --no-pager -n {lines}", sudo=True)
        return out

    # ── Host info ───────────────────────────────────────────────────────

    def get_host_info(self) -> dict:
        df_out, _, _ = self._exec("df -h /")
        mem_out, _, _ = self._exec("free -m")
        ss_out, _, _ = self._exec("ss -tlnp | grep -E '1194|943|openvpn' || ss -tlnp | head -20")
        return {
            "disk": df_out,
            "memory": mem_out,
            "ports": ss_out,
        }
