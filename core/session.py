"""
SSH Session Handler.
Manages the full lifecycle of a single attacker connection:
connect → authenticate → shell → disconnect.
All events are emitted to both the funnel log (for Wazuh) and the
system log (for operators).
"""
import logging
import json
import datetime
from logging.handlers import RotatingFileHandler

import paramiko

from config.settings import (
    get_timestamp,
    SSH_BANNER, HOST_KEY_PATH,
    FUNNEL_LOG, CMD_AUDIT_LOG, SYSTEM_LOG,
    LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    AUTH_USER, AUTH_PASS,
)
from core.ssh_server import HoneypotServer
from core.command_engine import emulated_shell
from core.threat_engine import log_connection


# ── Logger factory ────────────────────────────────────────────────────────────

def _make_logger(name: str, path: str) -> logging.Logger:
    logger  = logging.getLogger(name)
    if logger.handlers:
        return logger   # already configured
    logger.setLevel(logging.INFO)
    h = RotatingFileHandler(path, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
    h.setFormatter(logging.Formatter("%(message)s"))
    logger.addHandler(h)
    return logger


funnel_logger = _make_logger("funnel",   FUNNEL_LOG)
cmd_logger    = _make_logger("commands", CMD_AUDIT_LOG)
sys_logger    = _make_logger("system",   SYSTEM_LOG)



# ── Anti-fingerprinting: match real OpenSSH 8.2p1 Ubuntu algorithm order ────
_REAL_KEX = (
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
)
_REAL_CIPHERS = (
    "chacha20-poly1305@openssh.com",
    "aes128-ctr", "aes192-ctr", "aes256-ctr",
    "aes128-gcm@openssh.com", "aes256-gcm@openssh.com",
)
_REAL_MACS = (
    "umac-64-etm@openssh.com", "umac-128-etm@openssh.com",
    "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com",
    "hmac-sha1-etm@openssh.com", "umac-64@openssh.com",
    "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-sha1",
)
_REAL_KEYS = (
    "rsa-sha2-512", "rsa-sha2-256", "ssh-rsa",
    "ecdsa-sha2-nistp256", "ssh-ed25519",
)
_REAL_COMPRESSION = ("none", "zlib@openssh.com")


def _apply_openssh_fingerprint(transport) -> None:
    """Rewrite paramiko algorithm lists to match OpenSSH 8.2p1 exactly."""
    try:
        opts = transport.get_security_options()
        # Only set algorithms that paramiko + local crypto supports
        supported_kex     = set(transport.get_security_options().kex)
        supported_ciphers = set(transport.get_security_options().ciphers)
        opts.kex     = tuple(k for k in _REAL_KEX     if k in supported_kex)     or _REAL_KEX[:4]
        opts.ciphers = tuple(c for c in _REAL_CIPHERS if c in supported_ciphers) or _REAL_CIPHERS[:3]
        try:
            opts.digests     = _REAL_MACS
            opts.key_types   = _REAL_KEYS
            opts.compression = _REAL_COMPRESSION
        except (AttributeError, ValueError):
            pass  # older paramiko versions — skip gracefully
    except Exception as e:
        sys_logger.warning(json.dumps({"event": "fingerprint_warn", "msg": str(e)}))


# ── Session handler ───────────────────────────────────────────────────────────

def handle_client(
    client_sock,
    addr,
    username: str = AUTH_USER,
    password: str = AUTH_PASS,
    db=None,
):
    """
    Handle one inbound SSH connection.

    Parameters
    ----------
    client_sock : socket
    addr        : (ip, port) tuple
    username    : expected username (empty = accept all)
    password    : expected password (empty = accept all)
    db          : DatabaseManager instance or None
    """
    client_ip = addr[0]
    port      = addr[1]

    _log_event("CONNECT", client_ip, port=port)

    transport = None
    try:
        # Load or generate host key
        try:
            host_key = paramiko.RSAKey(filename=HOST_KEY_PATH)
        except FileNotFoundError:
            host_key = paramiko.RSAKey.generate(2048)
            host_key.write_private_key_file(HOST_KEY_PATH)
            sys_logger.info(json.dumps({
                "event": "host_key_generated", "path": HOST_KEY_PATH,
            }))

        transport = paramiko.Transport(client_sock)
        transport.local_version = SSH_BANNER
        transport.add_server_key(host_key)

        server = HoneypotServer(client_ip, username, password)
        transport.start_server(server=server)

        channel = transport.accept(30)
        if channel is None:
            _log_event("NO_CHANNEL", client_ip)
            return

        server.event.wait(10)

        # Record connection in DB and push to dashboard
        if db:
            db.insert_connection(client_ip, port)
        log_connection(client_ip, port)

        emulated_shell(channel, client_ip, cmd_logger, db=db)

    except Exception as exc:
        _log_event("ERROR", client_ip, error=str(exc))
    finally:
        if transport:
            try:
                transport.close()
            except Exception:
                pass
        try:
            client_sock.close()
        except Exception:
            pass
        _log_event("DISCONNECT", client_ip)
        if db:
            db.close_connection(client_ip)


def _log_event(event: str, ip: str, **kwargs):
    """Emit a structured JSON log entry to the funnel log."""
    entry = {
        "timestamp":  get_timestamp(),
        "event_type": f"session_{event.lower()}",
        "source_ip":  ip,
        **kwargs,
    }
    funnel_logger.info(json.dumps(entry))
    sys_logger.info(json.dumps(entry))
