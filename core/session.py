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
_IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
def _now_ist(): return datetime.datetime.now(_IST).isoformat(timespec="seconds")
from logging.handlers import RotatingFileHandler

import paramiko

from config.settings import (
    SSH_BANNER, HOST_KEY_PATH,
    FUNNEL_LOG, CMD_AUDIT_LOG, SYSTEM_LOG,
    LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    AUTH_USER, AUTH_PASS,
)
from core.ssh_server import HoneypotServer
from core.command_engine import emulated_shell


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

        # Record connection in DB
        if db:
            db.insert_connection(client_ip, port)

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
        "timestamp":  _now_ist(),
        "event_type": f"session_{event.lower()}",
        "source_ip":  ip,
        **kwargs,
    }
    funnel_logger.info(json.dumps(entry))
    sys_logger.info(json.dumps(entry))
