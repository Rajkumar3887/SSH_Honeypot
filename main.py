#!/usr/bin/env python3
"""
SSH Honeypot – Application Entry Point
=======================================
Usage:
    python main.py [--host HOST] [--port PORT] [--user USER] [--pass PASS]
                   [--open]            # open honeypot (accept any credentials)
                   [--no-db]           # disable SQLite logging
                   [--wazuh-host HOST] # enable real-time syslog to Wazuh manager
"""
import argparse
import os
import socket
import sys
import threading
import logging
import json
import datetime
from logging.handlers import RotatingFileHandler

from config.settings import (
    BIND_HOST, BIND_PORT, AUTH_USER, AUTH_PASS,
    LOG_DIR, SYSTEM_LOG, LOG_MAX_BYTES, LOG_BACKUP_COUNT,
    DB_ENABLED, DB_PATH,
)
from core.session import handle_client
from wazuh import WazuhIntegration


# ── Ensure log directory exists ───────────────────────────────────────────────
os.makedirs(LOG_DIR, exist_ok=True)

# ── System logger ─────────────────────────────────────────────────────────────
_sys = logging.getLogger("system")
if not _sys.handlers:
    _sys.setLevel(logging.INFO)
    _h = RotatingFileHandler(SYSTEM_LOG, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
    _h.setFormatter(logging.Formatter("%(message)s"))
    _sys.addHandler(_h)

# Also echo to stdout
_stdout = logging.StreamHandler(sys.stdout)
_stdout.setFormatter(logging.Formatter("%(asctime)s | %(message)s"))
_sys.addHandler(_stdout)


# ── Honeypot entry point ──────────────────────────────────────────────────────

def start_honeypot(
    host: str     = BIND_HOST,
    port: int     = BIND_PORT,
    username: str = AUTH_USER,
    password: str = AUTH_PASS,
    db=None,
    wazuh: WazuhIntegration = None,
):
    """Bind the SSH listener and spawn a thread per connection."""

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
    except PermissionError:
        print(f"[!] Cannot bind to port {port}. Try: sudo python main.py")
        sys.exit(1)

    sock.listen(100)

    mode = "open (log-all)" if not username else "credential-enforced"
    _sys.info(json.dumps({
        "event": "honeypot_start",
        "host": host, "port": port, "mode": mode,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
    }))
    print(f"[*] SSH honeypot listening on {host}:{port}  [{mode}]")
    print(f"[*] Logs → {LOG_DIR}/")
    if db:
        print(f"[*] Database → {DB_PATH}")
    if wazuh and wazuh._syslog_host:
        print(f"[*] Wazuh syslog → {wazuh._syslog_host}:{wazuh._syslog_port}")
    print("[*] Press Ctrl+C to stop.\n")

    while True:
        try:
            client_sock, addr = sock.accept()
            t = threading.Thread(
                target=handle_client,
                args=(client_sock, addr, username, password, db),
                daemon=True,
            )
            t.start()
        except KeyboardInterrupt:
            print("\n[*] Shutting down honeypot.")
            _sys.info(json.dumps({
                "event": "honeypot_stop",
                "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            }))
            break
        except Exception as exc:
            print(f"[!] Accept error: {exc}")

    sock.close()
    if db:
        db.close()
    if wazuh:
        wazuh.close()


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Enterprise SSH Honeypot")
    parser.add_argument("--host",       default=BIND_HOST,  help="Bind address")
    parser.add_argument("--port",       default=BIND_PORT,  type=int, help="Bind port")
    parser.add_argument("--user",       default=AUTH_USER,  help="Expected username")
    parser.add_argument("--pass",       dest="password", default=AUTH_PASS, help="Expected password")
    parser.add_argument("--open",       action="store_true", help="Open honeypot – accept all creds")
    parser.add_argument("--no-db",      action="store_true", help="Disable SQLite logging")
    parser.add_argument("--wazuh-host", default=None, help="Wazuh manager syslog IP")
    parser.add_argument("--wazuh-port", default=514,  type=int, help="Wazuh syslog port (default 514)")
    parser.add_argument("--wazuh-proto",default="udp", help="Wazuh syslog protocol: udp or tcp")
    parser.add_argument("--dashboard",      action="store_true", help="Start web dashboard on port 5000") # added taki ek hi command me chal jaye 
    parser.add_argument("--dashboard-port", default=5000, type=int, help="Dashboard port (default 5000)") # added taki user dashboard ka port bhi specify kar sake
    args = parser.parse_args()

    username = "" if args.open else args.user
    password = "" if args.open else args.password

    # Database
    db = None
    if not args.no_db and DB_ENABLED:
        from database.db import DatabaseManager
        db = DatabaseManager()

    # Wazuh
    wazuh = WazuhIntegration(
        syslog_host=args.wazuh_host,
        syslog_port=args.wazuh_port,
        syslog_proto=args.wazuh_proto,
    )

    # Dashboard              # added dashboard start hone ke sath hi dashboard bhi start ho jaye, taki user ko alag se command na chalani pade
    if args.dashboard:
        import threading
        from web.app import start_dashboard
        dash_thread = threading.Thread(
            target=start_dashboard,
            kwargs={"host": "0.0.0.0", "port": args.dashboard_port},
            daemon=True,
        )
        dash_thread.start()

    start_honeypot(
        host=args.host,
        port=args.port,
        username=username,
        password=password,
        db=db,
        wazuh=wazuh,
    )


if __name__ == "__main__":
    main()
