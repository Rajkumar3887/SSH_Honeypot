"""
Paramiko SSH Server Interface.
Handles channel negotiation and authentication against the honeypot.
"""
import threading
import time
import random
import logging
import json
import datetime
import hashlib
from collections import defaultdict

import paramiko

from config.settings import FUNNEL_LOG, LOG_MAX_BYTES, LOG_BACKUP_COUNT, get_timestamp
from core.threat_engine import log_auth_event
from logging.handlers import RotatingFileHandler

# ── Funnel logger (shared with session.py via name) ───────────────────────────
funnel_logger = logging.getLogger("funnel")

# ── IP-based rate limiting ────────────────────────────────────────────────────
_auth_attempts: dict[str, list] = defaultdict(list)
_auth_lock = threading.Lock()
AUTH_RATE_LIMIT = 10   # Max attempts per window
AUTH_WINDOW     = 60   # Window in seconds


def _check_rate_limit(ip: str) -> bool:
    """Return False if IP has exceeded auth rate limit, True otherwise."""
    current_time = time.time()
    with _auth_lock:
        # Remove attempts outside the window
        _auth_attempts[ip] = [t for t in _auth_attempts[ip]
                               if current_time - t < AUTH_WINDOW]
        if len(_auth_attempts[ip]) >= AUTH_RATE_LIMIT:
            return False   # Rate limited
        _auth_attempts[ip].append(current_time)
        return True


def _hash_password(password: str) -> str:
    """Return a short SHA-256 hash of the password for safe logging."""
    return hashlib.sha256(password.encode()).hexdigest()[:16]


class HoneypotServer(paramiko.ServerInterface):
    """
    Paramiko server interface that:
    * Accepts only password auth
    * Logs every credential attempt (passwords are HASHED, never plaintext)
    * Artificially slows down brute-force attempts
    * Optionally enforces a specific username/password (or accepts all)
    * Rate-limits excessive auth attempts per IP
    """

    def __init__(self, client_ip: str, valid_user: str = "", valid_pass: str = ""):
        self.client_ip  = client_ip
        self.valid_user = valid_user
        self.valid_pass = valid_pass
        self.event      = threading.Event()

    # ── Channel ───────────────────────────────────────────────────────────────

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def get_allowed_auths(self, username):
        return "password"

    # ── Authentication ────────────────────────────────────────────────────────

    def check_auth_password(self, username: str, password: str):
        # Check rate limit first
        if not _check_rate_limit(self.client_ip):
            funnel_logger.warning(json.dumps({
                "timestamp":  get_timestamp(),
                "event_type": "auth_rate_limited",
                "source_ip":  self.client_ip,
                "username":   username,
            }))
            time.sleep(random.uniform(5, 10))   # extra penalty for rate-limited IPs
            return paramiko.AUTH_FAILED

        # Log every attempt as JSON so Wazuh can ingest it
        # NOTE: password is HASHED (SHA-256 prefix) - never logged in plaintext
        entry = {
            "timestamp":       get_timestamp(),
            "event_type":      "ssh_auth_attempt",
            "source_ip":       self.client_ip,
            "username":        username,
            "password_hash":   _hash_password(password),   # safe: hashed
            "password_length": len(password),
        }
        funnel_logger.info(json.dumps(entry))

        # Slow down brute-forcers
        time.sleep(random.uniform(0.5, 1.5))

        if self.valid_user and self.valid_pass:
            if username == self.valid_user and password == self.valid_pass:
                funnel_logger.info(json.dumps({**entry, "result": "SUCCESS"}))
                return paramiko.AUTH_SUCCESSFUL
            log_auth_event(self.client_ip, username, password, success=False)
            funnel_logger.info(json.dumps({**entry, "result": "FAILED"}))
            return paramiko.AUTH_FAILED

        # Open honeypot – accept everything but still log the auth event
        log_auth_event(self.client_ip, username, password, success=True)
        funnel_logger.info(json.dumps({**entry, "result": "ACCEPT_ALL"}))
        return paramiko.AUTH_SUCCESSFUL

    # ── PTY / shell ───────────────────────────────────────────────────────────

    def check_channel_pty_request(self, channel, term, width, height,
                                   pixelwidth, pixelheight, modes):
        return True

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True
