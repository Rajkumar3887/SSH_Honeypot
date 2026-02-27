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

import paramiko

from config.settings import FUNNEL_LOG, LOG_MAX_BYTES, LOG_BACKUP_COUNT
from core.threat_engine import log_auth_event
from logging.handlers import RotatingFileHandler

# IST = UTC+5:30
_IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
def _now_ist() -> str:
    return datetime.datetime.now(_IST).isoformat(timespec="seconds")

# ── Funnel logger (shared with session.py via name) ───────────────────────────
funnel_logger = logging.getLogger("funnel")


class HoneypotServer(paramiko.ServerInterface):
    """
    Paramiko server interface that:
    * Accepts only password auth
    * Logs every credential attempt
    * Artificially slows down brute-force attempts
    * Optionally enforces a specific username/password (or accepts all)
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
        # Log every attempt as JSON so Wazuh can ingest it
        entry = {
            "timestamp":  _now_ist(),
            "event_type": "ssh_auth_attempt",
            "source_ip":  self.client_ip,
            "username":   username,
            "password":   password,
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
