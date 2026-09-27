"""
Wazuh SIEM Integration Module.

This module provides:
1. WazuhIntegration – runtime helper that enriches log entries and
   optionally sends alerts directly to a Wazuh manager via the
   active-response socket or syslog.
2. Helper functions consumed by other modules.

Log files monitored by the Wazuh agent:
  logs/funnel.log      – connection + auth events (JSON)
  logs/cmd_audits.log  – command execution (JSON)
  logs/threats.log     – threat detection alerts (JSON)
  logs/system.log      – system events (JSON)
"""

import json
import socket
import logging
import datetime
import os
from logging.handlers import RotatingFileHandler

from config.settings import (
    WAZUH_ENABLED, WAZUH_LOG_FORMAT,
    LOG_MAX_BYTES, LOG_BACKUP_COUNT, SYSTEM_LOG,
)


_sys_log = logging.getLogger("system")


class WazuhIntegration:
    """
    Runtime Wazuh integration.

    In most deployments the Wazuh agent reads the honeypot log files
    directly (file-based integration).  This class provides an optional
    additional channel: sending JSON events to a syslog socket so the
    Wazuh manager receives them in real time even before log rotation.
    """

    def __init__(
        self,
        syslog_host: str = None,
        syslog_port: int = 514,
        syslog_proto: str = "udp",
    ):
        self._enabled     = WAZUH_ENABLED
        self._syslog_host = syslog_host or os.getenv("WAZUH_SYSLOG_HOST")
        self._syslog_port = syslog_port
        self._proto       = syslog_proto.lower()
        self._sock        = None

        if self._enabled and self._syslog_host:
            self._init_socket()

    # ── Socket setup ──────────────────────────────────────────────────────────

    def _init_socket(self):
        try:
            if self._proto == "tcp":
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._sock.connect((self._syslog_host, self._syslog_port))
            else:
                self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            _sys_log.info(json.dumps({
                "event": "wazuh_socket_init",
                "host": self._syslog_host,
                "port": self._syslog_port,
                "proto": self._proto,
            }))
        except Exception as exc:
            _sys_log.error(json.dumps({
                "event": "wazuh_socket_error", "error": str(exc),
            }))
            self._sock = None

    # ── Public API ────────────────────────────────────────────────────────────

    def send_alert(self, alert: dict):
        """
        Forward an alert dict to Wazuh via syslog (if configured).
        The alert is always written to threats.log via the threat_engine.
        This method adds real-time socket delivery on top.
        """
        if not self._enabled or not self._sock:
            return
        try:
            msg = self._format_syslog(alert)
            if self._proto == "tcp":
                self._sock.sendall((msg + "\n").encode())
            else:
                self._sock.sendto(
                    msg.encode(),
                    (self._syslog_host, self._syslog_port),
                )
        except Exception as exc:
            _sys_log.error(json.dumps({
                "event": "wazuh_send_error", "error": str(exc),
            }))
            # Try to re-connect on next send
            self._sock = None
            self._init_socket()

    def send_event(self, event: dict):
        """Send a generic honeypot event (connection, command, etc.)."""
        self.send_alert(event)

    def enrich_alert(self, alert: dict) -> dict:
        """
        Add standard Wazuh-compatible fields to an alert dict.
        Rule IDs 100100-100199 are reserved for this honeypot.
        """
        severity_to_level = {
            "low":      3,
            "medium":   7,
            "high":     10,
            "critical": 15,
        }
        category_to_rule = {
            "BRUTE_FORCE": (100100, "SSH brute-force attempt on honeypot"),
            "RECON":       (100101, "Reconnaissance command executed on honeypot"),
            "PRIVESC":     (100102, "Privilege escalation attempt on honeypot"),
            "EXFIL":       (100103, "Data exfiltration command detected on honeypot"),
            "CRED_HUNT":   (100104, "Credential harvesting attempt on honeypot"),
            "PERSISTENCE": (100105, "Persistence mechanism attempt on honeypot"),
            "MALWARE":     (100106, "Malware or C2 tool detected on honeypot"),
        }

        category = alert.get("category", "UNKNOWN")
        severity = alert.get("severity", "low")
        rule_id, description = category_to_rule.get(
            category, (100199, "Honeypot generic alert")
        )

        return {
            **alert,
            "wazuh": {
                "rule_id":     rule_id,
                "rule_level":  severity_to_level.get(severity, 3),
                "description": description,
                "groups":      ["honeypot", "ssh", category.lower()],
                "decoded_as":  "honeypot_json",
            },
        }

    def close(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _format_syslog(event: dict) -> str:
        """Format event as RFC-5424-ish syslog message carrying JSON payload."""
        now  = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        host = socket.gethostname()
        prog = "honeypot"
        pri  = "<134>"  # facility=local0(16), severity=info(6) → (16*8+6)=134
        return f"{pri}{now} {host} {prog}: {json.dumps(event)}"
