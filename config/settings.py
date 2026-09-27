"""
Central configuration for the SSH Honeypot.
All settings can be overridden via environment variables.
"""
import os

# Manual .env loading (since python-dotenv is not installed)
_env_path = os.path.join(os.path.dirname(__file__), "..", ".env")
if os.path.exists(_env_path):
    with open(_env_path, "r", encoding="utf-8") as _f:
        for _line in _f:
            _line = _line.strip()
            if _line and not _line.startswith("#"):
                _k, _v = _line.split("=", 1)
                os.environ[_k.strip()] = _v.strip()
# ── SSH Server ────────────────────────────────────────────────────────────────
SSH_BANNER   = os.getenv("SSH_BANNER",   "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
HOST_KEY_PATH= os.getenv("HOST_KEY_PATH","server.key")
BIND_HOST    = os.getenv("BIND_HOST",    "0.0.0.0")
BIND_PORT    = int(os.getenv("BIND_PORT", "2222"))

# Auth credentials – leave both empty ("") for open honeypot (accept all)
AUTH_USER    = os.getenv("AUTH_USER",    "admin")
AUTH_PASS    = os.getenv("AUTH_PASS",    "password")

# ── Logging ───────────────────────────────────────────────────────────────────
LOG_DIR           = os.getenv("LOG_DIR",           "logs")
FUNNEL_LOG        = os.path.join(LOG_DIR, "funnel.log")
CMD_AUDIT_LOG     = os.path.join(LOG_DIR, "cmd_audits.log")
THREAT_LOG        = os.path.join(LOG_DIR, "threats.log")
SYSTEM_LOG        = os.path.join(LOG_DIR, "system.log")
LOG_MAX_BYTES     = int(os.getenv("LOG_MAX_BYTES",    "5000000"))   # 5 MB
LOG_BACKUP_COUNT  = int(os.getenv("LOG_BACKUP_COUNT", "5"))

# ── Threat Detection ─────────────────────────────────────────────────────────
# Patterns that trigger a THREAT alert when seen in a command
THREAT_PATTERNS = [
    # Reconnaissance
    r"\.\.\/",                          # path traversal
    r"etc/passwd",
    r"etc/shadow",
    r"/proc/",
    r"netstat",
    r"ss\s+-",

    # Privilege escalation
    r"\bsu\b",
    r"\bsudo\b",
    r"chmod\s+[0-9]*7",                 # world-writable
    r"chown\s+root",

    # Persistence / exfil
    r"wget\s+http",
    r"curl\s+http",
    r"base64",
    r"python.*-c",
    r"perl.*-e",
    r"bash.*-i",
    r"/dev/tcp",
    r"nc\s+-",
    r"ncat",
    r"mkfifo",
    r">\s*/tmp/",

    # Credential hunting
    r"secret",
    r"password",
    r"api.?key",
    r"\.ssh/",

    # Crypto-mining / malware
    r"xmrig",
    r"minerd",
    r"masscan",
    r"nmap",
]

# Severity mapping for threat categories
THREAT_SEVERITY = {
    "RECON":       "low",
    "PRIVESC":     "high",
    "PERSISTENCE": "critical",
    "EXFIL":       "critical",
    "CRED_HUNT":   "medium",
    "MALWARE":     "critical",
    "UNKNOWN":     "low",
}

# ── Wazuh / SIEM ──────────────────────────────────────────────────────────────
WAZUH_ENABLED        = os.getenv("WAZUH_ENABLED", "true").lower() == "true"
WAZUH_LOG_FORMAT     = os.getenv("WAZUH_LOG_FORMAT", "json")   # "json" or "syslog"
WAZUH_ALERTS_LOG     = os.path.join(LOG_DIR, "funnel.log")     # Wazuh monitors this file

# ── Database ──────────────────────────────────────────────────────────────────
DB_ENABLED = os.getenv("DB_ENABLED", "true").lower() == "true"
DB_PATH    = os.getenv("DB_PATH", "honeypot.db")

# ── Honeypot Identity ─────────────────────────────────────────────────────────
FAKE_HOSTNAME  = "ubuntu-server-01"
FAKE_IP        = "192.168.1.15"
FAKE_OS        = "Ubuntu 20.04.5 LTS"
FAKE_KERNEL    = "5.4.0-42-generic"

# -- Timezone (single definition, used by all modules) -----------------------
import datetime as _dt
TIMEZONE = _dt.timezone(_dt.timedelta(hours=5, minutes=30))   # IST = UTC+5:30

def get_timestamp() -> str:
    """Return current IST timestamp as ISO-8601 string."""
    return _dt.datetime.now(TIMEZONE).isoformat(timespec="seconds")

# -- Shell safety constants (env-overridable) ---------------------------------
MAX_COMMAND_LENGTH = int(os.getenv("MAX_COMMAND_LENGTH", "4096"))   # chars
MAX_ARGS           = int(os.getenv("MAX_ARGS",           "128"))    # tokens
MAX_OUTPUT_SIZE    = int(os.getenv("MAX_OUTPUT_SIZE",    str(1 * 1024 * 1024)))  # 1 MB
NANO_MAX_SIZE      = int(os.getenv("NANO_MAX_SIZE",      str(10 * 1024 * 1024))) # 10 MB
SESSION_TIMEOUT    = int(os.getenv("SESSION_TIMEOUT",    "3600"))   # seconds (1 h)


# ── Per-deployment identity (stable across restarts, unique per deploy) ───────
import json as _json

def _load_or_generate_identity() -> dict:
    """Generate once at first start, persist so identity stays consistent."""
    _id_file = os.path.join(os.path.dirname(__file__), "..", "instance_identity.json")
    _id_file = os.path.normpath(_id_file)
    if os.path.exists(_id_file):
        try:
            with open(_id_file, encoding="utf-8") as _f:
                return _json.load(_f)
        except Exception:
            pass
    _hostnames = [
        "web-prod-01", "app-server-02", "db-primary", "backend-01",
        "ubuntu-server-01", "prod-app-03", "api-gateway-01",
    ]
    import random as _rnd
    _identity = {
        "hostname":         _rnd.choice(_hostnames),
        "fake_ip":          f"10.0.{_rnd.randint(0,255)}.{_rnd.randint(2,254)}",
        "install_days_ago": _rnd.randint(60, 900),
    }
    try:
        with open(_id_file, "w", encoding="utf-8") as _f:
            _json.dump(_identity, _f)
    except Exception:
        pass
    return _identity

_IDENTITY = _load_or_generate_identity()
