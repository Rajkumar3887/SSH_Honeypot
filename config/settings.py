"""
Central configuration for the SSH Honeypot.
All settings can be overridden via environment variables.
"""
import os

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
