# 🍯 Enterprise SSH Honeypot

A high-interaction SSH honeypot with a fully emulated Linux shell, virtual
filesystem, permission model, nano-like editor, and complete
**Wazuh SIEM integration**.

---

## Features

| Feature | Detail |
|---------|--------|
| Realistic SSH banner | `OpenSSH_8.2p1 Ubuntu-4ubuntu0.5` |
| Virtual filesystem | Full `/etc`, `/home`, `/proc`, `/var/log` tree |
| Permission model | `corpuser` vs `root` (via `su`) |
| 40+ commands | `ls`, `cat`, `find`, `grep`, `nano`, `wget`, `curl`, `ping`, `python`… |
| Nano editor | Full TUI with arrow keys, save, scroll |
| Heredoc / redirect | `cat << EOF > file`, `echo x >> file` |
| Threat detection | Pattern-based, 8 categories, MITRE ATT&CK mapped |
| Wazuh integration | JSON logs + custom decoders + 20+ alert rules |
| SQLite database | Connections, auth attempts, commands, threats |
| Docker support | Single container or compose with optional Wazuh sidecar |

---

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run open honeypot (accepts all credentials)
python main.py --open

# 3. Or enforce specific credentials
python main.py --user admin --pass password --port 2222
```

### Docker

```bash
docker compose up --build
```

---

## CLI Options

```
python main.py [options]

  --host HOST        Bind address          (default: 0.0.0.0)
  --port PORT        Bind port             (default: 2222)
  --user USER        Expected username     (default: admin)
  --pass PASS        Expected password     (default: password)
  --open             Accept ALL credentials (open honeypot)
  --no-db            Disable SQLite logging
  --wazuh-host HOST  Wazuh manager syslog IP for real-time alerts
  --wazuh-port PORT  Wazuh syslog port     (default: 514)
  --wazuh-proto      udp|tcp               (default: udp)
```

---

## Log Files

All logs are written to `logs/` as **newline-delimited JSON** (one event per line).

| File | Content |
|------|---------|
| `funnel.log` | Connections and auth attempts |
| `cmd_audits.log` | Every command per session |
| `threats.log` | Threat detection alerts |
| `system.log` | System / operator events |

### Example log entry

```json
{
  "timestamp": "2024-01-10T12:04:15Z",
  "event_type": "honeypot_threat",
  "source_ip": "192.168.1.99",
  "username": "corpuser",
  "command": "cat /etc/shadow",
  "category": "CRED_HUNT",
  "severity": "high",
  "rule_id": "HP_CRED_HUNT",
  "message": "Honeypot threat detected: [CRED_HUNT/high] from 192.168.1.99"
}
```

---

## Wazuh Integration

See **[WAZUH_SETUP.md](WAZUH_SETUP.md)** for a complete step-by-step guide.

Quick summary:
1. Copy `wazuh/decoders.xml` → `/var/ossec/etc/decoders/honeypot_decoders.xml`
2. Copy `wazuh/rules.xml`    → `/var/ossec/etc/rules/honeypot_rules.xml`
3. Edit `wazuh/ossec.conf` with your manager IP and deploy to the agent
4. Restart `wazuh-manager` and `wazuh-agent`

---

## Project Structure

```

honeypot/
├── config/                         # Central configuration
│   └── settings.py                 # THREAT_PATTERNS and logging constants
├── core/                           # Core honeypot logic
│   ├── command_engine.py           # Shell loop and emulated command execution
│   ├── session.py                  # SSH lifecycle (connect, shell, disconnect)
│   ├── ssh_server.py               # Paramiko ServerInterface for auth/channel setup
│   ├── threat_engine.py            # RECON, LATERAL, EXFIL, PERSISTENCE, PRIVESC logic
│   │                               # 0-100 scoring system; GeoIP alert trigger for scores > 70
│   └── virtual_fs.py               # VFS alerts and sensitive file access monitoring
├── database/                       # Persistence layer
│   └── db.py                       # SQLite manager; stores commands, threats, and sessions
├── wazuh/                          # Wazuh SIEM integration
│   ├── __init__.py                 # WazuhIntegration class for log forwarding
│   ├── ossec.conf                  # Wazuh agent configuration
│   ├── decoders.xml                # JSON decoders for honeypot threat logs
│   └── rules.xml                   # 20 alert rules with MITRE ATT&CK mapping
├── web/                            # Real-time Web Dashboard (FastAPI)
│   ├── __init__.py                 # Web package initialization
│   ├── app.py                      # FastAPI server; SSE/WebSockets for live updates; DB connection
│   ├── static/                     # Frontend assets
│   │   ├── charts.js               # Chart.js logic for live threat graphs and timelines
│   │   └── style.css               # Dashboard UI styling
│   └── templates/                  # Jinja2 templates
│       ├── index.html              # Main real-time monitoring view
│       └── session_detail.html     # Deep-dive forensic view for specific sessions
├── logs/                           # Runtime JSON logs (funnel, cmd_audits, threats)
├── main.py                         # CLI entry point and socket listener
├── Dockerfile                      # Single-container image
├── docker-compose.yml              # Orchestration for honeypot and web services
├── requirements.txt                # Dependencies (FastAPI, Paramiko, GeoIP libraries)
└── .gitignore                      # Exclusion of logs and local databases

```

---

## Security Note

This honeypot is designed to attract, log, and analyse attackers.
**Never expose it on a production network without proper isolation.**
Run it in a sandboxed VM, container, or cloud instance with no access
to internal resources.
