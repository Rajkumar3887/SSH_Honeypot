# Project Structure

```
honeypot/
│
├── 📁 config/                      # Configuration management
│   ├── __init__.py
│   └── settings.py                 # All settings (env-var overrideable)
│
├── 📁 core/                        # Core honeypot logic
│   ├── __init__.py
│   ├── command_engine.py           # 40+ emulated shell commands + shell loop
│   ├── session.py                  # SSH session lifecycle (connect→shell→disconnect)
│   ├── ssh_server.py               # Paramiko ServerInterface (auth + channel setup)
│   ├── threat_engine.py            # Pattern-based detection (RECON, LATERAL, EXFIL, PERSISTENCE, PRIVESC)
│   │                               # Includes classification + scoring (0-100) and GeoIP for score >70.
│   └── virtual_fs.py               # Virtual filesystem (vfs dict + file_contents)
│
├── 📁 database/                    # Database layer
│   ├── __init__.py
│   └── db.py                       # SQLite manager (connections, commands, threats)
│
├── 📁 web/                         # Real-time monitoring dashboard (New)
│   ├── __init__.py                 # Makes it a Python package
│   ├── app.py                      # FastAPI or Flask app; connects to DB and uses SSE/WebSockets for live updates.
│   ├── static/
│   │   ├── chart.js                # Real-time Graph and Timeline visualization
│   │   └── style.css               # Dashboard styling
│   └── templates/
│       ├── index.html              # Main dashboard view
│       └── session_detail.html     # Deep-dive into specific attacker sessions
│
├── 📁 wazuh/                       # Wazuh SIEM integration
│   ├── __init__.py                 # WazuhIntegration class (syslog forwarding)
│   ├── ossec.conf                  # Wazuh agent config template
│   ├── decoders.xml                # Custom JSON log decoders
│   └── rules.xml                   # 20 alert rules with MITRE ATT&CK mapping
│
├── 📁 logs/                        # Log files (generated at runtime)
│   ├── funnel.log                  # Connection & auth events (JSON)
│   ├── cmd_audits.log              # Command execution log (JSON)
│   ├── threats.log                 # Threat detection alerts (JSON)
│   └── system.log                  # System / operator events (JSON)
│
├── 📄 main.py                      # CLI entry point + socket listener
├── 📄 requirements.txt             # paramiko, cryptography, fastapi/flask, sqlalchemy
├── 📄 Dockerfile                   # Single-container image
├── 📄 docker-compose.yml           # Honeypot + optional Wazuh agent sidecar
├── 📄 PROJECT_STRUCTURE.md          # Project documentation
└── 📄 README.md                    # Quick-start + feature overview
```

## Data Flow

```
Attacker SSH →  core/ssh_server.py  (auth)
                       ↓
               core/session.py      (session lifecycle)
                       ↓
               core/command_engine.py  (shell loop)
                    /        \
     core/threat_engine.py   core/virtual_fs.py
           ↓                        ↓
     logs/threats.log         per-session VFS
           ↓
     wazuh/                  database/db.py
     (real-time syslog)      (SQLite persistence)
```

## Module Responsibilities

| Module | Responsibility |
|--------|---------------|
| `config/settings.py` | Single source of truth for all configuration; reads env vars |
| `core/virtual_fs.py` | Builds the fake filesystem dict for each session |
| `core/command_engine.py` | Dispatches every command; handles VFS mutations, permissions, nano TUI |
| `core/ssh_server.py` | Paramiko `ServerInterface`; handles auth events |
| `core/session.py` | Manages transport lifecycle; wires ssh_server → command_engine |
| `core/threat_engine.py` | Regex-based threat detection; writes JSON threat log |
| `database/db.py` | SQLite CRUD; thread-safe via `threading.Lock` |
| `wazuh/__init__.py` | Optional real-time syslog forwarding; alert enrichment |
| `wazuh/decoders.xml` | Teaches Wazuh to parse honeypot JSON log fields |
| `wazuh/rules.xml` | 20 rules; levels 3-15; MITRE ATT&CK IDs |
| `main.py` | Argparse CLI; creates socket; spawns per-connection threads |
