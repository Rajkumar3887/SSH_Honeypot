<div align="center">

![SSH Honeypot Banner](assets/banner.png)



### Enterprise-Grade SSH Deception Technology with Real-Time Threat Intelligence

[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](Dockerfile)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red.svg)](https://attack.mitre.org/)

[📖 Documentation](#-documentation) •
[🚀 Quick Start](#-quick-start) •
[🎯 Features](#-features) •
[📊 Dashboard](#-live-dashboard-preview) •
[🔒 Security](#-security--realism) •
[📈 Benchmarks](#-performance--benchmarks)

</div>

---

## 📸 Live Dashboard Preview

```
╔════════════════════════════════════════════════════════════════════════════╗
║  🔴 LIVE THREAT DETECTION DASHBOARD        http://localhost:5000         ║
╠════════════════════════════════════════════════════════════════════════════╣
║                                                                          ║
║  📍 Active Threats (Real-Time)                                           ║
║  ├─ 192.168.1.100  [Recon Attempt]    Score: 85/100  🔴 CRITICAL        ║
║  ├─ 10.0.0.50      [Lateral Move]     Score: 42/100  🟡 MEDIUM          ║
║  └─ 172.16.0.25    [Cred Hunting]     Score: 28/100  🟢 LOW             ║
║                                                                          ║
║  🗺️  Geographic Distribution                                            ║
║  ├─ USA    (45%)  ████████████████                                       ║
║  ├─ China  (30%)  ███████████                                            ║
║  ├─ Russia (15%)  ██████                                                 ║
║  └─ Other  (10%)  ████                                                   ║
║                                                                          ║
║  📊 Attack Timeline (Last 24h)                                           ║
║  └─ ████████████████████░░░░  (847 attempts)                             ║
║                                                                          ║
║  🎯 Top Threats Detected                                                 ║
║  ├─ T1082 (System Info Discovery)     ███████████  67 attempts           ║
║  ├─ T1087 (Account Enumeration)       ████████     42 attempts           ║
║  ├─ T1021.004 (SSH Lateral Movement)  ██████       28 attempts           ║
║  └─ T1555 (Credential Dumping)        ██████       24 attempts           ║
║                                                                          ║
╚════════════════════════════════════════════════════════════════════════════╝
```

---

## 🎯 Features

<table>
<tr>
<td width="50%">

### 🖥️ Core Honeypot
- ✅ Realistic OpenSSH 8.2p1 emulation
- ✅ 40+ authentic Linux commands
- ✅ Virtual filesystem with lures
- ✅ Permission model (user/root)
- ✅ Session timeout & rate limiting
- ✅ Input validation & output limits

### 🐚 Advanced Shell Features
- ✅ Piping support (`ls | grep`)
- ✅ Wildcard/glob patterns (`*.txt`)
- ✅ Environment variables (`$HOME`, `$USER`)
- ✅ Command chaining (`&&`, `;`, `||`)
- ✅ Case-insensitive commands
- ✅ Full nano text editor (TUI)

</td>
<td width="50%">

### 🛡️ Threat Detection
- ✅ 70+ regex attack patterns
- ✅ MITRE ATT&CK mapping
- ✅ Composite threat scoring (0-100)
- ✅ GeoIP correlation
- ✅ Real-time threat alerts
- ✅ Session forensics

### 📊 Monitoring & Integration
- ✅ Live web dashboard (FastAPI)
- ✅ Server-Sent Events (real-time)
- ✅ Wazuh SIEM integration
- ✅ SQLite persistence (WAL mode)
- ✅ JSON audit logging
- ✅ Docker containerization

</td>
</tr>
</table>

---

## 🚀 Quick Start

### 30 Seconds to Running Honeypot

**Option 1: Docker (Recommended)**
```bash
# Clone
git clone https://github.com/yourusername/SSH_Honeypot.git
cd SSH_Honeypot

# Build & Run
docker compose up

# In another terminal:
ssh -p 2222 admin@localhost
# Type any password, then explore
```

**Option 2: Local Python**
```bash
# Install dependencies
pip install -r requirements.txt

# Start honeypot
python main.py --open --dashboard

# Test it (another terminal)
ssh -p 2222 admin@localhost
```

**Option 3: Production Deployment**
```bash
# With custom port & Wazuh integration
python main.py --open \
    --port 22 \
    --dashboard \
    --wazuh-syslog 192.168.1.100:514 \
    --log-dir /var/log/honeypot
```

**Access Dashboard:**
🌐 **http://localhost:5000**

---

## 📖 Documentation

| Document | Purpose |
|----------|---------|
| [INSTALLATION.md](docs/INSTALLATION.md) | Setup guide (bare metal, Docker, cloud) |
| [FEATURES.md](docs/FEATURES.md) | Complete command & detection reference |
| [DEPLOYMENT.md](docs/DEPLOYMENT.md) | Production deployment guide |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design & data flow |
| [API_ENDPOINTS.md](docs/API_ENDPOINTS.md) | Dashboard REST API reference |
| [TROUBLESHOOTING.md](docs/quick_guides/TROUBLESHOOTING.md) | Common issues & fixes |
| [SECURITY_NOTES.md](docs/SECURITY_NOTES.md) | Threat model & mitigations |
| [CHANGELOG.md](CHANGELOG.md) | Version history & release notes |

---

## 🎬 Usage Examples

### Example 1: Basic Connection
```
$ ssh -p 2222 admin@localhost
admin@localhost's password: [type anything]

Welcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-42-generic x86_64)

corpuser@ubuntu-server-01:~$ ls
file1.txt  notes.txt  projects  secret.txt  deploy.sh

corpuser@ubuntu-server-01:~$ cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
corpuser:x:1001:1001:Corp User:/home/corpuser:/bin/bash
```

### Example 2: Threat Detection
```bash
$ find / -name "*.key" -o -name "*secret*" 2>/dev/null
/home/corpuser/secret.txt
/opt/backup-scripts/.env.old

# 🎯 THREAT DETECTED: Credential Hunting (CRED_HUNT)
# MITRE: T1552 (Unsecured Credentials)
# Score: 67/100 (HIGH)
# [Dashboard updated in real-time]
```

### Example 3: Piping & Advanced Commands
```bash
corpuser@ubuntu-server-01:~$ cat /etc/passwd | grep bash | wc -l
2

corpuser@ubuntu-server-01:~$ echo $HOME
/home/corpuser

corpuser@ubuntu-server-01:~$ ls /etc/p*
/etc/passwd
```

---

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    SSH CLIENT (Attacker)                         │
└────────────────────────┬────────────────────────────────────────┘
                         │ SSH Protocol (Port 2222)
                         ▼
┌─────────────────────────────────────────────────────────────────┐
│               HONEYPOT SERVER (Paramiko)                         │
├─────────────────────────────────────────────────────────────────┤
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  SSH_Server (core/ssh_server.py)                         │   │
│  │  - Authentication (password hashing, rate limiting)      │   │
│  │  - Session lifecycle management                          │   │
│  │  - IP logging & forensics                                │   │
│  └──────────────────────────────────────────────────────────┘   │
│                         │                                        │
│       ┌─────────────────┼─────────────────┐                     │
│       ▼                 ▼                 ▼                     │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐            │
│  │Command Engine│ │Threat Engine │ │ Virtual FS   │            │
│  │(40+ commands)│ │(70+ patterns)│ │(realistic)   │            │
│  └──────────────┘ └──────────────┘ └──────────────┘            │
│       │                 │                 │                     │
│       └─────────────────┼─────────────────┘                     │
│                         ▼                                        │
│       ┌──────────────────────────────┐                          │
│       │   Database (SQLite WAL)      │                          │
│       │   - Connections              │                          │
│       │   - Auth Attempts            │                          │
│       │   - Commands Executed        │                          │
│       │   - Threat Alerts            │                          │
│       └──────────────────────────────┘                          │
│                         │                                        │
└─────────────────────────┼────────────────────────────────────────┘
                          │
          ┌───────────────┼───────────────┐
          ▼               ▼               ▼
     ┌────────┐   ┌──────────┐   ┌──────────────┐
     │ JSON   │   │Dashboard │   │ Wazuh SIEM   │
     │ Logs   │   │(FastAPI) │   │ Integration  │
     └────────┘   └──────────┘   └──────────────┘
```

---

## 🔒 Security & Realism

### Anti-Fingerprinting Measures
- ✅ **SSH KEX matching** — Paramiko algorithms rewritten to match OpenSSH 8.2p1 exactly
- ✅ **Realistic timing** — Commands have variable, realistic delays (not instant responses)
- ✅ **Dynamic filesystems** — File mtimes update when modified, not static
- ✅ **Behavioral realism** — `ps aux` / `top` vary per call, bash_history is messy

### Data Protection
- ✅ Password hashing (SHA-256) in logs
- ✅ Rate limiting (max 10 auth attempts/minute)
- ✅ Session timeout (1 hour idle)
- ✅ Input validation (4KB command limit)
- ✅ Output truncation (1MB limit)

---

## 📈 Performance & Benchmarks

| Metric | Value |
|--------|-------|
| Command Execution Latency | 15-150ms (realistic, not instant) |
| Database Query Time | <50ms (SQLite WAL optimized) |
| Dashboard Response Time | <500ms (FastAPI + SSE) |
| Memory Per Session | ~5-10MB (minimal overhead) |
| Concurrent Sessions Tested | 10+ simultaneous without degradation |
| Pattern Matching Time | <10ms per command |
| Scoring Algorithm | <5ms per session |
| GeoIP Lookup | ~100ms (cached, circuit breaker) |
| Real-Time Dashboard Update | <1s from event to UI |
| Docker Image Size | ~350MB |
| Startup Time | <2 seconds |
| Memory Footprint | ~50MB baseline |
| CPU Usage (idle) | <0.1% |
| CPU Usage (10 concurrent) | <5% |

---

## 🧪 Testing & Validation

### Test Coverage
- ✅ 10/10 Integration Tests Passing
- ✅ 11/11 Live SSH Tests Passing
- ✅ 5/5 Concurrent Session Tests Passing
- ✅ Database (WAL + CRUD) Verified
- ✅ Threat Detection Pattern Matching Validated
- ✅ GeoIP Circuit Breaker Tested
- ✅ Environment Variables Expansion Verified
- ✅ Piping & Redirection Confirmed
- ✅ Command Validation Working
- ✅ Output Truncation Tested

### Run Tests
```bash
# Full integration test suite
python tests/integration_test.py

# Live SSH functionality test
python tests/live_ssh_test.py
```

---

## 🛠️ Configuration

### CLI Options
```
python main.py [OPTIONS]

Options:
  --host TEXT              SSH bind address        [default: 0.0.0.0]
  --port INTEGER           SSH port                [default: 2222]
  --open                   Accept all credentials (no validation)
  --user TEXT              Valid username           [default: admin]
  --pass TEXT              Valid password           [default: password]
  --dashboard              Start web dashboard     [default: False]
  --dashboard-port INTEGER Dashboard port           [default: 5000]
  --wazuh-syslog TEXT      Wazuh syslog endpoint   [default: None]
  --log-dir TEXT           Log directory            [default: ./logs]
  --no-db                  Disable database logging [default: False]
  --help                   Show this help message
```

### Environment Variables
```bash
# SSH Configuration
SSH_BANNER="SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5"
BIND_HOST="0.0.0.0"
BIND_PORT="2222"
AUTH_USER="admin"
AUTH_PASS="password"

# Logging
LOG_DIR="logs"

# Database
DB_ENABLED="true"
DB_PATH="honeypot.db"

# Wazuh Integration
WAZUH_ENABLED="false"
```

---

## 📊 Dashboard API

### REST Endpoints
```
GET /              -> Main dashboard (HTML)
GET /api/scores    -> Current threat scores
GET /api/session/<ip>     -> Session forensics
GET /api/threats/timeline -> Threat timeline
GET /api/attackers/top    -> Top attacker IPs
GET /api/commands/top     -> Most used commands
GET /sse           -> Server-Sent Events stream
```

### Example API Usage
```bash
# Get threat scores
curl http://localhost:5000/api/scores

# Get session details
curl http://localhost:5000/api/session/192.168.1.100
```

---

## 🚨 Alerts & Notifications

### Threat Severity Levels
| Level | Score | Action |
|-------|-------|--------|
| 🔴 CRITICAL | 80-100 | Immediate response required |
| 🟠 HIGH | 60-79 | Investigate within 1 hour |
| 🟡 MEDIUM | 40-59 | Monitor and log |
| 🟢 LOW | 20-39 | Routine analysis |
| ⚪ INFO | 0-19 | Informational only |

### Example Alert
```json
{
  "timestamp": "2026-09-26T14:32:45+05:30",
  "source_ip": "203.0.113.42",
  "threat_score": 85,
  "severity": "CRITICAL",
  "mitre_techniques": ["T1082", "T1087", "T1555"],
  "commands": [
    "cat /etc/passwd",
    "find / -name '*.key'",
    "grep -r 'password' /etc"
  ],
  "detection": "Credential Hunting + System Enumeration"
}
```

---

## 📦 Installation

### Requirements
- Python 3.11+
- Linux/Mac/Windows
- 500MB disk space
- 256MB RAM minimum

### Quick Install
```bash
git clone https://github.com/yourusername/SSH_Honeypot.git
cd SSH_Honeypot
pip install -r requirements.txt
python main.py --open --dashboard
```

### Docker Install
```bash
docker compose up -d
docker logs -f ssh_honeypot
```

---

## 🗺️ Roadmap

### v1.0.0 ✅ (Current)
- [x] Core SSH server with 40+ commands
- [x] Threat detection (70+ patterns)
- [x] Real-time dashboard
- [x] Wazuh integration
- [x] Docker support

### v1.1.0 (Planned Q1 2027)
- [ ] Multi-user support
- [ ] X11 forwarding simulation
- [ ] Advanced network simulation
- [ ] Machine learning-based threat scoring

### v2.0.0 (Planned Q2 2027)
- [ ] Kubernetes native deployment
- [ ] Multi-honeypot coordination
- [ ] Advanced deception network
- [ ] AI-powered attack response

---

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md)

```bash
# Fork the repo
# Create feature branch: git checkout -b feature/amazing-feature
# Commit changes: git commit -m "Add amazing feature"
# Push: git push origin feature/amazing-feature
# Open pull request
```

---

## 📄 License

MIT License -- See [LICENSE](LICENSE) for details.

---

## 🙏 Acknowledgments

Built with:
- [Paramiko](https://www.paramiko.org/) -- SSH protocol implementation
- [FastAPI](https://fastapi.tiangolo.com/) -- Web framework
- [MITRE ATT&CK](https://attack.mitre.org/) -- Threat framework

Inspired by:
- [Cowrie](https://github.com/cowrie/cowrie) (excellent honeypot reference)
- [HonSSH](https://github.com/tnich/honssh)
- [Kippo](https://github.com/desaster/kippo)

---

<div align="center">

⭐ **Show Your Support** — Star the repository if you find it useful!

🍯 **Let's catch some attackers together!**

Made with ❤️ by the security community

</div>
