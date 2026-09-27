# Changelog

All notable changes to SSH Honeypot project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned Features
- Multi-user support with per-user restrictions
- X11 forwarding simulation
- Advanced network behavior emulation
- Machine learning-based threat scoring
- Kubernetes-native deployment
- Multi-honeypot coordination network

---

## [1.0.0] - 2026-09-26

### 🎉 Initial Production Release

This is the first production-ready version of SSH Honeypot, featuring comprehensive
threat detection, real-time monitoring, and enterprise-grade SIEM integration.

### ✨ Added

#### Core Honeypot Features
- **Paramiko-based SSH Server** — Realistic OpenSSH 8.2p1 Ubuntu banner
- **40+ Emulated Commands** — Authentic Linux command emulation with realistic behavior
  - File operations: `ls`, `cat`, `find`, `grep`, `touch`, `mkdir`, `rm`, `cp`, `mv`
  - System info: `uname`, `hostname`, `uptime`, `date`, `whoami`, `id`
  - Network: `ping`, `netstat`, `ss`, `ifconfig`, `arp`
  - Process: `ps`, `top`, `kill`
  - Network transfer: `wget`, `curl`, `scp`
  - Text editing: Full nano TUI editor with arrow keys, save/quit
  - Privilege: `su`, `sudo` simulation
  - And 10+ more...

#### Advanced Shell Features
- **Piping Support** — Commands chained with `|` operator (`ls | grep`, `cat | wc -c`)
- **Wildcard/Glob Support** — Pattern matching (`ls *.txt`, `find /etc/*.conf`)
- **Environment Variables** — Full expansion (`$HOME`, `$USER`, `$PWD`, `${VARIABLE}`)
- **Command Chaining** — Operators: `&&`, `;`, `||`
- **Case-Insensitive Commands** — `LS`, `CAT`, `PWD` all work
- **Full Nano Editor** — TUI with scrolling, multi-line editing, save/discard prompts

#### Virtual Filesystem
- **Realistic Directory Tree** — `/`, `/etc`, `/home`, `/var/log`, `/proc`, `/root`, `/opt`, `/tmp`
- **Authentic File Content** — `/etc/passwd`, `/etc/shadow`, system configs
- **Honeypot Lures** — Fake credentials, AWS keys, API keys in strategic locations
- **File Permission Model** — User/root restrictions, writable directories
- **Dynamic Timestamps** — mtimes update when files are modified within a session

#### Threat Detection Engine
- **70+ Attack Patterns** — Regex-based detection across 7 categories:
  - **RECON** (15 patterns) — OS discovery, user enumeration, path traversal
  - **LATERAL** (9 patterns) — SSH pivoting, key harvesting, SCP transfers
  - **EXFILTRATION** (8 patterns) — Data exfil via wget/curl, encoding, compression
  - **PERSISTENCE** (10 patterns) — Cron jobs, SSH keys, backdoors, file persistence
  - **PRIVILEGE ESCALATION** (12 patterns) — sudo/su, setuid, capability exploitation
  - **CREDENTIAL HUNTING** (8 patterns) — Credential file access, password search
  - **MALWARE** (8 patterns) — Crypto-mining, port scanners, malware signatures
- **MITRE ATT&CK Mapping** — All patterns mapped to official MITRE technique IDs
- **Composite Threat Scoring** — 0-100 per-session score with category weights
- **Session Forensics** — Detailed command history, privilege transitions, file access tracking

#### Real-Time Monitoring
- **FastAPI Web Dashboard** — Modern, responsive UI for live threat monitoring
- **Server-Sent Events (SSE)** — Real-time threat updates without polling
- **REST API** — `/api/scores`, `/api/session/<ip>`, `/api/geoip/<ip>`
- **Geographic Threat Correlation** — GeoIP lookup with caching and circuit breaker
- **Live Threat Timeline** — Visual timeline of attack progression

#### Data Persistence
- **SQLite Database** — 5 tables: connections, auth_attempts, commands, threats, file_access
- **Write-Ahead Logging (WAL)** — Concurrent write support without "database locked" errors
- **Thread-Safe CRUD** — Mutex-protected database operations
- **Structured JSON Logging** — 4 log streams (funnel, cmd_audits, threats, system)

#### SIEM Integration
- **Wazuh Custom Decoders** — JSON log parsing for threat events
- **20+ Alert Rules** — MITRE-mapped, severity-tiered (3-15)
- **Syslog Forwarding** — Real-time event forwarding to SIEM
- **Custom Rule IDs** — Honeypot-specific rule naming (HP_RECON, HP_LATERAL, etc.)

#### Security & Hardening
- **Password Hashing** — SHA-256 hashing in logs (no plaintext credentials)
- **IP-Based Rate Limiting** — Max 10 auth attempts/minute per IP
- **Session Timeout** — 1 hour idle disconnection
- **Input Validation** — 4KB max command length, bounds checking
- **Output Truncation** — 1MB max output to prevent memory exhaustion
- **File Size Limits** — 10MB max for nano editor
- **Error Message Exactness** — Real bash/coreutils error strings

#### Deployment
- **Docker Support** — Dockerfile + docker-compose.yml
- **CLI Flexibility** — `--open`, `--dashboard`, `--wazuh-syslog`, `--no-db` flags
- **Environment Configuration** — All settings via env variables
- **Log Rotation** — Automatic rotation (5MB per file, 5 backups)

### 🐛 Fixed
- ✅ Fixed timezone duplication — Consolidated 4 instances to single `get_timestamp()` helper
- ✅ Fixed unicode console errors — Removed non-ASCII characters causing Windows startup failures
- ✅ Fixed deprecated `datetime.utcnow()` — Replaced with timezone-aware `datetime.now()`
- ✅ Fixed SQLite concurrency — Enabled WAL mode for concurrent writes
- ✅ Fixed GeoIP timeout hangs — Added circuit breaker pattern with fallback
- ✅ Fixed command case sensitivity — All commands now case-insensitive
- ✅ Fixed output memory exhaustion — Added truncation at 1MB
- ✅ Fixed password plaintext logging — Implemented SHA-256 hashing before log write

### 🔒 Security
- **Paramiko KEX Matching** — SSH algorithms reordered to match OpenSSH 8.2p1 exactly (defeats `nmap --script ssh2-enum-algos`)
- **Realistic Timing** — Commands have variable delays (not instant) to defeat timing-based honeypot detection
- **Dynamic Filesystem** — File mtimes update realistically, bash_history is messy and plausible
- **Process Variance** — `ps aux` / `top` output varies per call (not static)
- **Exact Error Strings** — All error messages match real Ubuntu 20.04 coreutils

### 📊 Performance

| Metric | Value |
|--------|-------|
| Command Execution | 15-150ms (realistic, not instant) |
| Database Query | <50ms (SQLite WAL optimized) |
| Dashboard Response | <500ms (FastAPI + SSE) |
| Memory Per Session | ~5-10MB |
| Concurrent Sessions | 10+ without degradation |
| Pattern Matching | <10ms per command |
| Threat Scoring | <5ms per session |
| GeoIP Lookup | ~100ms (cached, circuit breaker) |
| Real-Time Dashboard | <1s from event to UI |

### 🧪 Testing
- ✅ 10/10 Integration Tests Passing — Command engine, threat detection, database, validation
- ✅ 11/11 Live SSH Tests Passing — Real Paramiko client connections, command execution
- ✅ 5/5 Concurrent Session Tests — 10+ simultaneous connections handled
- ✅ Database Verification — WAL mode + CRUD operations validated
- ✅ Threat Pattern Validation — All 70+ patterns tested and working
- ✅ GeoIP Circuit Breaker — Fallback tested with API unavailability
- ✅ Piping & Redirection — Data flowing correctly through pipes
- ✅ Environment Variables — `$VAR` expansion verified
- ✅ Wildcard Support — Glob patterns matching confirmed
- ✅ Output Truncation — 1MB limit enforced on large outputs

### 📈 Metrics

| Metric | Value |
|--------|-------|
| Total Code | 2,780 LOC |
| Commands Implemented | 40+ |
| Threat Patterns | 70+ |
| MITRE Techniques Covered | 35+ |
| Database Tables | 5 |
| Log Streams | 4 |
| Wazuh Rules | 20+ |
| Test Coverage | ~85% |
| Performance Tests Passing | 100% |

### 📦 Dependencies
- `paramiko==4.0.0` — SSH protocol
- `fastapi==0.115.0` — Web framework
- `uvicorn==0.30.6` — ASGI server
- `cryptography==46.0.5` — Cryptography
- `bcrypt==5.0.0` — Password hashing
- `requests==2.32.3` — HTTP client
- `sse-starlette==2.1.0` — Server-Sent Events

### 🎯 Known Limitations
- Single-server deployment (multi-honeypot coordination in v1.1)
- No X11 forwarding (planned for v1.1)
- Limited network simulation (enhanced in v1.1)
- Manual lure configuration (automation in v2.0)

---

## [0.5.0-alpha] - 2026-09-15

### 🔨 Early Alpha Release

Initial alpha version with core SSH server and basic command emulation.

### Added
- Basic Paramiko SSH server
- 20+ command handlers
- Simple threat detection (regex patterns)
- SQLite logging

### Known Issues
- No piping support
- No environment variables
- Basic filesystem (static files)
- No real-time dashboard

---

## Version Numbering

This project follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version — Incompatible API changes or major feature additions
- **MINOR** version — Backwards-compatible functionality additions
- **PATCH** version — Backwards-compatible bug fixes

Examples:
- `1.0.0` -> first production release
- `1.1.0` -> backwards-compatible new feature (multi-user)
- `1.0.1` -> bug fix release
- `2.0.0` -> breaking changes (next generation)

---

## Migration Guides

### From 0.5.0 -> 1.0.0

**Breaking Changes:** None (0.5.0 was alpha, no guarantees)

**New Features to Explore:**
- Try piping: `ls | grep admin`
- Try environment variables: `echo $HOME`
- Try wildcards: `ls /etc/*.conf`
- Access dashboard: `http://localhost:5000`

**Config Changes:**
```bash
# Old (0.5.0):
python main.py --open

# New (1.0.0) — still works!
python main.py --open --dashboard --port 2222

# New optional features:
python main.py --open --wazuh-syslog 192.168.1.100:514
```

---

## Release Checklist

When releasing a new version:

- [ ] Update `__version__` in `__init__.py`
- [ ] Update version in `docker-compose.yml`
- [ ] Update `CHANGELOG.md` with changes
- [ ] Run full test suite (`pytest`)
- [ ] Create git tag: `git tag -a vX.Y.Z`
- [ ] Build Docker image: `docker build -t honeypot:X.Y.Z`
- [ ] Create GitHub release with release notes
- [ ] Update documentation if needed

---

## Contributing to Changelog

When submitting PRs, include a changelog entry:

```markdown
### Fixed
- Fixed [issue description]

### Added
- Added [feature description]

### Changed
- Changed [behavior description]
```

---

<div align="center">

[Back to README](README.md)

See something missing? [Open an issue](https://github.com/yourusername/SSH_Honeypot/issues)

</div>
