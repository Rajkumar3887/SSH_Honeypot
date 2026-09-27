# Function Reference — SSH Honeypot

Quick reference for all key functions, classes, and parameters across the codebase.

---

## `main.py`

### `start_honeypot(host, port, username, password, db, wazuh)`
Binds the SSH listener socket and spawns a daemon thread per inbound connection.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | `BIND_HOST` | IP to bind to |
| `port` | `int` | `BIND_PORT` | Port to listen on |
| `username` | `str` | `AUTH_USER` | Expected username (empty = open) |
| `password` | `str` | `AUTH_PASS` | Expected password (empty = open) |
| `db` | `DatabaseManager\|None` | `None` | Database instance |
| `wazuh` | `WazuhIntegration\|None` | `None` | Wazuh integration instance |

---

## `core/ssh_server.py`

### Class `HoneypotServer(paramiko.ServerInterface)`
Paramiko server interface implementing authentication and channel negotiation.

#### `__init__(client_ip, valid_user, valid_pass)`
| Parameter | Type | Description |
|-----------|------|-------------|
| `client_ip` | `str` | Connecting client's IP address |
| `valid_user` | `str` | Expected username ("" = accept any) |
| `valid_pass` | `str` | Expected password ("" = accept any) |

#### `check_auth_password(username, password) -> int`
Called by Paramiko for each auth attempt. Logs (hashed) credentials, applies rate limiting, delays brute-forcers, returns `AUTH_SUCCESSFUL` or `AUTH_FAILED`.

### `_check_rate_limit(ip) -> bool`
Returns `False` if IP has exceeded `AUTH_RATE_LIMIT` attempts in `AUTH_WINDOW` seconds.

### `_hash_password(password) -> str`
Returns 16-character SHA-256 hex digest of password for safe logging.

---

## `core/session.py`

### `handle_client(client_sock, addr, username, password, db)`
Top-level handler for one inbound connection. Called in a daemon thread.

| Parameter | Type | Description |
|-----------|------|-------------|
| `client_sock` | `socket.socket` | Raw TCP socket from accept() |
| `addr` | `tuple[str,int]` | `(ip, port)` of client |
| `username` | `str` | Expected username (empty = open) |
| `password` | `str` | Expected password (empty = open) |
| `db` | `DatabaseManager\|None` | Database for persistence |

**Flow:**
1. Load/generate RSA host key
2. Set up Paramiko Transport with SSH banner
3. Start `HoneypotServer` and wait for auth
4. Accept channel, log connection to DB
5. Call `emulated_shell()` to handle commands
6. Clean up on disconnect

### `_log_event(event, ip, **kwargs)`
Emits a structured JSON log entry to both `funnel.log` and `system.log`.

---

## `core/command_engine.py`

### `emulated_shell(channel, client_ip, cmd_logger, db)`
Main shell emulation loop. Reads commands from PTY channel, dispatches to handlers.

| Parameter | Type | Description |
|-----------|------|-------------|
| `channel` | `paramiko.Channel` | SSH channel for I/O |
| `client_ip` | `str` | Attacker's IP (for logging/threats) |
| `cmd_logger` | `logging.Logger` | Logger for command audit trail |
| `db` | `DatabaseManager\|None` | For command persistence |

**Key internal state:**
- `current_dir` — working directory string
- `current_user` — `"corpuser"` or `"root"` 
- `current_uid` — `1001` or `0`
- `vfs`, `file_contents` — per-session virtual filesystem (from `build_vfs()`)

**Command dispatch pattern:**
```python
parts = shlex.split(cmd.strip())
cmd_name = parts[0]
args = parts[1:]

if cmd_name == "ls":
    # handle ls
elif cmd_name == "cat":
    # handle cat
# ... etc
```

### `STATIC_RESPONSES: dict[str, str]`
Lookup table for commands with fixed outputs: `"uname -a"`, `"uptime"`, `"ps aux"`, `"ifconfig"`, etc.

---

## `core/threat_engine.py`

### `analyse_command(cmd, client_ip, username, uid) -> list[dict]`
Main entry point for threat detection. Scans command against all 70+ patterns.

| Parameter | Type | Description |
|-----------|------|-------------|
| `cmd` | `str` | Raw command string |
| `client_ip` | `str` | Source IP |
| `username` | `str` | Logged-in username |
| `uid` | `int` | User's UID (0 = root) |

Returns list of alert dicts; also updates `_scores[client_ip]` and pushes high-priority alerts to `event_queue`.

### `analyse_file_access(path, client_ip, username)`
Checks if `path` is a sensitive lure file and logs the access to `threats.log`.

### `log_auth_event(ip, username, password, success)`
Logs authentication event to `threats.log` and optionally to database.

### `log_connection(ip, port)`
Logs TCP connection event and initializes `_scores[ip]` entry.

### `log_command_event(ip, username, command, uid)`
Logs command execution to `cmd_audits.log`.

### `geoip_lookup(ip) -> dict`
Queries ip-api.com for geolocation. Returns cached result if available (TTL: 1 hour). Returns `{}` for private IPs or on error.

**Returns:**
```python
{
    "country": "United States",
    "city": "New York",
    "isp": "Amazon.com Inc.",
    "lat": 40.7128,
    "lon": -74.0060,
    "is_private": False
}
```

### `_get_all_scores() -> dict[str, int]`  *(in web/app.py)*
Thread-safe snapshot of all session scores: `{ip: score}`.

### `event_queue: Queue`
Global SSE event queue (maxsize=1000). Threat engine pushes events, web/app.py consumes them for real-time dashboard.

### `_RAW: list[tuple]`
Pattern library: `[(regex, category, base_score, mitre_id, description), ...]`

---

## `core/virtual_fs.py`

### `build_vfs() -> tuple[dict, dict]`
Returns a fresh `(vfs, file_contents)` pair per session.

- **`vfs`**: `{path: [child_names]}` — directory structure
- **`file_contents`**: `{path: content_str}` — file text content

Each session gets its own copy so VFS mutations (touch, mkdir, rm) are isolated.

**Key lure files:**
- `/home/corpuser/secret.txt` — fake DB credentials + AWS keys
- `/root/.local_exploits` — fake CVE notes (attracts post-privesc attackers)
- `/root/.ssh/id_rsa` — fake RSA private key
- `/var/log/auth.log` — realistic auth log
- `/etc/shadow` — fake password hashes

---

## `database/db.py`

### Class `DatabaseManager`
Thread-safe SQLite manager with mutex locking and WAL mode.

#### `__init__(db_path)`
Opens connection, enables WAL mode, creates tables.

#### `insert_connection(source_ip, port)`
Records new TCP connection.

#### `close_connection(source_ip)`
Updates `disconnected_at` for open connection from this IP.

#### `insert_auth(source_ip, username, password, success)`
Logs authentication attempt. **Note:** `password` here is the raw value from `log_auth_event()` — consider hashing before calling.

#### `insert_command(source_ip, username, command)`
Logs command to audit trail.

#### `insert_threat(alert: dict)`
Logs threat detection alert. Expected dict keys: `source_ip`, `username`, `category`, `severity`, `rule_id`, `command`, `message`.

#### `insert_file_access(source_ip, file_path, username)`
Logs sensitive file access.

#### `get_top_attackers(limit=10) -> list[dict]`
Returns `[{source_ip, attempts}]` sorted by attempt count.

#### `get_top_commands(limit=10) -> list[dict]`
Returns `[{command, cnt}]` sorted by count.

#### `get_threats(severity=None, limit=100) -> list[dict]`
Returns threat records filtered by optional severity.

#### `close()`
Closes database connection.

---

## `web/app.py`

### `start_dashboard(host, port)`
Starts uvicorn ASGI server for FastAPI dashboard.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `host` | `str` | `"0.0.0.0"` | Bind address |
| `port` | `int` | `5000` | HTTP port |

### FastAPI Routes
| Method | Path | Handler | Description |
|--------|------|---------|-------------|
| `GET` | `/` | `index()` | Main dashboard HTML |
| `GET` | `/session/{ip}` | `session_page()` | Session detail HTML |
| `GET` | `/api/scores` | `api_scores()` | Current threat scores |
| `GET` | `/api/session/{ip}/summary` | `api_session_summary()` | Full forensic data for IP |
| `GET` | `/api/session/{ip}/threat_timeline` | `api_session_threat_timeline()` | Timeline per category |
| `GET` | `/api/threats/categories` | `api_threat_categories()` | Threat counts by category |
| `GET` | `/api/threats/timeline` | `api_threat_timeline()` | Hourly threat counts (24h) |
| `GET` | `/api/threats/severity_timeline` | `api_severity_timeline()` | Severity breakdown per hour |
| `GET` | `/api/attackers/top` | `api_top_attackers()` | Top 15 attackers with geo |
| `GET` | `/api/commands/top` | `api_top_commands()` | Most used commands |
| `GET` | `/api/commands/recent` | `api_recent_commands()` | Last 40 commands |
| `GET` | `/api/geo/attackers` | `api_geo_attackers()` | All attacker geo data |
| `GET` | `/api/alerts/high_priority` | `api_high_priority()` | Critical/high threats (30) |
| `GET` | `/sse` | `sse_stream()` | Server-Sent Events stream |

---

## `wazuh/__init__.py`

### Class `WazuhIntegration`
Optional SIEM integration for real-time syslog forwarding.

#### `__init__(syslog_host, syslog_port, syslog_proto)`
Initializes UDP/TCP socket to Wazuh manager. No-ops if `syslog_host` is None/empty.

#### `send_event(event: dict)`
Forwards JSON event to Wazuh via syslog. Handles both UDP and TCP.

#### `close()`
Closes the syslog socket.

---

## `config/settings.py`

All values can be overridden via environment variables.

| Constant | Env Var | Default | Description |
|----------|---------|---------|-------------|
| `SSH_BANNER` | `SSH_BANNER` | `SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5` | SSH version banner |
| `HOST_KEY_PATH` | `HOST_KEY_PATH` | `server.key` | RSA host key path |
| `BIND_HOST` | `BIND_HOST` | `0.0.0.0` | Bind address |
| `BIND_PORT` | `BIND_PORT` | `2222` | SSH port |
| `AUTH_USER` | `AUTH_USER` | `admin` | Expected username |
| `AUTH_PASS` | `AUTH_PASS` | `password` | Expected password |
| `LOG_DIR` | `LOG_DIR` | `logs` | Log directory |
| `FUNNEL_LOG` | — | `logs/funnel.log` | Connection+auth log |
| `CMD_AUDIT_LOG` | — | `logs/cmd_audits.log` | Command log |
| `THREAT_LOG` | — | `logs/threats.log` | Threat detection log |
| `SYSTEM_LOG` | — | `logs/system.log` | Operator events |
| `LOG_MAX_BYTES` | `LOG_MAX_BYTES` | `5000000` (5 MB) | Max log file size |
| `LOG_BACKUP_COUNT` | `LOG_BACKUP_COUNT` | `5` | Rotated files to keep |
| `WAZUH_ENABLED` | `WAZUH_ENABLED` | `true` | Enable Wazuh mode |
| `DB_ENABLED` | `DB_ENABLED` | `true` | Enable SQLite |
| `DB_PATH` | `DB_PATH` | `honeypot.db` | SQLite file path |
| `FAKE_HOSTNAME` | `FAKE_HOSTNAME` | `ubuntu-server-01` | Simulated hostname |
| `FAKE_IP` | `FAKE_IP` | `192.168.1.15` | Simulated IP |
| `FAKE_OS` | `FAKE_OS` | `Ubuntu 20.04.5 LTS` | Simulated OS |
| `FAKE_KERNEL` | `FAKE_KERNEL` | `5.4.0-42-generic` | Simulated kernel |
| `THREAT_PATTERNS` | — | (list) | Basic threat regex list |
| `THREAT_SEVERITY` | — | (dict) | Category → severity mapping |
