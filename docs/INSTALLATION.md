# Installation Guide — SSH Honeypot

---

## Prerequisites

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.10 | 3.11+ |
| pip | Any | Latest |
| RAM | 256 MB | 1 GB+ |
| Disk | 100 MB | 1 GB (for logs) |
| OS | Linux/macOS/Windows | Ubuntu 20.04+ |
| Docker (optional) | 20.10+ | 24.0+ |

---

## Method 1: Direct Python (Development)

### Step 1: Clone / Extract the Project
```bash
# If using git:
git clone <your-repo-url>
cd SSH_Honeypot-main

# If using ZIP:
unzip SSH_Honeypot.zip
cd SSH_Honeypot-main
```

### Step 2: Create a Virtual Environment
```bash
# Linux/macOS
python3 -m venv venv
source venv/bin/activate

# Windows PowerShell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

> [!IMPORTANT]
> The `requirements.txt` uses **FastAPI + uvicorn** (not Flask). If you see Flask-related import errors, verify you're using the updated `requirements.txt` from this package.

**Verify installation:**
```bash
python -c "import paramiko, fastapi, uvicorn; print('All OK')"
```

### Step 4: Run the Honeypot
```bash
# Open mode (accept all credentials) + web dashboard
python main.py --open --dashboard

# Expected output:
# 2026-09-26 12:00:00 | {"event": "honeypot_start", ...}
# [*] SSH honeypot listening on 0.0.0.0:2222  [open (log-all)]
# [*] Logs → logs/
# [*] Database → honeypot.db
# [*] Dashboard → http://0.0.0.0:5000
```

### Step 5: Test the Connection
```bash
# In a separate terminal:
ssh -p 2222 admin@localhost
# Type any password when prompted
# You should see a fake Ubuntu shell
```

### Step 6: View the Dashboard
Open `http://localhost:5000` in your browser.

---

## Method 2: Docker (Recommended for Production)

### Step 1: Build and Run
```bash
docker compose up -d
```

This automatically:
- Builds the Python image
- Starts the honeypot on port 2222
- Starts the dashboard on port 5000  
- Persists logs to `./logs/`
- Persists database to `./honeypot.db`

### Step 2: Test
```bash
# Test SSH
ssh -p 2222 admin@localhost

# Test dashboard
curl http://localhost:5000/api/scores
```

### Step 3: View Logs
```bash
# Container logs
docker compose logs -f honeypot

# Honeypot logs
tail -f logs/funnel.log
tail -f logs/threats.log
```

### Step 4: Stop
```bash
docker compose down
```

---

## Method 3: Credential-Enforced Mode

In this mode, only one specific username/password is accepted. All other attempts are rejected and logged.

```bash
python main.py --user admin --pass MyStr0ngP@ss --dashboard
```

This is more realistic for certain scenarios but reduces attacker "success" data.

---

## Environment Variables (Optional)

Create a `.env` file (copy from `examples/.env.example`):

```bash
cp examples/.env.example .env
# Edit .env as needed
```

Key settings:
```ini
BIND_PORT=2222
AUTH_USER=admin
AUTH_PASS=password
DB_ENABLED=true
WAZUH_ENABLED=false
```

> [!NOTE]
> Python's `main.py` does not automatically load `.env` files. Set variables in your shell or Docker environment. To use `.env` automatically, add `pip install python-dotenv` and add `from dotenv import load_dotenv; load_dotenv()` at the top of `main.py`.

---

## Verification Checklist

After installation, verify:

```bash
# 1. SSH port open
nc -z localhost 2222 && echo "SSH port OK"

# 2. Dashboard accessible
curl -s http://localhost:5000/ | head -5

# 3. Logs being created
ls -la logs/
# Should see: funnel.log, cmd_audits.log, threats.log, system.log

# 4. Database created
ls -la honeypot.db

# 5. Threat detection working
# Connect via SSH, run: cat /etc/passwd
# Check: tail logs/threats.log
```

---

## Troubleshooting Installation

### `ModuleNotFoundError: No module named 'fastapi'`
```bash
pip install fastapi uvicorn
# Or reinstall all:
pip install -r requirements.txt
```

### `PermissionError: Cannot bind to port 2222`
```bash
# On Linux, ports < 1024 need root. Port 2222 should not need it.
# If still failing, try a different port:
python main.py --port 2223 --open
```

### `Address already in use`
```bash
# Find what's using port 2222:
lsof -i :2222          # macOS/Linux
netstat -ano | findstr 2222  # Windows

# Kill it or use a different port
python main.py --port 2223
```

### Virtual environment activation fails (Windows)
```powershell
# Allow script execution:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
.\venv\Scripts\Activate.ps1
```

### Dashboard not showing real-time data
The dashboard connects to the running honeypot via shared in-memory state. The honeypot and dashboard **must run in the same process** (use `--dashboard` flag, not separate processes).
