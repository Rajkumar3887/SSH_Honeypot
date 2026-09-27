# Performance Benchmarks — SSH Honeypot

Performance characteristics, limits, and optimization recommendations based on codebase analysis.

> [!NOTE]
> These are baseline estimates based on architecture analysis. Run the tests in `docs/testing/performance-test.sh` against your deployment for actual measurements.

---

## 📊 Expected Performance Profile

### Command Execution Latency

| Command Type | Expected Latency | Notes |
|---|---|---|
| Static response (uname, hostname) | < 1 ms | Dictionary lookup, no I/O |
| VFS operation (ls, cat, find) | 1–5 ms | In-memory dict traversal |
| Auth with brute-force delay | 500–1500 ms | Intentional `time.sleep()` |
| GeoIP lookup (cache miss) | 100–2000 ms | External HTTP call to ip-api.com |
| GeoIP lookup (cache hit) | < 1 ms | In-memory LRU cache |
| Database insert | 1–10 ms | SQLite with WAL mode |
| Threat scan (70+ regex) | 1–5 ms | All patterns compiled at startup |

### Throughput Limits

| Metric | Estimate | Bottleneck |
|---|---|---|
| Concurrent SSH connections | 100–500 | OS thread limit, memory |
| Auth attempts/minute/IP | 40 max (60-attempt window at 1.5s delay) | Brute-force delay + rate limiter |
| Commands/session/second | 50–200 | Channel I/O speed |
| SSE clients (dashboard) | 10–50 | Python asyncio event loop |
| Database writes/second | 1,000–5,000 | SQLite WAL mode |

### Memory Usage

| Component | Memory | Notes |
|---|---|---|
| Base Python process | ~30 MB | Startup |
| Per SSH session | ~2–5 MB | Thread stack + VFS copy |
| 100 concurrent sessions | ~230–530 MB | Linear scaling |
| GeoIP cache (1000 IPs) | ~1 MB | Simple dict |
| Threat score store | < 1 MB | Dict per active session |
| SQLite cache | 64 MB | Configured (PRAGMA cache_size) |
| Event queue | < 10 MB | maxsize=1000 events |

---

## 🔧 Optimization Recommendations

### 1. Reduce GeoIP Latency (High Impact, Easy)
**Problem:** External API call on every new IP lookup can add 2s+ latency  
**Solution:** Increase cache TTL or use a local GeoIP database

```python
# In core/threat_engine.py
_GEO_TTL = 3600  # Current: 1 hour
# Change to:
_GEO_TTL = 86400  # 24 hours for stable data

# Or use maxminddb for local lookups (no network dependency):
# pip install geoip2
# Download GeoLite2-City.mmdb from MaxMind
```

### 2. SQLite WAL Mode (Already Applied)
**Status:** ✅ Fixed in latest version  
WAL mode enables concurrent reads while writing, improving multi-session performance.

```sql
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;  -- Faster than FULL, still crash-safe
PRAGMA cache_size=-64000;   -- 64 MB page cache
```

### 3. Threat Pattern Compilation (Already Optimal)
Patterns in `_RAW` are compiled to regex objects at module import time. No optimization needed.

### 4. Command Engine Optimization

**Large output truncation** (prevents memory exhaustion):
```python
# Add to command_engine.py
MAX_OUTPUT_SIZE = 1_048_576  # 1 MB
if len(output) > MAX_OUTPUT_SIZE:
    output = output[:MAX_OUTPUT_SIZE] + "\n... (output truncated)\n"
```

**Session VFS sharing:** Currently each session gets a fresh `build_vfs()` copy. For 500+ sessions, consider copy-on-write:
```python
# Share base VFS, only copy on write operations
_base_vfs, _base_contents = build_vfs()
session_vfs = _base_vfs.copy()  # Shallow copy (directories)
session_contents = dict(_base_contents)  # Shallow copy (files)
```

### 5. Database Batch Writes (Advanced)
For very high traffic (1000+ sessions), batch database inserts:
```python
# Instead of individual inserts, queue and flush periodically
_write_queue = []
_flush_interval = 5  # seconds
```

---

## 📈 Scaling Recommendations

### For < 100 Concurrent Sessions
Current architecture is sufficient. Use as-is.

### For 100–500 Concurrent Sessions
1. Increase OS file descriptor limits: `ulimit -n 65536`
2. Enable WAL mode (already done in latest version)
3. Add GeoIP local database (avoid external API dependency)
4. Add output truncation to prevent memory exhaustion

### For 500+ Concurrent Sessions
Consider architectural changes:
1. **Move to PostgreSQL** — better concurrent write handling than SQLite
2. **Add Redis** — for threat scores and event queue instead of in-memory
3. **Separate dashboard** — run web/app.py as independent process
4. **Connection pooling** — limit max concurrent connections at socket level
5. **Async SSH handler** — replace threading model with asyncio

---

## 🧪 Benchmark Methodology

### Testing Concurrent Connections
```bash
# 50 concurrent nc port checks
for i in $(seq 1 50); do
    nc -z -w 1 localhost 2222 &
done
wait
echo "Done"
```

### Testing Authentication Speed
```bash
# Measure auth attempt latency (includes brute-force delay)
time ssh -o "StrictHostKeyChecking=no" \
    -p 2222 wronguser@localhost \
    "echo test" 2>/dev/null
# Expect: 0.5-1.5s (intentional delay)
```

### Testing Dashboard Response Times
```bash
# Basic API response time
time curl -s http://localhost:5000/api/scores > /dev/null

# With multiple concurrent requests
ab -n 100 -c 10 http://localhost:5000/api/scores
```

### Testing Database Performance
```bash
# Count queries while honeypot is running
sqlite3 honeypot.db "
    SELECT COUNT(*) as connections FROM connections;
    SELECT COUNT(*) as commands FROM commands;
    SELECT COUNT(*) as threats FROM threats;
"

# Query timing
time sqlite3 honeypot.db \
    "SELECT source_ip, COUNT(*) FROM auth_attempts GROUP BY source_ip ORDER BY 2 DESC LIMIT 10;"
```

### Memory Monitoring
```bash
# Monitor memory growth over time
watch -n 5 'ps aux | grep "python main.py" | grep -v grep | awk "{print \$6/1024\" MB\"}"'

# Detailed memory breakdown
python3 -c "
import psutil, os
p = psutil.Process(os.getpid())
print(p.memory_info())
"
```

---

## 🚨 Known Performance Issues

### Issue 1: Unbounded Command Output
**Status:** Not yet fixed  
**Impact:** `find /` or `ls -R /` could generate very large outputs, consuming memory

**Fix:**
```python
MAX_OUTPUT_SIZE = 1_048_576  # 1 MB
output = output[:MAX_OUTPUT_SIZE] + "\n... truncated\n"
```

### Issue 2: GeoIP Network Dependency
**Status:** Not yet fixed  
**Impact:** Any network issue with ip-api.com adds 2s+ latency per new IP

**Fix:** Add circuit breaker or local MaxMind database

### Issue 3: Nano Editor Unbounded Buffer
**Status:** Not yet fixed  
**Impact:** Attacker can consume arbitrary memory by typing large inputs to nano

**Fix:**
```python
NANO_MAX_SIZE = 10 * 1024 * 1024  # 10 MB
if len(file_content) > NANO_MAX_SIZE:
    channel.send("Error: file too large\n")
    return
```

### Issue 4: Thread-per-Connection Model
**Status:** Design limitation  
**Impact:** 500+ concurrent connections may exhaust OS thread limits  
**Mitigation:** `ulimit -n 65536`; at very high concurrency consider asyncio migration
