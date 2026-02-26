"""
Threat Detection Engine  ·  v2
================================
· 7 attack categories  ·  70+ regex patterns
· Composite 0-100 session score (category-weighted)
· Score > 70  →  high_priority_alert pushed to SSE queue
· GeoIP via ip-api.com  (LRU cache, skips RFC-1918)
· Thread-safe session score store
· Global event_queue consumed by web/app.py
"""

from __future__ import annotations

import re, json, time, datetime, logging, threading, ipaddress
from queue import Queue, Full
from logging.handlers import RotatingFileHandler

# IST = UTC+5:30
_IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))

def _now_ist() -> str:
    """Return current time as ISO string in IST."""
    return datetime.datetime.now(_IST).isoformat(timespec="seconds")

try:
    import requests as _req; _HAS_REQ = True
except ImportError:
    _HAS_REQ = False

from config.settings import THREAT_LOG, LOG_MAX_BYTES, LOG_BACKUP_COUNT

# ── threat logger ─────────────────────────────────────────────────────────────
_tlog = logging.getLogger("threats")
if not _tlog.handlers:
    _tlog.setLevel(logging.INFO)
    _h = RotatingFileHandler(THREAT_LOG, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT)
    _h.setFormatter(logging.Formatter("%(message)s"))
    _tlog.addHandler(_h)

# ── global SSE queue ──────────────────────────────────────────────────────────
event_queue: Queue = Queue(maxsize=1000)

# ── session scores  {ip: {"score":int, "hits":[str], "commands":int}} ─────────
_scores: dict[str, dict] = {}
_score_lock = threading.Lock()

# ── GeoIP LRU cache ───────────────────────────────────────────────────────────
_geo_cache: dict[str, dict] = {}
_geo_lock  = threading.Lock()
_GEO_TTL   = 3600          # 1 hour

_PRIVATE = [
    ipaddress.ip_network(n) for n in (
        "10.0.0.0/8","172.16.0.0/12","192.168.0.0/16","127.0.0.0/8","::1/128"
    )
]


# ══════════════════════════════════════════════════════════════════════════════
# PATTERN LIBRARY
# (regex, category, base_score, mitre_id, description)
# ══════════════════════════════════════════════════════════════════════════════
_RAW: list[tuple[str,str,int,str,str]] = [

    # ─── RECON ────────────────────────────────────────────────────────────────
    (r"uname\s+-",               "RECON",       10, "T1082", "OS version discovery"),
    (r"cat\s+/etc/os-release",   "RECON",       10, "T1082", "OS release read"),
    (r"cat\s+/proc/version",     "RECON",       10, "T1082", "Kernel version read"),
    (r"cat\s+/proc/cpuinfo",     "RECON",        8, "T1082", "CPU info read"),
    (r"cat\s+/proc/meminfo",     "RECON",        8, "T1082", "Memory info read"),
    (r"cat\s+/etc/passwd",       "RECON",       22, "T1087", "User enumeration"),
    (r"cat\s+/etc/hosts",        "RECON",       12, "T1016", "Hosts file read"),
    (r"cat\s+/var/log/auth",     "RECON",       20, "T1083", "Auth log read"),
    (r"\bnetstat\b",             "RECON",       15, "T1049", "Network connection enum"),
    (r"\bss\s+-",                "RECON",       15, "T1049", "Socket statistics enum"),
    (r"\bps\s+(aux|ef|-e)\b",    "RECON",       15, "T1057", "Process enumeration"),
    (r"\benv\b|\bprintenv\b",    "RECON",       10, "T1083", "Environment dump"),
    (r"find\s+/\s+-",            "RECON",       20, "T1083", "Filesystem enumeration"),
    (r"\blast\b",                "RECON",       15, "T1033", "User session enum"),
    (r"ip\s+(addr|a\b|route)",   "RECON",       15, "T1016", "Network interface enum"),
    (r"\bifconfig\b",            "RECON",       15, "T1016", "ifconfig network enum"),
    (r"id\b|whoami\b",           "RECON",        8, "T1033", "Identity discovery"),
    (r"cat\s+/etc/issue",        "RECON",        8, "T1082", "OS issue read"),
    (r"\.\.\/",                  "RECON",       25, "T1083", "Path traversal attempt"),
    (r"df\s+-h\b",               "RECON",        8, "T1082", "Disk usage enumeration"),
    (r"\barp\b|\bnmcli\b",       "RECON",       15, "T1016", "ARP/network config read"),

    # ─── LATERAL MOVEMENT ─────────────────────────────────────────────────────
    (r"ssh\s+.+@",               "LATERAL",     35, "T1021.004", "SSH lateral movement"),
    (r"\bscp\s+",                "LATERAL",     30, "T1021.004", "SCP file transfer"),
    (r"\brsync\s+",              "LATERAL",     30, "T1021.004", "rsync lateral move"),
    (r"cat\s+.+known_hosts",     "LATERAL",     40, "T1021.004", "SSH known_hosts harvest"),
    (r"cat\s+.+authorized_keys", "LATERAL",     42, "T1021.004", "authorized_keys read"),
    (r"\.ssh/id_",               "LATERAL",     48, "T1552.004", "SSH private key access"),
    (r"ssh-keyscan",             "LATERAL",     45, "T1021.004", "SSH host key scanning"),
    (r"for\s+.+do\s+ssh",        "LATERAL",     55, "T1021.004", "SSH sweep loop"),
    (r"proxychains|tor\b",       "LATERAL",     50, "T1090",     "Proxy/Tor pivoting"),

    # ─── EXFIL ────────────────────────────────────────────────────────────────
    (r"wget\s+http",             "EXFIL",       40, "T1105",     "wget remote download"),
    (r"curl\s+http",             "EXFIL",       40, "T1105",     "curl remote request"),
    (r"curl\s+-X\s+POST",        "EXFIL",       55, "T1041",     "curl POST exfil"),
    (r"curl\s+.*-F\s+",          "EXFIL",       55, "T1041",     "curl form upload"),
    (r"base64\s+-d",             "EXFIL",       50, "T1027",     "base64 decode payload"),
    (r"\bbase64\b",              "EXFIL",       42, "T1027",     "base64 encode (prep)"),
    (r"python.*urllib|requests\.","EXFIL",      50, "T1041",     "Python HTTP exfil"),
    (r"nc\s+.+\d{2,5}\s*<",     "EXFIL",       65, "T1048",     "netcat file send"),
    (r"/dev/tcp/",               "EXFIL",       68, "T1048",     "Bash /dev/tcp exfil"),
    (r"tar\s+.+\|\s*(nc|curl)",  "EXFIL",       70, "T1048",     "Archive+pipe exfil"),
    (r"openssl\s+s_client",      "EXFIL",       55, "T1048",     "OpenSSL encrypted exfil"),
    (r"ftp\b.*put\b",            "EXFIL",       60, "T1048",     "FTP upload exfil"),

    # ─── PERSISTENCE ──────────────────────────────────────────────────────────
    (r"crontab\s+-e",            "PERSISTENCE", 50, "T1053.003", "Crontab edit"),
    (r"echo.+>>\s*/etc/cron",    "PERSISTENCE", 65, "T1053.003", "Cron job injection"),
    (r">\s*/etc/rc\.local",      "PERSISTENCE", 70, "T1037.004", "rc.local modification"),
    (r"echo.+>>\s*.+\.bashrc",   "PERSISTENCE", 60, "T1546.004", "bashrc backdoor"),
    (r"echo.+authorized_keys",   "PERSISTENCE", 72, "T1098.004", "SSH key persistence"),
    (r"\buseradd\b|\badduser\b", "PERSISTENCE", 72, "T1136.001", "New user creation"),
    (r"bash\s+-i\b",             "PERSISTENCE", 78, "T1059.004", "Interactive rev shell"),
    (r"\bmkfifo\b",              "PERSISTENCE", 70, "T1059.004", "Named pipe rev shell"),
    (r">\s*/tmp/[a-z0-9]+\.(sh|py|pl)","PERSISTENCE",62,"T1059","Script drop in /tmp"),
    (r"systemctl\s+enable",      "PERSISTENCE", 65, "T1543.002", "Systemd service enable"),
    (r"ln\s+-s.*/etc/",          "PERSISTENCE", 55, "T1546",     "Symlink persistence"),
    (r"\.profile|\.bash_login",  "PERSISTENCE", 50, "T1546.004", "Login script mod"),

    # ─── PRIVILEGE ESCALATION ─────────────────────────────────────────────────
    (r"\bsudo\b",                "PRIVESC",     45, "T1548.003", "sudo attempt"),
    (r"\bsu\s+root\b|\bsu\s*$",  "PRIVESC",     52, "T1548",     "su to root"),
    (r"chmod\s+[0-9]*[67][0-9]*\s+/","PRIVESC", 58, "T1222",     "World-writable path"),
    (r"chmod\s+\+s",             "PRIVESC",     72, "T1548.001", "SUID bit set"),
    (r"chown\s+root",            "PRIVESC",     65, "T1222",     "Chown to root"),
    (r"/etc/sudoers",            "PRIVESC",     78, "T1548.003", "sudoers access"),
    (r"cat\s+/etc/shadow",       "PRIVESC",     82, "T1003.008", "Shadow password read"),
    (r"python.*pty\.spawn",      "PRIVESC",     75, "T1059.006", "PTY shell upgrade"),
    (r"script\s+/dev/null",      "PRIVESC",     65, "T1059",     "TTY upgrade"),
    (r"pkexec\b|doas\b",         "PRIVESC",     70, "T1548",     "pkexec/doas privesc"),
    (r"exploit|CVE-\d{4}",       "PRIVESC",     85, "T1068",     "Exploit attempt"),

    # ─── CREDENTIAL HUNTING ───────────────────────────────────────────────────
    (r"secret\.txt|credentials|\.env\b","CRED_HUNT",50,"T1552.001","Credential file access"),
    (r"api[_\s-]*key",           "CRED_HUNT",   55, "T1552",     "API key search"),
    (r"aws_access|aws_secret",   "CRED_HUNT",   68, "T1552.005", "AWS credential access"),
    (r"password\s*=|passwd\s*=", "CRED_HUNT",   50, "T1552.001", "Hardcoded password"),
    (r"\.netrc|\.pgpass",        "CRED_HUNT",   55, "T1552",     "DB/FTP cred files"),
    (r"find\s+.+-name\s+.*pass", "CRED_HUNT",   62, "T1083",     "Password file search"),
    (r"grep\s+-r.*(pass|secret|token)","CRED_HUNT",62,"T1552","Credential grep"),
    (r"\bhistory\b",             "CRED_HUNT",   30, "T1552",     "Command history access"),
    (r"vault\s+(read|kv\s+get)", "CRED_HUNT",   65, "T1552",     "HashiCorp Vault read"),
    (r"docker\s+inspect",        "CRED_HUNT",   45, "T1552",     "Docker inspect (creds)"),

    # ─── MALWARE / C2 ─────────────────────────────────────────────────────────
    (r"\bnmap\b",                "MALWARE",     62, "T1046",     "Network scanner"),
    (r"\bmasscan\b",             "MALWARE",     72, "T1046",     "Mass port scanner"),
    (r"\bxmrig\b|\bminerd\b",    "MALWARE",     92, "T1496",     "Crypto miner"),
    (r"\bhydra\b|\bmedusa\b",    "MALWARE",     82, "T1110",     "Password cracker"),
    (r"\bmsfvenom\b|\bmetasploit\b","MALWARE",  92, "T1587",     "Metasploit framework"),
    (r"\bnc\s+-e\b|\bncat\b",    "MALWARE",     78, "T1059",     "Reverse shell tool"),
    (r"chmod\s+\+x.+\|\s*sh",   "MALWARE",     88, "T1059",     "Download + execute"),
    (r"\bsocat\b",               "MALWARE",     70, "T1059",     "Socat relay/shell"),
    (r"LD_PRELOAD\s*=",          "MALWARE",     80, "T1574.006", "LD_PRELOAD hijack"),
    (r"curl.+\|\s*(bash|sh|python)","MALWARE",  88, "T1059",     "Pipe to shell"),
    (r"wget.+\|\s*(bash|sh)",    "MALWARE",     88, "T1059",     "wget pipe to shell"),
]

# compile
_PATTERNS = [
    (re.compile(raw, re.IGNORECASE), cat, score, mitre, desc)
    for raw, cat, score, mitre, desc in _RAW
]

# sensitive VFS files → (category, bonus_score)
_SENSITIVE: dict[str,(str,int)] = {
    "/etc/shadow":                       ("PRIVESC",   32),
    "/etc/sudoers":                      ("PRIVESC",   28),
    "/home/corpuser/secret.txt":         ("CRED_HUNT", 38),
    "/home/corpuser/.ssh/id_rsa":        ("LATERAL",   42),
    "/home/corpuser/.ssh/authorized_keys":("LATERAL",  28),
    "/home/corpuser/projects/config.yaml":("CRED_HUNT",22),
    "/etc/passwd":                       ("RECON",     18),
    "/proc/version":                     ("RECON",      6),
    "/var/log/auth.log":                 ("RECON",     22),
}

_CAT_WEIGHT: dict[str,float] = {
    "RECON":       0.55,
    "LATERAL":     0.80,
    "EXFIL":       0.90,
    "PERSISTENCE": 0.90,
    "PRIVESC":     1.00,
    "CRED_HUNT":   0.70,
    "MALWARE":     1.00,
}

_CAT_SEVERITY: dict[str,str] = {
    "RECON":       "low",
    "LATERAL":     "medium",
    "EXFIL":       "high",
    "PERSISTENCE": "high",
    "PRIVESC":     "critical",
    "CRED_HUNT":   "medium",
    "MALWARE":     "critical",
}


# ══════════════════════════════════════════════════════════════════════════════
# GEOIP
# ══════════════════════════════════════════════════════════════════════════════

def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return any(a in n for n in _PRIVATE)
    except ValueError:
        return True


def geoip_lookup(ip: str) -> dict:
    """Enrich an IP with geographic data.  Private IPs return a local stub."""
    if _is_private(ip):
        return {"ip":ip,"country":"Local","country_code":"LO",
                "region":"","city":"Internal","lat":0.0,"lon":0.0,
                "isp":"Local Network","is_private":True}

    with _geo_lock:
        c = _geo_cache.get(ip)
        if c and (time.time() - c.get("_ts",0)) < _GEO_TTL:
            return c

    geo = {"ip":ip,"country":"Unknown","country_code":"??",
           "region":"","city":"Unknown","lat":0.0,"lon":0.0,
           "isp":"Unknown","is_private":False}

    if _HAS_REQ:
        try:
            r = _req.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields":"status,country,countryCode,regionName,city,lat,lon,isp,org"},
                timeout=3,
            )
            if r.status_code == 200:
                d = r.json()
                if d.get("status") == "success":
                    geo.update({
                        "country":      d.get("country","Unknown"),
                        "country_code": d.get("countryCode","??"),
                        "region":       d.get("regionName",""),
                        "city":         d.get("city",""),
                        "lat":          float(d.get("lat",0)),
                        "lon":          float(d.get("lon",0)),
                        "isp":          d.get("isp") or d.get("org","Unknown"),
                    })
        except Exception:
            pass

    geo["_ts"] = time.time()
    with _geo_lock:
        _geo_cache[ip] = geo
    return geo


# ══════════════════════════════════════════════════════════════════════════════
# SCORING
# ══════════════════════════════════════════════════════════════════════════════

def _add_score(ip: str, base: int, cat: str) -> int:
    delta = int(base * _CAT_WEIGHT.get(cat, 0.7))
    with _score_lock:
        e = _scores.setdefault(ip, {"score":0,"hits":[],"commands":0})
        e["score"] = min(100, e["score"] + delta)
        e["hits"].append(cat)
        return e["score"]

def _inc_commands(ip: str):
    with _score_lock:
        _scores.setdefault(ip, {"score":0,"hits":[],"commands":0})["commands"] += 1

def get_score(ip: str) -> int:
    with _score_lock:
        return _scores.get(ip, {}).get("score", 0)

def get_all_scores() -> dict[str,int]:
    with _score_lock:
        return {ip: v["score"] for ip,v in _scores.items()}

def get_session_detail(ip: str) -> dict:
    with _score_lock:
        e = _scores.get(ip, {})
        return {"score": e.get("score",0),
                "hits":  e.get("hits",[]),
                "commands": e.get("commands",0)}

def reset_score(ip: str):
    with _score_lock:
        _scores.pop(ip, None)


# ══════════════════════════════════════════════════════════════════════════════
# EVENT QUEUE
# ══════════════════════════════════════════════════════════════════════════════

def _push(ev: dict):
    try:
        event_queue.put_nowait(ev)
    except Full:
        try:
            event_queue.get_nowait()
            event_queue.put_nowait(ev)
        except Exception:
            pass


def _alert(ip, user, cmd, cat, base, mitre, desc, session_score, geo,
           etype="threat") -> dict:
    sev = _CAT_SEVERITY.get(cat, "low")
    return {
        "timestamp":     _now_ist(),
        "event_type":    etype,
        "source_ip":     ip,
        "username":      user,
        "command":       cmd,
        "category":      cat,
        "severity":      sev,
        "mitre_id":      mitre,
        "base_score":    base,
        "session_score": session_score,
        "high_priority": session_score > 70,
        "description":   desc,
        "rule_id":       f"HP_{cat}",
        "message":       f"[{cat}/{sev}] score={session_score} from {ip} ({geo.get('country','?')}) – {desc}",
        "geo": {
            "country":      geo.get("country","Unknown"),
            "country_code": geo.get("country_code","??"),
            "city":         geo.get("city",""),
            "region":       geo.get("region",""),
            "lat":          geo.get("lat",0.0),
            "lon":          geo.get("lon",0.0),
            "isp":          geo.get("isp","Unknown"),
        },
    }


# ══════════════════════════════════════════════════════════════════════════════
# PUBLIC API
# ══════════════════════════════════════════════════════════════════════════════

def analyse_command(ip: str, command: str, username: str = "corpuser") -> list[dict]:
    geo    = geoip_lookup(ip)
    alerts = []
    seen   = set()
    _inc_commands(ip)

    for pat, cat, base, mitre, desc in _PATTERNS:
        if pat.search(command) and cat not in seen:
            seen.add(cat)
            score = _add_score(ip, base, cat)
            a = _alert(ip, username, command, cat, base, mitre, desc, score, geo)
            alerts.append(a)
            _tlog.info(json.dumps(a))
            _push({**a, "event_type": "threat"})

            if score > 70:
                hp = {**a, "event_type": "high_priority_alert"}
                _tlog.info(json.dumps(hp))
                _push(hp)

    return alerts


def analyse_file_access(ip: str, path: str, username: str = "corpuser") -> list[dict]:
    if path not in _SENSITIVE:
        return []
    geo          = geoip_lookup(ip)
    cat, bonus   = _SENSITIVE[path]
    score        = _add_score(ip, bonus, cat)
    a = _alert(ip, username, f"READ:{path}", cat, bonus, "", f"Sensitive file: {path}", score, geo,
               etype="file_access")
    _tlog.info(json.dumps(a))
    _push(a)
    if score > 70:
        _push({**a, "event_type": "high_priority_alert"})
    return [a]


def log_auth_event(ip: str, username: str, password: str, success: bool):
    geo   = geoip_lookup(ip)
    score = get_score(ip)
    ev = {
        "timestamp":     _now_ist(),
        "event_type":    "auth",
        "source_ip":     ip,
        "username":      username,
        "password":      password,
        "success":       success,
        "session_score": score,
        "category":      "BRUTE_FORCE",
        "severity":      "medium",
        "message":       f"SSH auth {'OK' if success else 'FAIL'} from {ip} user={username!r}",
        "geo": {k: geo.get(k) for k in ("country","country_code","city","lat","lon","isp")},
    }
    if not success:
        _tlog.info(json.dumps(ev))
    _push(ev)


def log_connection(ip: str, port: int):
    geo = geoip_lookup(ip)
    _push({
        "timestamp":     _now_ist(),
        "event_type":    "connection",
        "source_ip":     ip,
        "port":          port,
        "session_score": 0,
        "geo": {k: geo.get(k) for k in ("country","country_code","city","lat","lon","isp")},
    })


def log_command_event(ip: str, command: str, username: str):
    """Push a raw command event to the SSE feed (non-threat commands)."""
    _push({
        "timestamp":     _now_ist(),
        "event_type":    "command",
        "source_ip":     ip,
        "username":      username,
        "command":       command,
        "session_score": get_score(ip),
    })
