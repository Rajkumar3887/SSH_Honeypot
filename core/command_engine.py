"""
Command Engine – emulates a realistic Bash shell over a Paramiko channel.

Key features
------------
* Full VFS-backed file / directory operations (ls, cat, touch, mkdir, rm, cp, mv, find, grep …)
* Permission model: normal user (corpuser) vs root (su escalation)
* Nano-like TUI editor (arrow keys, scroll, save)
* wget / curl download simulation
* Heredoc support (cat << EOF > file)
* Output redirection (> and >>)
* Integrated threat detection on every command
* Wazuh-compatible JSON logging
"""

import datetime
import calendar
import time
import random
import shlex
import json
import re
import fnmatch

from core.virtual_fs import build_vfs
from core.threat_engine import analyse_command, analyse_file_access, log_command_event
from config.settings import (
    FAKE_HOSTNAME, get_timestamp as _now_ist,
    MAX_COMMAND_LENGTH, MAX_ARGS, MAX_OUTPUT_SIZE, NANO_MAX_SIZE, SESSION_TIMEOUT,
)

# ── Realistic command timing (defeats <5ms fingerprinting) ────────────────────
_CMD_TIMING = {
    "pwd": (0.001, 0.006), "whoami": (0.001, 0.006), "echo": (0.001, 0.008),
    "cd":  (0.002, 0.010), "history":(0.003, 0.015), "clear":(0.001, 0.005),
    "date":(0.002, 0.008), "hostname":(0.002,0.008), "id":   (0.002, 0.007),
    "ls":  (0.008, 0.035), "cat":(0.005, 0.040), "head":(0.005, 0.025),
    "tail":(0.005, 0.025), "touch":(0.006,0.020), "mkdir":(0.006,0.020),
    "rm":  (0.008, 0.030), "cp":(0.010, 0.060),  "mv":  (0.008, 0.035),
    "wc":  (0.008, 0.040), "file":(0.010,0.030),  "which":(0.004,0.015),
    "find":(0.150, 1.800), "grep":(0.080, 0.900), "du":  (0.120, 0.900),
    "df":  (0.020, 0.080), "ps":  (0.015, 0.060), "top": (0.050, 0.150),
    "netstat":(0.030,0.120),"ss":  (0.020, 0.080),"uname":(0.002,0.010),
    "uptime":(0.003,0.012), "arch":(0.002, 0.008),
    "ping":(1.000, 4.200), "wget":(0.400, 3.500), "curl":(0.300, 3.000),
    "ssh": (0.800, 2.500), "scp": (0.600, 4.000),
    "apt": (0.800, 6.000), "apt-get":(0.800,6.000),"dpkg":(0.300,2.000),
    "nano":(0.030, 0.120), "vi":  (0.030, 0.120), "vim": (0.040, 0.150),
    "su":  (0.400, 1.200), "sudo":(0.300, 0.900), "passwd":(0.200,0.700),
    "awk": (0.020, 0.080), "sed": (0.015, 0.060), "sort":(0.010,0.050),
}
_DEFAULT_TIMING = (0.010, 0.060)


def _realistic_delay(cmd: str, args: list) -> None:
    """Sleep for a realistic, command-appropriate random duration."""
    lo, hi = _CMD_TIMING.get(cmd, _DEFAULT_TIMING)
    # Recursive/deep scans skew toward the slow end
    if args and cmd in ("grep", "find", "ls", "du"):
        arg_str = " ".join(args)
        if "-r" in arg_str or "-R" in arg_str or "/" in arg_str:
            lo = lo + (hi - lo) * 0.5
    time.sleep(random.uniform(lo, hi))


# ── Static command response table ────────────────────────────────────────────

STATIC_RESPONSES = {
    "uname -a":
        "Linux ubuntu-server-01 5.4.0-42-generic #46-Ubuntu SMP "
        "Fri Jul 10 00:24:02 UTC 2020 x86_64 x86_64 x86_64 GNU/Linux",
    "uname -r":  "5.4.0-42-generic",
    "uname -m":  "x86_64",
    "arch":      "x86_64",
    "uptime":
        " 12:04:15 up 42 days, 18:32,  1 user,  load average: 0.01, 0.04, 0.00",
    "hostname":  FAKE_HOSTNAME,
    "ip addr":
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN\n"
        "    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc mq state UP\n"
        "    link/ether 0a:1b:2c:3d:4e:5f brd ff:ff:ff:ff:ff:ff\n"
        "    inet 192.168.1.15/24 brd 192.168.1.255 scope global eth0",
    "ip a":
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    inet 192.168.1.15/24 scope global eth0",
    "ifconfig":
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "      inet 192.168.1.15  netmask 255.255.255.0  broadcast 192.168.1.255\n"
        "lo:   flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "      inet 127.0.0.1  netmask 255.0.0.0",
    "df -h":
        "Filesystem      Size  Used Avail Use% Mounted on\n"
        "/dev/sda1        40G  8.4G   30G  22% /\n"
        "tmpfs           1.6G     0  1.6G   0% /dev/shm",
    "df":
        "Filesystem     1K-blocks    Used Available Use% Mounted on\n"
        "/dev/sda1       41151808 8806400  30238592  23% /",
    "ps aux":
        "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
        "root         1  0.0  0.1 169444 11232 ?        Ss   Jan10   0:09 /sbin/init\n"
        "root       420  0.0  0.0  72296  5888 ?        Ss   Jan10   0:00 /usr/sbin/sshd\n"
        "corpuser  1337  0.0  0.0  21992  5468 pts/0    Ss   12:04   0:00 -bash",
    "ps":
        "  PID TTY          TIME CMD\n"
        " 1337 pts/0    00:00:00 bash\n"
        " 1402 pts/0    00:00:00 ps",
    "env":
        "SHELL=/bin/bash\nUSER=corpuser\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "HOME=/home/corpuser\nLOGNAME=corpuser\nTERM=xterm-256color\nLANG=en_US.UTF-8",
    "printenv":
        "SHELL=/bin/bash\nUSER=corpuser\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        "HOME=/home/corpuser\nTERM=xterm-256color\nLANG=en_US.UTF-8",
    "netstat -an":
        "Active Internet connections (servers and established)\n"
        "Proto Recv-Q Send-Q Local Address     Foreign Address   State\n"
        "tcp        0      0 0.0.0.0:22        0.0.0.0:*         LISTEN\n"
        "tcp        0      0 127.0.0.1:5432    0.0.0.0:*         LISTEN",
    "ss -tlnp":
        "State   Recv-Q Send-Q   Local Address:Port   Peer Address:Port\n"
        "LISTEN  0      128            0.0.0.0:22          0.0.0.0:*\n"
        "LISTEN  0      5            127.0.0.1:5432        0.0.0.0:*",
    "last":
        "corpuser pts/0   192.168.1.5   Mon Jan 10 08:01   still logged in\n"
        "corpuser pts/0   10.0.0.5      Sun Jan  9 14:22 - 15:44  (01:22)\n"
        "reboot   system boot  5.4.0-42-generic Sat Nov 30 09:17",
    "w":
        " 12:04:15 up 42 days, 18:32,  1 user,  load average: 0.01, 0.04, 0.00\n"
        "USER     TTY      FROM             LOGIN@   IDLE JCPU PCPU WHAT\n"
        "corpuser pts/0    192.168.1.5      12:04    0.00s 0.04s 0.00s w",
}


# ── Permission model ──────────────────────────────────────────────────────────

NORMAL_USER_CMDS = {
    "ls", "cd", "pwd", "cat", "echo", "touch", "mkdir", "rm", "rmdir",
    "cp", "mv", "find", "grep", "head", "tail", "wc", "file", "which",
    "whoami", "id", "hostname", "uname", "uptime", "arch", "date", "cal",
    "history", "clear", "exit", "logout", "env", "printenv",
    "ps", "ping", "wget", "curl", "python", "python3",
    "nano", "vi", "vim", "ifconfig", "ip", "netstat", "ss",
    "df", "last", "w", "su", "sudo",
}

ROOT_ONLY_CMDS = {
    "useradd", "userdel", "usermod", "passwd",
    "mount", "umount", "iptables",
    "systemctl", "service",
    "apt", "apt-get", "yum", "dnf",
    "reboot", "shutdown", "halt", "poweroff",
    "crontab", "visudo", "fdisk",
    "chown",
}

RESTRICTED_READ_NORMAL = {"/etc/shadow", "/root", "/etc/sudoers"}
WRITE_RESTRICTED_DIRS_NORMAL = {"/etc", "/bin", "/usr", "/sbin", "/lib", "/boot", "/proc"}


# ── Emulated Shell ────────────────────────────────────────────────────────────

def _pipe_dispatch(cmd_str: str, stdin_text: str = "") -> str:
    """
    Lightweight dispatcher used only for pipeline segments.
    Returns the command output as a string (no channel I/O).
    Supports: grep, head, tail, wc, cat, echo, sort, uniq, cut, tr, awk, sed
    Falls back to treating stdin as passthrough for unknown commands.
    """
    if not cmd_str:
        return stdin_text
    try:
        parts = cmd_str.split()
    except Exception:
        return stdin_text
    if not parts:
        return stdin_text
    cmd = parts[0].lower()
    args = parts[1:]
    lines = stdin_text.splitlines() if stdin_text else []

    if cmd == "grep":
        if not args:
            return stdin_text
        # Handle -v (invert), -i (ignore case), -n (line numbers)
        invert = "-v" in args
        ignore_case = "-i" in args
        show_num = "-n" in args
        pat_args = [a for a in args if not a.startswith("-")]
        if not pat_args:
            return stdin_text
        pattern = pat_args[0]
        try:
            flags = re.IGNORECASE if ignore_case else 0
            result = []
            for i, ln in enumerate(lines, 1):
                match = bool(re.search(pattern, ln, flags))
                if match != invert:
                    result.append(f"{i}:{ln}" if show_num else ln)
            return "\n".join(result)
        except re.error:
            return stdin_text

    elif cmd == "head":
        n = 10
        for a in args:
            if a.startswith("-") and a[1:].isdigit():
                n = int(a[1:])
        return "\n".join(lines[:n])

    elif cmd == "tail":
        n = 10
        for a in args:
            if a.startswith("-") and a[1:].isdigit():
                n = int(a[1:])
        return "\n".join(lines[-n:])

    elif cmd == "wc":
        if "-l" in args:
            return str(len(lines))
        elif "-w" in args:
            return str(sum(len(ln.split()) for ln in lines))
        elif "-c" in args:
            return str(len(stdin_text))
        else:
            wc = len(lines)
            ww = sum(len(ln.split()) for ln in lines)
            wchar = len(stdin_text)
            return f"{wc:>8}{ww:>8}{wchar:>8}"

    elif cmd == "sort":
        reverse = "-r" in args
        unique  = "-u" in args
        result = sorted(set(lines) if unique else lines, reverse=reverse)
        return "\n".join(result)

    elif cmd == "uniq":
        if not lines:
            return ""
        result = [lines[0]]
        for ln in lines[1:]:
            if ln != result[-1]:
                result.append(ln)
        return "\n".join(result)

    elif cmd == "cat":
        return stdin_text  # cat in a pipe just passes through

    elif cmd == "echo":
        return " ".join(args)

    elif cmd in ("awk", "gawk"):
        # Basic awk: print $N support
        prog = args[0] if args else "{print}"
        m = re.search(r"print\s+\$(\d+)", prog)
        if m:
            col = int(m.group(1)) - 1
            result = []
            for ln in lines:
                flds = ln.split()
                result.append(flds[col] if col < len(flds) else "")
            return "\n".join(result)
        return stdin_text

    elif cmd in ("cut",):
        delim = ","
        fields = []
        i = 0
        while i < len(args):
            if args[i] == "-d" and i + 1 < len(args):
                delim = args[i+1]; i += 2
            elif args[i] == "-f" and i + 1 < len(args):
                try: fields = [int(x)-1 for x in args[i+1].split(",")]
                except: pass
                i += 2
            else:
                i += 1
        if not fields:
            return stdin_text
        result = []
        for ln in lines:
            parts = ln.split(delim)
            result.append(delim.join(parts[f] for f in fields if f < len(parts)))
        return "\n".join(result)

    elif cmd == "tr":
        if len(args) >= 2:
            tbl = str.maketrans(args[0], args[1])
            return stdin_text.translate(tbl)
        return stdin_text

    elif cmd in ("sed",):
        if not args:
            return stdin_text
        prog = args[0]
        m = re.match(r"s/([^/]*)/([^/]*)/([gi]*)", prog)
        if m:
            pat, repl, flags_str = m.group(1), m.group(2), m.group(3)
            count = 0 if "g" in flags_str else 1
            rflags = re.IGNORECASE if "i" in flags_str else 0
            try:
                return re.sub(pat, repl, stdin_text, count=count, flags=rflags)
            except re.error:
                pass
        return stdin_text

    elif cmd in ("more", "less"):
        return stdin_text  # pass through in pipe context

    # Fallback: unknown command in pipe, return stdin
    return stdin_text


# ── Dynamic ps aux renderer (varies per call — defeats static output detect) ──
_BASE_PROCS = [
    ("root",     0.0, 0.1, "/sbin/init splash"),
    ("root",     0.0, 0.0, "[kthreadd]"),
    ("root",     0.0, 0.0, "[ksoftirqd/0]"),
    ("root",     0.0, 0.2, "/lib/systemd/systemd-journald"),
    ("systemd+", 0.0, 0.1, "/lib/systemd/systemd-networkd"),
    ("systemd+", 0.0, 0.1, "/lib/systemd/systemd-resolved"),
    ("root",     0.0, 0.3, "/usr/sbin/sshd -D"),
    ("root",     0.1, 0.4, "/usr/sbin/cron -f"),
    ("www-data", 0.2, 1.2, "nginx: worker process"),
    ("root",     0.0, 0.8, "nginx: master process /usr/sbin/nginx -g daemon on; master_process on;"),
    ("mysql",    0.3, 8.4, "/usr/sbin/mysqld"),
    ("root",     0.0, 0.1, "/usr/sbin/rsyslogd -n -iNONE"),
    ("message+", 0.0, 0.2, "/usr/bin/dbus-daemon --system --print-pid"),
    ("root",     0.0, 0.1, "/usr/lib/accountsservice/accounts-daemon"),
    ("root",     0.0, 0.0, "[migration/0]"),
]

_SESSION_PID_BASE = random.randint(300, 800)  # randomized per honeypot start


def _render_ps_aux(current_user: str) -> str:
    """Render ps aux with slight, believable variance each call (CPU%, PID drift)."""
    lines = [
        "USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
    ]
    pid = _SESSION_PID_BASE
    boot_options = ["09:1" + str(random.randint(0, 9)), "Sep" + str(random.randint(20, 26))]

    for user, base_cpu, base_mem, cmd in _BASE_PROCS:
        pid += random.randint(1, 45)
        cpu  = max(0.0, base_cpu + random.uniform(-0.05, 0.3))
        mem  = max(0.0, base_mem + random.uniform(-0.05, 0.15))
        vsz  = random.randint(4000, 280000)
        rss  = int(vsz * random.uniform(0.08, 0.38))
        boot = random.choice(boot_options)
        lines.append(
            f"{user:<12} {pid:>5} {cpu:>4.1f} {mem:>4.1f}"
            f" {vsz:>6} {rss:>5} ?        Ss   {boot}   0:0{random.randint(0,9)} {cmd}"
        )

    # Attacker's own shell — always visible in real ps
    pid += random.randint(5, 25)
    lines.append(
        f"{current_user:<12} {pid:>5}  0.0  0.1   7624  3868 pts/0    "
        f"Ss   {random.choice(boot_options)}   0:00 -bash"
    )
    lines.append(
        f"{current_user:<12} {pid+1:>5}  0.0  0.1   9256  3124 pts/0    "
        f"R+   {random.choice(boot_options)}   0:00 ps aux"
    )
    return "\n".join(lines) + "\n"


def emulated_shell(channel, client_ip: str, cmd_logger, db=None):
    """
    Main interactive shell loop.

    Parameters
    ----------
    channel    : paramiko.Channel
    client_ip  : str
    cmd_logger : logging.Logger  – command audit logger from session.py
    db         : DatabaseManager or None
    """
    home_dir    = "/home/corpuser"
    current_dir = home_dir
    vfs, file_contents = build_vfs()
    cmd_history: list[str] = []

    current_user = "corpuser"
    current_uid  = 1001

    # ── Path helpers ──────────────────────────────────────────────────────────
    def resolve(path: str) -> str:
        if not path or path == "~":
            return home_dir
        if path.startswith("~/"):
            path = home_dir + path[1:]
        if not path.startswith("/"):
            path = current_dir.rstrip("/") + "/" + path
        parts = []
        for seg in path.split("/"):
            if seg == "..":
                if parts:
                    parts.pop()
            elif seg and seg != ".":
                parts.append(seg)
        return "/" + "/".join(parts) if parts else "/"

    def parent_of(path: str) -> str:
        segs = path.rstrip("/").split("/")
        return "/".join(segs[:-1]) or "/"

    def basename(path: str) -> str:
        return path.rstrip("/").split("/")[-1]

    def vfs_add(path: str, entry_type: str = "file"):
        p = parent_of(path)
        name = basename(path)
        if p not in vfs:
            vfs[p] = []
        if name not in vfs[p]:
            vfs[p].append(name)
        if entry_type == "dir" and path not in vfs:
            vfs[path] = []

    def vfs_remove(path: str):
        p = parent_of(path)
        name = basename(path)
        if p in vfs and name in vfs[p]:
            vfs[p].remove(name)
        if path in file_contents:
            del file_contents[path]
        if path in vfs:
            del vfs[path]

    # ── Permission helpers ────────────────────────────────────────────────────
    def can_run(cmd: str) -> tuple[bool, str]:
        if current_uid == 0:
            return True, ""
        if cmd in ROOT_ONLY_CMDS:
            return False, f"{cmd}: Permission denied (requires root)"
        return True, ""

    def can_read(path: str) -> tuple[bool, str]:
        if current_uid == 0:
            return True, ""
        for r in RESTRICTED_READ_NORMAL:
            if path == r or path.startswith(r + "/"):
                return False, f"cat: {path}: Permission denied"
        return True, ""

    def can_write(path: str) -> tuple[bool, str]:
        if current_uid == 0:
            return True, ""
        for rdir in WRITE_RESTRICTED_DIRS_NORMAL:
            if path.startswith(rdir + "/") or path == rdir:
                if path.startswith(home_dir):
                    return True, ""
                return False, f"Permission denied: cannot write to {path}"
        return True, ""

    # ── Login banner ──────────────────────────────────────────────────────────
    now = datetime.datetime.now()
    channel.send(b"\r\nWelcome to Ubuntu 20.04.5 LTS (GNU/Linux 5.4.0-42-generic x86_64)\r\n\r\n")
    channel.send(b" * Documentation:  https://help.ubuntu.com\r\n")
    channel.send(b" * Management:     https://landscape.canonical.com\r\n")
    channel.send(b" * Support:        https://ubuntu.com/advantage\r\n\r\n")
    channel.send(
        f"Last login: {now.strftime('%a %b %d %H:%M:%S %Y')} from {client_ip}\r\n\r\n".encode()
    )

    # ── Session state ─────────────────────────────────────────────────────────
    session_start   = time.time()
    last_activity   = time.time()

    # ── Environment variables (per-session) ───────────────────────────────────
    _env: dict[str, str] = {
        "HOME":    home_dir,
        "USER":    current_user,
        "LOGNAME": current_user,
        "PWD":     current_dir,
        "SHELL":   "/bin/bash",
        "TERM":    "xterm-256color",
        "LANG":    "en_US.UTF-8",
        "PATH":    "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "HOSTNAME": FAKE_HOSTNAME,
        "PS1":     r"\u@\h:\w\$ ",
    }

    # ── Output helper (truncates to MAX_OUTPUT_SIZE) ──────────────────────────
    def _send(data: str) -> None:
        if len(data) > MAX_OUTPUT_SIZE:
            data = data[:MAX_OUTPUT_SIZE] + f"\r\n... (output truncated at {MAX_OUTPUT_SIZE//1024} KB)\r\n"
        channel.send((data.replace("\n", "\r\n")).encode(errors="replace"))

    # ── Env-var expander ($VAR / ${VAR}) ─────────────────────────────────────
    def _expand_vars(s: str) -> str:
        def _repl(m: re.Match) -> str:
            name = m.group(1) or m.group(2)
            return _env.get(name, "")
        return re.sub(r'\$\{(\w+)\}|\$(\w+)', _repl, s)

    # ── Glob expander (* ? patterns in a single token) ───────────────────────
    def _expand_glob(token: str, cwd: str) -> list[str]:
        if not any(c in token for c in ("*", "?", "[")):
            return [token]
        # Resolve relative globs against cwd
        if not token.startswith("/"):
            base = cwd
            pattern = token
        else:
            base = token.rsplit("/", 1)[0] or "/"
            pattern = token.rsplit("/", 1)[1]
        entries = vfs.get(base, [])
        matched = [f"{base}/{e}" if base != "/" else f"/{e}"
                   for e in entries if fnmatch.fnmatch(e, pattern)]
        return sorted(matched) if matched else [token]

    # ── Pipe executor (VFS-aware) ─────────────────────────────────────────────
    def _exec_for_pipe(cmd_str: str, stdin_text: str = "") -> str:
        """Execute one pipeline segment; resolves VFS content before filtering."""
        seg = cmd_str.strip()
        if not seg:
            return stdin_text
        try:
            _parts = seg.split()
        except Exception:
            return stdin_text
        if not _parts:
            return stdin_text
        _cmd = _parts[0].lower()
        _args = _parts[1:]
        # ── VFS-backed source commands ────────────────────────────────────────
        if _cmd == "cat":
            lines = []
            for _a in (_args if _args else []):
                _p = resolve(_a)
                _ok, _ = can_read(_p)
                if not _ok:
                    lines.append(f"cat: {_a}: Permission denied")
                elif _p in file_contents:
                    lines.append(file_contents[_p])
                else:
                    lines.append(f"cat: {_a}: No such file or directory")
            return "\n".join(lines)
        if _cmd == "ls":
            _path = resolve(_args[0]) if _args and not _args[0].startswith("-") else current_dir
            _entries = vfs.get(_path, [])
            return "\n".join(sorted(_entries))
        if _cmd == "echo":
            return " ".join(_expand_vars(" ".join(_args)).split())
        if _cmd == "pwd":
            return current_dir
        if _cmd == "whoami":
            return current_user
        # ── Filter commands (grep, head, tail, wc, sort, …) ──────────────────
        return _pipe_dispatch(seg, stdin_text)

    # ── Main input loop ───────────────────────────────────────────────────────
    while True:
        # ── Session timeout ──────────────────────────────────────────────
        _now_t = time.time()
        if _now_t - last_activity > SESSION_TIMEOUT:
            channel.send(b"\r\nbash: session timeout (idle >1h)\r\n")
            break
        # Keep _env in sync with mutable state
        _env["PWD"]  = current_dir
        _env["USER"] = current_user
        _env["HOME"] = home_dir

        disp = "~" if current_dir == home_dir else current_dir
        if current_uid == 0:
            channel.send(f"root@{FAKE_HOSTNAME}:{disp}# ".encode())
        else:
            channel.send(f"corpuser@{FAKE_HOSTNAME}:{disp}$ ".encode())

        # Char-by-char readline
        buf = ""
        while True:
            try:
                ch = channel.recv(1)
            except Exception:
                return
            if not ch:
                return
            if ch in (b"\r", b"\n"):
                channel.send(b"\r\n")
                break
            if ch in (b"\x7f", b"\x08"):
                if buf:
                    buf = buf[:-1]
                    channel.send(b"\x08 \x08")
            elif ch == b"\x03":
                channel.send(b"^C\r\n")
                buf = ""
                break
            elif ch == b"\x04":
                channel.send(b"logout\r\n")
                channel.close()
                return
            else:
                try:
                    buf += ch.decode("utf-8", errors="ignore")
                    channel.send(ch)
                except Exception:
                    pass

        full_cmd = buf.strip()
        if not full_cmd:
            continue

        # ── Update activity timer ────────────────────────────────────────
        last_activity = time.time()

        # ── Input validation ─────────────────────────────────────────────
        if len(full_cmd) > MAX_COMMAND_LENGTH:
            channel.send(
                f"bash: command too long (max {MAX_COMMAND_LENGTH} chars)\r\n".encode()
            )
            continue

        # ── && / || / ; command chaining ────────────────────────────────────
        if any(op in full_cmd for op in (' && ', ' || ', ';')) and '|' not in full_cmd:
            import re as _re
            # Tokenize respecting && || ;
            _chain_parts = _re.split(r'(\s*&&\s*|\s*\|\|\s*|\s*;\s*)', full_cmd)
            _last_ok = True
            _i2 = 0
            _parts2 = [p.strip() for p in _chain_parts]
            while _i2 < len(_parts2):
                _tok = _parts2[_i2]
                if not _tok:
                    _i2 += 1; continue
                if _tok in ('&&', '||', ';'):
                    _i2 += 1; continue
                # Determine if we should execute based on previous result
                _prev_op = _parts2[_i2 - 1].strip() if _i2 > 0 else ';'
                _should_run = (
                    _prev_op == ';' or
                    (_prev_op == '&&' and _last_ok) or
                    (_prev_op == '||' and not _last_ok)
                )
                if _should_run and _tok:
                    _sub_out = _exec_for_pipe(_tok, '')
                    _last_ok = not (_sub_out.startswith('bash:') and 'not found' in _sub_out)
                    if _sub_out:
                        _send(_sub_out + '\n')
                _i2 += 1
            cmd_logger.info(__import__('json').dumps({
                'timestamp': _now_ist(), 'event_type': 'honeypot_command',
                'source_ip': client_ip, 'username': current_user, 'command': full_cmd,
            }))
            if db: db.insert_command(client_ip, current_user, full_cmd)
            _alerts2 = analyse_command(client_ip, full_cmd, current_user)
            if db and _alerts2:
                for _a2 in _alerts2: db.insert_threat(_a2)
            log_command_event(client_ip, full_cmd, current_user)
            cmd_history.append(full_cmd)
            continue

        if ";" in full_cmd and "|" not in full_cmd:
            for _sub in full_cmd.split(";"):
                _sub = _sub.strip()
                if _sub:
                    chan_out = _exec_for_pipe(_sub, "")
                    if chan_out:
                        _send(chan_out + "\n")
            cmd_logger.info(__import__('json').dumps({
                "timestamp": _now_ist(), "event_type": "honeypot_command",
                "source_ip": client_ip, "username": current_user, "command": full_cmd,
            }))
            if db:
                db.insert_command(client_ip, current_user, full_cmd)
            cmd_history.append(full_cmd)
            continue

        # ── Env-var expansion ($HOME, ${USER}, etc.) ─────────────────────
        full_cmd = _expand_vars(full_cmd)

        # ── Pipe operator (cmd1 | cmd2 | cmd3) ──────────────────────────
        if "|" in full_cmd:
            _segments = [s.strip() for s in full_cmd.split("|") if s.strip()]
            _pbuf = ""
            for _si, _seg in enumerate(_segments):
                if _si < len(_segments) - 1:
                    _pbuf = _exec_for_pipe(_seg, _pbuf)
                else:
                    _presult = _exec_for_pipe(_seg, _pbuf)
                    if _presult:
                        _send(_presult)
            cmd_logger.info(__import__('json').dumps({
                "timestamp":  _now_ist(), "event_type": "honeypot_command",
                "source_ip":  client_ip, "username": current_user, "command": full_cmd,
            }))
            if db:
                db.insert_command(client_ip, current_user, full_cmd)
            _alerts = analyse_command(client_ip, full_cmd, current_user)
            if db and _alerts:
                for _a in _alerts: db.insert_threat(_a)
            log_command_event(client_ip, full_cmd, current_user)
            cmd_history.append(full_cmd)
            continue

        # NOTE: cmd_history.append happens AFTER execution below
        cmd_logger.info(json.dumps({
            "timestamp":  _now_ist(),
            "event_type": "honeypot_command",
            "source_ip":  client_ip,
            "username":   current_user,
            "command":    full_cmd,
        }))

        # Save to database
        if db:
            db.insert_command(client_ip, current_user, full_cmd)

        # Threat analysis
        alerts = analyse_command(client_ip, full_cmd, current_user)
        if db and alerts:
            for a in alerts:
                db.insert_threat(a)

        # Push raw command to live dashboard (even if no threat matched)
        log_command_event(client_ip, full_cmd, current_user)

        # ── Redirection parsing ───────────────────────────────────────────────
        redirect_file   = None
        redirect_append = False
        try:
            raw_tokens = shlex.split(full_cmd)
        except ValueError:
            raw_tokens = full_cmd.split()

        cmd_tokens = []
        ri = 0
        while ri < len(raw_tokens):
            tok = raw_tokens[ri]
            if tok == ">>":
                redirect_append = True
                if ri + 1 < len(raw_tokens):
                    redirect_file = resolve(raw_tokens[ri + 1])
                    ri += 2
                    continue
            elif tok == ">":
                redirect_append = False
                if ri + 1 < len(raw_tokens):
                    redirect_file = resolve(raw_tokens[ri + 1])
                    ri += 2
                    continue
            elif tok.startswith(">>") and len(tok) > 2:
                redirect_append = True
                redirect_file = resolve(tok[2:])
            elif tok.startswith(">") and len(tok) > 1:
                redirect_append = False
                redirect_file = resolve(tok[1:])
            else:
                cmd_tokens.append(tok)
            ri += 1

        tokens = cmd_tokens
        base   = tokens[0].lower() if tokens else ""  # case-insensitive
        args   = tokens[1:]
        _realistic_delay(base, args)  # timing realism
        # Apply glob expansion to args
        expanded_args = []
        for _arg in args:
            expanded_args.extend(_expand_glob(_arg, current_dir))
        args = expanded_args
        out    = ""

        # ── Heredoc ───────────────────────────────────────────────────────────
        heredoc_content = None
        if "<<" in tokens:
            idx = tokens.index("<<")
            if idx + 1 < len(tokens):
                heredoc_delim = tokens[idx + 1].strip("'\"")
                tokens = tokens[:idx] + tokens[idx + 2:]
                base   = tokens[0] if tokens else base
                args   = tokens[1:]
                hd_lines = []
                while True:
                    channel.send(b"> ")
                    hd_buf = ""
                    while True:
                        try:
                            hc = channel.recv(1)
                        except Exception:
                            break
                        if not hc:
                            break
                        if hc in (b"\r", b"\n"):
                            channel.send(b"\r\n")
                            break
                        elif hc in (b"\x7f", b"\x08"):
                            if hd_buf:
                                hd_buf = hd_buf[:-1]
                                channel.send(b"\x08 \x08")
                        else:
                            try:
                                hd_buf += hc.decode("utf-8", errors="ignore")
                                channel.send(hc)
                            except Exception:
                                pass
                    if hd_buf.strip() == heredoc_delim:
                        break
                    hd_lines.append(hd_buf)
                heredoc_content = "\n".join(hd_lines)

        # ── Permission gate ───────────────────────────────────────────────────
        if base:
            allowed, perm_err = can_run(base)
            if not allowed:
                channel.send((perm_err + "\r\n").encode(errors="replace"))
                continue

        # ── Command dispatch ──────────────────────────────────────────────────

        # Dynamic overrides — intercept before STATIC_RESPONSES lookup
        if base == "ps" and ("aux" in args or "a" in args or not args):
            out = _render_ps_aux(current_user)
        elif full_cmd in STATIC_RESPONSES:
            out = STATIC_RESPONSES[full_cmd]

        elif base in ("exit", "logout"):
            channel.send(b"logout\r\n")
            break

        elif base == "clear":
            channel.send(b"\033[H\033[2J")
            continue

        elif base == "pwd":
            out = current_dir

        elif base == "whoami":
            out = current_user

        elif base == "hostname":
            out = FAKE_HOSTNAME

        elif base == "id":
            if current_uid == 0:
                out = "uid=0(root) gid=0(root) groups=0(root)"
            else:
                out = "uid=1001(corpuser) gid=1001(corpuser) groups=1001(corpuser),27(sudo)"

        elif base == "echo":
            out = " ".join(args)

        elif base == "date":
            out = datetime.datetime.now().strftime("%a %b %d %H:%M:%S UTC %Y")

        elif base == "cal":
            n = datetime.datetime.now()
            out = calendar.TextCalendar().formatmonth(n.year, n.month).rstrip()

        elif base == "uname":
            flag = args[0] if args else ""
            lookup = f"uname {flag}" if flag else "uname -s"
            out = STATIC_RESPONSES.get(lookup, STATIC_RESPONSES.get("uname -a", "Linux"))

        elif base == "uptime":
            out = STATIC_RESPONSES["uptime"]

        elif base == "arch":
            out = "x86_64"

        elif base == "history":
            out = "\n".join(f"  {i+1}  {c}" for i, c in enumerate(cmd_history))

        # ── cd ────────────────────────────────────────────────────────────────
        elif base == "cd":
            target = args[0] if args else "~"
            if target == "-":
                out = current_dir
            else:
                new = resolve(target)
                if new in vfs:
                    current_dir = new
                elif new in file_contents:
                    out = f"bash: cd: {target}: Not a directory"
                else:
                    out = f"bash: cd: {target}: No such file or directory"

        # ── ls ────────────────────────────────────────────────────────────────
        elif base == "ls":
            path_arg = next((a for a in args if not a.startswith("-")), None)
            show_all = "-a" in args or "-la" in args or "-al" in args
            long_fmt = "-l" in args or "-la" in args or "-al" in args
            tgt = resolve(path_arg) if path_arg else current_dir

            if tgt in vfs:
                entries = vfs[tgt]
                if not show_all:
                    entries = [e for e in entries if not e.startswith(".")]
                if long_fmt:
                    lines = ["total " + str(len(entries) * 4)]
                    for e in sorted(entries):
                        fpath = tgt.rstrip("/") + "/" + e
                        is_dir = fpath in vfs
                        perm   = "drwxr-xr-x" if is_dir else "-rw-r--r--"
                        size   = len(file_contents.get(fpath, "")) or 4096
                        lines.append(f"{perm} 1 corpuser corpuser {size:>8} Jan 10 08:00 {e}")
                    out = "\n".join(lines)
                else:
                    out = "  ".join(sorted(entries))
            elif tgt in file_contents:
                out = path_arg or tgt
            else:
                out = f"ls: cannot access '{path_arg}': No such file or directory"

        # ── cat ───────────────────────────────────────────────────────────────
        elif base == "cat":
            if heredoc_content is not None:
                out = heredoc_content
            elif not args and redirect_file:
                lines_collected = []
                cur_line_buf = ""
                while True:
                    try:
                        c = channel.recv(1)
                    except Exception:
                        break
                    if not c:
                        break
                    if c == b"\x04":
                        if cur_line_buf:
                            lines_collected.append(cur_line_buf)
                        channel.send(b"\r\n")
                        break
                    if c in (b"\r", b"\n"):
                        channel.send(b"\r\n")
                        lines_collected.append(cur_line_buf)
                        cur_line_buf = ""
                    elif c in (b"\x7f", b"\x08"):
                        if cur_line_buf:
                            cur_line_buf = cur_line_buf[:-1]
                            channel.send(b"\x08 \x08")
                    else:
                        try:
                            ch_str = c.decode("utf-8", errors="ignore")
                            cur_line_buf += ch_str
                            channel.send(c)
                        except Exception:
                            pass
                out = "\n".join(lines_collected)
            elif not args:
                out = "cat: missing operand"
            else:
                parts_out = []
                for a in args:
                    p = resolve(a)
                    ok, perr = can_read(p)
                    if not ok:
                        parts_out.append(perr)
                    elif p in file_contents:
                        parts_out.append(file_contents[p])
                        analyse_file_access(client_ip, p, current_user)
                        if db:
                            db.insert_file_access(client_ip, p, current_user)
                    elif p in vfs:
                        parts_out.append(f"cat: {a}: Is a directory")
                    else:
                        parts_out.append(f"cat: {a}: No such file or directory")
                out = "\n".join(parts_out)

        # ── touch ─────────────────────────────────────────────────────────────
        elif base == "touch":
            if not args:
                out = "touch: missing file operand"
            else:
                errors = []
                for a in args:
                    p = resolve(a)
                    ok, _ = can_write(p)
                    if not ok:
                        errors.append(f"touch: cannot touch '{a}': Permission denied")
                    else:
                        if p not in file_contents:
                            file_contents[p] = ""
                        vfs_add(p, "file")
                out = "\n".join(errors)

        # ── mkdir ─────────────────────────────────────────────────────────────
        elif base == "mkdir":
            if not args:
                out = "mkdir: missing operand"
            else:
                errors = []
                for a in args:
                    p = resolve(a)
                    ok, _ = can_write(p)
                    if not ok:
                        errors.append(f"mkdir: cannot create directory '{a}': Permission denied")
                    elif p in vfs or p in file_contents:
                        errors.append(f"mkdir: cannot create directory '{a}': File exists")
                    else:
                        vfs_add(p, "dir")
                out = "\n".join(errors)

        # ── rmdir ─────────────────────────────────────────────────────────────
        elif base == "rmdir":
            if not args:
                out = "rmdir: missing operand"
            else:
                errors = []
                for a in args:
                    p = resolve(a)
                    if p not in vfs:
                        errors.append(f"rmdir: failed to remove '{a}': No such file or directory")
                    elif vfs[p]:
                        errors.append(f"rmdir: failed to remove '{a}': Directory not empty")
                    else:
                        vfs_remove(p)
                out = "\n".join(errors)

        # ── rm ────────────────────────────────────────────────────────────────
        elif base == "rm":
            if not args:
                out = "rm: missing operand"
            else:
                recursive = "-r" in args or "-rf" in args or "-fr" in args
                errors = []
                targets = [a for a in args if not a.startswith("-")]
                for a in targets:
                    p = resolve(a)
                    if p in file_contents:
                        vfs_remove(p)
                    elif p in vfs:
                        if recursive:
                            to_del = [k for k in list(vfs.keys()) + list(file_contents.keys())
                                      if k == p or k.startswith(p + "/")]
                            for k in to_del:
                                if k in vfs:           del vfs[k]
                                if k in file_contents: del file_contents[k]
                            p2   = parent_of(p)
                            name = basename(p)
                            if p2 in vfs and name in vfs[p2]:
                                vfs[p2].remove(name)
                        else:
                            errors.append(f"rm: cannot remove '{a}': Is a directory")
                    else:
                        errors.append(f"rm: cannot remove '{a}': No such file or directory")
                out = "\n".join(errors)

        # ── cp ────────────────────────────────────────────────────────────────
        elif base == "cp":
            if len(args) < 2:
                out = "cp: missing destination file operand"
            else:
                src = resolve(args[0])
                dst = resolve(args[1])
                if src in file_contents:
                    if dst in vfs:
                        dst = dst.rstrip("/") + "/" + basename(src)
                    file_contents[dst] = file_contents[src]
                    vfs_add(dst, "file")
                elif src in vfs:
                    out = f"cp: -r not specified; omitting directory '{args[0]}'"
                else:
                    out = f"cp: cannot stat '{args[0]}': No such file or directory"

        # ── mv ────────────────────────────────────────────────────────────────
        elif base == "mv":
            if len(args) < 2:
                out = "mv: missing destination file operand"
            else:
                src = resolve(args[0])
                dst = resolve(args[1])
                if dst in vfs:
                    dst = dst.rstrip("/") + "/" + basename(src)
                if src in file_contents:
                    file_contents[dst] = file_contents.pop(src)
                    vfs_add(dst, "file")
                    vfs_remove(src)
                elif src in vfs:
                    vfs[dst] = vfs.pop(src)
                    children = {k: v for k, v in vfs.items() if k.startswith(src + "/")}
                    for old_k, val in children.items():
                        new_k = dst + old_k[len(src):]
                        vfs[new_k] = val
                        del vfs[old_k]
                    fc_ch = {k: v for k, v in file_contents.items() if k.startswith(src + "/")}
                    for old_k, val in fc_ch.items():
                        new_k = dst + old_k[len(src):]
                        file_contents[new_k] = val
                        del file_contents[old_k]
                    p_src = parent_of(src); n_src = basename(src)
                    p_dst = parent_of(dst); n_dst = basename(dst)
                    if p_src in vfs and n_src in vfs[p_src]:
                        vfs[p_src].remove(n_src)
                    if p_dst not in vfs:
                        vfs[p_dst] = []
                    if n_dst not in vfs[p_dst]:
                        vfs[p_dst].append(n_dst)
                else:
                    out = f"mv: cannot stat '{args[0]}': No such file or directory"

        # ── find ──────────────────────────────────────────────────────────────
        elif base == "find":
            search_root = current_dir
            if args and not args[0].startswith("-"):
                search_root = resolve(args[0])
            name_filter = ""
            type_filter = ""
            if "-name" in args:
                idx = args.index("-name")
                if idx + 1 < len(args):
                    name_filter = args[idx + 1].strip("*\"'").lower()
            if "-type" in args:
                idx = args.index("-type")
                if idx + 1 < len(args):
                    type_filter = args[idx + 1].lower()
            results = set()
            if type_filter != "f":
                for path in vfs:
                    if path == search_root or path.startswith(search_root.rstrip("/") + "/"):
                        bn = path.rstrip("/").split("/")[-1] or "."
                        if not name_filter or name_filter in bn.lower():
                            results.add(path if path != search_root else ".")
            if type_filter != "d":
                for path in file_contents:
                    if path.startswith(search_root.rstrip("/") + "/") or path == search_root:
                        bn = path.split("/")[-1]
                        if not name_filter or name_filter in bn.lower():
                            results.add(path)
            formatted = []
            for r in sorted(results):
                if r == search_root or r == ".":
                    formatted.append(".")
                elif r.startswith(search_root.rstrip("/") + "/"):
                    rel = "." + r[len(search_root.rstrip("/")):]
                    formatted.append(rel)
                else:
                    formatted.append(r)
            out = "\n".join(sorted(set(formatted)))

        # ── grep ──────────────────────────────────────────────────────────────
        elif base == "grep":
            if len(args) < 2:
                out = "grep: missing pattern or file"
            else:
                pattern = args[0].lower()
                file_arg = resolve(args[1])
                if file_arg in file_contents:
                    matched = [l for l in file_contents[file_arg].splitlines()
                               if pattern in l.lower()]
                    out = "\n".join(matched) if matched else ""
                else:
                    out = f"grep: {args[1]}: No such file or directory"

        # ── nano / vi / vim ───────────────────────────────────────────────────
        elif base in ("nano", "vi", "vim"):
            if not args:
                out = f"{base}: missing filename"
            else:
                filepath_nano = resolve(args[0])
                filename_nano = args[0]
                ok_w, _ = can_write(filepath_nano)
                ok_r, _ = can_read(filepath_nano)
                if not ok_r:
                    out = f"{base}: {args[0]}: Permission denied"
                elif file_contents.get(filepath_nano) and len(file_contents[filepath_nano]) > NANO_MAX_SIZE:
                    out = (f"{base}: {args[0]}: File too large "
                           f"(max {NANO_MAX_SIZE // 1024 // 1024} MB)")
                else:
                    if filepath_nano not in file_contents:
                        file_contents[filepath_nano] = ""
                        vfs_add(filepath_nano, "file")

                    ROWS      = 24
                    COLS      = 80
                    EDIT_ROWS = ROWS - 3
                    raw_content   = file_contents.get(filepath_nano, "")
                    nano_lines    = raw_content.split("\n")
                    if nano_lines and nano_lines[-1] == "":
                        nano_lines.pop()
                    if not nano_lines:
                        nano_lines = [""]

                    cursor_row    = 0
                    cursor_col    = 0
                    scroll_top    = 0
                    nano_modified = False
                    read_only     = not ok_w

                    def t_row(): return (cursor_row - scroll_top) + 2
                    def t_col(): return cursor_col + 1

                    def nano_draw():
                        b = ["\033[2J\033[1;1H"]
                        ro_tag  = "[ Read Only ]" if read_only else ""
                        mod_tag = "Modified" if nano_modified else ""
                        header  = f"  GNU nano 4.8    {filename_nano}    {mod_tag} {ro_tag}"
                        b.append("\033[7m" + header.ljust(COLS)[:COLS] + "\033[0m\r\n")
                        visible = nano_lines[scroll_top: scroll_top + EDIT_ROWS]
                        for line in visible:
                            safe = line.replace("\r", "").replace("\n", "")[:COLS]
                            b.append(safe + "\033[K\r\n")
                        for _ in range(EDIT_ROWS - len(visible)):
                            b.append("\033[2m~\033[0m\033[K\r\n")
                        b.append("\033[7m" + "".ljust(COLS)[:COLS] + "\033[0m\r\n")
                        b.append("^G Help  ^O Write Out  ^X Exit  ^K Cut  ^U Paste  ^W Search")
                        b.append(f"\033[{t_row()};{t_col()}H")
                        channel.send("".join(b).encode(errors="replace"))

                    def nano_draw_line():
                        safe = nano_lines[cursor_row].replace("\r","").replace("\n","")[:COLS]
                        b = (
                            f"\033[{t_row()};1H\033[2K{safe}"
                            f"\033[{t_row()};{t_col()}H"
                        )
                        channel.send(b.encode(errors="replace"))

                    def nano_save(save_path: str):
                        file_contents[save_path] = "\n".join(nano_lines) + "\n"
                        vfs_add(save_path, "file")
                        cmd_logger.info(json.dumps({
                            "event_type": "nano_save",
                            "source_ip": client_ip,
                            "path": save_path,
                            "lines": len(nano_lines),
                        }))

                    def read_escape_seq() -> bytes:
                        try:
                            c1 = channel.recv(1)
                            if c1 in (b"[", b"O"):
                                c2 = channel.recv(1)
                                if c2 in (b"1",b"2",b"3",b"4",b"5",b"6"):
                                    c3 = channel.recv(1)
                                    return c1 + c2 + c3
                                return c1 + c2
                            return c1
                        except Exception:
                            return b""

                    nano_draw()

                    while True:
                        try:
                            nc = channel.recv(1)
                        except Exception:
                            break
                        if not nc:
                            break

                        cur = nano_lines[cursor_row]
                        need_full_redraw = False

                        if nc == b"\x18":   # Ctrl+X
                            if nano_modified and not read_only:
                                channel.send(
                                    f"\033[{ROWS};1H\033[K\033[7m"
                                    " Save modified buffer? (Y=Yes  N=No  ^C=Cancel) "
                                    "\033[0m".encode()
                                )
                                ans = channel.recv(1)
                                channel.send(b"\r\n")
                                if ans in (b"y", b"Y"):
                                    nano_save(filepath_nano)
                                elif ans not in (b"n", b"N"):
                                    nano_draw()
                                    continue
                            break

                        elif nc == b"\x03":
                            break

                        elif nc == b"\x0f":   # Ctrl+O
                            if read_only:
                                channel.send(
                                    f"\033[{ROWS};1H\033[K\033[7m [ File is read-only ] \033[0m".encode()
                                )
                                time.sleep(0.8)
                                nano_draw()
                                continue
                            channel.send(
                                f"\033[{ROWS};1H\033[K\033[7m"
                                f" File Name to Write: \033[0m {filename_nano}".encode()
                            )
                            fn_buf = filename_nano
                            while True:
                                fc = channel.recv(1)
                                if fc in (b"\r", b"\n"):
                                    channel.send(b"\r\n")
                                    break
                                elif fc in (b"\x7f", b"\x08"):
                                    if fn_buf:
                                        fn_buf = fn_buf[:-1]
                                        channel.send(b"\x08 \x08")
                                elif fc == b"\x03":
                                    fn_buf = None
                                    break
                                else:
                                    try:
                                        fn_buf += fc.decode("utf-8", errors="ignore")
                                        channel.send(fc)
                                    except Exception:
                                        pass
                            if fn_buf:
                                save_path = resolve(fn_buf)
                                nano_save(save_path)
                                nano_modified = False
                                filename_nano = fn_buf
                                channel.send(
                                    f"\033[{ROWS};1H\033[K\033[7m"
                                    f" [ Wrote {len(nano_lines)} lines ] \033[0m".encode()
                                )
                                time.sleep(0.6)
                            nano_draw()
                            continue

                        elif nc == b"\x1b":
                            seq = read_escape_seq()
                            need_full_redraw = True
                            if seq == b"[A":
                                if cursor_row > 0:
                                    cursor_row -= 1
                                    cursor_col = min(cursor_col, len(nano_lines[cursor_row]))
                                    if cursor_row < scroll_top:
                                        scroll_top -= 1
                            elif seq == b"[B":
                                if cursor_row < len(nano_lines) - 1:
                                    cursor_row += 1
                                    cursor_col = min(cursor_col, len(nano_lines[cursor_row]))
                                    if cursor_row - scroll_top >= EDIT_ROWS:
                                        scroll_top += 1
                            elif seq == b"[C":
                                if cursor_col < len(nano_lines[cursor_row]):
                                    cursor_col += 1
                                    need_full_redraw = False
                                    channel.send(f"\033[{t_row()};{t_col()}H".encode())
                                elif cursor_row < len(nano_lines) - 1:
                                    cursor_row += 1; cursor_col = 0
                                    if cursor_row - scroll_top >= EDIT_ROWS:
                                        scroll_top += 1
                            elif seq == b"[D":
                                if cursor_col > 0:
                                    cursor_col -= 1
                                    need_full_redraw = False
                                    channel.send(f"\033[{t_row()};{t_col()}H".encode())
                                elif cursor_row > 0:
                                    cursor_row -= 1
                                    cursor_col = len(nano_lines[cursor_row])
                                    if cursor_row < scroll_top:
                                        scroll_top -= 1
                            elif seq in (b"[H", b"OH"):
                                cursor_col = 0
                                need_full_redraw = False
                                channel.send(f"\033[{t_row()};{t_col()}H".encode())
                            elif seq in (b"[F", b"OF"):
                                cursor_col = len(nano_lines[cursor_row])
                                need_full_redraw = False
                                channel.send(f"\033[{t_row()};{t_col()}H".encode())

                        elif nc in (b"\r", b"\n"):
                            if not read_only:
                                before = cur[:cursor_col]
                                after  = cur[cursor_col:]
                                nano_lines[cursor_row] = before
                                nano_lines.insert(cursor_row + 1, after)
                                cursor_row += 1; cursor_col = 0
                                nano_modified = True
                                if cursor_row - scroll_top >= EDIT_ROWS:
                                    scroll_top += 1
                            need_full_redraw = True

                        elif nc in (b"\x7f", b"\x08"):
                            if not read_only:
                                if cursor_col > 0:
                                    nano_lines[cursor_row] = cur[:cursor_col-1] + cur[cursor_col:]
                                    cursor_col -= 1
                                    nano_modified = True
                                    nano_draw_line()
                                    continue
                                elif cursor_row > 0:
                                    prev_len = len(nano_lines[cursor_row - 1])
                                    nano_lines[cursor_row - 1] += cur
                                    nano_lines.pop(cursor_row)
                                    cursor_row -= 1; cursor_col = prev_len
                                    nano_modified = True
                                    if scroll_top > 0 and cursor_row < scroll_top:
                                        scroll_top -= 1
                                    need_full_redraw = True

                        elif nc == b"\x07":   # Ctrl+G help – ignore
                            pass

                        elif nc == b"\x0b":   # Ctrl+K cut line
                            if not read_only and nano_lines:
                                nano_lines.pop(cursor_row)
                                if not nano_lines:
                                    nano_lines = [""]
                                cursor_row = min(cursor_row, len(nano_lines) - 1)
                                cursor_col = min(cursor_col, len(nano_lines[cursor_row]))
                                nano_modified = True
                                need_full_redraw = True

                        else:
                            if not read_only:
                                try:
                                    ch_char = nc.decode("utf-8", errors="ignore")
                                    if ch_char and (ch_char.isprintable() or ch_char == "\t"):
                                        nano_lines[cursor_row] = (
                                            cur[:cursor_col] + ch_char + cur[cursor_col:]
                                        )
                                        cursor_col += 1
                                        nano_modified = True
                                        nano_draw_line()
                                        continue
                                except Exception:
                                    pass

                        if need_full_redraw:
                            nano_draw()
                        else:
                            channel.send(f"\033[{t_row()};{t_col()}H".encode())

                    channel.send(b"\033[2J\033[1;1H")
                    continue

        # ── wget ──────────────────────────────────────────────────────────────
        elif base == "wget":
            if not args:
                out = "wget: missing URL"
            else:
                url = next((a for a in args if a.startswith("http")), args[-1])
                cmd_logger.info(json.dumps({
                    "event_type": "wget", "source_ip": client_ip, "url": url,
                }))
                fname = url.rstrip("/").split("/")[-1] or "index.html"
                channel.send(
                    f"--{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}--  {url}\r\n".encode()
                )
                channel.send(b"Resolving host... connected.\r\n")
                time.sleep(random.uniform(0.3, 0.8))
                channel.send(b"HTTP request sent, awaiting response... 200 OK\r\n")
                channel.send(f"Saving to: '{fname}'\r\n\r\n".encode())
                for pct in range(0, 101, 25):
                    bar = ("#" * (pct // 5)).ljust(20)
                    channel.send(f"\r{fname}  [{bar}] {pct}%".encode())
                    time.sleep(0.1)
                channel.send(f"\r\n'{fname}' saved [4096/4096]\r\n".encode())
                p = resolve(fname)
                file_contents[p] = f"# downloaded from {url}\n"
                vfs_add(p, "file")
                continue

        # ── curl ──────────────────────────────────────────────────────────────
        elif base == "curl":
            if not args:
                out = "curl: try 'curl --help' for more information"
            else:
                url = next((a for a in args if a.startswith("http")), None)
                if not url:
                    out = "curl: (6) Could not resolve host"
                else:
                    cmd_logger.info(json.dumps({
                        "event_type": "curl", "source_ip": client_ip, "url": url,
                    }))
                    output_flag = False
                    if "-o" in args:
                        idx = args.index("-o")
                        if idx + 1 < len(args):
                            output_flag = True
                            out_file = resolve(args[idx + 1])
                            file_contents[out_file] = f"# downloaded from {url}\n"
                            vfs_add(out_file, "file")
                            out = "  % Total    % Received\n100  4096  100  4096    0     0   8192      0"
                    if not output_flag:
                        out = f"<!-- Response from {url} -->\n<html><body>404 Not Found</body></html>"

        # ── ping ──────────────────────────────────────────────────────────────
        elif base == "ping":
            if not args:
                out = "ping: usage error: Destination address required"
            else:
                host = args[-1]
                channel.send(f"PING {host} (93.184.216.34) 56(84) bytes of data.\r\n".encode())
                for seq in range(1, 5):
                    ms = round(random.uniform(12.0, 45.0), 3)
                    channel.send(
                        f"64 bytes from {host} ({host}): icmp_seq={seq} ttl=54 time={ms} ms\r\n".encode()
                    )
                    time.sleep(0.3)
                channel.send(
                    f"\n--- {host} ping statistics ---\r\n"
                    f"4 packets transmitted, 4 received, 0% packet loss, time 3004ms\r\n".encode()
                )
                continue

        # ── sudo ──────────────────────────────────────────────────────────────
        elif base == "sudo":
            cmd_logger.info(json.dumps({
                "event_type": "sudo_attempt", "source_ip": client_ip,
                "username": current_user, "command": full_cmd,
            }))
            channel.send(b"[sudo] password for corpuser: ")
            try:
                pw_buf = b""
                while True:
                    c = channel.recv(1)
                    if not c or c in (b"\r", b"\n"):
                        break
                    pw_buf += c
            except Exception:
                pass
            channel.send(b"\r\n")
            time.sleep(0.5)
            cmd_logger.info(json.dumps({
                "event_type": "sudo_password", "source_ip": client_ip,
                "password": pw_buf.decode(errors="ignore"),
            }))
            out = "Sorry, user corpuser may not run sudo on ubuntu-server-01."

        # ── su ────────────────────────────────────────────────────────────────
        elif base == "su":
            target_user = args[0] if args else "root"
            channel.send(b"Password: ")
            try:
                pw_buf = b""
                while True:
                    c = channel.recv(1)
                    if not c or c in (b"\r", b"\n"):
                        break
                    pw_buf += c
            except Exception:
                pass
            channel.send(b"\r\n")
            typed_pw = pw_buf.decode(errors="ignore")
            cmd_logger.info(json.dumps({
                "event_type": "su_attempt", "source_ip": client_ip,
                "target_user": target_user, "password": typed_pw,
            }))
            if target_user == "root":
                current_user = "root"
                current_uid  = 0
                home_dir     = "/root"
                channel.send(b"# \r\n")
                cmd_logger.info(json.dumps({
                    "event_type": "root_shell", "source_ip": client_ip,
                    "severity": "critical",
                }))
            else:
                out = f"su: user {target_user} does not exist"

        # ── EXPLOITABLE VULNERABILITIES ───────────────────────────────────────
        # These are intentional honeypot lures — realistic but fake vulns
        # that attackers can "exploit" so we can observe their techniques.

        # CVE-2021-4034  (polkit pkexec local privesc)
        elif base == "pkexec" and not args:
            time.sleep(0.4)
            if current_uid != 0:
                current_user = "root"
                current_uid  = 0
                home_dir     = "/root"
                channel.send(
                    b"bash: no job control in this shell\r\n"
                    b"root@ubuntu-server-01:/# "
                )
                cmd_logger.info(json.dumps({
                    "event_type": "exploit_used", "source_ip": client_ip,
                    "cve": "CVE-2021-4034", "desc": "pkexec privesc (PwnKit)",
                    "severity": "critical",
                }))
            else:
                out = ""

        # CVE-2019-14287  (sudo -u#-1)
        elif base == "sudo" and "-u#-1" in args:
            time.sleep(0.3)
            current_user = "root"
            current_uid  = 0
            home_dir     = "/root"
            channel.send(b"root@ubuntu-server-01:/home/corpuser# ")
            cmd_logger.info(json.dumps({
                "event_type": "exploit_used", "source_ip": client_ip,
                "cve": "CVE-2019-14287", "desc": "sudo -u#-1 bypass",
                "severity": "critical",
            }))

        # CVE-2021-3560  (polkit authentication bypass)
        elif full_cmd.strip().startswith("dbus-send") and "polkit" in full_cmd:
            time.sleep(0.6)
            if current_uid != 0:
                current_user = "root"
                current_uid  = 0
                home_dir     = "/root"
                out = "==== AUTHENTICATION COMPLETE ==="
                cmd_logger.info(json.dumps({
                    "event_type": "exploit_used", "source_ip": client_ip,
                    "cve": "CVE-2021-3560", "desc": "polkit dbus auth bypass",
                    "severity": "critical",
                }))

        # Writable /etc/passwd — add root-level user
        elif base == "openssl" and "passwd" in args:
            pw_arg = args[args.index("passwd") + 1] if "passwd" in args and len(args) > args.index("passwd") + 1 else "hacked"
            import hashlib, base64 as _b64
            salt = "ab"
            h = hashlib.md5(f"{pw_arg}{salt}".encode()).digest()
            out = f"$1${salt}${_b64.b64encode(h).decode()[:22]}"

        # SUID bash exploit
        elif full_cmd.strip() in ("bash -p", "/bin/bash -p", "/usr/bin/bash -p"):
            time.sleep(0.2)
            current_user = "root"
            current_uid  = 0
            home_dir     = "/root"
            channel.send(b"bash-5.0# ")
            cmd_logger.info(json.dumps({
                "event_type": "exploit_used", "source_ip": client_ip,
                "cve": "SUID-BASH", "desc": "SUID bash -p privesc",
                "severity": "critical",
            }))

        # Dirty Pipe style — write to read-only file
        elif base == "cp" and current_uid != 0 and args and args[-1] in ("/etc/passwd", "/etc/shadow"):
            time.sleep(0.3)
            current_user = "root"
            current_uid  = 0
            home_dir     = "/root"
            out = ""
            cmd_logger.info(json.dumps({
                "event_type": "exploit_used", "source_ip": client_ip,
                "cve": "CVE-2022-0847", "desc": "Dirty Pipe arbitrary write",
                "severity": "critical",
            }))

        # LD_PRELOAD hijack (if /tmp/evil.so exists in vfs)
        elif "LD_PRELOAD" in full_cmd and "/tmp/" in full_cmd:
            time.sleep(0.2)
            if current_uid != 0:
                current_user = "root"
                current_uid  = 0
                home_dir     = "/root"
                channel.send(b"# ")
                cmd_logger.info(json.dumps({
                    "event_type": "exploit_used", "source_ip": client_ip,
                    "cve": "LD_PRELOAD", "desc": "LD_PRELOAD privilege hijack",
                    "severity": "critical",
                }))

        # ── python / python3 ──────────────────────────────────────────────────
        elif base in ("python", "python3"):
            if args and args[0] == "-c":
                script = " ".join(args[1:]).strip("'\"")
                cmd_logger.info(json.dumps({
                    "event_type": "python_exec", "source_ip": client_ip,
                    "script": script,
                }))
                out = ""
            else:
                channel.send(b"Python 3.8.10 (default, Nov 14 2022, 12:59:47)\r\n")
                channel.send(b'[GCC 9.4.0] on linux\r\nType "help" for more info.\r\n')
                while True:
                    channel.send(b">>> ")
                    py_buf = ""
                    while True:
                        try:
                            c = channel.recv(1)
                        except Exception:
                            return
                        if not c or c in (b"\r", b"\n"):
                            channel.send(b"\r\n")
                            break
                        try:
                            py_buf += c.decode("utf-8", errors="ignore")
                            channel.send(c)
                        except Exception:
                            pass
                    py_cmd = py_buf.strip()
                    if py_cmd in ("exit()", "quit()"):
                        break
                    cmd_logger.info(json.dumps({
                        "event_type": "python_repl", "source_ip": client_ip, "cmd": py_cmd,
                    }))
                    if py_cmd:
                        channel.send(b'  File "<stdin>", line 1\r\nSyntaxError: invalid syntax\r\n')
                continue

        # ── which ─────────────────────────────────────────────────────────────
        elif base == "which":
            if not args:
                out = ""
            else:
                known = set(vfs.get("/bin", []))
                results = [f"/bin/{a}" if a in known else f"{a} not found" for a in args]
                out = "\n".join(results)

        # ── file ──────────────────────────────────────────────────────────────
        elif base == "file":
            if not args:
                out = "file: missing file operand"
            else:
                parts_out = []
                for a in args:
                    p = resolve(a)
                    if p in vfs:
                        parts_out.append(f"{a}: directory")
                    elif p in file_contents:
                        parts_out.append(f"{a}: ASCII text")
                    else:
                        parts_out.append(f"{a}: cannot open: No such file or directory")
                out = "\n".join(parts_out)

        # ── head / tail ───────────────────────────────────────────────────────
        elif base in ("head", "tail"):
            if not args:
                out = f"{base}: missing file operand"
            else:
                n = 10
                if "-n" in args:
                    idx = args.index("-n")
                    try:
                        n = int(args[idx + 1])
                        file_arg = args[idx + 2] if idx + 2 < len(args) else None
                    except (ValueError, IndexError):
                        file_arg = None
                else:
                    file_arg = next((a for a in args if not a.startswith("-")), None)
                if file_arg:
                    p = resolve(file_arg)
                    if p in file_contents:
                        lines = file_contents[p].splitlines()
                        chosen = lines[:n] if base == "head" else lines[-n:]
                        out = "\n".join(chosen)
                    else:
                        out = f"{base}: cannot open '{file_arg}': No such file or directory"

        # ── wc ────────────────────────────────────────────────────────────────
        elif base == "wc":
            file_arg = next((a for a in args if not a.startswith("-")), None)
            if file_arg:
                p = resolve(file_arg)
                if p in file_contents:
                    content = file_contents[p]
                    lines = len(content.splitlines())
                    words = len(content.split())
                    chars = len(content)
                    out = f"{lines:>7} {words:>7} {chars:>7} {file_arg}"
                else:
                    out = f"wc: {file_arg}: No such file or directory"

        # ── chmod / chown ─────────────────────────────────────────────────────
        elif base in ("chmod", "chown"):
            pass   # silently accept

        # ── apt / apt-get / yum / dnf ─────────────────────────────────────────
        elif base in ("apt", "apt-get", "yum", "dnf"):
            sub = args[0] if args else ""
            if sub in ("install", "update", "upgrade"):
                channel.send(b"Reading package lists... Done\r\nBuilding dependency tree\r\n")
                time.sleep(0.3)
                out = (
                    "E: Could not open lock file /var/lib/dpkg/lock-frontend"
                    " - open (13: Permission denied)\n"
                    "E: Unable to acquire the dpkg frontend lock, are you root?"
                )
            else:
                out = f"{base}: command requires superuser privilege"

        # ── service / systemctl ───────────────────────────────────────────────
        elif base in ("service", "systemctl"):
            out = "Failed to connect to bus: No such file or directory"

        # ── crontab ───────────────────────────────────────────────────────────
        elif base == "crontab":
            out = "no crontab for corpuser" if "-l" in args else ""

        # ── fallback ──────────────────────────────────────────────────────────
        else:
            out = f"bash: {base}: command not found"

        # ── Output / redirection ──────────────────────────────────────────────
        _cmd_failed = False
        if redirect_file is not None:
            if out is None:
                out = ""
            ok_w, _ = can_write(redirect_file)
            if not ok_w:
                channel.send(f"-bash: {redirect_file}: Permission denied\r\n".encode())
                _cmd_failed = True
            else:
                existing = file_contents.get(redirect_file, "") if redirect_append else ""
                if redirect_append and existing and not existing.endswith("\n"):
                    existing += "\n"
                file_contents[redirect_file] = existing + (out + "\n" if out else "")
                vfs_add(redirect_file, "file")
        elif out:
            # command not found = failure
            if out.startswith("bash: ") and "command not found" in out:
                _cmd_failed = True
            elif out.startswith("-bash: ") or "Permission denied" in out or \
                 (out.startswith("su: ") or out.startswith("bash: ")):
                _cmd_failed = True
            _send(out + "\n")  # truncation-safe _send()

        # Only add to history if command didn't outright fail
        if not _cmd_failed:
            cmd_history.append(full_cmd)

    channel.close()
