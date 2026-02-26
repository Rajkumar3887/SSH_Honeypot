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

# IST = UTC+5:30
_IST = datetime.timezone(datetime.timedelta(hours=5, minutes=30))
def _now_ist(): return datetime.datetime.now(_IST).isoformat(timespec="seconds")

from core.virtual_fs import build_vfs
from core.threat_engine import analyse_command, analyse_file_access, log_command_event
from config.settings import FAKE_HOSTNAME


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
    "whoami":    "corpuser",
    "id":
        "uid=1001(corpuser) gid=1001(corpuser) groups=1001(corpuser),27(sudo)",
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

    # ── Main input loop ───────────────────────────────────────────────────────
    while True:
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

        cmd_history.append(full_cmd)
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

        # Save every command to DB + push to live feed
        if db:
             db.insert_command(client_ip, current_user, full_cmd)
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
        base   = tokens[0] if tokens else ""
        args   = tokens[1:]
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

        if full_cmd in STATIC_RESPONSES:
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
        if redirect_file is not None:
            if out is None:
                out = ""
            ok_w, _ = can_write(redirect_file)
            if not ok_w:
                channel.send(f"-bash: {redirect_file}: Permission denied\r\n".encode())
            else:
                existing = file_contents.get(redirect_file, "") if redirect_append else ""
                if redirect_append and existing and not existing.endswith("\n"):
                    existing += "\n"
                file_contents[redirect_file] = existing + (out + "\n" if out else "")
                vfs_add(redirect_file, "file")
        elif out:
            channel.send((out.replace("\n", "\r\n") + "\r\n").encode(errors="replace"))

    channel.close()
