"""
Virtual Filesystem (VFS) for the SSH honeypot.
Returns a fresh (vfs, file_contents) pair per session so each attacker
gets an isolated environment.
"""
import random as _random
import time as _time
from datetime import datetime as _dt, timedelta as _td

# ── Per-session file mtime tracker ────────────────────────────────────────────
_file_mtimes: dict = {}   # {session_id: {path: float}}


def get_file_mtime(session_id: str, path: str, default_days_ago: int = None) -> float:
    """Get (or lazily generate) a realistic mtime for a VFS path."""
    _file_mtimes.setdefault(session_id, {})
    if path not in _file_mtimes[session_id]:
        days = default_days_ago if default_days_ago is not None else _random.randint(1, 400)
        base = _dt.now() - _td(
            days=days,
            hours=_random.randint(0, 23),
            minutes=_random.randint(0, 59),
        )
        _file_mtimes[session_id][path] = base.timestamp()
    return _file_mtimes[session_id][path]


def touch_file(session_id: str, path: str) -> None:
    """Update mtime to now — call when attacker creates/writes a file."""
    _file_mtimes.setdefault(session_id, {})
    _file_mtimes[session_id][path] = _time.time()


def format_ls_time(mtime: float) -> str:
    """Format mtime the way ls -l does: recent=month+day+time, old=month+day+year."""
    dt  = _dt.fromtimestamp(mtime)
    now = _dt.now()
    if (now - dt).days < 180:
        return dt.strftime("%b %d %H:%M")    # "Mar 14 09:22"
    return dt.strftime("%b %d  %Y")          # "Mar 14  2024"


def _gen_bash_history() -> str:
    """Generate a plausible, slightly messy bash_history for the fake user."""
    pool = [
        "ls -la", "cd /var/log", "tail -f syslog", "df -h",
        "sudo apt update", "sudo apt upgrade -y",
        "systemctl status nginx", "systemctl restart nginx",
        "cat /etc/nginx/nginx.conf",
        "vim /etc/nginx/sites-available/default",
        "sudo journalctl -xe", "ps aux | grep python",
        "kill -9 4821", "netstat -tulpn",
        "ssh deploy@10.0.1.42",
        "scp report.csv deploy@10.0.1.42:/tmp/",
        "git pull origin main", "git status",
        "docker ps", "docker logs -f web_app_1",
        "cd ~/projects/backend", "npm install", "npm run build",
        "exit", "history", "clear", "sudo -i", "whoami",
        "  ls", "ls  ", "cd ..", "cd ../..", "pwd",
        "cat /etc/passwd | grep bash",
        "chmod +x deploy.sh", "./deploy.sh",
        "tail -n 100 /var/log/auth.log",
        "crontab -l", "env | grep PATH",
        "find /var/www -name '*.php' -mtime -7",
        "grep -r 'password' /etc/nginx/ 2>/dev/null",
    ]
    count = _random.randint(18, 38)
    return "\n".join(_random.sample(pool, min(count, len(pool)))) + "\n"





def build_vfs():
    """Return a fresh (vfs, file_contents) pair for each session."""

    vfs = {
        "/":                        ["bin", "etc", "home", "lib", "proc", "root", "tmp", "usr", "var"],
        "/bin":                     ["bash", "cat", "cp", "curl", "df", "echo", "find",
                                     "grep", "hostname", "id", "ls", "mkdir", "mv",
                                     "nano", "ping", "ps", "pwd", "rm", "rmdir",
                                     "touch", "uname", "uptime", "wget", "whoami"],
        "/etc":                     ["hostname", "hosts", "issue", "os-release", "passwd",
                                     "resolv.conf", "shadow", "ssh"],
        "/etc/ssh":                 ["sshd_config"],
        "/home":                    ["corpuser"],
        "/home/corpuser":           [".bash_history", ".bashrc", ".ssh", "file1.txt",
                                     "notes.txt", "projects", "secret.txt"],
        "/home/corpuser/.ssh":      ["authorized_keys", "known_hosts"],
        "/home/corpuser/projects":  ["config.yaml", "deploy.sh", "honeypot.py"],
        "/lib":                     [],
        "/proc":                    ["cpuinfo", "meminfo", "version"],
        "/root":                    [".bash_history", ".bashrc", ".ssh", ".local_exploits"],
        "/root/.ssh":              ["authorized_keys", "id_rsa", "id_rsa.pub"],
        "/tmp":                     [],
        "/usr":                     ["bin", "lib", "local", "share"],
        "/usr/bin":                 [],
        "/usr/lib":                 [],
        "/usr/local":               [],
        "/usr/share":               [],
        "/var":                     ["log", "mail", "www"],
        "/var/log":                 ["auth.log", "syslog"],
        "/var/mail":                [],
        "/var/www":                 [],
    }

    file_contents = {
        "/etc/hostname":
            "ubuntu-server-01",

        "/etc/hosts":
            "127.0.0.1\tlocalhost\n"
            "127.0.1.1\tubuntu-server-01\n"
            "::1\t\tlocalhost ip6-localhost ip6-loopback\n",

        "/etc/issue":
            "Ubuntu 20.04.5 LTS \\n \\l\n",

        "/etc/os-release":
            'NAME="Ubuntu"\n'
            'VERSION="20.04.5 LTS (Focal Fossa)"\n'
            'ID=ubuntu\nID_LIKE=debian\n'
            'PRETTY_NAME="Ubuntu 20.04.5 LTS"\n'
            'VERSION_ID="20.04"\n'
            'HOME_URL="https://www.ubuntu.com/"\n',

        "/etc/passwd":
            "root:x:0:0:root:/root:/bin/bash\n"
            "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
            "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
            "corpuser:x:1001:1001:Corp User:/home/corpuser:/bin/bash\n",

        "/etc/shadow":
            "root:$6$xyz$hashedpassword:18900:0:99999:7:::\n"
            "corpuser:$6$abc$anotherhash:18900:0:99999:7:::\n",

        "/etc/resolv.conf":
            "nameserver 8.8.8.8\nnameserver 8.8.4.4\n",

        "/etc/ssh/sshd_config":
            "Port 22\nPermitRootLogin no\nPasswordAuthentication yes\n"
            "ChallengeResponseAuthentication no\nUsePAM yes\nX11Forwarding yes\n",

        "/proc/cpuinfo":
            "processor\t: 0\nvendor_id\t: GenuineIntel\n"
            "cpu family\t: 6\nmodel name\t: Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\n"
            "cpu MHz\t\t: 2400.072\ncache size\t: 30720 KB\n",

        "/proc/meminfo":
            "MemTotal:\t 8174848 kB\nMemFree:\t 3245600 kB\n"
            "MemAvailable:\t 5012344 kB\nSwapTotal:\t 2097148 kB\nSwapFree:\t 2097148 kB\n",

        "/proc/version":
            "Linux version 5.4.0-42-generic (buildd@lgw01-amd64-038) "
            "(gcc version 9.3.0 (Ubuntu 9.3.0-10ubuntu2)) "
            "#46-Ubuntu SMP Fri Jul 10 00:24:02 UTC 2020\n",

        "/home/corpuser/.bashrc":
            "# ~/.bashrc\nexport PATH=$PATH:/usr/local/bin\nalias ll='ls -la'\n",

        "/home/corpuser/.bash_history":
            "ls -la\ncd projects\ncat config.yaml\nnano honeypot.py\n"
            "sudo apt update\ngit pull origin main\nclear\nexit\n",

        "/home/corpuser/.ssh/authorized_keys": "",
        "/home/corpuser/.ssh/known_hosts":
            "github.com ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA...\n",

        "/home/corpuser/file1.txt":
            "Welcome to the corporate server.\nAuthorised access only.\n"
            "All activity is monitored and logged.\n",

        "/home/corpuser/notes.txt":
            "TODO:\n- Rotate DB creds (see secret.txt)\n- Update SSL cert by end of month\n"
            "- Check on dev server\n",

        # ← intentional lure
        "/home/corpuser/secret.txt":
            "# DO NOT SHARE\n"
            "DB_HOST=db.internal.corp.local\n"
            "DB_USER=dbadmin\n"
            "DB_PASSWORD=P@ssw0rd2024!\n"
            "API_KEY=sk-live-4f8a2b9c1d6e3f7a0b5c8d2e9f4a1b6c\n"
            "AWS_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",

        "/home/corpuser/projects/config.yaml":
            "server:\n  host: 0.0.0.0\n  port: 8080\n  debug: false\n"
            "database:\n  host: db.internal\n  port: 5432\n  name: corp_db\n",

        "/home/corpuser/projects/deploy.sh":
            "#!/bin/bash\nset -e\necho 'Deploying application...'\n"
            "git pull origin main\npip install -r requirements.txt\n"
            "systemctl restart app.service\necho 'Done.'\n",

        "/home/corpuser/projects/honeypot.py":
            "# Internal tooling - not for distribution\n",

        "/var/log/auth.log":
            "Jan 10 08:01:11 ubuntu-server-01 sshd[1234]: "
            "Accepted password for corpuser from 10.0.0.5 port 52341 ssh2\n"
            "Jan 10 08:01:11 ubuntu-server-01 sshd[1234]: "
            "pam_unix(sshd:session): session opened for user corpuser\n",

        "/var/log/syslog":
            "Jan 10 08:00:01 ubuntu-server-01 CRON[1100]: "
            "(root) CMD (run-parts /etc/cron.daily)\n"
            "Jan 10 08:01:00 ubuntu-server-01 systemd[1]: "
            "Started Session 4 of user corpuser.\n",

        # ── Root home files (visible once attacker gets root) ─────────────────
        "/root/.bashrc":
            "# ~/.bashrc: executed by bash for non-login shells.\n"
            "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
            "alias ll='ls -alF'\nalias la='ls -A'\nalias l='ls -CF'\n",

        "/root/.bash_history":
            "cat /etc/shadow\n"
            "useradd -m -s /bin/bash backdoor\n"
            "echo 'backdoor:toor' | chpasswd\n"
            "crontab -e\n"
            "ssh-keygen -t rsa -b 4096\n"
            "cat /home/corpuser/secret.txt\n"
            "find / -perm -4000 -type f 2>/dev/null\n",

        "/root/.local_exploits":
            "# Kernel: 5.4.0-42-generic\n"
            "# Possible privesc paths found:\n"
            "# [+] CVE-2021-4034 (PwnKit) - pkexec vulnerable version detected\n"
            "# [+] CVE-2022-0847 (Dirty Pipe) - kernel < 5.16.11\n"
            "# [+] SUID bash found: /usr/bin/bash -p\n"
            "# [+] Writable cron: /etc/cron.d/\n"
            "# [+] sudo -u#-1 (CVE-2019-14287) may work\n",

        "/root/.ssh/id_rsa":
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAA[FAKE KEY - HONEYPOT]\n"
            "AAABAAABAQC3fake0key0data0here0nothing0real\n"
            "-----END OPENSSH PRIVATE KEY-----\n",

        "/root/.ssh/authorized_keys":
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB[FAKE] root@ubuntu-server-01\n",
    }


    # ── Filesystem noise (realistic, varied per instance) ────────────────────
    _tmp_suffix  = "".join(_random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=8))
    _deploy_name = _random.choice(["deploy", "backup", "migrate", "update"])

    _noise_paths = {
        "/home/corpuser/.bash_logout":  "# ~/.bash_logout\n",
        "/home/corpuser/.viminfo":
            f"# This viminfo file was generated by Vim 8.1\n"
            f"# You may edit it if you're careful!\n",
        "/home/corpuser/.lesshst":  "",
        "/home/corpuser/.wget-hsts": "# HSTS 1.0 Known Hosts database\n",
        "/home/corpuser/.bash_history": _gen_bash_history(),
        f"/tmp/tmp.{_tmp_suffix}":  "",

        # ── Lure files (buried, realistic) ────────────────────────────────
        "/opt/backup-scripts/.env.old":
            "# Old backup config — do not delete\n"
            "DB_HOST=db-primary.internal\n"
            "DB_USER=backup_svc\n"
            "DB_PASSWORD=Bkp@2023!xK9\n"
            "S3_BUCKET=corp-backups-prod\n"
            "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",

        "/var/www/app/config/database.yml.bak":
            "production:\n"
            "  adapter: postgresql\n"
            "  host: db-primary.internal\n"
            "  database: app_production\n"
            "  username: app_user\n"
            "  password: 'Pr0d$ecret2023'\n",

        f"/home/corpuser/{_deploy_name}.sh":
            "#!/bin/bash\n"
            "set -e\n"
            "# Deploy script — DO NOT SHARE\n"
            f"API_KEY=sk_live_x8KqP2mN9vRjT4wL7hYcF1\n"
            "TARGET=deploy@10.0.1.42\n"
            "echo 'Deploying to production...'\n"
            "git pull origin main\n"
            "npm run build\n"
            f"scp -r dist/ $TARGET:/var/www/app/\n"
            "echo 'Done.'\n",

        "/home/corpuser/.ssh/known_hosts":
            "db-primary.internal ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAB\n"
            "10.0.1.42 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQC7Kj8\n"
            "10.0.1.55 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlz\n",

        "/etc/cron.d/backup-sync":
            "# Sync backups to remote — runs every 4 hours\n"
            "SHELL=/bin/bash\n"
            "PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin\n"
            "0 */4 * * * root /opt/backup-scripts/sync.sh >> /var/log/backup.log 2>&1\n",
    }

    for _np, _nc in _noise_paths.items():
        if _nc is not None:
            file_contents[_np] = _nc
        _parent = "/".join(_np.split("/")[:-1]) or "/"
        _fname  = _np.split("/")[-1]
        if _parent not in vfs:
            vfs[_parent] = []
        if _fname and _fname not in vfs[_parent]:
            vfs[_parent].append(_fname)

    # Ensure /opt and /opt/backup-scripts exist in VFS tree
    for _d in ["/opt", "/opt/backup-scripts", "/var/www", "/var/www/app",
               "/var/www/app/config", "/etc/cron.d"]:
        if _d not in vfs:
            vfs[_d] = []
        _parent_d = "/".join(_d.split("/")[:-1]) or "/"
        _dname    = _d.split("/")[-1]
        if _parent_d in vfs and _dname and _dname not in vfs[_parent_d]:
            vfs[_parent_d].append(_dname)

    return vfs, file_contents
