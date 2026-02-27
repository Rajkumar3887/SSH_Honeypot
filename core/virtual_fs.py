"""
Virtual Filesystem (VFS) for the SSH honeypot.
Returns a fresh (vfs, file_contents) pair per session so each attacker
gets an isolated environment.
"""


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

    return vfs, file_contents
