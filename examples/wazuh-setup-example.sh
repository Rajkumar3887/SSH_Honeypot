#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# wazuh-setup-example.sh
# Wazuh SIEM integration setup script for SSH Honeypot
# Run this on your Wazuh manager (or agent) machine.
# ══════════════════════════════════════════════════════════════════════════════

set -e

WAZUH_DIR="/var/ossec"
HONEYPOT_DIR="/opt/honeypot"  # Change this to where you deployed the honeypot

echo "[*] SSH Honeypot - Wazuh Integration Setup"
echo "============================================"

# 1. Copy custom decoders
echo "[1] Installing custom decoders..."
cp "${HONEYPOT_DIR}/wazuh/decoders.xml" "${WAZUH_DIR}/etc/decoders/honeypot_decoders.xml"
chown root:wazuh "${WAZUH_DIR}/etc/decoders/honeypot_decoders.xml"
chmod 660 "${WAZUH_DIR}/etc/decoders/honeypot_decoders.xml"
echo "    ✓ Decoders installed to ${WAZUH_DIR}/etc/decoders/honeypot_decoders.xml"

# 2. Copy custom rules
echo "[2] Installing custom rules..."
cp "${HONEYPOT_DIR}/wazuh/rules.xml" "${WAZUH_DIR}/etc/rules/honeypot_rules.xml"
chown root:wazuh "${WAZUH_DIR}/etc/rules/honeypot_rules.xml"
chmod 660 "${WAZUH_DIR}/etc/rules/honeypot_rules.xml"
echo "    ✓ Rules installed to ${WAZUH_DIR}/etc/rules/honeypot_rules.xml"

# 3. Configure log monitoring
echo "[3] Configuring log monitoring..."
OSSEC_CONF="${WAZUH_DIR}/etc/ossec.conf"

# Add log monitoring for honeypot log files (if not already present)
if ! grep -q "honeypot" "${OSSEC_CONF}"; then
    echo "
  <!-- SSH Honeypot Log Monitoring -->
  <localfile>
    <log_format>json</log_format>
    <location>/opt/honeypot/logs/funnel.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/opt/honeypot/logs/threats.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/opt/honeypot/logs/cmd_audits.log</location>
  </localfile>" >> "${OSSEC_CONF}"
    echo "    ✓ Log monitoring added to ossec.conf"
else
    echo "    ✓ Log monitoring already configured (skipped)"
fi

# 4. Ensure log directory is accessible by Wazuh agent
echo "[4] Setting log file permissions..."
if [ -d "/opt/honeypot/logs" ]; then
    chmod 750 /opt/honeypot/logs
    chmod 640 /opt/honeypot/logs/*.log 2>/dev/null || true
    echo "    ✓ Log permissions set"
else
    echo "    ! Honeypot log directory not found at /opt/honeypot/logs"
    echo "    ! Please ensure the honeypot is deployed and has run at least once"
fi

# 5. Restart Wazuh services
echo "[5] Restarting Wazuh services..."
if systemctl is-active --quiet wazuh-manager; then
    systemctl restart wazuh-manager
    echo "    ✓ Wazuh manager restarted"
elif systemctl is-active --quiet wazuh-agent; then
    systemctl restart wazuh-agent
    echo "    ✓ Wazuh agent restarted"
else
    echo "    ! No active Wazuh service found. Please restart manually:"
    echo "    ! systemctl restart wazuh-manager  (on manager)"
    echo "    ! systemctl restart wazuh-agent    (on agent)"
fi

echo ""
echo "✅ Wazuh integration setup complete!"
echo ""
echo "Verify setup:"
echo "  tail -f /var/ossec/logs/alerts/alerts.json | python3 -m json.tool"
echo "  grep 'honeypot' /var/ossec/logs/ossec.log"
echo ""
echo "Next: Configure WAZUH_SYSLOG_HOST in your honeypot environment:"
echo "  export WAZUH_SYSLOG_HOST=<wazuh-manager-ip>"
echo "  python main.py --open --wazuh-host <wazuh-manager-ip>"
