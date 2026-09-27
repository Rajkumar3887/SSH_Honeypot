#!/bin/bash
# ══════════════════════════════════════════════════════════════════════════════
# performance-test.sh
# Simple performance/load test for the SSH Honeypot
# WARNING: Run this only against YOUR OWN honeypot instance!
# ══════════════════════════════════════════════════════════════════════════════

HOST="${1:-localhost}"
PORT="${2:-2222}"
CONCURRENCY="${3:-10}"
DURATION="${4:-60}"

echo "SSH Honeypot - Performance Test"
echo "================================"
echo "Target:      ${HOST}:${PORT}"
echo "Concurrency: ${CONCURRENCY} connections"
echo "Duration:    ${DURATION} seconds"
echo "WARNING:     Run this only against YOUR OWN honeypot!"
echo ""
read -p "Continue? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
fi

START_TIME=$(date +%s)
CONNECTION_COUNT=0
FAIL_COUNT=0

echo "[*] Starting load test at $(date)"
echo "[*] Press Ctrl+C to stop early"
echo ""

# Function to make a single connection attempt
make_connection() {
    timeout 5 nc -z "${HOST}" "${PORT}" 2>/dev/null && return 0 || return 1
}

# Parallel connections using background jobs
while true; do
    CURRENT_TIME=$(date +%s)
    ELAPSED=$((CURRENT_TIME - START_TIME))

    if [ "${ELAPSED}" -ge "${DURATION}" ]; then
        break
    fi

    # Launch concurrent connection attempts
    for i in $(seq 1 "${CONCURRENCY}"); do
        (
            if make_connection; then
                echo "." > /dev/null
            fi
        ) &
    done

    # Wait a bit between waves
    sleep 2

    # Count active connections
    CONNECTION_COUNT=$((CONNECTION_COUNT + CONCURRENCY))
    echo -ne "\r[*] Elapsed: ${ELAPSED}s | Connections attempted: ${CONNECTION_COUNT}"

    wait
done

echo ""
echo ""
echo "Test Complete!"
echo "=============="
echo "Duration:    ${DURATION}s"
echo "Connections: ${CONNECTION_COUNT} attempted"
echo ""
echo "Check honeypot logs for impact:"
echo "  wc -l logs/funnel.log"
echo "  sqlite3 honeypot.db 'SELECT COUNT(*) FROM connections;'"
echo ""
echo "Check memory usage:"
echo "  ps aux | grep 'python main.py'"
