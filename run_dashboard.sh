#!/usr/bin/env bash
# Auto-restarting wrapper for dashboard.py
# Usage: ./run_dashboard.sh [--log /path/to/logfile]

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LOG_FILE="${SCRIPT_DIR}/data/dashboard.log"
RESTART_DELAY=3

# Allow overriding log path
if [[ "$1" == "--log" && -n "$2" ]]; then
    LOG_FILE="$2"
fi

mkdir -p "$(dirname "$LOG_FILE")"

echo "[run_dashboard] Starting dashboard with auto-restart. Log: $LOG_FILE"
echo "[run_dashboard] Press Ctrl+C to stop."

trap 'echo "[run_dashboard] Caught signal, stopping..."; kill $CHILD_PID 2>/dev/null; exit 0' INT TERM

while true; do
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$TIMESTAMP] [run_dashboard] Starting dashboard.py..." | tee -a "$LOG_FILE"

    cd "$SCRIPT_DIR"
    uv run python3 dashboard.py >> "$LOG_FILE" 2>&1 &
    CHILD_PID=$!

    wait $CHILD_PID
    EXIT_CODE=$?

    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$TIMESTAMP] [run_dashboard] dashboard.py exited with code $EXIT_CODE. Restarting in ${RESTART_DELAY}s..." | tee -a "$LOG_FILE"
    sleep $RESTART_DELAY
done
