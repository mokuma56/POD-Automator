#!/bin/bash
# TEMPORARY WORKAROUND — DELETE THIS FILE AND ITS LAUNCHD JOB
# (~/Library/LaunchAgents/com.maokuma.pod-automator-healthcheck.plist)
# once the host-writes-only DB refactor lands (containers write over HTTP
# instead of opening pod_state.db directly — see the /api/scc/run-check-sync
# pattern dashboard.py already uses for one case). That refactor removes the
# root cause (WAL locking across the Docker bind mount wedging the host
# process's own connections); this script only auto-clears the symptom.
# Context: ~/.claude/projects/-Users-maokuma-sw-projects/memory/pod-automator-db-corruption.md
#
# Logic: if /api/pods isn't healthy, confirm via a fresh sqlite3 CLI
# connection that the DB FILE itself is fine (integrity_check=ok) before
# touching anything — if it isn't, this is real corruption, not the wedge,
# and needs the manual dump/reload runbook in the memory file above, so we
# refuse to auto-act. Also refuse to restart while any non-VPN container
# (an ISE or pipeline run) is actively up, since restarting mid-run can kill
# a host-side watcher thread (SCC nav, cdFMC OTP) and cause a false failure.

set -u
DB="$HOME/sw_projects/pod_automator/data/pod_state.db"
LOG="$HOME/sw_projects/pod_automator/data/dashboard_health.log"
ts() { date -u +%Y-%m-%dT%H:%M:%SZ; }

http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:5050/api/pods)
if [ "$http_code" = "200" ]; then
  exit 0
fi

echo "$(ts) [health] /api/pods returned '$http_code' — investigating" >> "$LOG"

integrity=$(sqlite3 "$DB" "PRAGMA integrity_check;" 2>&1)
if [ "$integrity" != "ok" ]; then
  echo "$(ts) [health] integrity_check FAILED: $integrity — NOT auto-restarting, this needs the manual dump/reload runbook, not a restart" >> "$LOG"
  exit 1
fi

if docker ps --format '{{.Names}}' | grep -qv '^vpn-'; then
  echo "$(ts) [health] a non-VPN container is running (ISE/pipeline mid-flight) — skipping restart this cycle" >> "$LOG"
  exit 0
fi

pid=$(pgrep -f "python3 dashboard.py")
if [ -z "$pid" ]; then
  echo "$(ts) [health] no dashboard.py process found to restart" >> "$LOG"
  exit 1
fi

echo "$(ts) [health] file is healthy but process is wedged — killing PID $pid, launchd (KeepAlive) will relaunch" >> "$LOG"
kill "$pid"
sleep 3
new_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 http://localhost:5050/api/pods)
echo "$(ts) [health] post-restart /api/pods = $new_code" >> "$LOG"
