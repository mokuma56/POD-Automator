#!/usr/bin/env bash
# update.sh — Pull latest POD Automator code from GitHub and restart the dashboard.
#
# Called by the dashboard's /api/update endpoint.
# Streams progress line-by-line. Ends with either:
#   DONE:no-restart   — code was already up to date
#   DONE:restart      — code was updated; dashboard will restart in 3s
#   ERROR:<message>   — something failed

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

log() { echo "[update] $*"; }

# ── 1. Check we are in a git repo ────────────────────────────────────────────
if ! git rev-parse --is-inside-work-tree &>/dev/null; then
    echo "ERROR:Not a git repository — cannot auto-update"
    exit 1
fi

# ── 2. Fetch without merging so we can compare ───────────────────────────────
log "Fetching from origin..."
if ! git fetch origin main 2>&1; then
    echo "ERROR:git fetch failed — check network / GitHub access"
    exit 1
fi

LOCAL=$(git rev-parse HEAD)
REMOTE=$(git rev-parse origin/main)

if [ "$LOCAL" = "$REMOTE" ]; then
    log "Already up to date ($(git rev-parse --short HEAD))"
    echo "DONE:no-restart"
    exit 0
fi

log "Update available: $(git rev-parse --short HEAD) → $(git rev-parse --short origin/main)"

# ── 3. Show what changed ─────────────────────────────────────────────────────
log "Changed files:"
git diff --name-only HEAD origin/main | while read -r f; do log "  $f"; done

CHANGED=$(git diff --name-only HEAD origin/main)

# ── 4. Pull ──────────────────────────────────────────────────────────────────
log "Pulling latest code..."
git pull origin main 2>&1 | while IFS= read -r line; do log "$line"; done

# ── 5. Sync Python dependencies if pyproject.toml changed ───────────────────
if echo "$CHANGED" | grep -q "pyproject.toml\|requirements.txt"; then
    log "pyproject.toml changed — running uv sync..."
    uv sync 2>&1 | while IFS= read -r line; do log "$line"; done
else
    log "Dependencies unchanged — skipping uv sync"
fi

# ── 6. Rebuild Docker image if pipeline code changed ─────────────────────────
DOCKER_FILES="onboard_router.py onboard.py docker/Dockerfile docker/vpn-entrypoint.sh"
NEED_DOCKER=0
for f in $DOCKER_FILES; do
    if echo "$CHANGED" | grep -q "^${f}$"; then
        NEED_DOCKER=1
        break
    fi
done

if [ "$NEED_DOCKER" = "1" ]; then
    log "Pipeline code changed — rebuilding Docker image (this takes 2-4 minutes)..."
    docker compose -f docker/docker-compose.yml build 2>&1 | while IFS= read -r line; do log "$line"; done
    log "Docker image rebuilt successfully"
else
    log "No pipeline code changes — Docker rebuild not needed"
fi

# ── 7. Sync shared Knowledge Base articles ───────────────────────────────────
log "Syncing shared Knowledge Base articles..."
uv run python3 kb_sync.py pull 2>&1 | while IFS= read -r line; do log "$line"; done || true

# ── 8. Schedule dashboard restart ────────────────────────────────────────────
log "Update complete. Restarting dashboard in 3 seconds..."
echo "DONE:restart"

# Detach restart so the SSE response can flush before the process dies
(
    sleep 3
    # If launched via run_dashboard.sh the wrapper auto-restarts after kill.
    # If launched directly, we restart it ourselves.
    WRAPPER_PID=$(pgrep -f "run_dashboard.sh" | head -1 || true)
    DASH_PID=$(pgrep -f "python.*dashboard.py" | head -1 || true)

    if [ -n "$DASH_PID" ]; then
        kill "$DASH_PID" 2>/dev/null || true
    fi

    # If no wrapper is running, relaunch dashboard directly
    if [ -z "$WRAPPER_PID" ] && [ -n "$DASH_PID" ]; then
        sleep 1
        nohup uv run python3 "$SCRIPT_DIR/dashboard.py" >> "$SCRIPT_DIR/data/dashboard.log" 2>&1 &
    fi
) &

exit 0
