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

# ── 1b. Refuse while a run is in flight ─────────────────────────────────────
# Updating restarts the dashboard, which kills every in-flight Duo card and ISE
# host step (the old 15-minute auto-pull cron on the Linux host did exactly
# that). Read-only query; the host may read the DB.
DB="$SCRIPT_DIR/data/pod_state.db"
if command -v sqlite3 >/dev/null 2>&1 && [ -f "$DB" ]; then
    BUSY=$(sqlite3 -readonly "$DB" "SELECT group_concat(pod_id||':'||step_name, ', ') FROM (
        SELECT pod_id, step_name FROM duo_steps WHERE status='running'
        UNION ALL SELECT pod_id, step_name FROM ise_steps WHERE status='running'
        UNION ALL SELECT pod_id, step_name FROM pipeline_steps WHERE status='running');" 2>/dev/null || true)
    if [ -n "$BUSY" ]; then
        echo "ERROR:Runs in progress ($BUSY) — updating restarts the dashboard and would kill them. Try again when they finish."
        exit 1
    fi
else
    log "WARNING: sqlite3 not found — cannot check for running steps"
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

# Only a remote that is AHEAD is an update. "Different" is not enough: a copy
# deployed ahead of GitHub (2026-09-29, Linux host) was "updated" backwards —
# nothing pulled, image rebuilt, dashboard restarted for no reason.
if git merge-base --is-ancestor "$REMOTE" "$LOCAL"; then
    log "Local $(git rev-parse --short HEAD) is ahead of origin/main $(git rev-parse --short "$REMOTE") — nothing to pull"
    echo "DONE:no-restart"
    exit 0
fi
if ! git merge-base --is-ancestor "$LOCAL" "$REMOTE"; then
    echo "ERROR:Local $(git rev-parse --short HEAD) and origin/main $(git rev-parse --short "$REMOTE") have diverged — resolve by hand (git log --oneline --graph HEAD origin/main)"
    exit 1
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

# ── 6. Rebuild Docker image if any code baked into it changed ────────────────
# Read the file list from docker/Dockerfile's COPY lines, so it cannot drift
# from what the image really contains (a hardcoded list missed
# ise_integrations.py, duo_automation.py, hostdb.py, db_ops.py … and left the
# image stale). data/ is bind-mounted at run time, so it does not count.
IMAGE_FILES=$(awk '/^COPY /{for(i=2;i<NF;i++) print $i}' docker/Dockerfile | sed 's#/$##' | grep -vx "data")
NEED_DOCKER=0
while IFS= read -r f; do
    [ -z "$f" ] && continue
    if echo "$CHANGED" | grep -q "^${f}\(/\|$\)"; then NEED_DOCKER=1; log "  image input changed: $f"; fi
done <<< "$IMAGE_FILES
docker/Dockerfile"

if [ "$NEED_DOCKER" = "1" ]; then
    log "Image code changed — rebuilding Docker image (this takes 2-4 minutes)..."
    docker compose -f docker-compose.yml build 2>&1 | while IFS= read -r line; do log "$line"; done
    log "Docker image rebuilt successfully"
else
    log "No image code changes — Docker rebuild not needed"
fi

# ── 7. Sync shared Knowledge Base articles ───────────────────────────────────
log "Syncing shared Knowledge Base articles..."
uv run python3 kb_sync.py pull 2>&1 | while IFS= read -r line; do log "$line"; done || true

# ── 8. Schedule dashboard restart ────────────────────────────────────────────
log "Update complete. Restarting dashboard in 3 seconds..."
echo "DONE:restart"

# Detach restart so the SSE response can flush before the process dies.
# Under a service manager (systemd sets INVOCATION_ID; a launchd agent sets
# XPC_SERVICE_NAME) only stop the dashboard — the manager relaunches it.
# Relaunching it ourselves as well started a second copy outside the manager.
SUPERVISED=0
if [ -n "${INVOCATION_ID:-}" ] || { [ -n "${XPC_SERVICE_NAME:-}" ] && [ "${XPC_SERVICE_NAME}" != "0" ]; } \
   || pgrep -f "run_dashboard.sh" >/dev/null 2>&1; then
    SUPERVISED=1
fi
(
    sleep 3
    pkill -f "python3 dashboard.py" 2>/dev/null || true
    if [ "$SUPERVISED" = "0" ]; then
        sleep 2
        nohup uv run python3 "$SCRIPT_DIR/dashboard.py" >> "$SCRIPT_DIR/data/dashboard.log" 2>&1 &
    fi
) &

exit 0
