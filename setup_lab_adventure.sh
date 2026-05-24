#!/usr/bin/env bash
# =============================================================================
# setup_lab_adventure.sh
# Run ONCE on the Ubuntu lab host (198.18.134.12) to set up auto-updating
# lab_adventure.py from the POD-Automator GitHub repo.
#
# Usage:
#   bash setup_lab_adventure.sh
#
# What it does:
#   1. Clones POD-Automator repo to ~/pod_automator (if not already cloned)
#   2. Replaces ~/Documents/elevateLab/lab_adventure.py with a thin shim that:
#      - git pulls ~/pod_automator on every launch
#      - exec's the real lab_adventure.py from ~/pod_automator
#   3. The elevateLab repo is NOT touched (no git add/commit/pull on it)
# =============================================================================

set -e

REPO_URL="https://github.com/mokuma56/POD-Automator.git"
REPO_DIR="$HOME/pod_automator"
SHIM="$HOME/Documents/elevateLab/lab_adventure.py"

echo "==> Step 1: Clone POD-Automator repo"
if [ -d "$REPO_DIR/.git" ]; then
    echo "    Already cloned at $REPO_DIR — pulling latest"
    git -C "$REPO_DIR" pull --ff-only
else
    git clone "$REPO_URL" "$REPO_DIR"
    echo "    Cloned to $REPO_DIR"
fi

echo "==> Step 2: Install shim at $SHIM"
# Back up existing lab_adventure.py if it's not already a shim
if [ -f "$SHIM" ] && ! grep -q "POD-Automator shim" "$SHIM" 2>/dev/null; then
    cp "$SHIM" "${SHIM}.bak"
    echo "    Backed up existing lab_adventure.py to lab_adventure.py.bak"
fi

cat > "$SHIM" << 'SHIM_EOF'
#!/usr/bin/env python3
"""
POD-Automator shim — lab_adventure.py
======================================
This file lives in elevateLab/ but is NOT the real implementation.
On every launch it pulls the latest from ~/pod_automator (POD-Automator repo)
then exec's the real lab_adventure.py from there.

To update the lab: just push to GitHub — the next launch picks it up.
"""
import subprocess, sys, os

REPO = os.path.expanduser("~/pod_automator")
REAL = os.path.join(REPO, "lab_adventure.py")

# Pull latest from GitHub
print("[shim] Pulling latest lab_adventure.py from GitHub...", flush=True)
try:
    result = subprocess.run(
        ["git", "-C", REPO, "pull", "--ff-only"],
        capture_output=True, text=True, timeout=30
    )
    if result.returncode == 0:
        print(f"[shim] {result.stdout.strip() or 'Already up to date.'}", flush=True)
    else:
        print(f"[shim] git pull warning: {result.stderr.strip()}", flush=True)
except Exception as e:
    print(f"[shim] git pull failed (running cached version): {e}", flush=True)

# Exec the real file — replace this process entirely
os.chdir(REPO)
sys.argv[0] = REAL
with open(REAL) as f:
    code = compile(f.read(), REAL, "exec")
exec(code, {"__name__": "__main__", "__file__": REAL})
SHIM_EOF

echo "    Shim installed."

echo ""
echo "==> Setup complete!"
echo ""
echo "    Repo:  $REPO_DIR"
echo "    Shim:  $SHIM"
echo ""
echo "    To run the lab:"
echo "      cd ~/Documents/elevateLab && python3 lab_adventure.py"
echo ""
echo "    To update the lab going forward:"
echo "      Push changes to GitHub — next launch will auto-pull."
echo ""
