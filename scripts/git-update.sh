#!/bin/bash
# Pulls latest from GitHub — restarts dashboard only if code changed.
# Run by systemd timer every 5 minutes.

INSTALL_DIR="/opt/pod-automator"
GITHUB_TOKEN_FILE="/etc/pod-automator/github_token"

# Load token if stored
if [ -f "$GITHUB_TOKEN_FILE" ]; then
    GITHUB_TOKEN=$(cat "$GITHUB_TOKEN_FILE")
    git -C "$INSTALL_DIR" remote set-url origin \
        "https://mokuma56:${GITHUB_TOKEN}@github.com/mokuma56/POD-Automator.git"
fi

# Check for updates
BEFORE=$(git -C "$INSTALL_DIR" rev-parse HEAD)
git -C "$INSTALL_DIR" fetch origin main --quiet

AFTER=$(git -C "$INSTALL_DIR" rev-parse origin/main)

if [ "$BEFORE" != "$AFTER" ]; then
    echo "New commits detected ($BEFORE -> $AFTER) — updating..."
    git -C "$INSTALL_DIR" reset --hard origin/main

    # Re-sync dependencies if pyproject.toml changed
    if git -C "$INSTALL_DIR" diff "$BEFORE" "$AFTER" --name-only | grep -q "pyproject.toml"; then
        echo "pyproject.toml changed — syncing dependencies..."
        /home/pod-automator/.local/bin/uv sync --project "$INSTALL_DIR"
    fi

    echo "Restarting pod-automator service..."
    systemctl restart pod-automator
    echo "Update complete: $(git -C $INSTALL_DIR rev-parse --short HEAD)"
else
    echo "Already up-to-date ($(git -C $INSTALL_DIR rev-parse --short HEAD))"
fi
