#!/bin/bash
# Server setup for the POD Automator dashboard.
# Run once as root:  sudo bash ubuntu-setup.sh
#
# Named for Ubuntu but works on any Debian-family host. Verified on
# Kali GNU/Linux Rolling (the 198.18.134.12 automation PC) on 2026-09-11, which
# is where the three assumptions below were found to be wrong:
#
#   * GITHUB_TOKEN was mandatory. POD-Automator is public, so a token is only
#     needed for a private fork; without one this refused to run at all.
#   * Docker came from "docker.io docker-compose-v2". Kali does not package
#     docker-compose-v2, so that apt line could never succeed there — and on a
#     host that already has docker-ce it would install a second Docker.
#   * apt exit codes were trusted. A pre-existing third-party repo pinned to a
#     suite its vendor does not publish makes `apt-get update` exit non-zero
#     forever, and a Kali mirror rotation made a *recommended* package 404 and
#     fail the whole install. What matters is whether the packages arrived, so
#     that is what is checked.
# ---------------------------------------------------------------------------

set -euo pipefail

INSTALL_DIR="/opt/pod-automator"
SERVICE_USER="pod-automator"
REPO_PUBLIC="https://github.com/mokuma56/POD-Automator.git"

echo "=== POD Automator — server setup ==="
. /etc/os-release 2>/dev/null || true
echo "Host: ${PRETTY_NAME:-unknown} ($(dpkg --print-architecture 2>/dev/null || uname -m))"

# apt-get update is advisory: one broken third-party repo must not stop the
# install, so failures are reported and execution continues.
apt_refresh() {
    if ! apt-get update -qq 2>&1 | grep -E '^(E|W):' >/tmp/_apt_warn; then :; fi
    if [ -s /tmp/_apt_warn ]; then
        echo "  note: apt reported problems with some repos (continuing):"
        sed 's/^/    /' /tmp/_apt_warn | head -4
    fi
    rm -f /tmp/_apt_warn
}

# --no-install-recommends on purpose: a recommended package that has rotated
# off the mirror should not fail a Docker install (pigz did exactly that).
apt_install() {
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "$@"
}

# Install only what is genuinely absent.
#
# `apt-get install git` on a host that already has git is an UPGRADE request,
# and when apt's index is stale — as it is here, because the Kali signing key
# rotated and `apt-get update` can no longer refresh it — the newer .deb it
# wants is already off the mirror and returns 404. That aborted this script
# over six packages that were all present and working. Asking for what is
# missing is both the correct intent and the thing that survives a stale index.
apt_install_missing() {
    local want=() p
    for p in "$@"; do
        if dpkg-query -W -f='${db:Status-Status}' "$p" 2>/dev/null \
                | grep -qx installed; then
            continue
        fi
        want+=("$p")
    done
    if [ ${#want[@]} -eq 0 ]; then
        echo "  already present: $*"
        return 0
    fi
    echo "  installing: ${want[*]}"
    apt_install "${want[@]}"
}

# ── 1. Base dependencies ───────────────────────────────────────────────────
echo "Checking base dependencies..."
apt_refresh
apt_install_missing git curl ca-certificates gnupg python3 python3-pip python3-venv

for _cmd in git curl python3; do
    command -v "$_cmd" >/dev/null 2>&1 || {
        echo "ERROR: $_cmd is missing and could not be installed." >&2; exit 1; }
done

# ── 2. Docker, only if it is not already usable ────────────────────────────
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    echo "Docker already present: $(docker --version) / $(docker compose version)"
else
    echo "Installing Docker..."
    if apt-cache policy docker-compose-v2 2>/dev/null | grep -q 'Candidate: [0-9]'; then
        # Debian/Ubuntu, where both are packaged.
        apt_install docker.io docker-compose-v2
    else
        # Kali and anything else without docker-compose-v2: use Docker's own
        # repo. Docker publishes no Kali suite, so pin a Debian codename.
        echo "  docker-compose-v2 is not packaged here — using Docker's official repo"
        CODENAME="${VERSION_CODENAME:-}"
        case "$CODENAME" in
            bookworm|bullseye|trixie|jammy|noble|focal) ;;
            *) CODENAME="bookworm"
               echo "  no usable codename (\"${VERSION_CODENAME:-none}\") — pinning $CODENAME" ;;
        esac
        BASE="debian"
        [ "${ID:-}" = "ubuntu" ] && BASE="ubuntu"
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL "https://download.docker.com/linux/$BASE/gpg" \
            -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc]" \
             "https://download.docker.com/linux/$BASE $CODENAME stable" \
             > /etc/apt/sources.list.d/docker.list
        apt_refresh
        apt_install docker-ce docker-ce-cli containerd.io \
                    docker-buildx-plugin docker-compose-plugin
    fi
    systemctl enable --now docker
fi

# Verify the OUTCOME rather than trusting the steps above.
if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is still not installed — stopping." >&2
    exit 1
fi
if ! docker compose version >/dev/null 2>&1; then
    echo "ERROR: 'docker compose' is unavailable — the dashboard needs compose v2." >&2
    exit 1
fi

# ── 3. Service user ────────────────────────────────────────────────────────
# Before uv, because uv must belong to THIS user — see below.
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/bash -m -d "/home/$SERVICE_USER" "$SERVICE_USER"
    echo "Created user: $SERVICE_USER"
fi
usermod -aG docker "$SERVICE_USER"

# ── 4. uv, installed for the service user ──────────────────────────────────
# pod-automator.service hardcodes ExecStart=/home/pod-automator/.local/bin/uv,
# so installing uv into root's home (what running this script under sudo would
# otherwise do) leaves the unit pointing at a path that does not exist: the
# install looks clean and the service dies on every start with status=203.
UV="/home/$SERVICE_USER/.local/bin/uv"
if [ -x "$UV" ]; then
    echo "uv already present for $SERVICE_USER: $("$UV" --version 2>/dev/null)"
else
    echo "Installing uv for $SERVICE_USER..."
    sudo -u "$SERVICE_USER" bash -lc 'curl -LsSf https://astral.sh/uv/install.sh | sh'
fi
if [ ! -x "$UV" ]; then
    echo "ERROR: uv is not at $UV, which is the path the systemd unit uses." >&2
    exit 1
fi

# ── 5. Repo ────────────────────────────────────────────────────────────────
# A token is only needed for a private fork; the upstream repo is public.
if [ -n "${GITHUB_TOKEN:-}" ]; then
    REPO_URL="https://mokuma56:${GITHUB_TOKEN}@github.com/mokuma56/POD-Automator.git"
    echo "Using GITHUB_TOKEN for the clone"
else
    REPO_URL="$REPO_PUBLIC"
    echo "No GITHUB_TOKEN set — cloning the public repo"
fi

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Repo present, pulling latest..."
    git -C "$INSTALL_DIR" remote set-url origin "$REPO_URL"
    # chown BEFORE the pull: git refuses to operate on a tree owned by someone
    # else ("detected dubious ownership") and that error would look like a
    # network problem.
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR" pull --ff-only
else
    echo "Cloning to $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
fi
# Keep the token out of .git/config even when one was used.
git -C "$INSTALL_DIR" remote set-url origin "$REPO_PUBLIC"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
# As the owner, not as root: after the chown above, root reading this repo trips
# git's "detected dubious ownership" guard and the commit line prints empty.
echo "At commit: $(sudo -u "$SERVICE_USER" git -C "$INSTALL_DIR" log --oneline -1)"

# ── 6. Python dependencies ─────────────────────────────────────────────────
echo "Installing Python dependencies..."
sudo -u "$SERVICE_USER" bash -lc "cd '$INSTALL_DIR' && '$UV' sync"

# ── 7. Data directories ────────────────────────────────────────────────────
mkdir -p "$INSTALL_DIR/data/scc_keys" "$INSTALL_DIR/data/images"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/data"

# ── 8. systemd units ───────────────────────────────────────────────────────
echo "Installing systemd units..."
cp "$INSTALL_DIR/scripts/pod-automator.service" /etc/systemd/system/
cp "$INSTALL_DIR/scripts/pod-automator-updater.service" /etc/systemd/system/
cp "$INSTALL_DIR/scripts/pod-automator-updater.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable pod-automator
systemctl enable pod-automator-updater.timer
systemctl restart pod-automator-updater.timer
systemctl restart pod-automator

sleep 3
echo ""
echo "=== Setup complete ==="
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):5050"
echo "Service:   $(systemctl is-active pod-automator)"
echo "Status:    systemctl status pod-automator"
echo "Logs:      journalctl -u pod-automator -f"
echo "Update:    systemctl start pod-automator-updater"
echo ""
echo "=== Knowledge Base / Ollama ==="
echo "Ollama runs on the PROCTOR'S LOCAL MAC, not this server:"
echo "  brew install ollama && ollama serve & && ollama pull llama3.2"
echo "  cd ~/sw_projects/pod_automator && uv run python3 kb_seed.py seed"
echo "If Ollama is offline, KB search still works — only AI answers are unavailable."
