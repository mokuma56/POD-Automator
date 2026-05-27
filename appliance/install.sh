#!/usr/bin/env bash
# =============================================================================
# POD Automator — Appliance Install Script
# Tested on Ubuntu 24.04 LTS (server or desktop, x86_64)
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/mokuma56/POD-Automator/main/appliance/install.sh | sudo bash
#
#   OR after cloning:
#   sudo bash appliance/install.sh
#
# What this script does:
#   1. Installs Docker Engine + Docker Compose plugin
#   2. Installs uv (fast Python package manager)
#   3. Clones the pod-automator repo to /opt/pod-automator
#   4. Installs Python dependencies via uv
#   5. Builds the pod-automator Docker image
#   6. Installs and enables the systemd service (starts on boot)
#   7. Opens firewall port 5050
# =============================================================================
set -euo pipefail

REPO_URL="https://github.com/mokuma56/POD-Automator.git"
INSTALL_DIR="/opt/pod-automator"
SERVICE_USER="podmgr"
DASHBOARD_PORT="5050"
LOG="/var/log/pod-automator-install.log"

# ── Colours ────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info()    { echo -e "${CYAN}[INFO]${NC}  $*" | tee -a "$LOG"; }
success() { echo -e "${GREEN}[OK]${NC}    $*" | tee -a "$LOG"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*" | tee -a "$LOG"; }
die()     { echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG"; exit 1; }

# ── Pre-flight ──────────────────────────────────────────────────────────────
[[ $EUID -ne 0 ]] && die "Run as root or with sudo."
[[ "$(uname -m)" != "x86_64" ]] && die "Only x86_64 is supported."
grep -qi ubuntu /etc/os-release 2>/dev/null || warn "Not Ubuntu — continuing anyway."

touch "$LOG"
info "POD Automator install started at $(date)"
info "Log: $LOG"

# ── 1. System packages ──────────────────────────────────────────────────────
info "Updating apt and installing prerequisites..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq \
    ca-certificates curl gnupg lsb-release git \
    apt-transport-https software-properties-common \
    ufw jq >> "$LOG" 2>&1
success "System packages installed."

# ── 2. Docker Engine ────────────────────────────────────────────────────────
if ! command -v docker &>/dev/null; then
    info "Installing Docker Engine..."
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
      https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" \
      > /etc/apt/sources.list.d/docker.list
    apt-get update -qq
    apt-get install -y -qq docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin >> "$LOG" 2>&1
    systemctl enable --now docker >> "$LOG" 2>&1
    success "Docker installed."
else
    success "Docker already present: $(docker --version)"
fi

# ── 3. uv ───────────────────────────────────────────────────────────────────
if ! command -v uv &>/dev/null; then
    info "Installing uv..."
    curl -LsSf https://astral.sh/uv/install.sh | sh >> "$LOG" 2>&1
    # Make uv available system-wide
    ln -sf "$HOME/.local/bin/uv" /usr/local/bin/uv 2>/dev/null || true
    ln -sf /root/.local/bin/uv  /usr/local/bin/uv 2>/dev/null || true
    success "uv installed."
else
    success "uv already present: $(uv --version)"
fi

# ── 4. Service user ─────────────────────────────────────────────────────────
if ! id "$SERVICE_USER" &>/dev/null; then
    info "Creating service user '$SERVICE_USER'..."
    useradd -r -m -d "/home/$SERVICE_USER" -s /bin/bash "$SERVICE_USER"
    usermod -aG docker "$SERVICE_USER"
    success "User '$SERVICE_USER' created."
else
    usermod -aG docker "$SERVICE_USER"
    success "User '$SERVICE_USER' already exists."
fi

# ── 5. Clone repo ───────────────────────────────────────────────────────────
if [[ -d "$INSTALL_DIR/.git" ]]; then
    info "Repo already cloned — pulling latest..."
    git -C "$INSTALL_DIR" pull --ff-only >> "$LOG" 2>&1 || warn "Pull failed — using existing code."
else
    info "Cloning pod-automator to $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR" >> "$LOG" 2>&1
    success "Repo cloned."
fi

chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR"

# ── 6. Python dependencies ──────────────────────────────────────────────────
info "Installing Python dependencies via uv..."
sudo -u "$SERVICE_USER" bash -c "
    cd '$INSTALL_DIR'
    /usr/local/bin/uv sync --no-dev 2>&1 || \
    /usr/local/bin/uv pip install -r requirements.txt 2>&1
" >> "$LOG" 2>&1
success "Python dependencies installed."

# ── 7. Data directory ───────────────────────────────────────────────────────
install -d -m 755 -o "$SERVICE_USER" -g "$SERVICE_USER" "$INSTALL_DIR/data"
success "Data directory ready."

# ── 8. Build Docker image ───────────────────────────────────────────────────
info "Building pod-automator Docker image (this may take a few minutes)..."
docker build -f "$INSTALL_DIR/docker/Dockerfile" \
    -t pod-automator:latest "$INSTALL_DIR" >> "$LOG" 2>&1
success "Docker image built: pod-automator:latest"

# ── 9. systemd service ──────────────────────────────────────────────────────
info "Installing systemd service..."
cat > /etc/systemd/system/pod-automator.service << EOF
[Unit]
Description=POD Automator Dashboard
Documentation=https://github.com/mokuma56/POD-Automator
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=simple
User=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=/usr/local/bin:/usr/bin:/bin"
ExecStart=/usr/local/bin/uv run python3 dashboard.py
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=pod-automator

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable pod-automator >> "$LOG" 2>&1
systemctl restart pod-automator >> "$LOG" 2>&1
sleep 3
if systemctl is-active --quiet pod-automator; then
    success "pod-automator service is running."
else
    warn "Service may not have started yet. Check: journalctl -u pod-automator -n 50"
fi

# ── 10. Firewall ────────────────────────────────────────────────────────────
if command -v ufw &>/dev/null; then
    info "Opening port $DASHBOARD_PORT in UFW..."
    ufw allow "$DASHBOARD_PORT/tcp" comment "POD Automator Dashboard" >> "$LOG" 2>&1 || true
    success "Firewall rule added."
fi

# ── 11. MOTD ─────────────────────────────────────────────────────────────────
cat > /etc/motd << 'MOTD'

  ╔══════════════════════════════════════════════════════════╗
  ║          POD Automator Appliance                        ║
  ║          Cisco SD-WAN Router Onboarding                 ║
  ╠══════════════════════════════════════════════════════════╣
  ║  Dashboard : http://<this-vm-ip>:5050                   ║
  ║  Install dir: /opt/pod-automator                        ║
  ║  Logs      : journalctl -u pod-automator -f             ║
  ║  Service   : systemctl status pod-automator             ║
  ║  Docs      : /opt/pod-automator/appliance/GETTING-STARTED.md ║
  ╚══════════════════════════════════════════════════════════╝

MOTD

# ── Done ─────────────────────────────────────────────────────────────────────
IP=$(hostname -I | awk '{print $1}')
echo ""
success "======================================================"
success " Installation complete!"
success " Dashboard: http://${IP}:${DASHBOARD_PORT}"
success " Docs:      ${INSTALL_DIR}/appliance/GETTING-STARTED.md"
success " Logs:      journalctl -u pod-automator -f"
success "======================================================"
echo ""
