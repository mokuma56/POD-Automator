#!/bin/bash
# Ubuntu Server Setup Script for POD Automator
# Run once as root: sudo bash ubuntu-setup.sh
# ---------------------------------------------

set -e

REPO_URL="https://mokuma56:${GITHUB_TOKEN}@github.com/mokuma56/POD-Automator.git"
INSTALL_DIR="/opt/pod-automator"
SERVICE_USER="pod-automator"

echo "=== POD Automator — Ubuntu Server Setup ==="

# 1. Install system dependencies
echo "Installing dependencies..."
apt-get update -qq
apt-get install -y --no-install-recommends git curl python3 python3-pip python3-venv docker.io docker-compose-v2

# 2. Install uv
echo "Installing uv..."
curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

# 3. Create service user
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/bash -m -d /home/$SERVICE_USER $SERVICE_USER
    usermod -aG docker $SERVICE_USER
    echo "Created user: $SERVICE_USER"
fi

# 4. Clone repo
if [ -z "$GITHUB_TOKEN" ]; then
    echo "ERROR: Set GITHUB_TOKEN env var before running this script"
    echo "  export GITHUB_TOKEN=ghp_..."
    exit 1
fi

if [ -d "$INSTALL_DIR/.git" ]; then
    echo "Repo already cloned, pulling latest..."
    sudo -u $SERVICE_USER git -C $INSTALL_DIR pull
else
    echo "Cloning repo to $INSTALL_DIR..."
    git clone "$REPO_URL" "$INSTALL_DIR"
    chown -R $SERVICE_USER:$SERVICE_USER "$INSTALL_DIR"
fi

# 5. Install Python dependencies
echo "Installing Python dependencies..."
sudo -u $SERVICE_USER bash -c "cd $INSTALL_DIR && ~/.local/bin/uv sync"

# 6. Create data directories
mkdir -p $INSTALL_DIR/data/scc_keys $INSTALL_DIR/data/images
chown -R $SERVICE_USER:$SERVICE_USER $INSTALL_DIR/data

# 7. Install systemd units
echo "Installing systemd units..."
cp $INSTALL_DIR/scripts/pod-automator.service /etc/systemd/system/
cp $INSTALL_DIR/scripts/pod-automator-updater.service /etc/systemd/system/
cp $INSTALL_DIR/scripts/pod-automator-updater.timer /etc/systemd/system/

systemctl daemon-reload
systemctl enable pod-automator
systemctl enable pod-automator-updater.timer
systemctl start pod-automator-updater.timer
systemctl start pod-automator

echo ""
echo "=== Setup complete ==="
echo "Dashboard: http://$(hostname -I | awk '{print $1}'):5050"
echo "Status:    systemctl status pod-automator"
echo "Logs:      journalctl -u pod-automator -f"
echo "Force update: systemctl start pod-automator-updater"
