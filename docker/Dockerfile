FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    openconnect \
    iproute2 \
    net-tools \
    openssh-client \
    sshpass \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /pipeline
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Install Playwright Chromium and its system dependencies
RUN playwright install --with-deps chromium

ENV VMANAGE=198.18.133.10 \
    VMANAGE_USER=admin \
    ROUTER_USER=admin \
    PYTHONUNBUFFERED=1

COPY onboard.py onboard_router.py evpn_fabric.py reset_switches.py tftp_server.py sda_fabric.py cloud_fabric.py duo_automation.py ise_integrations.py ui_wait.py hostdb.py db_ops.py lab_secrets.py PseudocoBranches_Config-Group-Template.csv ./
COPY base_configs/ ./base_configs/
# Lab passwords for lab_secrets.py. .env is gitignored and this image is
# local-only (never pushed); .env.example keeps the COPY valid without one.
COPY .env.example .env* ./
COPY docker/vpn-entrypoint.sh /vpn-entrypoint.sh
COPY data/ ./data/

# onboard_router.py has hardcoded ~/sw_projects/pod_automator/ paths
RUN mkdir -p /root/sw_projects/pod_automator/data && \
    ln -s /pipeline/PseudocoBranches_Config-Group-Template.csv /root/sw_projects/pod_automator/ && \
    ln -s /pipeline/data /root/sw_projects/pod_automator/data && \
    chmod +x /vpn-entrypoint.sh

ENTRYPOINT ["python3", "onboard.py"]
