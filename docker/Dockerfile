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
    VMANAGE_PASS=C1sco12345 \
    ROUTER_USER=admin \
    ROUTER_PASS=C1sco12345 \
    PYTHONUNBUFFERED=1

COPY onboard.py onboard_router.py evpn_fabric.py reset_switches.py tftp_server.py sda_fabric.py duo_automation.py ise_integrations.py PseudocoBranches_Config-Group-Template.csv ./
COPY base_configs/ ./base_configs/
COPY docker/vpn-entrypoint.sh /vpn-entrypoint.sh
COPY data/ ./data/

# onboard_router.py has hardcoded ~/sw_projects/pod_automator/ paths
RUN mkdir -p /root/sw_projects/pod_automator/data && \
    ln -s /pipeline/PseudocoBranches_Config-Group-Template.csv /root/sw_projects/pod_automator/ && \
    ln -s /pipeline/data /root/sw_projects/pod_automator/data && \
    chmod +x /vpn-entrypoint.sh

ENTRYPOINT ["python3", "onboard.py"]
