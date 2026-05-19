# POD Automator — Getting Started Guide

Welcome to the **POD Automator Appliance** — a self-contained Ubuntu VM that
automates Cisco SD-WAN C8231-G2 router onboarding for dCloud lab sessions.

---

## What's included

| Component | Details |
|-----------|---------|
| **Dashboard** | Flask web UI at `http://<vm-ip>:5050` |
| **Pipeline** | 16-step SD-WAN onboarding automation per POD |
| **Docker** | Per-POD isolated VPN + pipeline containers |
| **AD Verify** | LDAP check that user accounts are correctly provisioned |
| **cdFMC tab** | Terraform deploy status + FTD device verification |
| **Upgrade tab** | Switch (C9300) and Router (C8231-G2) software upgrade |

---

## Option A — Import the pre-built OVA

> Use this if you have a pre-built `.ova` file from the release page.

### VMware ESXi / vSphere
1. Log in to vSphere Client
2. **Actions → Deploy OVF Template**
3. Select `pod-automator-appliance.ova`
4. Accept defaults — 2 vCPU, 4 GB RAM, 40 GB disk
5. Power on the VM
6. Note the IP address shown on the console
7. Open `http://<vm-ip>:5050` in your browser

### VMware Fusion / Workstation (macOS/Windows)
1. **File → Import**
2. Select the `.ova` file
3. Power on — the dashboard starts automatically

### Proxmox
```bash
# On the Proxmox host:
qm importovf 200 pod-automator-appliance.ova local-lvm
qm start 200
```

### VirtualBox
1. **File → Import Appliance**
2. Select the `.ova` file → Import
3. Start the VM

---

## Option B — Install on any Ubuntu 24.04 VM

> Use this if you already have an Ubuntu 24.04 server/VM and want to turn it
> into the appliance. Works on bare metal, cloud instances, or VMs.

```bash
curl -fsSL \
  https://raw.githubusercontent.com/maokuma_cisco/pod-automator/main/appliance/install.sh \
  | sudo bash
```

The script will:
- Install Docker Engine and Docker Compose
- Install `uv` (Python package manager)
- Clone the repo to `/opt/pod-automator`
- Build the `pod-automator:latest` Docker image
- Start the dashboard as a systemd service on port **5050**
- Open port 5050 in UFW

---

## Option C — Build the OVA yourself with Packer

> Use this to create a fresh, reproducible OVA from scratch.

### Prerequisites
```bash
# macOS
brew install hashicorp/tap/packer

# Ubuntu
wget -O- https://apt.releases.hashicorp.com/gpg | sudo gpg --dearmor \
  -o /usr/share/keyrings/hashicorp-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] \
  https://apt.releases.hashicorp.com $(lsb_release -cs) main" \
  | sudo tee /etc/apt/sources.list.d/hashicorp.list
sudo apt-get update && sudo apt-get install -y packer

# Install VMware plugin
packer plugins install github.com/hashicorp/vmware
```

### Update ISO checksum
Before building, get the current SHA256 checksum for the Ubuntu 24.04 ISO:
```bash
curl -s https://releases.ubuntu.com/24.04/SHA256SUMS | grep live-server-amd64
```
Update `ubuntu_iso_checksum` in `appliance/packer/pod-automator.pkr.hcl`.

### Build
```bash
cd appliance/packer
packer init .
packer build pod-automator.pkr.hcl
# Output: appliance/packer/output-pod-automator/pod-automator-appliance.ova
```

---

## First-time Setup

### 1. Log in to the dashboard
Open `http://<vm-ip>:5050` in a browser.

### 2. Upload EventsDetails.csv
Click **Upload CSV** at the top of the dashboard and upload your
`EventsDetails.csv` from the dCloud session booking.

Expected format:
```csv
Session Id,POD Number,vpn host,Username,Password
1329155,4,dcloud-rtp-anyconnect.cisco.com,v4130user1,9dcf3c
1329155,5,dcloud-rtp-anyconnect.cisco.com,v4130user1,9dcf3c
```

This populates the POD list. Each row = one POD.

### 3. Connect VPNs
Click **Connect All VPN** and wait for all POD rows to show a green dot
in the VPN column (typically 15–30 seconds per POD).

### 4. Run Automation
Click **Run All POD Automation**. The pipeline runs 16 steps per POD:

| Step | What it does |
|------|-------------|
| 1 | Onboard device to vManage (quickConnect) |
| 2 | Assign WAN Advantage license |
| 3 | Associate config group |
| 4 | Set device variables |
| 5 | Deploy config group |
| 6 | Generate bootstrap config |
| 7 | Copy bootstrap to router via TFTP |
| 8 | Enable SD-WAN controller mode (router reboots) |
| 9 | Verify 3 SD-WAN control tunnels |
| 10 | Connectivity test (switches → 198.18.5.100) |
| 11 | Verify Border Spine switch |
| 12 | Verify Leaf 1 switch |
| 13 | Verify Leaf 2 switch |
| 14 | Check cdFMC / Terraform deployment |
| 15 | Verify AD user provisioning |
| 16 | Final ready check |

Full automation takes **15–25 minutes** per POD.

### 5. Monitor progress
- Click any POD row to open the detail panel
- **Pipeline Steps tab** — per-step status with results
- **Live Logs tab** — real-time log stream from the container
- **Switches tab** — per-switch OSPF / VLAN / VRF verification
- **cdFMC tab** — Terraform + FTD status
- **AD Verify tab** — AD user email domain check
- **Upgrade tab** — software version status for switches and router

---

## Software Upgrades

### Configure golden versions
At the top of the dashboard, the **Software Upgrade Images** card lets you:
1. Set the **golden version** (target version) for switches and router
2. Upload a `.bin` image — the file is transferred to the Ubuntu PC
   (`198.18.134.12`) and served via HTTP during upgrades

### Run an upgrade
1. Open a POD's detail panel → **Upgrade** tab
2. Each device shows its current status
3. Click **Run Upgrade** — the system compares current vs golden version
   - If current ≥ golden: skips (never downgrades)
   - If current < golden: downloads and installs the image
4. Switches take ~20 minutes (install + reload)
5. Router takes ~25 minutes (install + reload + SD-WAN tunnel restore)

---

## VM Credentials

| What | Value |
|------|-------|
| VM username | `podmgr` |
| VM password | `C1sco12345` |
| Dashboard port | `5050` |

---

## Managing the service

```bash
# Status
systemctl status pod-automator

# Restart dashboard
systemctl restart pod-automator

# Live logs
journalctl -u pod-automator -f

# Stop
systemctl stop pod-automator

# Update to latest code
cd /opt/pod-automator && git pull
docker build -f docker/Dockerfile -t pod-automator:latest .
systemctl restart pod-automator
```

---

## File layout

```
/opt/pod-automator/
├── dashboard.py          # Flask dashboard (all tabs, all API endpoints)
├── onboard.py            # Docker entrypoint — pipeline loop
├── onboard_router.py     # All phase functions (sdwan, ad, cdfmc, upgrade)
├── requirements.txt      # Python dependencies
├── docker/
│   ├── Dockerfile        # pod-automator:latest image
│   ├── compose-template.yml
│   ├── generate.py       # Generates per-POD docker-compose stacks
│   ├── launch.sh
│   ├── status.sh
│   └── stop.sh
├── data/
│   └── pod_state.db      # SQLite — all POD state, steps, logs, upgrade config
└── appliance/
    ├── install.sh        # This install script
    ├── GETTING-STARTED.md
    └── packer/
        ├── pod-automator.pkr.hcl
        └── http/
            ├── user-data  # Ubuntu autoinstall config
            └── meta-data
```

---

## Troubleshooting

### Dashboard won't start
```bash
journalctl -u pod-automator -n 100
# Common cause: port 5050 in use
ss -tlnp | grep 5050
```

### VPN won't connect
- Ensure the VM has internet access (or access to the dCloud VPN host)
- Check that `openconnect` is installed in the Docker image:
  `docker run --rm pod-automator:latest openconnect --version`
- Verify VPN credentials in the uploaded CSV

### Pipeline step fails
- Click the POD row → **Live Logs** tab for detailed output
- Most failures are transient — click **Run Automation** again to retry
- The pipeline is idempotent — completed steps are not re-run

### Can't reach switches from the VM
Switches (`198.18.128.x`) are reachable from the Ubuntu automation PC
(`198.18.134.12`), not directly from the pipeline containers.
The upgrade pipeline SSHes to the Ubuntu PC, which then connects to switches.

### Docker image outdated after code update
```bash
cd /opt/pod-automator
git pull
docker build -f docker/Dockerfile -t pod-automator:latest .
# Running containers are unaffected until next POD launch
```

---

## Architecture overview

```
┌─────────────────────────────────────────────────────┐
│  POD Automator VM  (Ubuntu 24.04)                   │
│                                                     │
│  ┌──────────────────────────────────────────────┐   │
│  │  systemd: pod-automator.service              │   │
│  │  └── uv run python3 dashboard.py :5050       │   │
│  └──────────────────────────────────────────────┘   │
│                                                     │
│  Per-POD Docker Compose stack                       │
│  ┌──────────────┐   ┌───────────────────────────┐  │
│  │  vpn         │   │  pipeline                 │  │
│  │  openconnect │   │  onboard.py               │  │
│  │  → tun0      │◄──│  network_mode: service:vpn│  │
│  └──────────────┘   └───────────────────────────┘  │
│                                                     │
│  SQLite: /opt/pod-automator/data/pod_state.db       │
└─────────────────────────────────────────────────────┘
         │ VPN tunnel per POD
         ▼
┌────────────────────┐     ┌─────────────────────┐
│  vManage           │     │  Ubuntu auto PC     │
│  198.18.133.10     │     │  198.18.134.12      │
│  (per-POD)         │     │  (switch upgrades)  │
└────────────────────┘     └─────────────────────┘
         │
┌────────────────────┐
│  C8231-G2 Router   │
│  198.18.133.25     │
└────────────────────┘
```
