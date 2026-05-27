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
| **Knowledge Base** | Semantic search + Ollama AI assistant for lab issues |

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
  https://raw.githubusercontent.com/mokuma56/POD-Automator/main/appliance/install.sh \
  | sudo bash
```

The script will:
- Install Docker Engine and Docker Compose
- Install `uv` (Python package manager)
- Clone the repo to `/opt/pod-automator`
- Build the `pod-automator:latest` Docker image
- Start the dashboard as a systemd service on port **5050**
- Open port 5050 in UFW

### Verify the install succeeded

The script prints a success banner when complete:
```
[OK]    ======================================================
[OK]     Installation complete!
[OK]     Dashboard: http://<server-ip>:5050
[OK]     Docs:      /opt/pod-automator/appliance/GETTING-STARTED.md
[OK]     Logs:      journalctl -u pod-automator -f
[OK]     ======================================================
```

Check the install log at any time (including during the install):
```bash
sudo tail -50 /var/log/pod-automator-install.log
```

Check the service is running:
```bash
systemctl status pod-automator
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:5050
# Should print: 200
```

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
2. Upload a `.bin` image — the file is saved locally to `data/images/`
   on the appliance. At upgrade time, the pipeline checks whether the
   image already exists on the Ubuntu PC (`198.18.134.12:/home/cisco/`):
   - **Already there** (e.g. pre-staged manually) → used directly, no copy
   - **Not there** → copied from `data/images/` through that POD's VPN tunnel

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

# Restart dashboard (also pulls latest code automatically)
sudo systemctl restart pod-automator

# Live logs (follow)
journalctl -u pod-automator -f

# Last 50 log lines
journalctl -u pod-automator -n 50 --no-pager

# Stop
sudo systemctl stop pod-automator
```

---

## Keeping the appliance up to date

The service automatically pulls the latest code from GitHub **every time it starts**
(on boot or on `systemctl restart`). No manual update steps are needed for normal
code changes to `dashboard.py`, `onboard_router.py`, `sda_fabric.py`, etc.

### How it works
The systemd service runs `git pull` before starting the dashboard:
```
ExecStartPre=git -C /opt/pod-automator pull --ff-only
ExecStart=uv run python3 dashboard.py
```
So pushing to `main` on GitHub → `systemctl restart pod-automator` on the server
is all it takes to deploy an update.

### To deploy your latest push immediately
```bash
sudo systemctl restart pod-automator
```

### When a Docker image rebuild is also needed
Only required if you changed `docker/Dockerfile` or `onboard.py` (the pipeline
container entrypoint). Code-only changes to dashboard/pipeline Python files do
**not** need a rebuild.
```bash
sudo git -C /opt/pod-automator pull
sudo docker build -f /opt/pod-automator/docker/Dockerfile -t pod-automator:latest /opt/pod-automator
sudo systemctl restart pod-automator
```

### Optional — auto-update every 15 minutes
If you want the server to pick up pushes without any manual step:
```bash
sudo tee /etc/cron.d/pod-automator-update << 'EOF'
*/15 * * * * root systemctl restart pod-automator
EOF
```
Because the service already does `git pull` on start, this is all that's needed.
To remove it:
```bash
sudo rm /etc/cron.d/pod-automator-update
```

To check if the cron job is installed:
```bash
sudo cat /etc/cron.d/pod-automator-update
```

To see recent cron activity:
```bash
grep pod-automator /var/log/syslog | tail -20
```

---

## File layout

```
/opt/pod-automator/
├── dashboard.py          # Flask dashboard (all tabs, all API endpoints)
├── onboard.py            # Docker entrypoint — pipeline loop
├── onboard_router.py     # All phase functions (sdwan, ad, cdfmc, upgrade)
├── kb.py                 # Knowledge base — SQLite + embeddings + Ollama RAG
├── kb_seed.py            # KB seeder — AGENTS.md import + paste/file ingest
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

## Knowledge Base & AI Assistant

The Knowledge Base tab is available in every POD detail panel. It provides semantic
search over lab documentation and AI-assisted answers powered by a local Ollama model.

**Ollama runs on the proctor's Mac** — not on the appliance VM. Set it up once:

```bash
# Install Ollama
brew install ollama          # macOS
# or: curl -fsSL https://ollama.com/install.sh | sh

# Start and pull the model
ollama serve &
ollama pull llama3.2

# Seed the KB from known issues (AGENTS.md)
cd ~/sw_projects/pod_automator
uv run python3 kb_seed.py seed
```

Once Ollama is running, the Knowledge Base tab in the dashboard will show a green
status dot and AI answers will be available.

**Search works without Ollama** — semantic search (vector embeddings via
`sentence-transformers`) runs locally on the Mac as part of the dashboard process.
Only the AI answer generation requires Ollama.

### Adding documentation

| Method | How |
|--------|-----|
| **Paste Doc button** | Click in the KB tab, paste text, click Ingest |
| **From OpenCode chat** | Paste content and say "add this to the KB" |
| **CLI** | `uv run python3 kb_seed.py ingest path/to/file.txt` |
| **Seed from AGENTS.md** | Click the Seed button in the KB tab (idempotent) |

### Auto-draft on pipeline failure

When any pipeline step hard-fails, a **draft KB article** is automatically created
with the step name, error text, and POD ID. Proctors can:
1. Open the KB tab → filter by **Drafts**
2. Review the auto-generated article
3. Fill in the resolution and root cause
4. Click **Publish** to make it searchable for future runs

---

## Troubleshooting

### Check install log
```bash
sudo tail -50 /var/log/pod-automator-install.log
```

### Dashboard won't start
```bash
# See exactly why it's failing
journalctl -u pod-automator -n 50 --no-pager

# Common: port 5050 already in use
ss -tlnp | grep 5050

# Common: data directory permissions
sudo mkdir -p /opt/pod-automator/data
sudo chown -R podmgr:podmgr /opt/pod-automator/data
sudo systemctl restart pod-automator
```

### Install script stops with no error message
The script uses `set -euo pipefail` — any error causes a silent exit.
Check the log immediately:
```bash
sudo tail -20 /var/log/pod-automator-install.log
```
Then re-run with the cache-busting timestamp to get the latest script:
```bash
sudo rm -rf /opt/pod-automator
curl -fsSL \
  "https://raw.githubusercontent.com/mokuma56/POD-Automator/main/appliance/install.sh?$(date +%s)" \
  | sudo bash
```

### git pull fails with "dubious ownership"
```bash
sudo git config --global --add safe.directory /opt/pod-automator
sudo git -C /opt/pod-automator pull
sudo systemctl restart pod-automator
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
sudo git -C /opt/pod-automator pull
sudo docker build -f /opt/pod-automator/docker/Dockerfile -t pod-automator:latest /opt/pod-automator
# Running containers are unaffected until next POD launch
sudo systemctl restart pod-automator
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
