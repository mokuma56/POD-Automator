# POD Automator

Automates the Hardware POD stack for the Cisco One Experience Lab. Fully orchestrates
multi-POD SD-WAN onboarding, switch baseline verification, software upgrades, cdFMC
deployment verification, and Active Directory validation — all from a single web dashboard.
Upload a session CSV, connect per-POD VPNs, and run parallel pipelines across any number of PODs.

---

## What It Does

### SD-WAN Router Onboarding (C8231-G2)
Runs the first 11 steps of the pipeline to take a factory-reset C8231-G2 router through
the full SD-WAN onboarding process on vManage — Quick Connect, license assignment,
config group association, variable injection, config deploy, bootstrap generation,
bootstrap delivery, and controller-mode enable. Each step is tracked individually
in the dashboard with live logs, retry capability, and soft-fail handling so the
pipeline continues even if non-critical steps fail. The remaining 5 steps cover
switch verification, connectivity testing, and cdFMC validation.

### Per-POD VPN Isolation
Each POD runs inside its own Docker Compose stack with a dedicated OpenConnect VPN
container. The pipeline container shares the VPN network namespace, so all traffic
routes through that POD's specific tunnel. Multiple PODs run in parallel with no IP
conflicts — every POD has the same internal IP range but completely isolated network
namespaces.

### Switch Baseline Verification
After router onboarding, the pipeline SSHes to all three Catalyst 9300 switches
(Border Spine, Leaf 1, Leaf 2) through the POD's VPN and verifies:
- **Model** — correct C9300 variant (C9300-48UB, C9300-48P, C9300-48U)
- **VRF** — only `Mgmt-vrf` present (no leftover student VRFs from previous sessions)
- **VLANs** — only VLAN 1 present (no leftover student VLANs)
- **IOS XE version** — matches golden version (17.12.x)
- **OSPF neighbors** — Border Spine confirms 2 neighbors
- **Connectivity** — each switch can ping Catalyst Center (198.18.5.100)

Verification failures are soft-fail — the pipeline continues and flags a WARN rather
than halting, so other checks always run.

### Switch Reset to Baseline
If a switch has leftover student configuration (VRFs, VLANs, LISP fabric, SVIs),
the pipeline can push the baseline config from `base_configs/` to restore it.
Each device has its own baseline file (`leaf1.txt`, `leaf2.txt`, `border_spine.txt`).

### Software Upgrades (Switches + Router)
Configurable golden versions for switches (C9300) and router (C8231-G2). The upgrade
tab in each POD's detail panel shows current vs golden version per device and runs
upgrades on demand:
- Never downgrades — only upgrades if current version < golden
- Switch upgrade: copies image via HTTP from Ubuntu PC → flash, installs and reloads
- Router upgrade: copies image to bootflash, installs, reloads, waits for SD-WAN tunnels
- Firmware images are uploaded once via the dashboard and stored locally in `data/images/`
- At upgrade time each pipeline container checks Ubuntu PC first; if the image is not
  already there it copies it through its own VPN tunnel (pre-staged images are used as-is)

### cdFMC / Terraform Verification
Checks the Cisco Defense Orchestrator (CDO) / cloud-delivered FMC deployment status
for each POD:
- Verifies SCC org is provisioned (`scc_org` field)
- Confirms Terraform automation completed successfully
- Shows FTD device connection status
- Re-check and Reset & Redeploy buttons available from the cdFMC tab
- All Terraform commands run on the Ubuntu automation PC via SSH

### Active Directory Verification
Verifies that the AD users (Kit, Lee, Pat, Nik) in the POD's domain
(`corp.pseudoco.com`) do not have `@corp.pseudoco.com` email addresses —
confirming the AD automation ran and set POD-specific emails. LDAP query
runs against AD DC `198.18.5.102` through the POD's VPN. A **Re-run AD Automation**
button triggers `ADDuoTenantUserProvisioning.ps1` on Jumphost1 via WinRM and
re-verifies.

### Web Dashboard
Single-page Flask dashboard at `http://localhost:5050`:
- **Upload CSV** — import EventsDetails.csv to register PODs and VPN credentials
- **Stats bar** — live counts: Fully Ready / SD-WAN Online / Running / Partial / Pending
- **POD table** — sortable by Status; per-row VPN dot, SD-WAN dot, pipeline progress bar
- **Connect / Reconnect / Disconnect VPN** per POD
- **Run Automation** per POD (or Run All)
- **Detail panel** — per-POD tabbed view:
  - **Pipeline Steps** — all 16 steps with status badges and results
  - **Live Logs** — streaming pipeline output
  - **Switches** — per-switch cards with model, VRF, VLAN, version, OSPF, connectivity
  - **cdFMC** — deployment status, re-check, reset & redeploy
  - **AD Verify** — user email status, re-run automation
  - **Upgrade** — per-device version status and upgrade trigger
- **Software Upgrade Images card** — configure golden versions, upload firmware `.bin` files
- **Clickable SSH** — click any switch name to open macOS Terminal.app with SSH
  connected through the Docker VPN (password automated via `sshpass`)

### Knowledge Base & AI Assistant
A searchable knowledge base built into the dashboard, powered by local semantic
search (sentence-transformers) and an optional Ollama LLM for AI-assisted answers:
- **Search** — semantic search across all published articles using vector embeddings
- **Ask** — type a question; the system finds the most relevant articles and passes
  them to a local Ollama model (`llama3.2`) to produce a grounded answer
- **Paste Documentation** — paste any text (Cisco docs, release notes, runbooks) directly
  into the dashboard and it is chunked, embedded, and made searchable immediately
- **Auto-draft on failure** — when a pipeline step hard-fails, a draft KB article is
  automatically created with the step name, error output, and POD context; proctors
  review and publish it so future runs benefit from the captured knowledge
- **Seed from AGENTS.md** — one-click import of all known issues, infrastructure notes,
  and pipeline quirks from the central `AGENTS.md` file
- **Update from chat** — paste documentation here in the OpenCode chat and it is
  ingested directly into the KB via `kb_seed.ingest_text()`

---

## Pipeline Steps

| # | Step | Description |
|---|------|-------------|
| 1 | **verify_router** | SSH reachability check on router mgmt IP |
| 2 | **reset_device** | Pushes base router config (credentials, SSH, HTTP) |
| 3 | **quick_connect** | Sets system-ip, site-id, host-name via vManage Quick Connect API |
| 4 | **config_group_associate** | Associates device to PseudocoBranches config group |
| 5 | **assign_license** | Assigns WAN Advantage license (C8K_MEDIUM_WAN_A) |
| 6 | **set_variables** | Pushes 34 config group variables from CSV template |
| 7 | **deploy_config_group** | Deploys config group, polls until In Sync |
| 8 | **generate_bootstrap** | Generates ciscosdwan.cfg via vManage bootstrap API |
| 9 | **copy_bootstrap** | HTTP server on tun0 IP → router copies file to bootflash |
| 10 | **controller_mode_enable** | SSH command to reboot router into SD-WAN controller mode |
| 11 | **verify_online** | Polls vManage for 3 control tunnels (vBond/vManage/vSmart) |
| 12 | **verify_border_spine** | C9300-48UB — model, VRF, VLAN, version, OSPF, connectivity |
| 13 | **verify_leaf1** | C9300-48P — model, VRF, VLAN, version, connectivity |
| 14 | **verify_leaf2** | C9300-48U — model, VRF, VLAN, version, connectivity |
| 15 | **connectivity_test** | Each switch pings Catalyst Center (198.18.5.100) |
| 16 | **cdfmc_check** | cdFMC/Terraform deployment and FTD connection verification |

Steps 10–16 are **soft-fail** — on failure the pipeline records a WARN and continues
so switch checks always run even if the router or cdFMC step fails.

---

## Quick Start

### Prerequisites
- Docker Desktop
- Python 3.9+ with `uv`
- Access to dCloud One Experience Lab session

### Start Dashboard
```bash
cd pod-automator
uv run python3 dashboard.py
# Open http://localhost:5050
```

### Run Onboarding
1. **Upload CSV** — upload `EventsDetails.csv` from your dCloud session booking
2. **Connect All VPN** — spins up a Docker stack with OpenConnect per POD
3. Wait for VPN dots to turn green
4. **Run All POD Automation** — launches the 16-step pipeline in parallel across all PODs

### Event CSV Format
```csv
Session Id,POD Number,vpn host,Username,Password
1329155,9,dcloud-rtp-anyconnect.cisco.com,v4130user1,9dcf3c
1329155,10,dcloud-rtp-anyconnect.cisco.com,v4130user1,9dcf3c
```

Router IP is auto-derived as `198.18.133.{21 + pod_num}`.

---

## Infrastructure Reference

| Device | IP | Credentials |
|--------|----|-------------|
| vManage | `198.18.133.10` | `admin` / `C1sco12345` |
| Router (C8231-G2) | `198.18.133.{21+N}` | `admin` / `C1sco12345` |
| Border Spine (C9300-48UB) | `198.18.128.24` | `netadmin` / `C1sco12345` |
| Leaf 1 (C9300-48P) | `198.18.128.22` | `netadmin` / `C1sco12345` |
| Leaf 2 (C9300-48U) | `198.18.128.23` | `netadmin` / `C1sco12345` |
| Ubuntu Automation PC | `198.18.134.12` | `cisco` / `C1sco12345` |
| AD Domain Controller | `198.18.5.102` | `administrator` / (session creds) |
| Jumphost1 | `198.18.133.36` | RDP only |
| Catalyst Center | `198.18.5.100` | — |

**Config group:** `ae290e0f-7bc4-40f7-9bfa-23b1e7b2a71a` (PseudocoBranches)

**License:** `C8K_MEDIUM_WAN_A` — WAN Advantage for C8000 Secure Router, Medium
Smart Account: `dCloud Cisco Internal Account` / VA: `dCloud-Pseudoco-Campus`

> **Important:** The old MSLA API (`/dataservice/msla/assignLicenses`) returns HTTP 200
> but does NOT enable SD-WAN controller mode. Always use
> `POST /dataservice/v1/licensing/assign-licenses` with `C8K_MEDIUM_WAN_A`.

---

## Project Structure

```
pod-automator/
├── dashboard.py                          # Flask dashboard — all UI, API endpoints, tabs
├── onboard_router.py                     # All pipeline phase functions
├── onboard.py                            # Docker entrypoint — pipeline loop, soft-fail logic
├── kb.py                                 # Knowledge base — SQLite + embeddings + Ollama RAG
├── kb_seed.py                            # KB seeder — AGENTS.md import + ingest_text() API
├── base_configs/
│   ├── border_spine.txt                  # Baseline config for C9300-48UB Border Spine
│   ├── leaf1.txt                         # Baseline config for C9300-48P Leaf 1
│   ├── leaf2.txt                         # Baseline config for C9300-48U Leaf 2
│   └── branch_sec_rtr.txt                # Baseline config for C8231-G2 router
├── docker/
│   ├── Dockerfile                        # python:3.14-slim + openconnect + sshpass
│   ├── compose-template.yml              # Per-POD compose stack (vpn + pipeline containers)
│   ├── generate.py                       # Launch / status / teardown POD stacks
│   ├── launch.sh                         # Shortcut: --db --up
│   ├── status.sh                         # Shortcut: --db --status
│   └── stop.sh                           # Shortcut: --db --down
├── data/
│   ├── pod_state.db                      # SQLite: pods, pipeline_steps, pipeline_logs, upgrade_config, knowledge_base
│   ├── bootstrap/                        # Generated bootstrap configs (gitignored)
│   └── images/                           # Uploaded firmware .bin files (gitignored)
├── scripts/
│   ├── ubuntu-setup.sh                   # One-command Ubuntu server setup (systemd + auto-update)
│   ├── git-update.sh                     # Pull latest from GitHub, restart if changed
│   ├── pod-automator.service             # systemd service unit for dashboard
│   ├── pod-automator-updater.service     # systemd oneshot unit for git pull
│   └── pod-automator-updater.timer       # systemd timer — triggers updater every 5 min
├── appliance/
│   ├── install.sh                        # One-command Ubuntu appliance installer
│   ├── GETTING-STARTED.md                # Deployment and usage guide
│   └── packer/
│       ├── pod-automator.pkr.hcl         # Packer HCL — VMware ISO → OVA
│       └── http/user-data                # Ubuntu 24.04 autoinstall (unattended)
├── PseudocoBranches_Config-Group-Template.csv  # 34 SD-WAN config group variables
├── requirements.txt
└── pyproject.toml
```

---

## Docker Architecture

Each POD runs as an isolated Docker Compose stack:

```
vpn-POD-N   (pod-automator:latest)  ← OpenConnect VPN tunnel (tun0)
     │
pipeline-POD-N  (pod-automator:latest)  ← network_mode: service:vpn
```

All pipeline traffic routes through the POD's VPN tunnel. Bootstrap delivery
uses a Python HTTP server on `tun0` IP — the router downloads `ciscosdwan.cfg`
directly from the container.

### CLI
```bash
# Launch all PODs from DB
uv run python3 docker/generate.py --db --up

# Single POD
uv run python3 docker/generate.py --db --up --pod POD-9

# VPN only (no pipeline)
uv run python3 docker/generate.py --db --up --pod POD-9 --vpn-only

# Status
uv run python3 docker/generate.py --db --status

# Teardown
uv run python3 docker/generate.py --db --down
```

---

## Appliance Deployment

For production use, deploy as a self-contained Ubuntu 24.04 VM:

```bash
# One-command install on Ubuntu 24.04
curl -fsSL https://raw.githubusercontent.com/.../install.sh | sudo bash
```

Or build an OVA with Packer:
```bash
cd appliance/packer
packer build pod-automator.pkr.hcl
```

See `appliance/GETTING-STARTED.md` for full deployment options (OVA import,
install script, Packer build), upgrade instructions, and troubleshooting.

---

## Ubuntu Server Deployment (Auto-Updating)

Deploy on any Ubuntu 22.04/24.04 server so the dashboard runs as a system
service and automatically pulls the latest code from GitHub every 5 minutes.
Push from your Mac → server picks it up with no manual intervention.

### Prerequisites

- Ubuntu 22.04 or 24.04 server
- `sudo` / root access
- Docker installed (the setup script will install it if missing)
- A GitHub Personal Access Token with `repo` scope for `mokuma56/POD-Automator`

### One-Time Setup

```bash
# 1. SSH into the Ubuntu server as root (or a sudo user)
ssh user@<server-ip>

# 2. Set your GitHub token
export GITHUB_TOKEN=ghp_YourPersonalAccessTokenHere

# 3. Download and run the setup script
curl -fsSL https://raw.githubusercontent.com/mokuma56/POD-Automator/main/scripts/ubuntu-setup.sh \
  | sudo -E bash

# 4. Store the token permanently so the auto-updater can pull
sudo mkdir -p /etc/pod-automator
echo "ghp_YourPersonalAccessTokenHere" | sudo tee /etc/pod-automator/github_token
sudo chmod 600 /etc/pod-automator/github_token
```

The setup script will:
- Install system dependencies (`git`, `docker`, `uv`, Python 3)
- Clone the repo to `/opt/pod-automator`
- Install Python dependencies via `uv sync`
- Register and start the `pod-automator` systemd service
- Register and start the `pod-automator-updater` timer (polls every 5 min)

Dashboard will be available at `http://<server-ip>:5050` immediately.

### Auto-Update Behaviour

Every 5 minutes the updater timer runs `scripts/git-update.sh` which:
1. Fetches `origin/main` from GitHub
2. If new commits are detected — pulls, re-syncs deps if `pyproject.toml` changed, restarts the dashboard
3. If already up-to-date — does nothing (no restart, no disruption)

To force an immediate update at any time:
```bash
sudo systemctl start pod-automator-updater
```

### Useful Commands

```bash
# Dashboard status
sudo systemctl status pod-automator

# Live dashboard logs
sudo journalctl -u pod-automator -f

# Auto-updater last run
sudo journalctl -u pod-automator-updater -n 20

# Timer schedule
sudo systemctl list-timers pod-automator-updater.timer

# Restart dashboard manually
sudo systemctl restart pod-automator

# Stop everything
sudo systemctl stop pod-automator pod-automator-updater.timer
```

### Development Workflow

```
Mac (develop) ──git push──► GitHub (mokuma56/POD-Automator)
                                        │
                                  (every 5 min)
                                        ▼
                             Ubuntu Server (auto-pull + restart)
                             http://<server-ip>:5050
```

1. Develop and test locally on your Mac (`uv run python3 dashboard.py`)
2. Push to GitHub (`git push`)
3. Within 5 minutes the Ubuntu server picks up the change automatically

---

## Knowledge Base Setup

The Knowledge Base requires **Ollama** running on the proctor's local Mac.
Search works without Ollama — only AI-assisted answers require it.

### 1. Install Ollama (Mac)
```bash
brew install ollama
# or
curl -fsSL https://ollama.com/install.sh | sh
```

### 2. Start Ollama and pull the model
```bash
ollama serve &
ollama pull llama3.2
```

### 3. Install Python dependencies
```bash
uv sync   # picks up sentence-transformers and ollama from pyproject.toml
```

### 4. Seed the KB from AGENTS.md
```bash
uv run python3 kb_seed.py seed
```

### 5. Use it
- Open the dashboard → click any POD row → **Knowledge Base** tab
- **Search bar** — semantic search across all published articles
- **Ask bar** — natural language question answered by Ollama using KB context
- **Paste Doc button** — paste any documentation text to add it to the KB
- **Seed from AGENTS.md button** — re-import all known issues (idempotent)

### Adding knowledge from the OpenCode chat
Paste any documentation or issue description here in chat and say
"add this to the KB" — it will be ingested via `kb_seed.ingest_text()`
directly without going through the dashboard.

### CLI
```bash
# Seed from AGENTS.md
uv run python3 kb_seed.py seed

# Check KB status
uv run python3 kb.py status

# Ask a question from the CLI
uv run python3 kb.py ask "why does the router boot with no config"

# Ingest a file
uv run python3 kb_seed.py ingest path/to/doc.txt "My Doc Title" "tag1,tag2"

# Rebuild all embeddings (after changing embed model)
uv run python3 kb.py reembed
```

---

## Security Notes

- VPN credentials stored in `data/pod_state.db` — keep the file secure
- Firmware images stored in `data/images/` — excluded from git
- Bootstrap configs contain device secrets — excluded from git
- Default lab passwords (`C1sco12345`) are dCloud session credentials
