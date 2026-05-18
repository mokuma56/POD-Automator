# POD Automator

Automate Cisco SD-WAN router (C8231-G2) onboarding in dCloud lab environments.
Upload an event CSV, connect per-POD VPNs, launch pipelines, and monitor progress
— all from a web dashboard.

## Features

- **Per-POD Docker VPN isolation** — each POD gets its own OpenConnect tunnel
- **15-step pipeline** — Quick Connect → License → Associate → Variables → Deploy
  → Bootstrap → HTTP Copy → Controller-Mode → Verification
- **Web dashboard** — upload CSV, per-POD Connect VPN / Reconnect VPN / Run / Disconnect
  buttons, live logs, switch verification cards
- **Switch verification** — inline SSH checks for Border Spine, Leaf 1, Leaf 2,
  plus Catalyst Center connectivity
- **Clickable SSH** — click a switch name to open macOS Terminal.app with SSH
  connected through the Docker VPN (password automated via `sshpass`)
- **Switch model detection** — model numbers shown on cards (e.g. C9300-48UB)

## Quick Start

### Prerequisites

- Docker Desktop
- Access to a dCloud SD-WAN lab with C8231-G2 routers

### Start Dashboard

```bash
cd pod-automator
uv run python3 dashboard.py
# Open http://localhost:5050
# Upload EventsDetails.csv → see per-POD cards
```

### Run Onboarding

1. **Connect All VPN** — spins up Docker stacks with OpenConnect per POD
2. Wait for VPN dots to turn green
3. **Run All POD Automation** — starts the 15-step pipeline in each POD

Per-POD retry buttons available if a pipeline fails (VPN stays up).

## Dashboard Workflow

```
Upload CSV → Connect All VPN → Wait for green dots → Run All POD Automation
                                ↘ Reconnect VPN (if one drops)
                                      ↘ Re-check (re-run switch checks)
```

### Per-POD Actions

| Button | Action |
|--------|--------|
| **Connect VPN** | Generates compose file & starts VPN container via `generate.py --db --up --pod <id> --vpn-only` |
| **Reconnect VPN** | Tears down then brings up VPN fresh (picks up latest Docker image) |
| **Run Automation** | Starts the 15-step pipeline (VPN must be green) |
| **Disconnect VPN** | Tears down the Docker compose stack |

### Switch Cards

Click any switch name (Border Spine, Leaf 1, Leaf 2) to open macOS Terminal.app
with SSH to that switch through the Docker VPN. No password prompt —
`sshpass` feeds `C1sco12345` automatically (credentials: `netadmin` / `C1sco12345`).

Model numbers (C9300-48UB, C9300-48P, C9300-48U) are extracted from
`show inventory` PID fields.

Catalyst Center connectivity shows per-switch labels:
- "Border Spine -> Ping Catalyst Center"
- "Leaf 1 -> Ping Catalyst Center"
- "Leaf 2 -> Ping Catalyst Center"

Results show "Success" (green) or "Failed" (red).

## Pipeline Phases

| # | Phase | Description |
|---|-------|-------------|
| 1 | **Verify Router** | SSH reachability check on mgmt IP |
| 2 | **Reset Device** | Writes base config (username, SSH, HTTP) |
| 3 | **Quick Connect** | Sets system-ip, site-id, host-name via vManage API |
| 4 | **Config Group Associate** | Associates device to PseudocoBranches CG |
| 5 | **Assign License** | WAN Advantage (C8K_MEDIUM_WAN_A) |
| 6 | **Set Variables** | Pushes 34 variables from CSV template |
| 7 | **Deploy** | Deploys config group to device |
| 8 | **Generate Bootstrap** | Generates cloud-init bootstrap via vManage API |
| 9 | **Copy Bootstrap** | HTTP server on tun0 IP → router bootflash |
| 10 | **Controller-mode Enable** | Reboots router into SD-WAN mode |
| 11 | **Verify Online** | Polls for 3 control tunnels (vbond/vmanage/vsmart) |
| 12-14 | **Switch Checks** | Border Spine, Leaf 1, Leaf 2 |
| 15 | **Connectivity Test** | End-to-end ping test |

## Event CSV Format

Upload this to the dashboard:

```csv
Session Id,POD Number,vpn host,Username,Password
1329155,4,dcloud-rtp-anyconnect.cisco.com,v4130user1,9dcf3c
1329155,5,dcloud-rtp-anyconnect.cisco.com,v4130user1,9dcf3c
```

The dashboard extracts: `POD Number → pod_id`, VPN host/user/pass, session ID.
Router IP is auto-derived as `198.18.133.{21 + pod_num}`.

## Key Configuration

### Environment Variables (for `onboard.py`)

| Variable | Default | Description |
|----------|---------|-------------|
| `VMANAGE` | `198.18.133.10` | vManage IP |
| `VMANAGE_USER` | `admin` | vManage username |
| `VMANAGE_PASS` | `C1sco12345` | vManage password |
| `ROUTER_IP` | `198.18.133.25` | Router management IP |
| `ROUTER_USER` | `admin` | Router SSH username |
| `ROUTER_PASS` | `C1sco12345` | Router SSH password |
| `SERIAL` | — | Router chassis serial number |

### Config Group ID

Hardcoded in `onboard_router.py` as `ae290e0f-7bc4-40f7-9bfa-23b1e7b2a71a`
(PseudocoBranches).

### License Tag

`C8K_MEDIUM_WAN_A` — **WAN Advantage for C8000 Secure Router, Medium**
Smart Account: `dCloud Cisco Internal Account`
Virtual Account: `dCloud-Pseudoco-Campus`
Billing: Prepaid

> **Note**: The old MSLA API returns HTTP 200 but does NOT enable SD-WAN
> controller mode. Always use the WAN Advantage license via
> `POST /dataservice/v1/licensing/assign-licenses`.

### Switch Credentials

All switches: `netadmin` / `C1sco12345`

## Project Structure

```
pod-automator/
├── dashboard.py                # Flask web UI — upload CSV, VPN/POD controls, switch cards
├── onboard_router.py           # Core 15-step pipeline (DO NOT CHANGE without asking)
├── onboard.py                  # Docker entrypoint — imports onboard_router
├── docker/
│   ├── Dockerfile                    # python:3.14-slim + openconnect + sshpass + iproute2
│   ├── compose-template.yml          # Per-POD compose stack template (vpn + pipeline)
│   ├── generate.py                   # Orchestrator: launch/status/teardown PODs
│   ├── launch.sh                     # Shortcut: launch all PODs from DB
│   ├── status.sh                     # Shortcut: show POD status
│   └── stop.sh                       # Shortcut: teardown all PODs
├── data/
│   ├── pod_state.db                  # SQLite DB (pods, pipeline_steps, pipeline_logs)
│   └── bootstrap/                    # Generated bootstrap configs (gitignored)
├── PseudocoBranches_Config-Group-Template.csv  # 34 CG variables
├── requirements.txt
├── pyproject.toml
└── README.md
```

## Docker Multi-POD Architecture

Each POD runs in an isolated Docker Compose stack with the project name
matching the POD ID (e.g. `pod-4`):

```
pod-X/
├── vpn (pod-automator:latest)       ──┐  OpenConnect VPN tunnel
└── pipeline (pod-automator:latest)  ──┘  network_mode: service:vpn
```

`network_mode: service:vpn` routes all pipeline traffic through its POD's
VPN tunnel. No IP conflicts between PODs — each has its own network namespace.

Bootstrap is copied via HTTP: the pipeline starts a Python HTTP server on
its `tun0` IP, and the router downloads the config from that server.

The image includes `sshpass` for automated SSH password entry when opening
terminal sessions to switches.

### Container Network Access

Switch IPs (198.18.128.22–24) are only reachable from within the Docker
VPN containers. The dashboard opens Terminal.app via osascript, running:

```bash
docker exec -it vpn-POD-<N> sshpass -p 'C1sco12345' \
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
  netadmin@<switch-ip>
```

### VPN Status Detection

Uses `docker inspect vpn-{pod_id}` directly (not `docker compose ps`) —
works regardless of how the container was started or whether the compose
file still exists.

## CLI Usage

```bash
# Launch all pending PODs from DB
uv run python3 docker/generate.py --db --up

# Launch a single POD
uv run python3 docker/generate.py --db --up --pod POD-4

# VPN only (no pipeline)
uv run python3 docker/generate.py --db --up --pod POD-4 --vpn-only

# Teardown
uv run python3 docker/generate.py --db --down --pod POD-4

# Show status
uv run python3 docker/generate.py --db --status

# Write compose files to a directory (deploy manually)
uv run python3 docker/generate.py --db --generate /tmp/compose_gen
```

## Security Notes

- Credentials are stored in SQLite DB (`data/pod_state.db`) — keep it secure
- Docker containers have lab credentials via env vars
- Bootstrap files contain device secrets — `.gitignore` excludes them
- Default passwords (`C1sco12345`) should be rotated in production

## License

MIT
