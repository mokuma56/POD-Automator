# POD Automator

Automate Cisco SD-WAN router (C8231-G2) onboarding in dCloud lab environments. Upload an event CSV, connect per-POD VPNs, launch pipelines, and monitor progress — all from a web dashboard.

## Features

- **Per-POD Docker VPN isolation** — each POD gets its own OpenConnect tunnel in Docker
- **15-step pipeline** — Quick Connect → License → Associate → Variables → Deploy → Bootstrap → HTTP Copy → Controller-Mode → Verification
- **Web dashboard** — upload CSV, connect VPNs, monitor live logs per POD
- **Switch verification** — confirms Border Spine, Leaf 1, Leaf 2 connectivity

## Quick Start

### Prerequisites

- Docker Desktop
- Access to a dCloud SD-WAN lab with C8231-G2 routers

### Start Dashboard

```bash
python3 dashboard.py
# Open http://localhost:5050
# Upload EventsDetails.csv → see per-POD cards
```

### Run Onboarding

1. **Connect All VPN** — spins up Docker stacks with OpenConnect per POD
2. Wait for VPN dots to turn green
3. **Run All POD Automation** — starts the pipeline in each POD

Per-POD retry buttons available if a pipeline fails (VPN stays up).

## Dashboard Workflow

```
Upload CSV → Connect All VPN → Wait for green dots → Run All POD Automation
                                                  ↘ Run per-POD if one fails
```

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

Hardcoded in `onboard_router.py` as `ae290e0f-7bc4-40f7-9bfa-23b1e7b2a71a` (PseudocoBranches).

### License Tag

`C8K_MEDIUM_WAN_A` — **WAN Advantage for C8000 Secure Router, Medium**
Smart Account: `dCloud Cisco Internal Account`
Virtual Account: `dCloud-Pseudoco-Campus`
Billing: Prepaid

> **Note**: The old MSLA API returns HTTP 200 but does NOT enable SD-WAN controller mode.
> Always use the WAN Advantage license via `POST /dataservice/v1/licensing/assign-licenses`.

## Project Structure

```
pod-automator/
├── dashboard.py              # Flask web UI — upload CSV, connect VPNs, monitor
├── onboard_router.py         # Core 15-step pipeline (DO NOT CHANGE without asking)
├── onboard.py                # Docker entrypoint — imports onboard_router
├── docker-compose.yml        # Builds the pod-automator Docker image
├── docker/
│   ├── Dockerfile                 # python:3.14-slim + openconnect + iproute2
│   ├── compose-template.yml       # Per-POD compose stack template
│   ├── generate.py                # Orchestrator: launch/status/teardown PODs
│   ├── launch.sh                  # Shortcut: launch all PODs from DB
│   ├── status.sh                  # Shortcut: show POD status
│   └── stop.sh                    # Shortcut: teardown all PODs
├── data/
│   ├── pod_state.db               # SQLite DB (pods, pipeline_steps, pipeline_logs)
│   └── bootstrap/                 # Generated bootstrap configs (gitignored)
├── PseudocoBranches_Config-Group-Template.csv  # 34 CG variables
├── requirements.txt
└── pyproject.toml
```

## Docker Multi-POD Details

Each POD runs in an isolated Docker Compose stack:

```
pod-X/
├── vpn (pod-automator:latest)        ──┐  OpenConnect VPN tunnel
└── pipeline (pod-automator:latest)   ──┘  network_mode: service:vpn
```

`network_mode: service:vpn` routes all pipeline traffic through its POD's VPN tunnel.
No IP conflicts between PODs — each has its own network namespace.

Bootstrap is copied via HTTP: the pipeline starts a Python HTTP server on its `tun0` IP,
and the router downloads the config from that server.

## Security Notes

- Credentials are stored in SQLite DB (`data/pod_state.db`) — keep it secure
- Docker containers have lab credentials via env vars
- Bootstrap files contain device secrets — `.gitignore` excludes them
- Default passwords (`C1sco12345`) should be rotated in production

## License

MIT
