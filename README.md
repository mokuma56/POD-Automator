# POD Automator

Automate Cisco SD-WAN router (C8231-G2) onboarding in dCloud lab environments. Upload an event CSV, launch the pipeline, and monitor progress — all from a web dashboard.

## Features

- **Single POD onboarding** — full 8-phase pipeline from the dashboard or CLI
- **Multi-POD parallel onboarding** — Docker Compose stacks with isolated VPN tunnels per POD
- **Pipeline phases**: Quick Connect onboard → WAN Advantage License → Config Group Associate → Variables → Deploy → Bootstrap Generate → TFTP Copy → Controller-mode Enable
- **Verification**: 3 control tunnels (vbond/vmanage/vsmart), switch connectivity checks
- **Per-POD VPN status** — live colored indicators in the dashboard

## Quick Start

### Prerequisites

- Python 3.10+
- Docker Desktop (for multi-POD mode only)
- Access to a dCloud SD-WAN lab with C8231-G2 routers
- `openconnect` CLI (for host VPN — macOS: `brew install openconnect`)

### Install

```bash
git clone <repo-url> pod-automator
cd pod-automator
pip install -r requirements.txt
# or: uv sync (if using uv)
```

### Single POD (Dashboard)

```bash
python3 dashboard.py
# Open http://localhost:5050
# Upload EventsDetails.csv → click "Start" on a POD
```

### Multi-POD (Docker)

```bash
# Build image (one-time)
docker compose -f docker-compose.yml build

# Upload CSV to dashboard first, then:
docker/launch.sh          # launches all PODs in parallel
docker/status.sh          # check VPN + pipeline status
docker/stop.sh            # teardown all PODs
```

### CLI Only (no dashboard)

```bash
python3 onboard.py --serial FJC300412NA
```

## How It Works

### Architecture

```
┌──────────────┐     ┌──────────────────────┐     ┌─────────────┐
│   Browser    │────▶│   dashboard.py        │────▶│  SQLite DB   │
│  localhost:5050│     │  Flask web UI        │     │ pod_state.db │
└──────────────┘     └──────────┬───────────┘     └─────────────┘
                                │
                    ┌───────────┴───────────┐
                    ▼                       ▼
           ┌─────────────────┐   ┌──────────────────────┐
           │ Local Pipeline   │   │  Docker (multi-POD)  │
           │ (single POD,     │   │  per-POD compose     │
           │  host VPN)       │   │  stacks with VPN     │
           └─────────────────┘   └──────────────────────┘
```

### Pipeline Phases

| # | Phase | Description |
|---|-------|-------------|
| 1 | **Quick Connect Onboard** | Sets system-ip, site-id, host-name on unclaimed vedge |
| 2 | **WAN Advantage License** | Assigns C8K_MEDIUM_WAN_A license to the device |
| 3 | **Config Group Associate** | Associates device to PseudocoBranches CG |
| 4 | **Set Variables** | Pushes 34 variables from CSV template |
| 5 | **Deploy** | Deploys config group to device |
| 6 | **Generate Bootstrap** | Generates cloud-init bootstrap via vManage API |
| 7 | **TFTP Copy** | SCP→Jump host→TFTP→Router bootflash |
| 8 | **Controller-mode Enable** | Reboots router into SD-WAN mode |
| — | **Verify** | Polls for 3 control tunnels (vbond/vmanage/vsmart) |
| — | **Switch Checks** | Pings Catalyst Center from each switch |

### Event CSV Format

Upload this to the dashboard. The file from dCloud typically includes these columns:

```csv
Session Id,POD Number,vpn host,Username,Password
1329155,4,dcloud-rtp-anyconnect.cisco.com,v4130user1,9dcf3c
1329155,5,dcloud-rtp-anyconnect.cisco.com,v4130user1,9dcf3c
```

The dashboard extracts: `POD Number → pod_id`, `vpn host/Username/Password → VPN credentials`,
`Session Id → reference`. Router IP is auto-derived as `198.18.133.{21 + pod_num}`.

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
| `JUMP_HOST` | `198.18.133.36` | TFTP jump host IP |

### Config Group ID

Hardcoded in `onboard.py` as `ae290e0f-7bc4-40f7-9bfa-23b1e7b2a71a` (PseudocoBranches).
Change to match your vManage config group.

### License Tag

`C8K_MEDIUM_WAN_A` — **WAN Advantage for C8000 Secure Router, Medium**
Smart Account: `dCloud Cisco Internal Account`
Virtual Account: `dCloud-Pseudoco-Campus`
Billing: Prepaid

> **Note**: The old MSLA license API (`POST /dataservice/msla/assignLicenses`) with
> `C8K_SMALL_WAN_A` returns HTTP 200 but does NOT enable SD-WAN controller mode.
> Always use the WAN Advantage license via `POST /dataservice/v1/licensing/assign-licenses`.

## Project Structure

```
pod-automator/
├── dashboard.py          # Flask web UI — upload CSV, start/monitor pipelines
├── onboard.py            # Main 8-phase pipeline (CLI + Docker entrypoint)
├── onboard_router.py     # Module with all phase functions (used by dashboard)
├── docker-compose.yml    # Builds the pipeline Docker image
├── docker/
│   ├── Dockerfile             # Python + openconnect pipeline image
│   ├── compose-template.yml   # Per-POD compose stack template
│   ├── generate.py            # Orchestrator: launch/status/teardown PODs
│   ├── launch.sh              # Shortcut: launch all PODs from DB
│   ├── status.sh              # Shortcut: show POD status
│   └── stop.sh                # Shortcut: teardown all PODs
├── data/
│   └── bootstrap/             # Generated bootstrap configs (gitignored)
├── base_configs/              # Switch/router IOS base config templates
├── PseudocoBranches_Config-Group-Template.csv  # 34 CG variables
├── pods.example.csv           # Example upload CSV format
├── requirements.txt           # Python dependencies
├── pyproject.toml             # Project metadata
└── .gitignore
```

## Docker Multi-POD Details

Each POD runs in an isolated Docker Compose stack:

```
stack-POD-4/
├── vpn (alpine/openconnect)      ──┐
└── pipeline (pod-automator:latest)──┘ network_mode: service:vpn
```

`network_mode: service:vpn` ensures the pipeline container routes all traffic
through its POD's VPN tunnel. No IP conflicts between PODs — each has its
own network namespace with identical internal IPs.

## Security Notes

- Credentials are stored in the SQLite DB (`data/pod_state.db`) — keep it secure
- The Docker pipeline container has access to your lab credentials via env vars
- Bootstrap files contain device secrets — `.gitignore` excludes them by default
- All default passwords (`C1sco12345`) should be rotated in production

## License

MIT
