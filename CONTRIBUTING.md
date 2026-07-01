# Contributing to POD Automator

Two-engineer workflow guide. Read this before making your first commit.

---

## Getting Started

```bash
git clone https://github.com/maokuma_cisco/pod-automator.git
cd pod-automator
uv sync
```

Start the dashboard locally:
```bash
uv run python3 dashboard.py
# http://localhost:5050
```

---

## Branch Workflow

**Never commit directly to `main`** unless it is a single-line typo fix.
All real work goes on a short-lived feature branch.

```bash
# 1. Always pull latest main before starting anything
git checkout main
git pull origin main

# 2. Create a branch named after what you are doing
git checkout -b fix/switch-reset-timeout
git checkout -b feat/ise-step6-sgt-verify
git checkout -b chore/update-readme

# 3. Work, commit often
git add <files>
git commit -m "fix: describe what changed and why"

# 4. Push your branch
git push origin fix/switch-reset-timeout

# 5. Open a PR on GitHub → maokuma_cisco/pod-automator
#    Tag the other engineer for review before merging to main
```

**Branch naming:**
| Prefix | Use for |
|--------|---------|
| `fix/` | Bug fixes |
| `feat/` | New features or steps |
| `chore/` | Config, deps, docs |
| `refactor/` | Restructuring without behaviour change |
| `test/` | Debugging branches — delete when done |

**Keep branches short-lived.** Merge and delete within a day or two.
Long-running branches accumulate merge conflicts.

---

## Before You Push

```bash
# Confirm you are on your feature branch, not main
git branch

# Check what you are about to commit
git diff --staged

# Import check — make sure nothing is broken
uv run python3 -c "import dashboard, onboard, onboard_router, reset_switches; print('OK')"
```

If your change affects the Docker pipeline container, rebuild the image:
```bash
docker compose -f docker-compose.yml build --no-cache
```

---

## Locked Files — Do Not Touch Without Discussion

These files have been hard-won and are marked locked. Bugs were painful to
fix and the current state is known-good. **Check with the other engineer
before editing any of these.**

| File | Locked scope | Tag |
|------|-------------|-----|
| `evpn_fabric.py` | Entire file | `evpn-aaa-clean` @ `47f0e18` |
| `sda_fabric.py` | Entire file | `sda-evpn-working` @ `cdd5754` |
| `dashboard.py` | `_scc_auto_reset_manual()` only | `scc-reset-locked` @ `d5a9ef1` |
| `onboard_router.py` | All SD-WAN phase functions (steps 2–13) and `phase_catc_discover()` | see below |
| `ise_integrations.py` | All 5 ISE steps + host-side functions in `dashboard.py` | `ise-all-steps-working` @ `db53401` |

**Locked phase functions in `onboard_router.py`** (steps 2–13):
`phase_reset`, `phase_quick_connect`, `phase_associate`, `phase_assign_license`,
`phase_set_variables`, `phase_deploy`, `phase_generate_bootstrap`,
`phase_copy_bootstrap`, `phase_controller_mode`, `verify_router`,
`verify_online`, `phase_redeploy_config_group`, `phase_catc_discover`

If a bug fix genuinely requires touching a locked function, open a PR and tag
the other engineer. Do not merge without explicit approval.

---

## High-Collision Files

These files are edited most often. Coordinate before both working on them at
the same time to avoid merge conflicts:

| File | Touches |
|------|---------|
| `dashboard.py` | All UI, all API endpoints, all tab logic (~6000 lines) |
| `onboard_router.py` | All pipeline phase functions (~3800 lines) |
| `onboard.py` | Pipeline step list, soft-fail logic |
| `reset_switches.py` | Switch reset logic |

If you need to work on `dashboard.py` or `onboard_router.py`, give the other
engineer a heads-up so you are not both editing it simultaneously.

---

## Commit Message Format

```
<type>: short description in present tense (≤72 chars)

Optional longer explanation if the why is not obvious.
```

Examples:
```
fix: restore missing def _make_stub_lines(switch_key) line
feat: add soft-fail handling to scc_reset_check step
refactor: replace telnet two-pass with SSH configure replace
chore: add missing netmiko dependency to pyproject.toml
```

Types: `fix`, `feat`, `refactor`, `chore`, `docs`, `test`

---

## Key Context

Before making changes, read through **`AGENTS.md`** in `~/.config/opencode/`
(or ask for a copy). It contains:

- Full pipeline architecture and step order
- Root causes of previously fixed bugs (do not re-introduce them)
- Infrastructure IPs, credentials, and API quirks
- Known hardware faults (e.g. Leaf1 C9300-48UB ignores startup-config)
- VPN setup and Docker networking model

A few critical things to know upfront:

**License API** — always use `POST /dataservice/v1/licensing/assign-licenses`
with `C8K_MEDIUM_WAN_A`. The old MSLA API returns HTTP 200 but silently fails.

**SCP from macOS** — macOS `scp` binary does not work with IOS XE (OpenSSH ≥9.0
defaults to SFTP). Use Python `netmiko.file_transfer()` instead.

**Config register** — if a router shows `0x2142` in `show bootvar`, it will
ignore startup-config on every boot. Fix: `config-register 0x2102` → `write mem`
→ `reload`.

**Switch reset** — `reset_switches.py` uses SSH + `copy flash:X startup-config`
to restore base config. It is config-agnostic (works for EVPN, SDA, or any
other state). Do not revert to the old telnet two-pass approach.

---

## Docker After Code Changes

Any change to `reset_switches.py`, `onboard_router.py`, `onboard.py`, or any
file that runs inside the pipeline container requires a Docker image rebuild
before the change takes effect in real resets:

```bash
docker compose -f docker-compose.yml build --no-cache
```

Changes to `dashboard.py` take effect on the next dashboard restart — no Docker
rebuild needed.

---

## Pushing to Both Remotes (if applicable)

The repo has two GitHub remotes. Push to both after merging to main:

```bash
git push origin main
git push mokuma56 main   # secondary mirror
```
