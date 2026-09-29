# POD Automator — setup check for another operator

**Audience: a Claude (or other AI) client helping someone run their own copy of
the POD Automator.** Work through this top to bottom and report the results in
the table at the end. It compares their setup with a known-good one (the
maintainer's Mac, 2026-09-29, which ran 7 PODs end to end — pipeline + Duo + ISE —
at the same time).

Read `CLAUDE.md` in this repo first (LOCKED files, hard-won gotchas).

## Ground rules for you (the AI)

- **Everything in sections 1–4 is read-only.** Do not start pipelines, Duo or ISE
  cards, delete PODs, or change `data/pod_state.db` without the operator saying so.
- **Never run two automators against the same POD / Duo org.** If the maintainer's
  dashboard (or anyone else's) already ran Duo on a lab session, this copy must not
  run Duo there too. The Duo admin is activated once and its passkey lives only in
  the database that activated it; two copies drift the passkey's sign counter and
  lock the admin out (it has happened twice). Ask the operator before any Duo run
  on a POD someone else touched.
- Do not commit or push.
- Never print passwords, tokens or keys; redact them in anything you show.

---

## 1. Code version

**Target: the same `main` as the known-good setup — the commit that added this
file (`Add SETUP_CHECK.md …`) or later.** Code only: never copy another
operator's `data/` folder (it holds their PODs' Duo passkeys and admin logins).

```bash
git fetch --all
git log -1 --oneline origin/main    # should be the "Add SETUP_CHECK.md" commit or newer
git log -1 --oneline HEAD           # yours
git status -sb                      # on main, clean, not behind?
```

These fixes must all be present (search by subject; hashes differ on forks),
on `main` of GitHub `maokuma_cisco/pod-automator` or `mokuma56/POD-Automator`:

| Commit subject | What breaks without it |
|---|---|
| Host-writes-only DB access: containers never open pod_state.db | Dashboard hangs with `disk I/O error` while pipelines/ISE run |
| Detect a new Duo org even when the iDAC URL did not change | Duo drives the previous session's org; admin lockouts |
| Replace a Secure Access SSO config left over from a replaced Duo org | `sso_test` "Invalid credentials" after a Duo org change |
| Prune Secure Access users left behind by a previous Duo org | `sso_test` picks a dead user |
| Verify SD-WAN is really online before skipping the router steps | Reset PODs skip all SD-WAN steps |
| Fix two ISE false soft-fails seen in the multi-POD run | ISE step 3 / 4 false failures |
| Cap host browsers and run ISE host halves in parallel | Mac runs out of memory; ISE steps queue and time out |
| Retry a stalled Cisco sign-on instead of skipping the iDAC button | Random "could not reach Security Cloud Control" |
| ISE step 4: start a fresh browser and SCC sign-in before giving up | cdFMC step stuck on a grey page |
| Discard a stored Admin API app that belongs to a previous Duo org | Duo configured half in an old org: `org_setup … admins=0, users=8`, users from another lab's domain, `sso_test` "Invalid credentials" |

```bash
for s in "Host-writes-only DB access" "Detect a new Duo org even when the iDAC URL" \
         "Replace a Secure Access SSO config left over" "Prune Secure Access users left behind" \
         "Verify SD-WAN is really online" "Fix two ISE false soft-fails" \
         "Cap host browsers and run ISE host halves" "Retry a stalled Cisco sign-on" \
         "ISE step 4: start a fresh browser" "Discard a stored Admin API app"; do
  printf '%-55s %s\n' "$s" "$(git log --oneline --grep="$s" | head -1 | cut -c1-8)"
done                                 # every line must show a hash
git diff --stat                      # local edits that differ from upstream?
```

**If anything is missing:** `git pull` (or rebase local edits onto `origin/main`),
then do section 2 — pulling alone is not enough.

## 2. After pulling: three things that are easy to forget

Most "same code, different behaviour" cases are one of these.

```bash
# a) Python deps
uv sync

# b) Rebuild the Docker image — pipeline, ISE and fabric code is BAKED INTO it
#    (docker/Dockerfile COPYs the .py files). Old image = old container code.
docker compose -f docker-compose.yml build

# c) Restart the dashboard so the host side (Duo card, ISE host halves,
#    /api/hostdb) runs the new code.
pkill -f "python3 dashboard.py"          # if a launchd agent (KeepAlive) runs it,
                                         # it relaunches by itself; otherwise:
uv run python3 dashboard.py              # (from the repo root)
```

Only restart the dashboard when nothing is running (it kills in-flight Duo cards
and ISE host steps):
```bash
sqlite3 data/pod_state.db "SELECT 'running', COUNT(*) FROM duo_steps WHERE status='running'
  UNION ALL SELECT 'ise', COUNT(*) FROM ise_steps WHERE status='running'
  UNION ALL SELECT 'pipe', COUNT(*) FROM pipeline_steps WHERE status='running';"
```

**Remove the old auto-restart job if it exists** (it was a workaround for the
dashboard hang and now only gets in the way):
```bash
launchctl list | grep pod-automator-healthcheck && {
  launchctl unload ~/Library/LaunchAgents/com.maokuma.pod-automator-healthcheck.plist
  rm ~/Library/LaunchAgents/com.maokuma.pod-automator-healthcheck.plist; }
```

## 3. Verify the code that is actually RUNNING

Each check has the expected result from the known-good setup.

```bash
# 3.1 Tests — expect "1 failed, 2xx passed"; the ONE known failure is
#     test_reused_org_residue.py::test_a_foreign_active_instance_is_flagged_not_silently_passed
uv run --with pytest python3 -m pytest tests/ -q | tail -3

# 3.2 The image has the new container code (each should print 1 or more)
docker run --rm --entrypoint sh pod-automator:latest -c '
  ls /pipeline/hostdb.py /pipeline/db_ops.py &&
  grep -c "_sdwan_live_online" /pipeline/onboard.py &&
  grep -c "on both tries" /pipeline/ise_integrations.py &&
  grep -c "timeout=1500" /pipeline/onboard_router.py'

# 3.3 The dashboard is running the new host code
curl -s -o /dev/null -w 'dashboard %{http_code}\n' http://localhost:5050/api/pods          # 200
curl -s -X POST -H 'Content-Type: application/json' -d '{}' \
     -o /dev/null -w 'hostdb route %{http_code}\n' http://localhost:5050/api/hostdb/nope      # 404 = route exists
curl -s http://localhost:5050/api/resources | python3 -c "import json,sys; d=json.load(sys.stdin); print('duo slots', d['browsers']['duo_slots_max'])"   # 5

# 3.4 A container can reach the dashboard (replace N with a POD whose VPN is up)
docker run --rm --network container:vpn-POD-N --entrypoint python3 pod-automator:latest \
  -c "import hostdb; print(hostdb.call('pipeline_state', pod_id='POD-N'))"
#    -> a dict, not HostDBError. If it fails: containers reach the host at
#       192.168.65.254:5050 (Docker Desktop); set DASHBOARD_URL if that differs.

# 3.5 The container tripwire is armed (containers must not open the DB file)
docker run --rm --network container:vpn-POD-N -v "$PWD/data:/pipeline/host-data" \
  --entrypoint python3 pod-automator:latest -c "
import sqlite3, hostdb
try: sqlite3.connect('/pipeline/host-data/pod_state.db'); print('BAD: direct open allowed')
except sqlite3.OperationalError as e: print('ok:', str(e)[:60])"

# 3.6 Database is healthy
sqlite3 data/pod_state.db "PRAGMA journal_mode; PRAGMA quick_check;"                        # wal / ok
grep -c "disk I/O error" /tmp/dashboard.log    # should not grow while PODs run (use your log path)
```

## 4. Things NOT in git that the known-good setup has

Compare each; differences here are the usual cause of "his fails, mine works".

| Item | Known-good | How to check |
|---|---|---|
| macOS host, Apple Silicon | M4 Pro, 24 GB | `sysctl hw.memsize machdep.cpu.brand_string` |
| Docker Desktop memory | 7.75 GB | `docker info --format '{{.MemTotal}}'` |
| Playwright Chromium (host) | installed | `uv run playwright install chromium` |
| Dashboard via launchd (optional) | `KeepAlive` + `RunAtLoad`, log `/tmp/dashboard.log` | `launchctl list \| grep pod-automator` |
| `data/pod_state.db` → `org_credentials` | one row per SCC org with `sa_org_id`, `pxgrid_cloud_email/_password/_account`, `sa_scim_token`, `idac_url` | see query below |
| pxGrid account per org | `PseudoCo-<org>` under the right `ciscoxarN` login (**exception: org 500 = "XAR1 Gmail Test", register ISE by hand**) | ISE step 1 log "Select an Account" |

```bash
sqlite3 -header data/pod_state.db "SELECT org_number,
  length(sa_org_id)>0 sa, pxgrid_cloud_email, pxgrid_cloud_account,
  length(pxgrid_cloud_password)>0 px_pw, length(sa_scim_token)>0 scim,
  length(duo_ikey)>0 duo_api, duo_admin_email
  FROM org_credentials ORDER BY CAST(org_number AS INT);"
```
Missing `sa_org_id` / pxGrid values for an org = ISE cannot run for PODs on that org.

## 5. Per-POD lab prerequisites (not code — check before blaming the code)

Run from the POD's VPN namespace (`docker run --rm --network container:vpn-POD-N …`)
or use the dashboard's pre-check (`POST /api/preflight/POD-N`).

1. **VPN container healthy** — `docker ps` shows `vpn-POD-N … (healthy)`. A loop of
   "Login failed" = wrong VPN user/password in the imported CSV.
2. **Jump host WinRM** `198.18.133.36:5985` open. RTP lab images ship with it OFF:
   RDP to the jump host, admin PowerShell:
   `Enable-PSRemoting -Force -SkipNetworkProfileCheck; Set-Service WinRM -StartupType Automatic; Get-NetFirewallRule -Name 'WINRM-HTTP-In-TCP*' | Set-NetFirewallRule -Enabled True -Profile Any -RemoteAddress Any`
3. **cdFMC Terraform set up on the Ubuntu PC** (`198.18.134.12`,
   `~/Documents/elevateLab/terraform.tfvars`): `cdfmc_host` must NOT be
   `"Insert Host"`. If it is, the lab's Step 1 (fill `scc_token`/`cdfmc_host`,
   then `./cli.py deploy`) hasn't been done — the pipeline can't learn the SCC org
   and Duo/ISE will fail.
4. **iDAC link present** on the jump host (Duo needs it to activate the admin).
5. AD1 `198.18.5.102` 5985/389, ISE `198.18.5.101:443`, router `198.18.133.25:22`,
   vManage `198.18.133.10:443` reachable.
6. **CSV imports:** a row whose POD Number already exists **resets that POD and
   wipes its pipeline/Duo/ISE history.** Only import rows for new POD numbers.

## 6. Known behaviour (not bugs in his copy)

- `redeploy_config_group` sometimes soft-fails with an empty reason — vManage is
  still pushing its own config ("Transaction … conflicts"). Harmless; re-run the
  pipeline to retry soft-failed steps.
- ISE step 4 can still soft-fail on a stuck SCC page; re-running from step 4
  (`POST /api/ise/run/POD-N?from_step=3`) passes.
- `sso_test` can hit a slow Cisco sign-on; the code retries once; a manual re-run
  (`POST /api/duo/run/POD-N?from_step=10`) passes.
- Duo runs at most 5 cards at once and starts new ones only above 20 % free memory
  ("queued for a Duo slot" / "waiting for host memory" in the log = working as designed).

## 7. Report back in this form

| # | Check | Result | Notes |
|---|---|---|---|
| 1 | On the target commit (or newer), all 10 subjects found | | list any missing |
| 2 | `uv sync` done / image rebuilt / dashboard restarted | | dates |
| 2 | Old healthcheck job absent | | |
| 3.1 | Tests: 1 failed (the known one), rest pass | | counts |
| 3.2 | Image has new container code | | |
| 3.3 | Dashboard: 200 / hostdb 404 / duo slots 5 | | |
| 3.4 | Container → dashboard hostdb call works | | |
| 3.5 | Tripwire armed | | |
| 3.6 | DB wal + ok; no new disk I/O errors | | |
| 4 | Host / Docker / Playwright / org_credentials | | differences |
| 5 | Per-POD prerequisites for the failing POD | | which one fails |

Then quote the **exact failing step and its result text** (from the dashboard, or
`sqlite3 data/pod_state.db "SELECT step_name,status,result FROM duo_steps WHERE pod_id='POD-N';"`
and the same for `pipeline_steps` / `ise_steps`), plus the last 40 lines of
`pipeline_logs` for that POD. That plus this table is usually enough to find it.
