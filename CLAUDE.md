# POD Automator

Cisco lab POD provisioning automation: SD-WAN router onboarding, switch fabric
(SDA/EVPN), ISE/SCC/Duo integrations, and a Flask dashboard that orchestrates it
all across multiple PODs via per-POD Docker VPN namespaces.

## Commands

```bash
# Dashboard (http://localhost:5050)
cd ~/sw_projects/pod_automator && uv run python3 dashboard.py

# Single-POD onboard pipeline
uv run python3 onboard.py
uv run python3 onboard_router.py [SERIAL]        # --stop-after-copy to pause before controller-mode

# Multi-POD Docker (per-POD VPN namespaces)
docker compose -f docker-compose.yml build       # once
uv run python3 docker/generate.py --db --up      # launch all PODs from DB
uv run python3 docker/generate.py --db --status
uv run python3 docker/generate.py --db --down

# SCC session refresh (needed if sessions >12h old)
uv run python3 refresh_scc_sessions.py data/pod_state.db
```

## Credentials

Lab credentials live in `.env` (gitignored) — see `.env.example`. Do **not** hardcode
new credentials in `.py` files. A shared lab password is currently hardcoded across
several modules (`dashboard.py`, `duo_automation.py`, `pod_automator.py`,
`reset_switches.py`, `evpn_fabric.py`, `generate_lab_cards.py`, and the `base_configs/`
templates); when you touch one of those call sites, read it from `os.environ` rather
than copying the literal forward.

Never write a credential into this file, a commit message, or a log line.

## Architecture

- `dashboard.py` — Flask app, 106 routes, plus a ~5,000-line embedded HTML/CSS/JS
  template string (`DASHBOARD_HTML`, from line ~6872). All UI lives there.
- `onboard.py` — 21-step pipeline driver; `SOFT_FAIL_STEPS` marks non-blocking steps
- `onboard_router.py` — SD-WAN router phases (steps 2–13) + switch/router upgrade logic
- `ise_integrations.py` — 5 ISE steps (pxGrid, SCC, deactivate/reactivate, cdFMC, SGT verify)
- `duo_automation.py` — Duo card steps, authproxy push via WinRM, SCIM
- `sda_fabric.py` / `evpn_fabric.py` — fabric deploy pipelines
- `reset_switches.py` — raw `telnetlib` base-config push (Netmiko fails on blank C9300)
- `generate_lab_cards.py` — reportlab PDF lab detail cards
- `data/pod_state.db` — SQLite: `pods`, `pipeline_steps`, `pipeline_logs`, `upgrade_config`,
  `org_credentials`

Pipeline order: onboard (quickConnect) → license → associate → set variables → deploy →
generate bootstrap → TFTP copy → controller-mode enable → verify tunnels → switch checks.

## LOCKED — do not modify without explicit user approval

Ask before touching any of these. They are hard-won working code, each tagged in git.

| File / function | Tag |
|---|---|
| `sda_fabric.py` (whole file) | `sda-evpn-working` @ `cdd5754` |
| `evpn_fabric.py` (whole file) | `evpn-aaa-clean` @ `47f0e18` |
| `dashboard.py` → `_scc_auto_reset_manual()` (13 reset items) | `scc-reset-locked` @ `d5a9ef1` |
| `ise_integrations.py` → all 5 ISE step functions + `dashboard.py` host-side halves | `ise-all-steps-working` @ `2a89ba7` |
| `onboard_router.py` → `phase_reset/quick_connect/associate/assign_license/set_variables/deploy/generate_bootstrap/copy_bootstrap/controller_mode/redeploy_config_group`, verify_router, verify_online | various |
| `onboard_router.py` → `phase_catc_discover()` Step 7 provision loop | `62db180` |
| `onboard.py` → `SDWAN_STEPS` list and SD-WAN skip-guard logic | — |

If a fix requires touching one, STOP and ask first.

## Hard-won gotchas

### Licensing
- Correct API: `POST /dataservice/v1/licensing/assign-licenses` with `C8K_MEDIUM_WAN_A`
  (WAN Advantage). The old `msla/assignLicenses` + `C8K_SMALL_WAN_A` returns HTTP 200
  but never enables SD-WAN controller mode.
- Onboard (quickConnect) must run **before** license — the device needs a system-ip to
  appear in licensing.

### Config register 0x2142 — silent bootstrap killer
Router boots into controller mode with no config even though `ciscosdwan.cfg` is correct.
`0x2142` = ignore NVRAM on boot. The tell is this warning in `controller_mode_enable` output:
`WARNING: Boot variable either does not exist or buffer is too small`. Check `show bootvar`
immediately; fix with `config-register 0x2102` → `write mem` → `reload`.

### File transfer
TFTP via the jump host is the only reliable path to router bootflash. SCP fails —
macOS OpenSSH ≥9.0 defaults to SFTP, which IOS XE's SCP server doesn't speak. File must
be named `ciscosdwan.cfg` in `bootflash:` root.

### Switch base-config reset (`reset_switches.py`)
- Management mask must be `/18` (255.255.192.0), not `/24` — `/24` isolates switches
  from the VPN tunnel.
- `no boot manual` must be the first boot line. C9300 NVRAM can hold `boot manual` in
  encrypted `private-config` (invisible in `show startup-config`), dropping it to ROMMON
  on every reload.
- Use `flash:packages.conf`, not `bootflash:` — C9300 install-mode only knows `flash:`.
- No `Exit` (capital E) in base configs — `no vlan ...` drops into VLAN database mode and
  `Exit` leaves config mode entirely, so `write memory` silently fails.
- No inline `crypto key generate rsa` — done in `_post_reload()` over SSH after reboot.
- `write memory` must poll for `[OK]`, not `#` — DNS errors appear mid-output and cause
  `read_until(b"#")` to return early, leaving NVRAM unsaved.
- Inject `no ip domain lookup` first to keep DNS noise out of the telnet stream.

### ISE / SCC
- One SCC login covers all PODs and all 4 SCC-dependent operations. Log in as the **POD
  org account**, not the lab manager.
- ISE step 3 (SCC deactivate + reactivate) must **always** run — SCC never reaches Active
  after step 2 without the cycle. No idempotency guard. cdFMC (step 4) does not need this.
- ISE step 4 idempotency: if Deactivate is visible, deactivate first, then New instance +
  Activate — otherwise ISE reissues an OTP tied to the old cdFMC instance name.
- Always use "New instance", never "Existing instances".
- React synthetic events ignore JS `.click()` on SCC pages. Use a JS coordinate lookup then
  `page.mouse.click()` for three-dot menus, Edit, toggles, and Save.
- Okta ignores Playwright `fill()` — use `press_sequentially()`.

### Duo admin UI
- The application page is ~5,400px tall and its **Save is a submit at y≈5353**. Neither
  a coordinate click nor Playwright's locator click reaches it — `scroll_into_view_if_needed`
  times out on the sticky layout — and **both fail silently with no POST at all**. Submit
  the form instead: `form.requestSubmit()` on `modify-integration-form` (SAML/app settings)
  or `outbound-scim-configuration` (SCIM/provisioning).
- `entity_id` / `acs_url` are **hidden** fields. Writing to them is discarded on save; they
  are populated only by uploading Secure Access's SP XML through `input[name=xml_file]`.
  While they read "None", Duo silently refuses to persist "Enable for all users".
- The IdP metadata URL is **not derivable**. `api-{hash}` does not map to `sso-{hash}.sso` —
  the SSO host has a different hash and an extra segment (`admin-demodemo…` vs
  `sso-3d52ddf2.demo.sso…`). Use the "Download XML" control.
- Attribute mapping: the editable control is the **cds combobox on the table row**,
  identified via hidden `attributeMapping.0.internalName`. Do not open "Edit mappings" —
  that is the checklist of *which* attributes to send, and its modal covers the row.
  Mapped correctly, `internalName` flips `uname` -> `email`.
- Group multi-select: clicking the picker with **no text** lists exactly the groups not yet
  selected. Do not type to filter — clearing the input drops the chips already chosen, which
  is why only the last group ever survived Save. Re-open the dropdown each round.

### Duo SSO (getting a user actually logged in)
Four things beyond the SAML metadata exchange, all of which fail silently or with
misleading messages:
- The **AD external authentication source must be Enabled** *and* carry its server
  configuration (host/port/base DN). Blank config → "The authentication source is not
  configured"; disabled → the login is refused before any auth event is logged.
- **Every user email domain must be a Permitted Domain.** These are pod-specific — POD-17
  carries both `corp.pseudoco.com` and `rtp17.corp.pseudoco.com` — so derive them from the
  users in Duo, never hardcode.
- The **Routing Rules default rule** must point at Active Directory. It defaults to Duo,
  which cannot authenticate AD-synced users.
- The **Auth Proxy must be enrolled with Duo SSO**, or the login reaches the password
  prompt and returns "Invalid credentials". The tell is `40112` / "Rotate call failed" in
  `authproxy.log`. Enrol with **`authproxy_update_sso_enrollment_code.exe`** — *not*
  `authproxyctl.exe` — and get the code from the UI ("Add Authentication Proxy" →
  "Generate command"); it only renders on a freshly created proxy page, is single-use, and
  the base64 blob wraps across lines and contains characters PowerShell treats specially,
  so rejoin it and pass it as a quoted argument.
- `/admin/v1/integrations` returns 403 for the lab's Admin API key; the guide never uses
  the API for any of this.
- MFA is on by default and blocks the lab. The guide sets **Global Policy** → New user
  policy = "Allow access without MFA" (`sections.new_user.new_user_behavior=no-mfa`) and
  Authentication policy = "Skip MFA"
  (`sections.authentication_policy.user_auth_behavior=bypass`). Do **not** edit the
  separate Default Self-Service Portal Policy. The editor's first-run overlay blocks its
  section nav until dismissed, those sections live in a `<nav>`, and saving navigates back
  to the table — so capture the editor URL before saving or verification reads the wrong page.
- Secure Access's SSO rows are **collapsed accordions**; the label is inert, the chevron
  opens them, and only then do "Edit" and "Test Configuration" exist.

### Secure Access SSO wizard
- **SAML is selected by default**; clicking the tile toggles it OFF and leaves Next
  permanently disabled.
- `authName` is the input's **id/placeholder**, not its `name` attribute.
- cds comboboxes render options as **plain visible leaves** — not `li`, not `[role=option]`.
  Match on text among leaf nodes.
- A directory can back only **one** SSO configuration. Once used it vanishes from the User
  Directory dropdown ("No matches found") rather than erroring, so re-running the wizard on
  a configured org fails at step 1. Check the SSO card first.
- Abandoning the wizard before Done creates nothing, so a metadata-download pass is safe.

### Embedding JS in Python strings
- Nested backtick template literals that interpolate variables are fine.
- Do **not** use `\'` inside triple-quoted Python to build `onclick="..."` attributes —
  escaped quotes collapse and break the JS string.
- Pattern: build HTML with `+` concatenation, attach handlers after render via
  `setTimeout(() => { el.onclick = fn; }, 0)`.
- In Python→JS triple-quoted strings, use `\\n` not `\n` for JS literal newlines.

### Dashboard JS
- Parse ISO timestamps with a strict regex (`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z`).
  A loose `[\d\-T:Z]+` captures a trailing `:` → `NaN` → elapsed always reads `0s`.
- Long-running pollers need generous limits: base-config reset takes ~390s, so a
  40-poll/120s cap freezes the card mid-run.
- Re-start the poller on page load if a RUNNING state is detected.

### Switch recheck
`api_switches_recheck` must not call `_ensure_pipeline_container()` — launching the
pipeline container re-runs `cdfmc_check` and `ad_verify` even when already completed.
Use `docker run --rm --network container:vpn-{pod_id}` directly.

### AD verification
Use `get_info=NONE` + UPN bind (`administrator@corp.pseudoco.com`). `get_info=ALL` hangs;
NTLM needs MD4, which is disabled in Python 3.14-slim.

## Conventions

- Package manager: `uv`. Run scripts as `uv run python3 <script>`.
- Dashboard table column order: POD → Assigned → Session → Status → VPN → Serial →
  SD-WAN → SCC Org → Pipeline → Actions → Notes.
- There are no tests. When you fix a bug in a pure function (version parsing, timestamp
  handling, config generation), add a `pytest` test next to it — start the suite rather
  than deferring it again.
- Broad `except Exception` is heavily used (~780 occurrences). Don't add more; when you
  touch one, narrow it and log the exception rather than swallowing it.
