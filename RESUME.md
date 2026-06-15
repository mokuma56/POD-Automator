# POD Automator — Resume State
**Last updated:** 2026-06-12
**Branch:** `fixes/sda-evpn-cleanup`
**Latest commit:** `72cbe07`

---

## Current Active Session

| Field | Value |
|---|---|
| Active POD | POD-2 |
| VPN user | `v1808user1` / `6b0983` |
| VPN host | `dcloud-sjc-anyconnect.cisco.com` |
| Session ID | `483136` |
| VPN container | `vpn-POD-2` (Up) |
| Duo org | 504 — `admin-2bb9ad3d.duosecurity.com` |
| SA org ID | `8381271` |
| Dashboard | `http://localhost:5050` |

---

## Pipeline Status — POD-2

All 20 pipeline steps **completed**.

| # | Step | Status |
|---|------|--------|
| 1–19 | All SD-WAN, switch, cdFMC, AD steps | completed |
| 20 | scc_reset_check | completed |

---

## Duo Integration Status — POD-2 / Org 504

| Item | State |
|---|---|
| `duo_ikey` | `DID2UDQINBOY8067K5CL` (Admin API) |
| `duo_host` | `api-2bb9ad3d.duosecurity.com` |
| `duo_saml_app_ikey` | `DIGI7UL5W7ZPTCEVY8BZ` (Generic SAML SP) |
| `authproxy_cfg` | 3 sections: `[cloud]` + `[ad_client]` + `[sso]` (rikey=`RIE7KGAX1NCV1SLTWMQT`) |
| `sa_scim_token` | Set (`ZjkyMGFm...`) |
| `duo_steps` table | Empty — Duo card not yet run this session |
| DuoAuthProxy on AD1 | Running + Connected (last verified Jun 10) |
| SA SCIM users | 8 users present (`totalResults=8`) |
| Duo SSO endpoint | `sso-2bb9ad3d.sso.duosecurity.com/saml2/sp/DIGI7UL5W7ZPTCEVY8BZ/sso` |

**Mode on next Duo card Run:** SESSION REFRESH (all 3 conditions met)

---

## Dashboard Tab Order (current)

`Pipeline Steps | Live Logs | Switches | cdFMC | AD Verify | EVPN Fabric | SDA Fabric | SCC Reset | 🔒 Duo | Base Config Reset | Upgrade | Knowledge Base`

---

## Duo Card Steps (7 steps, SESSION REFRESH skips step 4)

| # | Step | Refresh mode |
|---|------|-------------|
| 1 | Duo Org Setup | Verify creds only |
| 2 | Auth Proxy Config Push | Push authproxy.cfg → AD1, restart |
| 3 | AD Directory Sync | Trigger via Admin API |
| 4 | SA SAML + SCIM Config | **Skipped** |
| 5 | Auth Proxy Enroll | `authproxyctl enroll`, update rikey |
| 6 | SA SCIM User Push | Push Duo users to SA SCIM (idempotent) |
| 7 | Verify Auth Proxy | WinRM: DuoAuthProxy service Running |

---

## Known Blockers

| Item | Status |
|---|---|
| SA management JWT | Permanently blocked — `invalid_client` on Okta client `0oa1awuntd3BRMMBe358`; SA SAML IdP upload stays manual |
| Leaf1 hardware fault | C9300-48UB at `198.18.128.22` ignores startup-config on boot; needs hardware replacement |

---

## Next Steps (in order)

1. **New session** — when session expires, upload new `EventsDetails.csv` to dashboard
2. **Run Duo card** — hits SESSION REFRESH, re-links AD→Duo→SA automatically
3. **Verify** — DuoAuthProxy Running, 8 users in SA SCIM, SSO endpoint reachable
4. If SA SAML needs re-upload — go to SA portal, upload `~/Downloads/duo_idp_metadata.xml`

---

## Key Infrastructure

| Device | IP | Credentials |
|---|---|---|
| vManage | `198.18.133.10` | `admin` / `C1sco12345` |
| Router (C8231-G2) | `198.18.133.25` | `admin` / `C1sco12345` |
| Border Spine (C9300-48U) | `198.18.128.24` | `netadmin` / `C1sco12345` |
| Leaf 1 (C9300-48UB) | `198.18.128.22` | `netadmin` / `C1sco12345` |
| Leaf 2 (C9300-48P) | `198.18.128.23` | `netadmin` / `C1sco12345` |
| Ubuntu Automation PC | `198.18.134.12` | `cisco` / `C1sco12345` |
| AD DC | `198.18.5.102` | `administrator@corp.pseudoco.com` / `C1sco12345` |
| Jumphost1 (RDP) | `198.18.133.36` | RDP only |
| Jump Host (lab cards) | `198.18.133.35` | `corp.pseudoco.com\demouser` / `C1sco12345` |

---

## Relevant Files

| File | Notes |
|---|---|
| `onboard_router.py` | All pipeline phase functions; steps 3–13 LOCKED |
| `onboard.py` | Pipeline loop, SOFT_FAIL_STEPS, SDWAN_STEPS; LOCKED |
| `dashboard.py` | Flask dashboard, all tabs, API endpoints |
| `duo_automation.py` | `duo_run_card()`, SESSION REFRESH/FULL SETUP, SCIM push |
| `reset_switches.py` | Telnet-based switch baseline reset |
| `evpn_fabric.py` | EVPN fabric deploy — LOCKED at `47f0e18` |
| `sda_fabric.py` | SDA fabric deploy — LOCKED at `cdd5754` |
| `data/pod_state.db` | SQLite: all POD state, org credentials, duo_steps |
