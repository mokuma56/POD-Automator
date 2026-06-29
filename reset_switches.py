"""
reset_switches.py — Reset a switch to base config via raw Telnet config push.

Workflow:
  1. Raw Telnet connect (telnetlib) — works on blank and configured switches
  2. Authenticate if needed, get to enable prompt
  3. Enter 'conf t', push base config lines, exit config mode
  4. write memory — saves base config to NVRAM (also regenerates nvram_config on flash)
  5. Delete flash files that would re-apply lab config on reload:
     - nvram_config / nvram_config_bkup (C9300 restores from these if present,
       overriding NVRAM — must be deleted AFTER write memory so they don't
       get deleted then regenerated with the old lab config)
     - .dbpersist, .prst_sync, vlan.dat, dc_profile_dir (CC/DNAC provisioning)
  6. reload — switch boots from NVRAM (base config) since flash backups are gone
  7. Wait 300s, reconnect SSH, generate RSA keys, final write memory
"""

import time
import telnetlib
import logging

logger = logging.getLogger(__name__)

SWITCH_USER   = "netadmin"
SWITCH_PASS   = "C1sco12345"
SWITCH_SECRET = "C1sco12345"

SWITCH_IPS = {
    "border_spine": "198.18.128.24",
    "leaf1":        "198.18.128.22",
    "leaf2":        "198.18.128.23",
}

TELNET_TIMEOUT = 30

# Flash files deleted AFTER write memory to prevent lab config being restored on reload.
# nvram_config / nvram_config_bkup are the key ones — C9300 loads these in preference
# to NVRAM if they exist. Delete them after saving base config so reload uses NVRAM.
FLASH_CLEANUP = [
    "flash:nvram_config",
    "flash:nvram_config_bkup",
    "flash:vlan.dat",
    "flash:.dbpersist",
    "flash:.prst_sync",
    "flash:iosxe_config.txt",
    "flash:dc_profile_dir",
    "flash:pnp-info",
    "flash:pnp-tech",
    "flash:nve_cfg.json",
    "flash:evpn_cfg.json",
    "flash:.evpn",
    "flash:dnac_evpn.cfg",
]

# Teardown block injected at the START of every conf t push (before base config lines).
# All commands are idempotent — safe on clean switches (IOS-XE silently ignores
# 'no X' when X does not exist).
#
# Order is critical:
#   1. Per-interface template/IPDT refs FIRST — IOS-XE refuses to delete a global
#      template that is still referenced via 'source template' on any interface.
#   2. SVIs before VRFs/VLANs they belong to.
#   3. AAA group references before removing the group itself.
#   4. Global objects (LISP, CTS, templates, IPDT, RADIUS server) after per-iface cleanup.
CATC_TEARDOWN_LINES = [
    # ── 1. Per-interface dot1x / IPDT / template refs (all 48 switch ports) ──
    # Enter interface range, strip all CatC-pushed per-port config, then exit.
    "interface range GigabitEthernet1/0/1 - 48",
    "no source template DefaultWiredDot1xClosedAuth",
    "no source template DefaultWiredDot1xOpenAuth",
    "no source template DefaultWiredDot1xFlexAuth",
    "no device-tracking attach-policy IPDT_POLICY",
    "no device-tracking attach-policy IPDT_EXTENDED_POLICY",
    "no service-policy type control subscriber PMAP_DefaultWiredDot1xClosedAuth_1x_Open",
    "no service-policy type control subscriber PMAP_DefaultWiredDot1xClosedAuth_MAB_Closed",
    "no service-policy type control subscriber PMAP_DefaultWiredDot1xClosedAuth_MAB_Open",
    "no service-policy type control subscriber PMAP_DefaultWiredDot1xClosedAuth_Closed",
    "exit",
    # ── 2. Remove CatC-pushed SVI interfaces (before VRFs/VLANs they use) ────
    "no interface Vlan10",
    "no interface Vlan101",
    "no interface Vlan102",
    "no interface Vlan1010",
    "no interface Vlan1101",
    "no interface Vlan1102",
    # ── 3. Disable dot1x globally ─────────────────────────────────────────────
    "no dot1x system-auth-control",
    # ── 4. Remove AAA list references before removing the RADIUS group ────────
    "no aaa authentication login dnac-cts-list group dnac-client-radius-group local",
    "no aaa authentication dot1x default group dnac-client-radius-group",
    "no aaa authorization network default group dnac-client-radius-group local",
    "no aaa authorization network dnac-cts-list group dnac-client-radius-group local",
    "no aaa group server radius dnac-client-radius-group",
    # ── 5. Remove CatC RADIUS server entry ───────────────────────────────────
    "no radius server dnac-radius_198.18.5.101",
    # ── 6. Remove dot1x templates (per-interface refs cleared above) ──────────
    "no template DefaultWiredDot1xClosedAuth",
    "no template DefaultWiredDot1xOpenAuth",
    "no template DefaultWiredDot1xFlexAuth",
    # ── 7. Remove IPDT device-tracking policies ───────────────────────────────
    "no device-tracking policy IPDT_POLICY",
    "no device-tracking policy IPDT_EXTENDED_POLICY",
    "no device-tracking tracking auto-source",
    # ── 8. Remove CTS role-based enforcement (affects traffic forwarding) ─────
    "no cts role-based enforcement",
    # ── 9. Remove LISP (active LISP affects routing — critical to remove) ─────
    "no router lisp",
    # ── 10. Remove CatC VRF definitions (SVIs removed above) ──────────────────
    "no vrf definition Main",
    "no vrf definition IOT",
    "no vrf definition PROD",
    # ── 11. Remove CatC VLANs ─────────────────────────────────────────────────
    "no vlan 10,101,102,1010,1101,1102",
    # ── 12. Remove webauth redirect ACL ──────────────────────────────────────
    "no ip access-list extended ACL_WEBAUTH_REDIRECT",
    # ── 13. Remove CatC ISE control-plane policy-maps ─────────────────────────
    "no policy-map PMAP_DefaultWiredDot1xClosedAuth_1x_Open",
    "no policy-map PMAP_DefaultWiredDot1xClosedAuth_MAB_Closed",
    "no policy-map PMAP_DefaultWiredDot1xClosedAuth_MAB_Open",
    "no policy-map PMAP_DefaultWiredDot1xClosedAuth_Closed",
    # ── 14. Remove CatC NETCONF-pushed accounting/radius commands ─────────────
    # These arrive via NETCONF during reload — also re-run in _post_reload()
    # for belt-and-suspenders coverage.
    "no aaa accounting update newinfo",
    "no aaa accounting identity default start-stop group dnac-client-radius-group",
    "no aaa server radius dynamic-author",
]


def _wait_for_enable(tn, log_fn, timeout=15):
    """
    Read until we see an enable prompt: ends with '#' but NOT '(config'.
    Sends blank lines periodically to get a fresh prompt.
    """
    deadline = time.time() + timeout
    buf = ""
    while time.time() < deadline:
        tn.write(b"\n")
        time.sleep(0.5)
        chunk = tn.read_very_eager().decode("utf-8", errors="replace")
        buf += chunk
        lines = [l.strip() for l in buf.splitlines() if l.strip()]
        if lines:
            last = lines[-1]
            if last.endswith("#") and "(config" not in last:
                log_fn(f"  Enable prompt confirmed: {last!r}")
                return True
            log_fn(f"  Waiting for enable prompt, current: {last!r}")
        buf = buf[-200:]
    return False


def _send_cmd(tn, cmd, wait=1.5):
    """Send a command and drain output after a short wait."""
    tn.write(cmd.encode("utf-8") + b"\n")
    time.sleep(wait)
    return tn.read_very_eager().decode("utf-8", errors="replace")


def _telnet_reset(host, local_config_path, log_fn):
    """
    Raw Telnet to switch:
      1. Authenticate + enable
      2. Push base config via conf t
      3. write memory  (base config now in NVRAM AND flash:nvram_config)
      4. Delete flash files that would override NVRAM on reload
      5. reload
    """
    log_fn(f"  Raw Telnet connecting to {host}:23...")
    tn = telnetlib.Telnet(host, 23, timeout=TELNET_TIMEOUT)

    # Wait for initial prompt
    banner = tn.read_until(b">", timeout=20).decode("utf-8", errors="replace")
    log_fn(f"  Initial prompt: {banner[-50:].strip()!r}")

    if "Username:" in banner or "sername" in banner:
        log_fn(f"  Authenticating...")
        tn.write(SWITCH_USER.encode() + b"\n")
        tn.read_until(b"Password:", timeout=10)
        tn.write(SWITCH_PASS.encode() + b"\n")
        tn.read_until(b">", timeout=15)

    # Enable
    log_fn(f"  Entering enable mode...")
    tn.write(b"enable\n")
    out = tn.read_until(b"#", timeout=10).decode("utf-8", errors="replace")
    if "Password:" in out or "assword" in out:
        tn.write(SWITCH_SECRET.encode() + b"\n")
        tn.read_until(b"#", timeout=10)

    tn.write(b"\n")
    time.sleep(0.5)
    tn.read_very_eager()
    log_fn(f"  At enable prompt")

    # Suppress DNS lookups immediately
    _send_cmd(tn, "terminal length 0", wait=0.5)
    _send_cmd(tn, "no ip domain lookup", wait=0.5)

    # ── Step 0: Erase NVRAM so conf t push is the ONLY config on reload ───────
    # Without this, conf t MERGES with existing config — CatC AAA/dot1x/RADIUS
    # commands survive because they are never explicitly removed.
    log_fn(f"  Erasing NVRAM (write erase)...")
    tn.write(b"write erase\n")
    out = tn.read_until(b"?", timeout=10).decode("utf-8", errors="replace")
    tn.write(b"\n")  # confirm
    deadline = time.time() + 15
    erase_buf = ""
    while time.time() < deadline:
        chunk = tn.read_very_eager().decode("utf-8", errors="replace")
        erase_buf += chunk
        if "erase" in erase_buf.lower() and "#" in erase_buf:
            break
        time.sleep(0.5)
    log_fn(f"  NVRAM erased")

    # ── Step 1: Push base config ──────────────────────────────────────────────
    log_fn(f"  Reading base config from {local_config_path}...")
    with open(local_config_path) as f:
        base_lines = [l.rstrip() for l in f if l.strip() and not l.strip().startswith("!")]

    # Build final config_lines: teardown first, then base config
    # Teardown removes CatC SVIs/AAA/VRFs/VLANs from running-config so write memory
    # saves a clean state — without this, conf t merges and CatC remnants survive.
    config_lines = list(CATC_TEARDOWN_LINES) + base_lines

    if "no ip domain lookup" not in config_lines:
        config_lines.insert(0, "no ip domain lookup")
    if "config-register 0x2102" not in config_lines:
        config_lines.append("config-register 0x2102")
    config_lines.append("end")

    log_fn(f"  Entering config mode, pushing {len(config_lines)} lines (incl. {len(CATC_TEARDOWN_LINES)}-line CatC teardown)...")
    tn.write(b"conf t\n")
    tn.read_until(b"(config)#", timeout=10)

    BATCH = 10
    for i in range(0, len(config_lines), BATCH):
        batch = config_lines[i:i + BATCH]
        for line in batch:
            tn.write(line.encode("utf-8") + b"\r\n")
            time.sleep(0.08)
        time.sleep(0.5)
        log_fn(f"  Pushed lines {i+1}–{min(i+BATCH, len(config_lines))}/{len(config_lines)}")

    log_fn(f"  Waiting for enable prompt after config push...")
    time.sleep(2)
    ok = _wait_for_enable(tn, log_fn, timeout=20)
    if not ok:
        raise RuntimeError(f"Did not return to enable prompt after config push on {host}")

    # Double-end safety
    tn.write(b"end\n")
    time.sleep(1)
    tn.read_very_eager()
    ok = _wait_for_enable(tn, log_fn, timeout=10)
    if not ok:
        raise RuntimeError(f"Still in config mode before write memory on {host}")

    # ── Step 2: write memory FIRST ───────────────────────────────────────────
    # This saves base config to NVRAM. It also regenerates flash:nvram_config
    # and flash:nvram_config_bkup — but with the BASE config, not the lab config.
    # We delete those files next so reload falls back to NVRAM (base config).
    log_fn(f"  Saving base config to NVRAM (write memory)...")
    tn.write(b"write memory\n")
    deadline = time.time() + 30
    wm_buf = ""
    while time.time() < deadline:
        chunk = tn.read_very_eager().decode("utf-8", errors="replace")
        wm_buf += chunk
        if "[OK]" in wm_buf:
            log_fn(f"  write memory OK")
            break
        if "(config" in wm_buf:
            raise RuntimeError(f"write memory ran inside config mode on {host}")
        time.sleep(0.5)
    else:
        raise RuntimeError(f"write memory did not confirm [OK] on {host} — output: {wm_buf.strip()[-120:]!r}")

    # ── Step 3: Delete flash files AFTER write memory ────────────────────────
    # nvram_config / nvram_config_bkup now have base config — delete them so
    # the C9300 cannot restore the old lab config. Also wipe NVRAM now that
    # the flash backups are gone (so there is NO config backup path left except
    # NVRAM which has the base config).
    log_fn(f"  Deleting flash config backup files (post write memory)...")
    for fname in FLASH_CLEANUP:
        log_fn(f"    Deleting {fname}...")
        tn.write(f"delete /force /recursive {fname}\n".encode())
        time.sleep(2)
        tn.read_very_eager()
    log_fn(f"  Flash cleanup done")

    # ── Step 4: reload ───────────────────────────────────────────────────────
    log_fn(f"  Reloading switch...")
    tn.write(b"reload\n")
    out = tn.read_until(b"?", timeout=15).decode("utf-8", errors="replace")
    if "Save?" in out or "save" in out.lower():
        tn.write(b"no\n")
        tn.read_until(b"?", timeout=10)
    tn.write(b"\n")
    time.sleep(2)
    try:
        tn.close()
    except Exception:
        pass
    log_fn(f"  Reload initiated — waiting 300s for reboot...")


def _post_reload(host, log_fn):
    """Reconnect via SSH after reload, generate RSA keys, write memory."""
    from netmiko import ConnectHandler

    log_fn(f"  Reconnecting via SSH to {host}...")
    params_ssh = {
        "device_type": "cisco_ios",
        "host": host,
        "username": SWITCH_USER,
        "password": SWITCH_PASS,
        "secret": SWITCH_SECRET,
        "port": 22,
        "conn_timeout": 20,
        "banner_timeout": 30,
        "auth_timeout": 30,
    }
    conn = None
    for attempt in range(1, 9):
        try:
            conn = ConnectHandler(**params_ssh)
            log_fn(f"  SSH connected (attempt {attempt})")
            break
        except Exception as e:
            log_fn(f"  SSH attempt {attempt}/8: {e}")
            time.sleep(30)

    if not conn:
        raise RuntimeError(f"Could not SSH to {host} after reload")

    if ">" in conn.find_prompt():
        conn.enable()

    log_fn(f"  Generating RSA keys...")
    out = conn.send_command(
        "crypto key generate rsa modulus 2048",
        expect_string=r"#|already exist",
        read_timeout=60,
    )
    log_fn(f"  RSA: {out[:80].strip()}")

    # Remove any CatC NETCONF-pushed config that arrived during the 300s reload window.
    # CatC reconnects via NETCONF after reload and re-pushes AAA/accounting/dot1x even
    # when the device was deleted from inventory.  Run the full teardown set again here
    # (all commands are idempotent — harmless on a clean switch).
    log_fn(f"  Post-reload CatC teardown (removes NETCONF-pushed AAA/dot1x)...")
    try:
        conn.send_config_set(CATC_TEARDOWN_LINES)
        log_fn(f"  Post-reload teardown complete")
    except Exception as e:
        log_fn(f"  Warning: post-reload teardown error (non-fatal): {e}")

    log_fn(f"  Final write memory...")
    out = conn.send_command("write memory", expect_string=r"\[OK\]|#", read_timeout=20)
    if "[OK]" not in out:
        log_fn(f"  Warning: write memory output: {out[:80]}")
    conn.disconnect()
    log_fn(f"  Done — SSH verified OK on {host}")
    return True


def reset_switch(switch_key, local_config_path, log_fn=print):
    """Full reset cycle. Returns (ok, detail)."""
    host = SWITCH_IPS.get(switch_key)
    if not host:
        return False, f"Unknown switch key: {switch_key}"

    try:
        _telnet_reset(host, local_config_path, log_fn)
        time.sleep(300)
        _post_reload(host, log_fn)
        return True, f"OK: {switch_key} ({host}) reset to base config"
    except Exception as e:
        return False, f"FAILED: {switch_key} ({host}): {e}"
