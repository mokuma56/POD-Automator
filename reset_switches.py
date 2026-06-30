"""
reset_switches.py — Two-pass wipe and restore for C9300 switches.

Pass 1 — Wipe to stub:
  1. Raw Telnet connect (works on any switch state)
  2. Authenticate + enable
  3. write erase  (clears NVRAM — removes every saved config)
  4. Push minimal stub config via conf t:
       hostname, Mgmt-vrf, Gi0/0 IP, default route, enable password,
       username, VTY transport telnet  (nothing from the lab)
  5. write memory  (saves STUB ONLY to NVRAM)
  6. reload        (switch boots from stub — clean slate, no EVPN, no CatC,
                    no RADIUS, no dot1x, no dirty config of any kind)

Wait 300 s for switch to come back.

Pass 2 — Push base config:
  7. Telnet connect (stub has management IP + VTY — always reachable)
  8. Authenticate + enable
  9. Push full base config via conf t  (running config is stub-only — no merge)
  10. write memory  (saves base config to NVRAM)
  11. Delete flash files (nvram_config, vlan.dat, EVPN/LISP artifacts)
  12. crypto key generate rsa modulus 2048  (SSH works after reload)
  13. reload        (switch boots cleanly from base config in NVRAM)

Wait 300 s for switch to come back.

Pass 3 — SSH verify:
  14. SSH connect + write memory  (confirms SSH works, final save)
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

# Must match the base config hostnames — used in the stub so RSA key naming
# is consistent between the stub boot and the final base config boot.
SWITCH_HOSTNAMES = {
    "border_spine": "Site_105-Border-Spine",
    "leaf1":        "Site_105-Leaf1",
    "leaf2":        "Site_105-Leaf2",
}

MGMT_GATEWAY   = "198.18.128.1"
MGMT_MASK      = "255.255.192.0"
TELNET_TIMEOUT = 30

# Flash files deleted AFTER write memory in Pass 2.
# nvram_config / nvram_config_bkup are the critical ones — C9300 loads these
# in preference to NVRAM if they exist.  Delete them so reload uses NVRAM
# (which has the base config).
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


def _make_stub_lines(switch_key):
    """
    Minimal config pushed to NVRAM before Pass 1 reload.

    Contains NOTHING from the lab — no EVPN, no CatC, no RADIUS, no AAA beyond
    local auth.  Just enough to telnet in for Pass 2 after the clean boot.

    Each sub-config block ends with an explicit 'exit' so subsequent global
    commands land in (config)# context.  The final 'end' exits conf t entirely
    so _wait_for_enable sees the enable prompt.
    """
    hostname = SWITCH_HOSTNAMES[switch_key]
    ip       = SWITCH_IPS[switch_key]
    return [
        "no ip domain lookup",
        f"hostname {hostname}",
        "vrf definition Mgmt-vrf",
        " address-family ipv4",
        " exit-address-family",
        "exit",                                          # (config-vrf)# → (config)#
        f"enable password {SWITCH_SECRET}",
        f"username {SWITCH_USER} privilege 15 password {SWITCH_PASS}",
        "interface GigabitEthernet0/0",
        " vrf forwarding Mgmt-vrf",
        f" ip address {ip} {MGMT_MASK}",
        " no shutdown",
        "exit",                                          # (config-if)# → (config)#
        f"ip route vrf Mgmt-vrf 0.0.0.0 0.0.0.0 {MGMT_GATEWAY}",
        "line vty 0 4",
        " login local",
        " transport input telnet",
        "line vty 5 31",
        " transport input telnet",
        "end",                                           # exit conf t → enable mode
    ]


# ── Shared helpers ────────────────────────────────────────────────────────────

def _wait_for_enable(tn, log_fn, timeout=15):
    """Read until we see an enable prompt (ends with '#', not in config mode)."""
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


def _telnet_auth(tn, log_fn):
    """Authenticate and reach the enable prompt."""
    banner = tn.read_until(b">", timeout=20).decode("utf-8", errors="replace")
    log_fn(f"  Initial prompt: {banner[-50:].strip()!r}")

    if "Username:" in banner or "sername" in banner:
        log_fn(f"  Authenticating...")
        tn.write(SWITCH_USER.encode() + b"\n")
        tn.read_until(b"Password:", timeout=10)
        tn.write(SWITCH_PASS.encode() + b"\n")
        tn.read_until(b">", timeout=15)

    log_fn(f"  Entering enable mode...")
    tn.write(b"enable\n")
    out = tn.read_until(b"#", timeout=10).decode("utf-8", errors="replace")
    if "Password:" in out or "assword" in out:
        tn.write(SWITCH_SECRET.encode() + b"\n")
        tn.read_until(b"#", timeout=10)

    tn.write(b"\n")
    time.sleep(0.5)
    tn.read_very_eager()
    _send_cmd(tn, "terminal length 0", wait=0.5)
    _send_cmd(tn, "no ip domain lookup", wait=0.5)
    log_fn(f"  At enable prompt")


def _push_config_lines(tn, config_lines, log_fn, host):
    """Enter conf t, push config_lines in batches, verify return to enable."""
    tn.write(b"conf t\n")
    tn.read_until(b"(config)#", timeout=10)

    BATCH = 10
    for i in range(0, len(config_lines), BATCH):
        for line in config_lines[i:i + BATCH]:
            tn.write(line.encode("utf-8") + b"\r\n")
            time.sleep(0.08)
        time.sleep(0.5)
        log_fn(f"  Pushed lines {i+1}–{min(i+BATCH, len(config_lines))}/{len(config_lines)}")

    time.sleep(2)
    ok = _wait_for_enable(tn, log_fn, timeout=20)
    if not ok:
        raise RuntimeError(f"Did not return to enable prompt after config push on {host}")

    # Double-end safety — ensures we are not still inside config mode
    tn.write(b"end\n")
    time.sleep(1)
    tn.read_very_eager()
    ok = _wait_for_enable(tn, log_fn, timeout=10)
    if not ok:
        raise RuntimeError(f"Still in config mode before write memory on {host}")


def _write_memory(tn, host, log_fn):
    """Run write memory and wait for [OK]."""
    log_fn(f"  Saving config (write memory)...")
    tn.write(b"write memory\n")
    deadline = time.time() + 30
    wm_buf = ""
    while time.time() < deadline:
        chunk = tn.read_very_eager().decode("utf-8", errors="replace")
        wm_buf += chunk
        if "[OK]" in wm_buf:
            log_fn(f"  write memory OK")
            return
        if "(config" in wm_buf:
            raise RuntimeError(f"write memory ran inside config mode on {host}")
        time.sleep(0.5)
    raise RuntimeError(
        f"write memory did not confirm [OK] on {host}: {wm_buf.strip()[-120:]!r}"
    )


def _do_reload(tn, log_fn):
    """Issue reload (answer 'no' to save prompt) and close the telnet session."""
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
    log_fn(f"  Reload initiated")


# ── Pass 1 ───────────────────────────────────────────────────────────────────

def _telnet_wipe_to_stub(host, switch_key, log_fn):
    """
    Pass 1 — complete wipe.

    Erases NVRAM, pushes a minimal stub config (management IP + VTY only),
    saves to NVRAM, then reloads.  After this reload the switch has ZERO lab
    config — no EVPN, no CatC AAA/RADIUS/dot1x, nothing.  Only the stub.
    """
    log_fn(f"  [Pass 1] Connecting to {host}:23 (wipe to stub)...")
    tn = telnetlib.Telnet(host, 23, timeout=TELNET_TIMEOUT)
    _telnet_auth(tn, log_fn)

    # Erase NVRAM — every saved config is gone
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

    # Push stub config into running config, then save to NVRAM
    stub_lines = _make_stub_lines(switch_key)
    log_fn(f"  Pushing stub config ({len(stub_lines)} lines — connectivity only)...")
    _push_config_lines(tn, stub_lines, log_fn, host)
    _write_memory(tn, host, log_fn)

    # Delete flash files NOW (before stub reload) so they cannot override NVRAM
    # during the stub boot.  flash:nvram_config / nvram_config_bkup take priority
    # over NVRAM if they exist — if still present they would load the full EVPN
    # config at stub-boot time, causing Pass 2 to push base config on top of it.
    # vlan.dat and dnac_evpn.cfg cause VLANs/VRFs/NVE to reload from flash.
    # Deleting here guarantees a truly clean stub boot.  Pass 2 flash cleanup
    # is kept as a belt-and-suspenders measure for any files written by CatC
    # during the stub-boot window.
    log_fn(f"  [Pass 1] Deleting flash EVPN/config-backup files before reload...")
    for fname in FLASH_CLEANUP:
        log_fn(f"    Deleting {fname}...")
        tn.write(f"delete /force /recursive {fname}\n".encode())
        time.sleep(2)
        tn.read_very_eager()
    log_fn(f"  Flash cleanup done")

    # Reload — switch boots from NVRAM = stub only, with no flash overrides
    _do_reload(tn, log_fn)
    log_fn(f"  [Pass 1] Complete — waiting 300s for stub boot...")


# ── Pass 2 ───────────────────────────────────────────────────────────────────

def _telnet_push_base(host, local_config_path, log_fn):
    """
    Pass 2 — push base config onto the clean stub-booted switch.

    The running config at this point has ONLY the stub — no dirty config of any
    kind.  Push the full base config, write memory, clean flash, generate RSA
    keys, then reload into the final clean base config.
    """
    log_fn(f"  [Pass 2] Connecting to {host}:23 (push base config)...")
    tn = telnetlib.Telnet(host, 23, timeout=TELNET_TIMEOUT)
    _telnet_auth(tn, log_fn)

    log_fn(f"  Reading base config from {local_config_path}...")
    with open(local_config_path) as f:
        base_lines = [l.rstrip() for l in f if l.strip() and not l.strip().startswith("!")]

    config_lines = list(base_lines)
    if "no ip domain lookup" not in config_lines:
        config_lines.insert(0, "no ip domain lookup")
    if "config-register 0x2102" not in config_lines:
        config_lines.append("config-register 0x2102")
    config_lines.append("end")

    log_fn(f"  Pushing base config ({len(config_lines)} lines)...")
    _push_config_lines(tn, config_lines, log_fn, host)
    _write_memory(tn, host, log_fn)

    # Delete flash files that could override NVRAM on reload
    log_fn(f"  Deleting flash config backup files...")
    for fname in FLASH_CLEANUP:
        log_fn(f"    Deleting {fname}...")
        tn.write(f"delete /force /recursive {fname}\n".encode())
        time.sleep(2)
        tn.read_very_eager()
    log_fn(f"  Flash cleanup done")

    # Generate RSA keys before reload so SSH daemon starts immediately on boot.
    # IOS-XE stores RSA keys in NVRAM private-config (separate from startup-config).
    log_fn(f"  Generating RSA 2048 keys...")
    tn.write(b"crypto key generate rsa modulus 2048\n")
    rsa_buf = ""
    deadline = time.time() + 60
    while time.time() < deadline:
        chunk = tn.read_very_eager().decode("utf-8", errors="replace")
        rsa_buf += chunk
        if "[yes/no]" in rsa_buf:
            tn.write(b"yes\n")
            rsa_buf = ""
        lines = [l.strip() for l in rsa_buf.splitlines() if l.strip()]
        if lines and lines[-1].endswith("#") and "(config" not in lines[-1]:
            break
        time.sleep(0.5)
    log_fn(f"  RSA keys ready")

    # Reload — boots cleanly from base config in NVRAM
    _do_reload(tn, log_fn)
    log_fn(f"  [Pass 2] Complete — waiting 300s for base config boot...")


# ── Pass 3 ───────────────────────────────────────────────────────────────────

def _post_reload(host, log_fn):
    """Pass 3 — SSH verify + final write memory."""
    from netmiko import ConnectHandler

    log_fn(f"  [Pass 3] Reconnecting via SSH to {host}...")
    params_ssh = {
        "device_type": "cisco_ios",
        "host":         host,
        "username":     SWITCH_USER,
        "password":     SWITCH_PASS,
        "secret":       SWITCH_SECRET,
        "port":         22,
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

    log_fn(f"  Final write memory...")
    out = conn.send_command("write memory", expect_string=r"\[OK\]|#", read_timeout=20)
    if "[OK]" not in out:
        log_fn(f"  Warning: write memory output: {out[:80]}")
    conn.disconnect()
    log_fn(f"  [Pass 3] Done — SSH verified OK on {host}")
    return True


# ── Public entry point ────────────────────────────────────────────────────────

def reset_switch(switch_key, local_config_path, log_fn=print, on_pass1_wait=None):
    """
    Full two-pass reset. Returns (ok, detail).

    Total time: ~10 min (two 300 s reload waits).

    Pass 1: write erase → stub → reload     (guaranteed clean slate)
    Pass 2: push base config → reload       (base config only in NVRAM)
    Pass 3: SSH verify

    on_pass1_wait: optional callable(log_fn) invoked ~60s into the Pass 1 wait
                   (when the switch is in stub mode and CatC has marked it
                   unreachable).  Used to delete the switch from CatC while it
                   has no loopback IP, so CatC cannot re-provision after reload.
    """
    host = SWITCH_IPS.get(switch_key)
    if not host:
        return False, f"Unknown switch key: {switch_key}"

    try:
        _telnet_wipe_to_stub(host, switch_key, log_fn)

        # Give switch ~60s to fully go offline and CatC ~60s to mark it
        # unreachable (no active provisioning task).  Then run on_pass1_wait
        # (CatC delete) while the window is clean.
        time.sleep(60)
        if on_pass1_wait:
            try:
                on_pass1_wait(log_fn)
            except Exception as cb_e:
                log_fn(f"  on_pass1_wait callback error (continuing): {cb_e}")
        time.sleep(240)  # remaining 240s of the 300s total Pass 1 boot wait

        _telnet_push_base(host, local_config_path, log_fn)
        time.sleep(300)

        _post_reload(host, log_fn)
        return True, f"OK: {switch_key} ({host}) wiped and restored to base config"
    except Exception as e:
        return False, f"FAILED: {switch_key} ({host}): {e}"
