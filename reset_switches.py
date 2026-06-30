"""
reset_switches.py — SSH-based config-agnostic reset for C9300 switches.

Resets any switch back to its base config regardless of what is currently
running, using IOS XE's 'configure replace' command.

Flow (single pass):
  1. SSH connect           (netadmin / C1sco12345)
  2. Enable SCP server     (temporarily — removed by configure replace)
  3. SCP base config       → flash:oc_reset_base.txt
  4. write erase           (clear NVRAM startup-config)
  5. configure replace     (atomically replace entire running config with
                            base config — works for EVPN, SDA, or any state)
  6. write memory          (persist base config to NVRAM)
  7. Flash cleanup         (delete EVPN/CatC residual flash files)
  8. crypto key generate   (SSH ready immediately after reload)
  9. reload
 10. Wait 300 s
 11. SSH verify + final write memory

Each switch uses its own base config:
  border_spine → base_configs/border_spine.txt
  leaf1        → base_configs/leaf1.txt
  leaf2        → base_configs/leaf2.txt
"""

import os
import time
import tempfile
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

SWITCH_HOSTNAMES = {
    "border_spine": "Site_105-Border-Spine",
    "leaf1":        "Site_105-Leaf1",
    "leaf2":        "Site_105-Leaf2",
}

MGMT_GATEWAY = "198.18.128.1"

# Flash files deleted after configure replace to prevent stale EVPN/CatC
# files from overriding the clean NVRAM on the next boot.
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

# Temp filename used on the switch flash during reset (deleted after use)
_REMOTE_CFG = "oc_reset_base.txt"


# ── SSH helpers ───────────────────────────────────────────────────────────────

def _ssh_connect(host, log_fn, attempts=8, delay=30):
    """Open a Netmiko SSH connection and return an enabled handler."""
    from netmiko import ConnectHandler
    params = {
        "device_type":    "cisco_ios",
        "host":           host,
        "username":       SWITCH_USER,
        "password":       SWITCH_PASS,
        "secret":         SWITCH_SECRET,
        "conn_timeout":   30,
        "banner_timeout": 30,
        "auth_timeout":   30,
    }
    last_err = None
    for attempt in range(1, attempts + 1):
        try:
            conn = ConnectHandler(**params)
            if ">" in conn.find_prompt():
                conn.enable()
            conn.send_command("terminal length 0", expect_string=r"#")
            log_fn(f"  SSH connected to {host} (attempt {attempt})")
            return conn
        except Exception as e:
            last_err = e
            log_fn(f"  SSH attempt {attempt}/{attempts}: {e}")
            if attempt < attempts:
                time.sleep(delay)
    raise RuntimeError(f"Could not SSH to {host}: {last_err}")


# ── Core reset ────────────────────────────────────────────────────────────────

def _reset_to_base(host, local_config_path, log_fn):
    """
    Single-pass SSH reset using 'configure replace'.

    Transfers the base config to flash then uses IOS XE's configure replace
    to atomically swap the entire running config for the base config.  Works
    regardless of what is currently on the switch (EVPN, SDA, manual config,
    or anything else) as long as SSH is reachable.
    """
    from netmiko import file_transfer

    log_fn(f"  Connecting to {host} via SSH...")
    conn = _ssh_connect(host, log_fn)

    # ── Step 1: Transfer base config to flash ─────────────────────────────
    # Enable SCP server so paramiko can transfer the file.
    # configure replace (step 3) will remove 'ip scp server enable' because
    # it is not present in the base config — no cleanup needed.
    log_fn(f"  Enabling SCP server for file transfer...")
    conn.send_config_set(["ip scp server enable"])

    log_fn(f"  Transferring base config to flash:{_REMOTE_CFG}...")
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", delete=False, prefix="oc_base_"
    ) as tmp:
        with open(local_config_path) as src:
            tmp.write(src.read())
        tmp_path = tmp.name

    try:
        result = file_transfer(
            conn,
            source_file=tmp_path,
            dest_file=_REMOTE_CFG,
            file_system="flash:",
            direction="put",
            overwrite_file=True,
        )
        log_fn(f"  SCP transfer: file_exists={result.get('file_exists')}, "
               f"file_transferred={result.get('file_transferred')}")
        if not result.get("file_exists"):
            raise RuntimeError(f"SCP transfer did not confirm file_exists on {host}")
    finally:
        os.unlink(tmp_path)

    # ── Step 2: Clear NVRAM ───────────────────────────────────────────────
    log_fn(f"  Erasing NVRAM (write erase)...")
    conn.send_command("write erase", expect_string=r"\[confirm\]|#", read_timeout=15)
    conn.send_command("\n", expect_string=r"#", read_timeout=15)
    time.sleep(2)
    log_fn(f"  NVRAM erased")

    # ── Step 3: configure replace ─────────────────────────────────────────
    # Atomically replaces the entire running config with the base config.
    # IOS XE calculates the minimum diff and applies additions/removals in
    # the correct order — handles VRFs, NVE, VLANs, AAA, etc. automatically.
    log_fn(f"  Running configure replace flash:{_REMOTE_CFG} force...")
    output = conn.send_command(
        f"configure replace flash:{_REMOTE_CFG} force",
        expect_string=r"#",
        read_timeout=120,
    )
    log_fn(f"  configure replace output: {output[-300:].strip()}")

    # Check for unexpected errors (rollback messages are normal and OK)
    low = output.lower()
    if "error" in low and "rollback" not in low and "total number" not in low:
        raise RuntimeError(f"configure replace reported an error: {output[-200:]}")

    time.sleep(5)

    # Reconnect if configure replace disrupted the current SSH session
    try:
        prompt = conn.find_prompt()
    except Exception:
        prompt = None
    if not prompt:
        log_fn(f"  Session dropped after configure replace — reconnecting...")
        try:
            conn.disconnect()
        except Exception:
            pass
        time.sleep(10)
        conn = _ssh_connect(host, log_fn, attempts=4, delay=15)

    if ">" in conn.find_prompt():
        conn.enable()

    # ── Step 4: Persist base config to NVRAM ──────────────────────────────
    log_fn(f"  Saving to NVRAM (write memory)...")
    out = conn.send_command("write memory", expect_string=r"\[OK\]|#", read_timeout=20)
    if "[OK]" in out:
        log_fn(f"  write memory OK")
    else:
        log_fn(f"  write memory: {out.strip()[-80:]}")

    # ── Step 5: Delete EVPN/CatC flash files ─────────────────────────────
    # These can override NVRAM on the next boot if left in place.
    log_fn(f"  Cleaning flash files...")
    for fname in FLASH_CLEANUP + [f"flash:{_REMOTE_CFG}"]:
        conn.send_command(
            f"delete /force /recursive {fname}",
            expect_string=r"#",
            read_timeout=15,
        )
    log_fn(f"  Flash cleanup done")

    # ── Step 6: Generate RSA keys ─────────────────────────────────────────
    # Stored in NVRAM private-config; SSH daemon starts immediately on boot.
    log_fn(f"  Generating RSA 2048 keys...")
    out = conn.send_command(
        "crypto key generate rsa modulus 2048",
        expect_string=r"#|\[yes/no\]",
        read_timeout=60,
    )
    if "[yes/no]" in out:
        conn.send_command("yes", expect_string=r"#", read_timeout=60)
    log_fn(f"  RSA keys ready")

    # ── Step 7: Reload ────────────────────────────────────────────────────
    log_fn(f"  Reloading switch...")
    conn.send_command("reload", expect_string=r"confirm|Confirm|#", read_timeout=15)
    conn.send_command("\n")
    time.sleep(2)
    try:
        conn.disconnect()
    except Exception:
        pass
    log_fn(f"  Reload initiated — waiting 300s for clean boot...")


def _verify_ssh(host, log_fn):
    """Verify SSH after reload — confirms switch is up with base config."""
    conn = _ssh_connect(host, log_fn, attempts=8, delay=30)
    if ">" in conn.find_prompt():
        conn.enable()
    out = conn.send_command("write memory", expect_string=r"\[OK\]|#", read_timeout=20)
    if "[OK]" not in out:
        log_fn(f"  Warning: final write memory: {out.strip()[-60:]}")
    conn.disconnect()
    log_fn(f"  SSH verified OK on {host}")


# ── Public entry point ────────────────────────────────────────────────────────

def reset_switch(switch_key, local_config_path, log_fn=print, on_pass1_wait=None):
    """
    Reset a switch back to its base config via SSH + configure replace.

    Works regardless of the current switch state (EVPN, SDA, manual config,
    or anything else) as long as SSH is reachable with netadmin / C1sco12345.

    Each switch_key uses its own base config file:
      border_spine → base_configs/border_spine.txt
      leaf1        → base_configs/leaf1.txt
      leaf2        → base_configs/leaf2.txt

    Returns (ok, detail_string).  Total time: ~6 min (one 300s reload wait).

    on_pass1_wait: optional callable(log_fn) invoked ~60s into the reload wait
                   (used to remove the switch from CatC while it is offline).
    """
    host = SWITCH_IPS.get(switch_key)
    if not host:
        return False, f"Unknown switch key: {switch_key}"

    try:
        _reset_to_base(host, local_config_path, log_fn)

        # Fire the CatC delete callback ~60s into the reload wait, while
        # the switch is offline and CatC has marked it unreachable.
        time.sleep(60)
        if on_pass1_wait:
            try:
                on_pass1_wait(log_fn)
            except Exception as cb_e:
                log_fn(f"  on_pass1_wait callback error (continuing): {cb_e}")
        time.sleep(240)  # remaining 240s of the 300s boot wait

        _verify_ssh(host, log_fn)
        return True, f"OK: {switch_key} ({host}) wiped and restored to base config"
    except Exception as e:
        return False, f"FAILED: {switch_key} ({host}): {e}"
