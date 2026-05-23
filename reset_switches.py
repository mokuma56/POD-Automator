"""
reset_switches.py — Reset a switch to base config via raw Telnet config push.

Workflow:
  1. Raw Telnet connect (telnetlib) — works on blank and configured switches
  2. Authenticate if needed, get to enable prompt
  3. Enter 'conf t', push config lines, end with 'end' in the stream
  4. Wait for enable prompt (hostname#, not hostname(config*)#)
  5. write memory
  6. reload
  7. Wait 240s, reconnect SSH, generate RSA keys, write memory
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


def _wait_for_enable(tn, log_fn, timeout=15):
    """
    Read until we see an enable prompt: ends with '# ' or '#\r' but NOT '(config'.
    Sends blank lines periodically to get a fresh prompt.
    """
    deadline = time.time() + timeout
    buf = ""
    while time.time() < deadline:
        tn.write(b"\n")
        time.sleep(0.5)
        chunk = tn.read_very_eager().decode("utf-8", errors="replace")
        buf += chunk
        # Look for enable prompt — last line ends with # but not (config...#
        lines = [l.strip() for l in buf.splitlines() if l.strip()]
        if lines:
            last = lines[-1]
            if last.endswith("#") and "(config" not in last:
                log_fn(f"  Enable prompt confirmed: {last!r}")
                return True
            log_fn(f"  Waiting for enable prompt, current: {last!r}")
        buf = buf[-200:]  # keep last 200 chars
    return False


def _telnet_reset(host, local_config_path, log_fn):
    """
    Raw Telnet to switch: push base config lines directly, write memory, reload.
    Works on blank switches (no AAA) and configured switches alike.
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

    # Confirm at enable prompt
    tn.write(b"\n")
    time.sleep(0.5)
    tn.read_very_eager()
    log_fn(f"  At enable prompt")

    # Read config lines
    log_fn(f"  Reading base config from {local_config_path}...")
    with open(local_config_path) as f:
        config_lines = [l.rstrip() for l in f if l.strip() and not l.strip().startswith("!")]

    # Prepend 'no ip domain lookup' to prevent DNS errors mid-output
    if "no ip domain lookup" not in config_lines:
        config_lines.insert(0, "no ip domain lookup")

    if "config-register 0x2102" not in config_lines:
        config_lines.append("config-register 0x2102")

    # Always end with 'end' to ensure we exit config mode cleanly
    config_lines.append("end")

    log_fn(f"  Entering config mode, pushing {len(config_lines)} lines...")
    tn.write(b"conf t\n")
    tn.read_until(b"(config)#", timeout=10)

    # Push in small batches with pauses
    BATCH = 10
    for i in range(0, len(config_lines), BATCH):
        batch = config_lines[i:i+BATCH]
        for line in batch:
            tn.write(line.encode("utf-8") + b"\r\n")
            time.sleep(0.08)
        time.sleep(0.5)
        log_fn(f"  Pushed lines {i+1}–{min(i+BATCH, len(config_lines))}/{len(config_lines)}")

    # Wait for enable prompt — 'end' in the stream should have exited config mode
    log_fn(f"  Waiting for enable prompt after 'end'...")
    time.sleep(2)
    ok = _wait_for_enable(tn, log_fn, timeout=20)
    if not ok:
        raise RuntimeError(f"Did not return to enable prompt after config push on {host}")

    # Send 'end' again + flush to be absolutely sure we are NOT in config mode
    tn.write(b"end\n")
    time.sleep(1)
    tn.read_very_eager()
    ok = _wait_for_enable(tn, log_fn, timeout=10)
    if not ok:
        raise RuntimeError(f"Still in config mode before write memory on {host}")

    # Write memory — read until [OK] explicitly, not just #
    # DNS errors can appear mid-output and cause read_until(#) to return early
    log_fn(f"  Saving config (write memory)...")
    tn.write(b"write memory\n")
    # Collect output for up to 30s looking for [OK]
    deadline = time.time() + 30
    wm_buf = ""
    while time.time() < deadline:
        chunk = tn.read_very_eager().decode("utf-8", errors="replace")
        wm_buf += chunk
        if "[OK]" in wm_buf:
            log_fn(f"  write memory OK")
            break
        if "(config" in wm_buf:
            raise RuntimeError(f"write memory ran inside config mode on {host} — config not saved")
        time.sleep(0.5)
    else:
        raise RuntimeError(f"write memory did not confirm [OK] on {host} — output: {wm_buf.strip()[-120:]!r}")

    # Reload
    log_fn(f"  Reloading switch...")
    tn.write(b"reload\n")
    out = tn.read_until(b"?", timeout=15).decode("utf-8", errors="replace")
    if "Save?" in out or "save" in out.lower():
        tn.write(b"yes\n")
        tn.read_until(b"?", timeout=10)
    tn.write(b"\n")
    time.sleep(2)
    try:
        tn.close()
    except Exception:
        pass
    log_fn(f"  Reload initiated — waiting 240s for reboot...")


def _post_reload(host, log_fn):
    """Reconnect via SSH, generate RSA keys, write memory."""
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
        read_timeout=30,
    )
    log_fn(f"  RSA: {out[:60].strip()}")

    log_fn(f"  Final write memory...")
    out = conn.send_command("write memory", expect_string=r"#", read_timeout=20)
    if "[OK]" not in out:
        log_fn(f"  Warning: {out[:80]}")
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
        time.sleep(240)
        _post_reload(host, log_fn)
        return True, f"OK: {switch_key} ({host}) reset to base config"
    except Exception as e:
        return False, f"FAILED: {switch_key} ({host}): {e}"
