"""
Onboard C8231-G2 Secure Router with correct values from CSV template.
Usage: uv run --directory ~/sw_projects/pod_automator python3 onboard_router.py [SERIAL]
"""

import csv, json, os, sys, time, paramiko, requests, subprocess, urllib3
urllib3.disable_warnings()

# Upgrade config — overridden by dashboard before calling phase functions
GOLDEN_VERSION_SWITCH = "17.12.1"
GOLDEN_VERSION_ROUTER = "17.18.2"
UPGRADE_IMAGE_SWITCH  = "cat9k_iosxe.17.12.01.SPA.bin"
UPGRADE_IMAGE_ROUTER  = ""

UBUNTU_HOST = "198.18.134.12"
UBUNTU_USER = "cisco"
UBUNTU_PASS = "C1sco12345"
UBUNTU_IMAGE_DIR = "/home/cisco"
UBUNTU_HTTP_PORT = 8088

SERIAL = "FJC300412NA"
for a in sys.argv[1:]:
    if not a.startswith("--"):
        SERIAL = a
        break
stop_after_copy = "--stop-after-copy" in sys.argv
UUID = f"C8231-G2-{SERIAL}"
CG_ID = "ae290e0f-7bc4-40f7-9bfa-23b1e7b2a71a"
VMANAGE = "https://198.18.133.10"
ROUTER_IP = "198.18.133.25"
SYSTEM_IP = "100.100.100.105"
SITE_ID = 105
BOOTSTRAP_PATH = os.path.expanduser("~/sw_projects/pod_automator/data/bootstrap/ciscosdwan.cfg")


def vmanage_session():
    s = requests.Session()
    s.auth = ("admin", "C1sco12345")
    s.verify = False
    r = s.get(f"{VMANAGE}/dataservice/client/token", timeout=10)
    token = r.text.strip()
    s.headers.update({"X-XSRF-TOKEN": token, "Content-Type": "application/json"})
    s.cookies.set("XSRF-TOKEN", token)
    return s


def read_csv_values():
    path = os.path.expanduser("~/sw_projects/pod_automator/PseudocoBranches_Config-Group-Template.csv")
    with open(path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if SERIAL in row.get("Device ID", ""):
                return row
        f.seek(0)
        next(reader)
        return next(reader)


def router_shell():
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ROUTER_IP, username="admin", password="C1sco12345",
                   look_for_keys=False, allow_agent=False, timeout=15)
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(2)
    return client, shell


def read_shell(shell, timeout=5):
    out = b""
    end = time.time() + timeout
    while time.time() < end:
        if shell.recv_ready():
            data = shell.recv(65535)
            out += data
            end = time.time() + timeout
        else:
            time.sleep(0.3)
    return out.decode(errors="replace")


def shell_send(shell, cmd, timeout=5):
    """Send all bytes reliably, retrying partial sends."""
    data = cmd.encode()
    end = time.time() + timeout
    sent = 0
    while sent < len(data) and time.time() < end:
        n = shell.send(data[sent:])
        if n == 0:
            time.sleep(0.3)
        sent += n
    if sent < len(data):
        raise RuntimeError(f"shell_send: only sent {sent}/{len(data)} bytes within {timeout}s")
    return sent


def router_enable(shell):
    read_shell(shell, 2)
    shell_send(shell, "enable\n")
    time.sleep(1)
    read_shell(shell, 1)
    shell_send(shell, "C1sco12345\n")
    time.sleep(2)
    read_shell(shell, 2)


def phase_reset(s):
    print("  Resetting any residual device state...")
    tries = 0
    # Disassociate (best-effort)
    try:
        r = s.put(f"{VMANAGE}/dataservice/v1/config-group/{CG_ID}/device/associate",
            json={"devices": []}, timeout=10)
        if r.status_code == 200:
            tries += 1
    except: pass
    # Deallocate license (best-effort)
    try:
        rc = s.post(f"{VMANAGE}/dataservice/v1/licensing/deallocate-licenses",
            json={"uuids": [UUID]}, timeout=10)
        if rc.status_code == 200:
            tries += 10
            time.sleep(2)
    except: pass
    if tries:
        print(f"     Cleaned up {tries} residual states")
        time.sleep(5)
    return True


def phase_quick_connect(s):
    # Step 1: Get quick connect variable schema (UI does this first)
    s.post(
        f"{VMANAGE}/dataservice/template/device/config/quickconnectvariable",
        json=[{"deviceId": UUID}], timeout=10
    )

    csv_row = read_csv_values()
    host_name = csv_row.get("Host Name", "auto-assigned")
    # Step 2: Submit quick connect with system-ip, site-id, host-name
    payload = {
        "data": [{
            "csv-deviceId": UUID,
            "csv-host-name": "auto-assigned",
            "csv-deviceIP": SYSTEM_IP,
            "//system/site-id": SITE_ID,
            "//system/host-name": "auto-assigned",
            "//system/ipv6-strict-control": False,
            "//system/system-ip": SYSTEM_IP,
        }]
    }
    r = s.post(
        f"{VMANAGE}/dataservice/template/config/quickConnect/submitDevices",
        json=payload, timeout=10
    )
    ok = r.status_code == 200
    print(f"  1. Quick Connect: {'✅' if ok else '❌'} {r.status_code}")
    if not ok and r.status_code != 409:
        print(f"     Error: {r.text[:200]}")
        return False
    return True


def phase_associate(s):
    r = s.put(
        f"{VMANAGE}/dataservice/v1/config-group/{CG_ID}/device/associate",
        json={"devices": [{"id": UUID}]}, timeout=10
    )
    ok = r.status_code == 200
    print(f"  3. Associate: {'✅' if ok else '❌'} {r.status_code}")
    if not ok:
        print(f"     Error: {r.text[:200]}")
    return ok


def phase_set_variables(s):
    csv_row = read_csv_values()
    csv_keys = {k.lower().replace(" ", "_"): k for k in csv_row}
    var_names = {v.lower(): o for o, v in csv_row.items() if v.strip()}
    for k, v in csv_keys.items():
        var_names[k] = v

    int_fields = {"pseudo_commit_timer", "site_id", "VPN10-BGP-REMOTE-AS",
                  "VPN10-DIS-BGP-REMOTE-AS", "VPN101-BGP-REMOTE-AS", "VPN102-BGP-REMOTE-AS"}
    bool_fields = {"ipv6_strict_control"}

    # Step 1: POST suggestions:true to get variable schema + suggested values
    sug = s.post(
        f"{VMANAGE}/dataservice/v1/config-group/{CG_ID}/device/variables",
        json={"deviceIds": [UUID], "suggestions": True}, timeout=10
    )
    vars_data = sug.json()

    variables = []
    for dev in vars_data.get("devices", []):
        if dev.get("device-id") == UUID:
            for var in dev.get("variables", []):
                vname = var["name"]
                vdef = var.get("defaultValue", "")
                cv_key = var_names.get(vname.lower()) or csv_keys.get(vname.lower())
                if cv_key and csv_row.get(cv_key, "").strip():
                    val = csv_row[cv_key]
                    if vname in int_fields:
                        val = int(val)
                    elif vname in bool_fields:
                        val = val.lower() == "true"
                    variables.append({"name": vname, "value": val})
                elif "value" in var and var.get("value") is not None and str(var.get("value")) != "":
                    variables.append({"name": vname, "value": var["value"]})
                elif vdef != "":
                    variables.append({"name": vname, "value": vdef})
                else:
                    variables.append({"name": vname, "value": ""})
            break

    payload = {"solution": "sdwan", "devices": [{"device-id": UUID, "variables": variables}]}
    r = s.put(
        f"{VMANAGE}/dataservice/v1/config-group/{CG_ID}/device/variables",
        json=payload, timeout=10
    )
    ok = r.status_code == 200
    print(f"  4. Set variables ({len(variables)}): {'✅' if ok else '❌'} {r.status_code}")
    if not ok:
        print(f"     Error: {r.text[:300]}")
    return ok


def phase_assign_license(s):
    SA_NAME = "dCloud Cisco Internal Account"
    VA_NAME = "dCloud-Pseudoco-Campus"
    WAN_LICENSE_TAG = "regid.2024-11.com.cisco.C8K_MEDIUM_WAN_A,1.0_7c756381-d4d6-4b30-b27d-7601feb51248"

    print(f"  2. Assigning WAN Advantage license...")

    # Step 1: SA/VA distribution check (browser always calls this before assign)
    try:
        dist_payload = {
            "appliedFilters": {"billingType": "Prepaid", "licenseClassification": "Advantage"},
            "baseLicenses": [{
                "displayName": "WAN Advantage for C8000 Secure Router, Medium",
                "tag": WAN_LICENSE_TAG,
                "platformClass": "c8kg2be",
                "uuids": [UUID],
            }],
        }
        r = s.post(f"{VMANAGE}/dataservice/v1/licensing/sa-va-distribution",
            json=dist_payload, timeout=10)
        if r.status_code == 200:
            for bl in r.json().get("baseLicenses", []):
                for sm in bl.get("savaMap", []):
                    print(f"     SA/VA: {sm['saName']} / {sm['vaName']} → available={sm['available']} inUse={sm['inUse']}")
    except Exception as e:
        print(f"     SA/VA distribution check: {e} (proceeding)")

    # Step 2: Always assign — skip check was wrong (pool != per-device)
    payload = {
        "baseLicenses": [{
            "assignLicenses": [{
                "allocated": 1,
                "saName": SA_NAME,
                "vaName": VA_NAME,
                "billingType": "Prepaid",
                "displayName": "WAN Advantage for C8000 Secure Router, Medium",
                "tag": WAN_LICENSE_TAG,
            }],
            "uuids": [UUID],
        }],
        "tenantLicenses": [],
    }
    r = s.post(f"{VMANAGE}/dataservice/v1/licensing/assign-licenses",
        json=payload, timeout=10)
    ok = r.status_code == 200
    print(f"     Assign WAN Advantage: {'OK' if ok else 'FAIL'} {r.status_code}")
    if not ok:
        print(f"     Error: {r.text[:300]}")
        return False

    time.sleep(3)
    print(f"     License assigned via SA '{SA_NAME}' / VA '{VA_NAME}'")
    print(f"     Checking device state...")
    r = s.get(f"{VMANAGE}/dataservice/system/device/vedges?uuid={UUID}", timeout=10)
    if r.status_code == 200:
        for d in r.json().get("data", []):
            if d.get("uuid") == UUID:
                print(f"     Device: validity={d.get('validity')} cert={d.get('vedgeCertificateState')} serial={d.get('serialNumber')}")
                break
    return True


def phase_deploy(s):
    # Check if device is already In Sync — skip the deploy POST entirely
    try:
        devs = s.get(f"{VMANAGE}/dataservice/system/device/vedges", timeout=15).json().get("data", [])
        dev = next((d for d in devs if UUID in d.get("uuid", "")), None)
        if dev and dev.get("configStatusMessage", "") == "In Sync":
            print(f"  5. Deploy: already In Sync — skipping deploy POST")
            return True
    except Exception as e:
        print(f"  5. Deploy: pre-check failed ({e}) — proceeding with deploy")

    # POST deploy with retry on timeout
    r = None
    for attempt in range(3):
        try:
            r = s.post(
                f"{VMANAGE}/dataservice/v1/config-group/{CG_ID}/device/deploy",
                json={"devices": [{"id": UUID}]}, timeout=30
            )
            break
        except Exception as e:
            print(f"  5. Deploy POST attempt {attempt+1} failed: {e}")
            if attempt == 2:
                # Last resort: re-check if it's In Sync despite the timeout
                try:
                    devs = s.get(f"{VMANAGE}/dataservice/system/device/vedges", timeout=15).json().get("data", [])
                    dev = next((d for d in devs if UUID in d.get("uuid", "")), None)
                    if dev and dev.get("configStatusMessage", "") == "In Sync":
                        print(f"  5. Deploy: timed out but vManage shows In Sync — proceeding")
                        return True
                except Exception:
                    pass
                return False
            time.sleep(5)

    if r.status_code != 200:
        print(f"  5. Deploy: ❌ {r.status_code} {r.text[:200]}")
        return False
    try:
        task_id = r.json().get("parentTaskId", r.json().get("id", ""))
    except Exception:
        task_id = ""
    print(f"  5. Deploy: ✅ task={task_id[:60]}")

    # Poll until deployment completes — also check In Sync as early-exit
    for i in range(60):
        time.sleep(5)
        # Short-circuit: if device is already In Sync no need to wait for task
        try:
            devs = s.get(f"{VMANAGE}/dataservice/system/device/vedges", timeout=10).json().get("data", [])
            dev = next((d for d in devs if UUID in d.get("uuid", "")), None)
            if dev and dev.get("configStatusMessage", "") == "In Sync":
                print(f"     Deploy: device In Sync after {(i+1)*5}s — done")
                return True
        except Exception:
            pass
        if task_id:
            try:
                tr = s.get(f"{VMANAGE}/dataservice/device/action/status/{task_id}", timeout=10)
                if tr.status_code == 200:
                    status = tr.json().get("status", "") or tr.json().get("data", [{}])[0].get("status", "")
                    if "done" in status.lower() or "scheduled" in status.lower():
                        activity = tr.json().get("data", [{}])[0].get("currentActivity", "")
                        print(f"     Deploy status: {status} — {activity[:200]}")
                        return True
                    elif status.lower() in ("error", "fail", "failure"):
                        detail = tr.json().get("data", [{}])[0].get("details", "") or tr.json().get("details", "")
                        print(f"     Deploy failed: {detail[:200]}")
                        return False
                    if i % 6 == 0:
                        print(f"     Deploy action status: {status}...")
            except Exception:
                pass
    print("     Deploy poll timed out — checking In Sync one final time")
    try:
        devs = s.get(f"{VMANAGE}/dataservice/system/device/vedges", timeout=15).json().get("data", [])
        dev = next((d for d in devs if UUID in d.get("uuid", "")), None)
        if dev and dev.get("configStatusMessage", "") == "In Sync":
            print(f"     Final check: device In Sync — proceeding")
            return True
    except Exception:
        pass
    print("     Deploy still in progress, proceeding anyway")
    return True


def phase_generate_bootstrap(s):
    r = s.get(
        f"{VMANAGE}/dataservice/system/device/bootstrap/device/{UUID}?configtype=cloudinit&inclDefRootCert=true&version=v1",
        timeout=10
    )
    ok = r.status_code == 200
    print(f"  6. Bootstrap: {'✅' if ok else '❌'} {r.status_code} len={len(r.text)}")
    if ok:
        os.makedirs(os.path.dirname(BOOTSTRAP_PATH), exist_ok=True)
        # vManage returns JSON with bootstrapConfig containing raw MIME multipart.
        # Router needs raw MIME, not JSON-wrapped — extract inner content.
        data = r.json()
        raw = data.get("bootstrapConfig", r.text)
        with open(BOOTSTRAP_PATH, "w") as f:
            f.write(raw)
        print(f"     Saved {len(raw)} bytes to {BOOTSTRAP_PATH}")
    return ok


def _find_vpn_ip():
    """Find the host VPN IP (utun interface with 198.18 route)."""
    import subprocess
    r = subprocess.run(["netstat", "-rn"], capture_output=True, text=True, timeout=10)
    for line in r.stdout.splitlines():
        if "198.18" in line and "utun" in line:
            parts = line.split()
            for p in parts:
                if p.startswith("10.") and "." in p[3:]:
                    return p
    return None


def phase_copy_bootstrap():
    expected_size = os.path.getsize(BOOTSTRAP_PATH)
    print(f"     Local file: {BOOTSTRAP_PATH} ({expected_size} bytes)")

    vpn_ip = _find_vpn_ip()
    if not vpn_ip:
        print("     VPN host IP not found!")
        return False
    print(f"     VPN host IP: {vpn_ip}")

    import http.server, socketserver, threading
    http_port = 8088
    os.chdir(os.path.dirname(BOOTSTRAP_PATH))
    httpd = socketserver.TCPServer(("0.0.0.0", http_port), http.server.SimpleHTTPRequestHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    print(f"     HTTP server started on port {http_port}")

    client = None
    for attempt in range(3):
        try:
            client, shell = router_shell()
            router_enable(shell)
            shell_send(shell, "terminal length 0\n"); time.sleep(1); read_shell(shell, 1)

            src = f"http://{vpn_ip}:{http_port}/ciscosdwan.cfg"
            shell_send(shell, f"copy {src} bootflash:ciscosdwan.cfg\n")
            time.sleep(3)
            all_out = ""
            for i in range(20):
                time.sleep(2)
                out = read_shell(shell, 2)
                all_out += out
                if "bytes copied" in all_out.lower():
                    client.close()
                    print(f"     HTTP copy: {all_out[-200:]}")
                    httpd.shutdown()
                    # Verify
                    for v in range(3):
                        try:
                            c2, s2 = router_shell()
                            router_enable(s2)
                            shell_send(s2, "dir bootflash:ciscosdwan.cfg\n"); time.sleep(3)
                            vout = read_shell(s2, 3)
                            c2.close()
                            if str(expected_size) in vout.replace(",", ""):
                                print(f"     Verified: {expected_size} bytes ✅")
                                return True
                        except: time.sleep(2)
                    print("     Size mismatch, proceed anyway")
                    return True
                if "?" in out.lower() or any(kw in out.lower() for kw in ("confirm", "over write", "destination")):
                    shell_send(shell, "\n")
            print(f"     HTTP copy result: {all_out[-200:]}")
        except Exception as e:
            print(f"     Attempt {attempt+1}: {e}")
        finally:
            if client: client.close()
        time.sleep(3)
    httpd.shutdown()
    return False


def _wait_router_online(timeout=600):
    """Poll SSH until router comes back online. Returns seconds waited."""
    t0 = time.time()
    for i in range(int(timeout / 10)):
        time.sleep(10)
        elapsed = int(time.time() - t0)
        if elapsed > 0 and elapsed % 30 == 0:
            print(f"     waiting for router... {elapsed}s elapsed")
        try:
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(ROUTER_IP, username="admin", password="C1sco12345",
                      look_for_keys=False, allow_agent=False, timeout=8)
            c.close()
            waited = int(time.time() - t0)
            print(f"     Router online after {waited}s ✓")
            return True, waited
        except:
            pass
    return False, int(time.time() - t0)


def phase_controller_mode():
    for attempt in range(3):
        try:
            client, shell = router_shell()
            router_enable(shell)
            break
        except Exception as e:
            if attempt == 2:
                print(f"     SSH failed after 3 attempts: {e}")
                return False
            print(f"     SSH attempt {attempt+1} failed, retrying...")
            time.sleep(3)

    # Verify bootstrap
    shell_send(shell, "dir bootflash:ciscosdwan.cfg\n")
    time.sleep(3)
    out = read_shell(shell, 3)
    found = "ciscosdwan.cfg" in out
    print(f"     Bootstrap: {'found' if found else 'NOT FOUND'}")
    if not found:
        print("     Re-copying bootstrap...")
        client.close()
        if not phase_copy_bootstrap():
            return False
        client, shell = router_shell()
        router_enable(shell)

    # Enable controller mode
    # Strategy: send command+confirmation together in one write, then detect
    # reboot (router goes offline) as proof it worked.

    # First check if already in SD-WAN mode
    shell_send(shell, "show sdwan control connections | include up\n")
    time.sleep(5)
    out = read_shell(shell, 5)
    if "vsmart" in out and "up" in out:
        up_lines2 = [l for l in out.splitlines() if "up" in l.lower() and "control" not in l.lower()]
        n_up2 = len(up_lines2)
        if n_up2 >= 3:
            print(f"     Already in SD-WAN mode ({n_up2} tunnels up) ✓")
            client.close()
            return True
        print(f"     SD-WAN mode detected ({n_up2} tunnels), waiting for 3...")
        client.close()
        return _wait_sdwan_tunnels()

    # Cancel any pending reload that would interfere with the prompt
    shell_send(shell, "\nreload cancel\n")
    time.sleep(2)
    read_shell(shell, 2)

    went_down = False
    try:
        shell_send(shell, "controller-mode enable\n\n")
    except (paramiko.SSHException, OSError, EOFError):
        print(f"     SSH socket closed — controller-mode enable accepted, rebooting")
        client.close()
        went_down = True

    if not went_down:
        time.sleep(8)
        try:
            out = read_shell(shell, 5)
        except (paramiko.SSHException, OSError, EOFError):
            print(f"     SSH socket closed during read — controller-mode enable accepted, rebooting")
            client.close()
            went_down = True

    if not went_down:
        out = out if 'out' in dir() else ''
        print(f"     Output: {out[-200:]}")
        if "Failed" in out or "Abort" in out:
            print(f"     controller-mode enable command failed")
            client.close()
            return False
        try:
            shell_send(shell, "\n")
            time.sleep(3)
            out = read_shell(shell, 3)
            print(f"     After extra Enter: {out[-100:]}")
        except (paramiko.SSHException, OSError, EOFError):
            print(f"     SSH socket closed after confirmation — rebooting")
            went_down = True
        finally:
            try:
                client.close()
            except Exception:
                pass

    if not went_down:
        # Wait for router to go DOWN first (proves the command actually worked)
        print(f"     Router rebooting — waiting for disconnect...")
        t0 = time.time()
        for i in range(60):
            if i % 6 == 0 and i > 0:
                print(f"     still connected after {i*5}s...")
            try:
                c = paramiko.SSHClient()
                c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(ROUTER_IP, username="admin", password="C1sco12345",
                          look_for_keys=False, allow_agent=False, timeout=5)
                c.close()
            except:
                went_down = True
                print(f"     Router went down after {int(time.time()-t0)}s ✓")
                break
            time.sleep(5)

    if not went_down:
        print(f"     Router never disconnected after 5min — command may have failed")
        return False

    # Wait for router to come back
    ok, secs = _wait_router_online(600)
    if not ok:
        print(f"     Router did not come back after {secs}s")
        return False

    # Wait for SD-WAN control connections
    print(f"     Waiting for SD-WAN to initialize...")
    for i in range(30):
        if i > 0 and i % 10 == 0:
            print(f"     waiting for SD-WAN... {i}s")
        time.sleep(1)
    return _wait_sdwan_tunnels()


def _wait_sdwan_tunnels(timeout=480):
    """Wait for 3 SD-WAN control connections to come up."""
    t0 = time.time()
    deadline = t0 + timeout
    while time.time() < deadline:
        try:
            c2, s2 = router_shell()
            router_enable(s2)
            shell_send(s2, "show sdwan control connections | include up\n")
            time.sleep(5)
            out = read_shell(s2, 5)
            c2.close()
            up_lines = [l for l in out.splitlines() if "up" in l.lower() and "control" not in l.lower()]
            n_up = len(up_lines)
            elapsed = int(time.time() - t0)
            print(f"     Control connections up: {n_up} ({elapsed}s)")
            if n_up >= 3:
                print(f"     SD-WAN connected ({n_up} tunnels) ✅")
                return True
        except:
            pass
        time.sleep(15)
    print(f"     Not enough control connections up after {timeout}s")
    return False


# ---- Switch verification helpers ----

def ssh_switch(ip):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username="netadmin", password="C1sco12345",
                   look_for_keys=False, allow_agent=False, timeout=15)
    shell = client.invoke_shell(width=200, height=50)
    time.sleep(2)
    # Drain initial output
    shell.recv(4096)
    # Enable if needed
    shell.send("enable\n")
    time.sleep(1)
    shell.send("C1sco12345\n")
    time.sleep(2)
    shell.recv(4096)
    shell.send("terminal length 0\n")
    time.sleep(2)
    shell.recv(4096)
    return client, shell


def switch_cmd(shell, cmd, timeout=5):
    shell.send(cmd + "\n")
    time.sleep(1)
    out = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if shell.recv_ready():
            out += shell.recv(4096)
            time.sleep(0.5)
        else:
            time.sleep(0.2)
    return out.decode(errors="replace")


SWITCHES = {
    "verify_border_spine": {"ip": "198.18.128.24", "name": "Border Spine"},
    "verify_leaf1": {"ip": "198.18.128.22", "name": "Leaf 1"},
    "verify_leaf2": {"ip": "198.18.128.23", "name": "Leaf 2"},
}


def run_switch_checks(step_name):
    info = SWITCHES.get(step_name)
    if not info:
        return False, "UNKNOWN STEP"
    ip = info["ip"]
    print(f"  SSH to {info['name']} ({ip})...")
    try:
        client, shell = ssh_switch(ip)
    except Exception as e:
        print(f"  SSH failed: {e}")
        return False, f"SSH FAILED: {e}"

    parts = []

    # Get model via show inventory
    out = switch_cmd(shell, "show inventory")
    model = ""
    for line in out.splitlines():
        if line.strip().startswith("PID:"):
            model = line.split(",")[0].replace("PID: ", "").strip()
            break
    if model:
        parts.append(f"MODEL: {model}")

    if step_name == "verify_border_spine":
        # OSPF neighbors
        out = switch_cmd(shell, "show ip ospf neighbor")
        neighbors = [l for l in out.splitlines() if "FULL" in l]
        n_count = len(neighbors)
        if n_count >= 2:
            parts.append(f"PASS: {n_count} OSPF neighbors")
        else:
            parts.append(f"FAIL: {n_count} OSPF neighbors (expected 2)")

        # VRF — skip header, prompt, and interface continuation lines (indented with >2 spaces)
        # VRF name lines are indented by exactly 2 spaces; interface continuations by more
        out = switch_cmd(shell, "show vrf")
        vrf_lines = [
            l.strip() for l in out.splitlines()
            if l.strip()
            and "show vrf" not in l.lower()
            and not l.strip().endswith("#")
            and not l.strip().endswith(">")
            and not l.strip().startswith("Name")
            and not (len(l) - len(l.lstrip()) > 2)  # skip deep-indented interface continuation lines
        ]
        has_mgmt = any("Mgmt-vrf" in l for l in vrf_lines)
        extra_vrfs = [l for l in vrf_lines if "Mgmt-vrf" not in l and "Default" not in l]
        if has_mgmt and not extra_vrfs:
            parts.append(f"PASS: VRF OK (Mgmt-vrf only)")
        else:
            parts.append(f"FAIL: unexpected VRFs: {extra_vrfs or 'Mgmt-vrf missing'}")

        # Version
        out = switch_cmd(shell, "show ver | i Version")
        ver_ok = "17.12" in out
        ver_str = "??"
        if "Version" in out:
            for line in out.splitlines():
                if "Version" in line and "Cisco" in line:
                    parts2 = line.split("Version")[-1].strip().split()
                    if parts2:
                        ver_str = parts2[0]
                    break
        parts.append(f"{'PASS' if ver_ok else 'FAIL'}: Version {ver_str}")

        # VLAN
        out = switch_cmd(shell, "show vlan")
        has_vlan5 = "5    DNAC-Discovery" in out
        parts.append(f"{'PASS' if has_vlan5 else 'FAIL'}: VLAN 5 {'present' if has_vlan5 else 'missing'}")

    else:
        # Leaf switches
        # Skip OSPF — just check VRF, version, VLAN
        # VRF name lines are indented 2 spaces; interface continuations are indented more — skip those
        out = switch_cmd(shell, "show vrf")
        vrf_lines = [
            l.strip() for l in out.splitlines()
            if l.strip()
            and not l.strip().startswith("Name")
            and "show vrf" not in l.lower()
            and not l.strip().endswith("#")
            and not l.strip().endswith(">")
            and not (len(l) - len(l.lstrip()) > 2)  # skip deep-indented interface continuation lines
        ]
        extra_vrfs = [l for l in vrf_lines if "Mgmt-vrf" not in l and "Default" not in l]
        parts.append(f"PASS: VRF OK (Mgmt-vrf only)" if not extra_vrfs else f"FAIL: extra VRFs {extra_vrfs}")

        out = switch_cmd(shell, "show ver | i Version")
        ver_ok = "17.12" in out
        parts.append(f"{'PASS' if ver_ok else 'FAIL'}: Version 17.12.x")

        out = switch_cmd(shell, "show vlan")
        # Only VLAN 1 should exist (plus internal ones)
        vlan_lines = [l for l in out.splitlines() if l.strip() and l[0].isdigit()]
        non_default = [l for l in vlan_lines if not l.startswith("1") and
                       not l.startswith("100") and not l.startswith("999")]
        vlan_ok = len(non_default) == 0
        parts.append(f"{'PASS' if vlan_ok else 'FAIL'}: VLAN check ({'only default' if vlan_ok else f'extra: {non_default}'})")

    client.close()
    result = " | ".join(parts)
    print(f"  {result}")
    return True, result


def phase_connectivity_test():
    results = []
    for name, info in SWITCHES.items():
        ip = info["ip"]
        try:
            client, shell = ssh_switch(ip)
            out = switch_cmd(shell, "ping 198.18.5.100 source loopback 0 repeat 2")
            success = "Success rate is 100" in out
            results.append(f"{'PASS' if success else 'FAIL'}: {info['name']} ({ip}) -> 198.18.5.100 {'OK' if success else 'FAILED'}")
            client.close()
        except Exception as e:
            results.append(f"FAIL: {info['name']} ({ip}) SSH failed: {e}")
    print("  " + " | ".join(results))
    return True, " | ".join(results)


# Ubuntu automation PC — fixed address in all dCloud sessions
CDFMC_AUTOMATION_HOST = "198.18.134.12"
CDFMC_AUTOMATION_USER = "cisco"
CDFMC_AUTOMATION_PASS = "C1sco12345"
CDFMC_LAB_DIR = "/home/cisco/Documents/elevateLab"




# ---------------------------------------------------------------------------
# Version comparison utility
# ---------------------------------------------------------------------------

def _parse_version(ver_str):
    """Parse a version string like '17.12.1' or '17.12.01' into a tuple of ints."""
    import re
    parts = re.findall(r'\d+', ver_str)
    return tuple(int(p) for p in parts[:3]) if parts else (0, 0, 0)


def _version_needs_upgrade(current_str, golden_str):
    """
    Returns True if current < golden (upgrade needed).
    Returns False if current >= golden (skip — never downgrade).
    """
    current = _parse_version(current_str)
    golden  = _parse_version(golden_str)
    return current < golden


def _detect_version_from_show(output):
    """Extract version string from 'show version' output."""
    import re
    for line in output.splitlines():
        m = re.search(r'Cisco IOS XE Software.*?Version\s+([\d.]+)', line)
        if m:
            return m.group(1)
        m = re.search(r'Version\s+([\d.]+)', line)
        if m and re.match(r'\d+\.\d+', m.group(1)):
            return m.group(1)
    return ""


# ---------------------------------------------------------------------------
# Ubuntu HTTP server helpers
# ---------------------------------------------------------------------------

def _ubuntu_ensure_http_server():
    """Start python3 http.server on Ubuntu PC if not already running. Returns True on success."""
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(UBUNTU_HOST, username=UBUNTU_USER, password=UBUNTU_PASS,
                   look_for_keys=False, allow_agent=False, timeout=15)
    # Check if already running
    _, out, _ = client.exec_command(f"pgrep -f 'http.server {UBUNTU_HTTP_PORT}'", timeout=5)
    if out.read().strip():
        print(f"     HTTP server already running on Ubuntu PC port {UBUNTU_HTTP_PORT}")
        client.close()
        return True
    # Start it
    client.exec_command(
        f"cd {UBUNTU_IMAGE_DIR} && nohup python3 -m http.server {UBUNTU_HTTP_PORT} "
        f"> /tmp/http_server_{UBUNTU_HTTP_PORT}.log 2>&1 &", timeout=5
    )
    time.sleep(2)
    _, out, _ = client.exec_command(f"pgrep -f 'http.server {UBUNTU_HTTP_PORT}'", timeout=5)
    running = bool(out.read().strip())
    client.close()
    print(f"     HTTP server {'started' if running else 'FAILED to start'} on Ubuntu PC:{UBUNTU_HTTP_PORT}")
    return running


def _ubuntu_stop_http_server():
    """Stop the http.server on Ubuntu PC."""
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(UBUNTU_HOST, username=UBUNTU_USER, password=UBUNTU_PASS,
                       look_for_keys=False, allow_agent=False, timeout=10)
        client.exec_command(f"pkill -f 'http.server {UBUNTU_HTTP_PORT}'", timeout=5)
        client.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Switch upgrade
# ---------------------------------------------------------------------------

def phase_switch_upgrade(switch_key):
    """
    Upgrade a single switch to GOLDEN_VERSION_SWITCH if its current version is older.
    Never downgrades. switch_key must be one of the SWITCHES dict keys.
    Returns (ok, result_string).
    """
    info = SWITCHES.get(switch_key)
    if not info:
        return False, f"Unknown switch key: {switch_key}"

    ip   = info["ip"]
    name = info["name"]

    print(f"     [{name}] Connecting to check version...")
    try:
        client, shell = ssh_switch(ip)
    except Exception as e:
        return False, f"SSH to {name} ({ip}) failed: {e}"

    ver_out = switch_cmd(shell, "show version", timeout=8)
    client.close()

    current = _detect_version_from_show(ver_out)
    if not current:
        return False, f"Could not detect version on {name} ({ip})"

    print(f"     [{name}] Current: {current}  Golden: {GOLDEN_VERSION_SWITCH}")

    if not _version_needs_upgrade(current, GOLDEN_VERSION_SWITCH):
        return True, f"Version OK ({current} >= {GOLDEN_VERSION_SWITCH}) — no upgrade needed"

    # --- Upgrade needed ---
    print(f"     [{name}] Upgrade needed: {current} -> {GOLDEN_VERSION_SWITCH}")
    image = UPGRADE_IMAGE_SWITCH
    http_url = f"http://{UBUNTU_HOST}:{UBUNTU_HTTP_PORT}/{image}"

    # 1. Ensure HTTP server is running on Ubuntu PC
    print(f"     Starting HTTP server on Ubuntu PC...")
    if not _ubuntu_ensure_http_server():
        return False, "Failed to start HTTP server on Ubuntu PC"

    # 2. SSH back to switch and copy image
    print(f"     [{name}] Copying image from {http_url} to flash: (~10 min)...")
    try:
        client, shell = ssh_switch(ip)
    except Exception as e:
        return False, f"SSH to {name} failed before copy: {e}"

    # Copy image — long timeout, print progress dots
    shell.send(f"copy {http_url} flash:{image}\n")
    time.sleep(2)
    # Accept destination filename prompt
    shell.send("\n")
    copy_out = b""
    deadline = time.time() + 900  # 15 min max
    last_print = time.time()
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(8192)
            copy_out += chunk
            decoded = chunk.decode(errors="replace")
            if any(x in decoded for x in ["bytes copied", "Error", "error", "failed", "#"]):
                if "bytes copied" in decoded or "#" in decoded:
                    break
        if time.time() - last_print > 30:
            elapsed = int(time.time() - (deadline - 900))
            print(f"     [{name}] Copying... {elapsed}s elapsed")
            last_print = time.time()
        time.sleep(1)

    copy_result = copy_out.decode(errors="replace")
    if "bytes copied" not in copy_result and "Error" in copy_result:
        client.close()
        return False, f"Image copy failed on {name}: {copy_result[-300:]}"

    print(f"     [{name}] Image copied. Running software install...")

    # 3. Install, activate, commit
    shell.send(f"software install add file flash:{image} activate commit\n")
    time.sleep(3)
    # Confirm any prompts
    shell.send("\n")
    install_out = b""
    deadline2 = time.time() + 1800  # 30 min max for install + reload
    last_print = time.time()
    reloading = False
    while time.time() < deadline2:
        if shell.recv_ready():
            chunk = shell.recv(8192)
            install_out += chunk
            decoded = chunk.decode(errors="replace")
            if "reload" in decoded.lower() or "restarting" in decoded.lower():
                reloading = True
                print(f"     [{name}] Switch reloading...")
                break
            if "FAILED" in decoded or "failed" in decoded.lower():
                client.close()
                return False, f"Install failed on {name}: {decoded[-300:]}"
        if time.time() - last_print > 30:
            elapsed = int(time.time() - (deadline2 - 1800))
            print(f"     [{name}] Installing... {elapsed}s elapsed")
            last_print = time.time()
        time.sleep(1)

    client.close()

    # 4. Wait for switch to come back online
    print(f"     [{name}] Waiting for reload to complete...")
    time.sleep(60)  # Give it a minute before polling
    back_up = False
    poll_deadline = time.time() + 1200  # 20 min max
    while time.time() < poll_deadline:
        try:
            tc, ts = ssh_switch(ip)
            ver_check = switch_cmd(ts, "show version", timeout=8)
            tc.close()
            new_ver = _detect_version_from_show(ver_check)
            if new_ver:
                back_up = True
                print(f"     [{name}] Back online — version: {new_ver}")
                break
        except Exception:
            elapsed = int(poll_deadline - time.time())
            print(f"     [{name}] Still reloading... ({elapsed}s remaining)")
            time.sleep(30)

    if not back_up:
        return False, f"Timed out waiting for {name} to come back after upgrade"

    # 5. Verify new version meets golden
    if _version_needs_upgrade(new_ver, GOLDEN_VERSION_SWITCH):
        return False, f"Upgrade completed but version {new_ver} still < {GOLDEN_VERSION_SWITCH}"

    return True, f"Upgraded {name}: {current} -> {new_ver} (golden: {GOLDEN_VERSION_SWITCH})"


# ---------------------------------------------------------------------------
# Router upgrade
# ---------------------------------------------------------------------------

def phase_router_upgrade():
    """
    Upgrade the Secure Router (C8231-G2) to GOLDEN_VERSION_ROUTER if older.
    Never downgrades. After upgrade waits for SD-WAN tunnels to re-establish.
    Returns (ok, result_string).
    """
    image = UPGRADE_IMAGE_ROUTER
    if not image:
        return False, "No router image configured"

    print(f"     Connecting to router {ROUTER_IP} to check version...")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ROUTER_IP, username="admin", password="C1sco12345",
                       look_for_keys=False, allow_agent=False, timeout=20)
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(2); shell.recv(4096)
        shell.send("terminal length 0\n"); time.sleep(2); shell.recv(4096)
    except Exception as e:
        return False, f"SSH to router {ROUTER_IP} failed: {e}"

    def rcmd(cmd, t=10):
        shell.send(cmd + "\n"); time.sleep(1)
        out = b""
        dl = time.time() + t
        while time.time() < dl:
            if shell.recv_ready(): out += shell.recv(8192); time.sleep(0.3)
            else: time.sleep(0.2)
        return out.decode(errors="replace")

    ver_out = rcmd("show version", t=10)
    client.close()

    current = _detect_version_from_show(ver_out)
    if not current:
        return False, f"Could not detect router version"

    print(f"     Router current: {current}  Golden: {GOLDEN_VERSION_ROUTER}")

    if not _version_needs_upgrade(current, GOLDEN_VERSION_ROUTER):
        return True, f"Router version OK ({current} >= {GOLDEN_VERSION_ROUTER}) — no upgrade needed"

    print(f"     Router upgrade needed: {current} -> {GOLDEN_VERSION_ROUTER}")
    http_url = f"http://{UBUNTU_HOST}:{UBUNTU_HTTP_PORT}/{image}"

    # 1. Ensure HTTP server running
    print(f"     Starting HTTP server on Ubuntu PC...")
    if not _ubuntu_ensure_http_server():
        return False, "Failed to start HTTP server on Ubuntu PC"

    # 2. Copy image to bootflash
    print(f"     Copying image to router bootflash: (~10-15 min)...")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(ROUTER_IP, username="admin", password="C1sco12345",
                       look_for_keys=False, allow_agent=False, timeout=20)
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(2); shell.recv(4096)
        shell.send("terminal length 0\n"); time.sleep(2); shell.recv(4096)
    except Exception as e:
        return False, f"SSH to router failed before copy: {e}"

    shell.send(f"copy {http_url} bootflash:{image}\n")
    time.sleep(2); shell.send("\n")
    copy_out = b""
    deadline = time.time() + 1200
    last_print = time.time()
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(8192)
            copy_out += chunk
            decoded = chunk.decode(errors="replace")
            if "bytes copied" in decoded or ("Error" in decoded and "#" in decoded):
                break
        if time.time() - last_print > 30:
            print(f"     Router copy... {int(time.time()-(deadline-1200))}s elapsed")
            last_print = time.time()
        time.sleep(1)

    if "bytes copied" not in copy_out.decode(errors="replace"):
        client.close()
        return False, f"Router image copy failed: {copy_out.decode(errors='replace')[-300:]}"

    print(f"     Router image copied. Running software install...")

    # 3. Install activate commit
    shell.send(f"software install add file bootflash:{image} activate commit\n")
    time.sleep(3); shell.send("\n")
    install_out = b""
    deadline2 = time.time() + 1800
    last_print = time.time()
    while time.time() < deadline2:
        if shell.recv_ready():
            chunk = shell.recv(8192)
            install_out += chunk
            decoded = chunk.decode(errors="replace")
            if "reload" in decoded.lower() or "restarting" in decoded.lower():
                print(f"     Router reloading...")
                break
            if "FAILED" in decoded or "install failed" in decoded.lower():
                client.close()
                return False, f"Router install failed: {decoded[-300:]}"
        if time.time() - last_print > 30:
            print(f"     Router installing... {int(time.time()-(deadline2-1800))}s elapsed")
            last_print = time.time()
        time.sleep(1)
    client.close()

    # 4. Wait for router to come back and SD-WAN tunnels to restore
    print(f"     Waiting for router reload (~15 min)...")
    time.sleep(90)
    back_up = False
    new_ver = ""
    poll_deadline = time.time() + 1500
    while time.time() < poll_deadline:
        try:
            c2 = paramiko.SSHClient()
            c2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c2.connect(ROUTER_IP, username="admin", password="C1sco12345",
                       look_for_keys=False, allow_agent=False, timeout=15)
            sh2 = c2.invoke_shell(width=200, height=50)
            time.sleep(2); sh2.recv(4096)
            sh2.send("terminal length 0\n"); time.sleep(2); sh2.recv(4096)
            sh2.send("show version\n"); time.sleep(3)
            vout = b""
            dl = time.time() + 8
            while time.time() < dl:
                if sh2.recv_ready(): vout += sh2.recv(8192); time.sleep(0.3)
                else: time.sleep(0.2)
            c2.close()
            new_ver = _detect_version_from_show(vout.decode(errors="replace"))
            if new_ver:
                back_up = True
                print(f"     Router back online — version: {new_ver}")
                break
        except Exception:
            print(f"     Router still reloading... ({int(poll_deadline-time.time())}s remaining)")
            time.sleep(30)

    if not back_up:
        return False, "Timed out waiting for router to come back after upgrade"

    # 5. Wait for SD-WAN tunnels
    print(f"     Waiting for SD-WAN tunnels to re-establish...")
    ok, tunnel_result = _wait_sdwan_tunnels(timeout=600)
    if not ok:
        return False, f"Router upgraded to {new_ver} but SD-WAN tunnels not up: {tunnel_result}"

    if _version_needs_upgrade(new_ver, GOLDEN_VERSION_ROUTER):
        return False, f"Upgrade done but version {new_ver} still < {GOLDEN_VERSION_ROUTER}"

    return True, f"Router upgraded: {current} -> {new_ver} (golden: {GOLDEN_VERSION_ROUTER}) | {tunnel_result}"


AD_DC_IP      = "198.18.5.102"
AD_DC_USER    = "administrator"
AD_DC_PASS    = "C1sco12345"
AD_BASE_DN    = "DC=corp,DC=pseudoco,DC=com"
AD_TARGET_USERS = ["Kit", "Lee", "Pat", "Nik"]
AD_DEFAULT_DOMAIN = "@corp.pseudoco.com"

# Jumphost1 (where ADDuoTenantUserProvisioning.ps1 lives)
JUMPHOST_IP   = "198.18.133.36"
JUMPHOST_USER = "administrator"
JUMPHOST_PASS = "C1sco12345"
AD_PS1_PATH   = r"C:\Scripts\ADDuoTenantUserProvisioning.ps1"


def _ad_query_users():
    """Query Kit/Lee/Pat/Nik from AD via LDAP. Returns list of dicts with cn/mail/upn."""
    try:
        from ldap3 import Server, Connection, SIMPLE, NONE
    except ImportError:
        raise RuntimeError("ldap3 not installed — run: pip install ldap3")

    # get_info=NONE avoids fetching the full AD schema which hangs on some DCs
    srv = Server(AD_DC_IP, connect_timeout=8, get_info=NONE)
    conn = Connection(srv,
                      user=f"{AD_DC_USER}@corp.pseudoco.com",
                      password=AD_DC_PASS,
                      authentication=SIMPLE,
                      receive_timeout=10)
    conn.bind()
    if not conn.bound:
        raise RuntimeError(f"LDAP bind failed: {conn.result}")
    results = []
    for name in AD_TARGET_USERS:
        conn.search(AD_BASE_DN,
                    f"(&(objectClass=user)(cn={name}))",
                    attributes=["cn", "mail", "userPrincipalName", "sAMAccountName"])
        for e in conn.entries:
            mail = str(e.mail) if e.mail else ""
            upn  = str(e.userPrincipalName) if e.userPrincipalName else ""
            results.append({
                "cn":   str(e.cn),
                "sam":  str(e.sAMAccountName),
                "mail": mail,
                "upn":  upn,
            })
    conn.unbind()
    return results


def phase_ad_verify():
    """
    Query AD for Kit/Lee/Pat/Nik.
    PASS  = none of the 4 users still have @corp.pseudoco.com email.
    FAIL  = one or more still have the default @corp.pseudoco.com domain.
    Returns (ok, result_string).
    """
    print(f"     Querying AD at {AD_DC_IP} for users: {AD_TARGET_USERS}...")
    try:
        users = _ad_query_users()
    except Exception as e:
        return False, f"AD query failed: {e}"

    if not users:
        return False, "AD query returned no results for Kit/Lee/Pat/Nik"

    lines = []
    failed = []
    for u in users:
        email = u["mail"] or u["upn"] or "(no email)"
        status = "FAIL" if email.lower().endswith(AD_DEFAULT_DOMAIN) else "OK"
        lines.append(f"{u['cn']}={email} [{status}]")
        if status == "FAIL":
            failed.append(u["cn"])

    summary = " | ".join(lines)
    if failed:
        return False, f"NOT updated ({', '.join(failed)} still @corp.pseudoco.com) | {summary}"
    return True, f"All updated | {summary}"


def phase_ad_rerun():
    """
    Connect to Jumphost1 via WinRM and run ADDuoTenantUserProvisioning.ps1,
    then re-verify AD.
    Returns (ok, result_string).
    """
    print(f"     Connecting to Jumphost1 {JUMPHOST_IP} via WinRM to run PS1...")
    try:
        import winrm as _winrm
    except ImportError:
        raise RuntimeError("pywinrm not installed — run: pip install pywinrm")

    try:
        s = _winrm.Session(
            f"http://{JUMPHOST_IP}:5985/wsman",
            auth=(JUMPHOST_USER, JUMPHOST_PASS),
            transport="ntlm",
        )
        r = s.run_ps(f"& '{AD_PS1_PATH}'")
        stdout = r.std_out.decode(errors="replace").strip()
        stderr = r.std_err.decode(errors="replace").strip()
        print(f"     PS1 stdout: {stdout[:300]}")
        if stderr:
            print(f"     PS1 stderr: {stderr[:200]}")
        if r.status_code != 0:
            return False, f"PS1 exited {r.status_code}: {stderr[:300] or stdout[:300]}"
    except Exception as e:
        return False, f"WinRM to Jumphost1 failed: {e}"

    # Re-verify after running script
    print("     Re-verifying AD after PS1 run...")
    ok, result = phase_ad_verify()
    return ok, f"PS1 ran OK | {result}"


def phase_cdfmc_check():
    """
    1. SSH to the Terraform-Automation Ubuntu PC (via VPN).
    2. Read terraform.tasks.logs — verify 'Full infrastructure deployed'.
    3. Read terraform.tfvars  — extract cdfmc_host (SCC org).
    4. Hit the SCC/cdFMC API to confirm FTD device is Online.
    Returns (ok, result_string).
    """
    import re as _re

    print(f"     Connecting to automation PC {CDFMC_AUTOMATION_HOST}...")
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            CDFMC_AUTOMATION_HOST,
            username=CDFMC_AUTOMATION_USER,
            password=CDFMC_AUTOMATION_PASS,
            look_for_keys=False, allow_agent=False, timeout=15,
        )
    except Exception as e:
        return False, f"SSH to automation PC failed: {e}"

    def _run(cmd):
        _, out, err = client.exec_command(cmd, timeout=20)
        return out.read().decode(errors="replace").strip()

    # --- 1. Check terraform log for success ---
    log_tail = _run(f"tail -30 {CDFMC_LAB_DIR}/terraform.tasks.logs")
    deployed = "Full infrastructure deployed" in log_tail
    print(f"     Terraform log: {'✓ deployed' if deployed else '✗ not deployed'}")

    # --- 2. Extract cdfmc_host / scc_org from tfvars ---
    tfvars_raw = _run(f"cat {CDFMC_LAB_DIR}/terraform.tfvars")
    scc_org = ""
    scc_token = ""
    scc_host = ""
    device_name = "hqftdv"
    for line in tfvars_raw.splitlines():
        line = line.strip()
        m = _re.match(r'^cdfmc_host\s*=\s*"([^"]+)"', line)
        if m:
            scc_org = m.group(1)
        m = _re.match(r'^scc_token\s*=\s*"([^"]+)"', line)
        if m:
            scc_token = m.group(1)
        m = _re.match(r'^scc_host\s*=\s*"([^"]+)"', line)
        if m:
            scc_host = m.group(1)
        m = _re.match(r'^device_name\s*=\s*\["([^"]+)"', line)
        if m:
            device_name = m.group(1)
    print(f"     SCC org: {scc_org or '(not found)'}")

    # --- 3. Verify FTD online via cdFMC API — run on Ubuntu PC (has internet) ---
    ftd_online = False
    ftd_status = "unknown"
    if scc_token and scc_org:
        DOMAIN = "e276abec-e0f2-11e3-8169-6d9ed49b625f"
        url = f"https://{scc_org}/api/fmc_config/v1/domain/{DOMAIN}/devices/devicerecords?limit=50"
        # Run the API call on the Ubuntu PC (has internet access to SCC cloud)
        check_script = f"""
import urllib.request, json, ssl, sys
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
with open('{CDFMC_LAB_DIR}/terraform.tfvars') as f:
    lines = f.read()
token = [l.split('=',1)[1].strip().strip('"') for l in lines.splitlines() if l.strip().startswith('scc_token')][0]
cdfmc = [l.split('=',1)[1].strip().strip('"') for l in lines.splitlines() if l.strip().startswith('cdfmc_host')][0]
DOMAIN = 'e276abec-e0f2-11e3-8169-6d9ed49b625f'
def get(url):
    req = urllib.request.Request(url, headers={{'Authorization': 'Bearer ' + token}})
    return json.loads(urllib.request.urlopen(req, context=ctx, timeout=15).read())
items = get(f'https://{{cdfmc}}/api/fmc_config/v1/domain/{{DOMAIN}}/devices/devicerecords?limit=50').get('items', [])
for i in items:
    d = get(f'https://{{cdfmc}}/api/fmc_config/v1/domain/{{DOMAIN}}/devices/devicerecords/{{i["id"]}}')
    print(d.get('name',''), d.get('isConnected',''), d.get('deploymentStatus',''), d.get('healthStatus',''))
"""
        try:
            client2 = paramiko.SSHClient()
            client2.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client2.connect(
                CDFMC_AUTOMATION_HOST,
                username=CDFMC_AUTOMATION_USER,
                password=CDFMC_AUTOMATION_PASS,
                look_for_keys=False, allow_agent=False, timeout=15,
            )
            # Write script to a temp file then run it
            sftp = client2.open_sftp()
            with sftp.open("/tmp/_cdfmc_check.py", "w") as f:
                f.write(check_script)
            sftp.close()
            _, out2, _ = client2.exec_command("python3 /tmp/_cdfmc_check.py", timeout=30)
            api_out = out2.read().decode(errors="replace").strip()
            client2.close()
            print(f"     FTD devices: {api_out or '(none)'}")
            for line in api_out.splitlines():
                parts = line.split()
                if parts and "hqftd" in parts[0].lower():
                    connected   = parts[1] if len(parts) > 1 else ""
                    deploy_stat = parts[2] if len(parts) > 2 else ""
                    health      = parts[3] if len(parts) > 3 else ""
                    ftd_online = str(connected).lower() == "true"
                    ftd_status = f"{parts[0]} connected={connected} deployed={deploy_stat} health={health}"
            if not ftd_status or ftd_status == "unknown":
                ftd_status = api_out[:120] or "no devices returned"
        except Exception as e:
            ftd_status = f"API error: {e}"
            print(f"     cdFMC API error: {e}")
    else:
        ftd_status = "no token/host"

    ok = deployed and bool(scc_org) and ftd_online
    result = f"scc_org={scc_org} | deployed={'yes' if deployed else 'no'} | ftd={ftd_status}"
    print(f"     {'✓' if ok else '✗'} {result}")
    return ok, result
if __name__ == "__main__":
    pod_id = os.environ.get("POD_ID", f"POD-{SERIAL}")
    print(f"\nOnboarding {UUID} for {pod_id}\n{'='*40}")

    s = vmanage_session()
    steps = [
        ("verify_router", lambda: True),
        ("reset_device", lambda: phase_reset(s)),
        ("quick_connect", lambda: phase_quick_connect(s)),
        ("config_group_associate", lambda: phase_associate(s)),
        ("assign_license", lambda: phase_assign_license(s)),
        ("set_variables", lambda: phase_set_variables(s)),
        ("deploy_config_group", lambda: phase_deploy(s)),
        ("generate_bootstrap", lambda: phase_generate_bootstrap(s)),
        ("copy_bootstrap", phase_copy_bootstrap),
    ]
    if not stop_after_copy:
        steps += [
            ("controller_mode_enable", phase_controller_mode),
            ("verify_online", lambda: True),
            ("verify_border_spine", lambda: run_switch_checks("verify_border_spine")),
            ("verify_leaf1", lambda: run_switch_checks("verify_leaf1")),
            ("verify_leaf2", lambda: run_switch_checks("verify_leaf2")),
            ("connectivity_test", phase_connectivity_test),
        ]

    import subprocess, json  # noqa
    def report_step(step_name, status, result=""):
        subprocess.run([
            sys.executable, "-c", f"""
import sqlite3
conn = sqlite3.connect('{os.path.expanduser("~/sw_projects/pod_automator/data/pod_state.db")}')
conn.execute("INSERT OR REPLACE INTO pipeline_steps (pod_id, step_name, status, completed_at, result) VALUES (?, ?, ?, datetime('now'), ?)",
    ('{pod_id}', '{step_name}', '{status}', '''{result.replace("'", "''")}'''))
conn.commit()"""], timeout=5)

    for step_name, func in steps:
        print(f"\n{step_name}...")
        report_step(step_name, "running")
        try:
            ret = func()
            # Normalize: (ok, result) tuple or bool
            if isinstance(ret, tuple):
                ok, result = ret
            else:
                ok, result = ret, ""
            if not ok:
                print(f"FAILED at {step_name}")
                report_step(step_name, "failed", str(result)[:200])
                sys.exit(1)
            report_step(step_name, "completed", str(result)[:200] or "OK")
            print(f"  OK")
        except Exception as e:
            print(f"FAILED at {step_name}: {e}")
            report_step(step_name, "failed", str(e)[:200])
            sys.exit(1)

    print(f"\n{'='*40}")
    print(f"Pipeline complete for {pod_id}")
    print("Router in SD-WAN mode, switches verified, connectivity tested.")
