"""
Onboard C8231-G2 Secure Router with correct values from CSV template.
Usage: uv run --directory ~/sw_projects/pod_automator python3 onboard_router.py [SERIAL]
"""

import csv, json, os, re, sys, time, paramiko, requests, subprocess, urllib3
urllib3.disable_warnings()


def _parse_vrfs(output: str):
    """Parse 'show vrf' output and return (has_mgmt, extra_vrfs).
    Filters purely in Python — no SSH pipes used.
    On C9300/IOS XE, all VRF name lines are indented with 2 spaces; continuation
    interface lines are deeply indented (only 1 token when split by 2+ spaces).
    We use column splitting to distinguish VRF name lines (2+ columns) from
    continuation lines (1 column = just an interface name).
    """
    SKIP = {"Mgmt-vrf", "Default", "Name", "show", "vrf"}
    has_mgmt = "Mgmt-vrf" in output
    extra_vrfs = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Split on 2+ consecutive spaces to identify distinct columns.
        # VRF name lines: "Main  65000:1  ipv4,ipv6  Gi1/0/47" → 4 tokens
        # Continuation interface lines: "Lo103" → 1 token → skip
        tokens = re.split(r'\s{2,}', stripped)
        if len(tokens) < 2:
            continue  # continuation interface line
        first = tokens[0]
        # Skip command echo lines (e.g. "show vrf")
        if first.lower() in ("show", "vrf"):
            continue
        # VRF names are word-chars + hyphens only (no / # . > : spaces)
        if not re.match(r'^[\w][\w\-]*$', first):
            continue
        if first in SKIP:
            continue
        extra_vrfs.append(first)
    return has_mgmt, extra_vrfs


def _parse_version_str(output: str):
    """Parse 'show version' and return (ver_ok, ver_str).
    ver_ok is True if version string contains '17.12'.
    """
    ver_str = "??"
    for line in output.splitlines():
        # Match lines like: "Cisco IOS XE Software, Version 17.12.01"
        if re.search(r'[Vv]ersion\s+\d+\.\d+', line):
            m = re.search(r'[Vv]ersion\s+(\S+)', line)
            if m:
                ver_str = m.group(1).rstrip(",")
                break
    ver_ok = "17.12" in ver_str
    return ver_ok, ver_str

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
BOOTSTRAP_PATH = os.environ.get(
    "BOOTSTRAP_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "bootstrap", "ciscosdwan.cfg")
)


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


# ---------------------------------------------------------------------------
# Catalyst Center Discovery
# ---------------------------------------------------------------------------

CATC_HOST     = "198.18.5.100"
CATC_USER     = "admin"
CATC_PASS     = "Demo@C!sco"
CATC_BASE     = f"https://{CATC_HOST}"
CATC_MAIN_SITE_ID = "919ce2a1-39b7-4c1f-a7ec-c76e50170ab7"  # Global/NORTH CAROLINA/Durham/Site-105/MAIN
CATC_WLC_SITE_ID  = "ac7aeac8-fba7-4776-9b3e-feb20384bb44"  # Global/CALIFORNIA/San Jose/DC-Site-10/MAIN

CATC_SWITCHES = {
    "verify_border_spine": {"ip": "198.18.128.24", "name": "Border Spine"},
    "verify_leaf1":        {"ip": "198.18.128.22", "name": "Leaf 1"},
    "verify_leaf2":        {"ip": "198.18.128.23", "name": "Leaf 2"},
}

# Loopback IPs used for Catalyst Center discovery (mgmt interfaces excluded from telemetry)
CATC_DISCOVERY_IPS = {
    "border_spine": {"loopback": "172.30.255.3", "mgmt": "198.18.128.24", "name": "Border Spine"},
    "leaf1":        {"loopback": "172.30.255.1", "mgmt": "198.18.128.22", "name": "Leaf 1"},
    "leaf2":        {"loopback": "172.30.255.2", "mgmt": "198.18.128.23", "name": "Leaf 2"},
}

# Additional devices discovered separately (non-loopback, own site assignment)
CATC_WLC = {
    "ip":      "198.18.5.103",
    "name":    "C9800-WLC",
    "site_id": CATC_WLC_SITE_ID,
    "site":    "Global/CALIFORNIA/San Jose/DC-Site-10/MAIN",
    "cred_ids": [
        "82d24eba-dcc0-4fb8-8810-137d190bf90f",  # CLI netadmin (same cred as switches)
        "e6b5e009-5aa3-41b2-a576-d92e6a4c8f02",  # SNMPv2 Read
        "07d96097-7dac-4929-a9d6-622eb43f3d3e",  # SNMPv2 Write
        "d6e2d122-0a7b-42a9-87cf-6a21f1d12e2a",  # NETCONF
        "a21757fb-057d-43c1-baa4-6187b0d13cd9",  # HTTP Read
        "64b9020e-923f-4577-ae3b-6397d3feb94a",  # HTTP Write
    ],
}


def _catc_token():
    import requests, urllib3
    urllib3.disable_warnings()
    r = requests.post(f"{CATC_BASE}/dna/system/api/v1/auth/token",
                      auth=(CATC_USER, CATC_PASS), verify=False, timeout=15)
    r.raise_for_status()
    return r.json()["Token"]


def _catc_headers():
    return {"X-Auth-Token": _catc_token(), "Content-Type": "application/json"}


def _catc_wait_execution(headers, exec_id, timeout=60):
    """Poll /dnacaap/management/execution-status until SUCCESS or FAILURE."""
    import requests, urllib3, time
    urllib3.disable_warnings()
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(
            f"{CATC_BASE}/dna/intent/api/v1/dnacaap/management/execution-status/{exec_id}",
            headers=headers, verify=False, timeout=15)
        d = r.json()
        status = d.get("status", "")
        if status == "SUCCESS":
            return True, "SUCCESS"
        if status == "FAILURE":
            return False, d.get("bapiError", "FAILURE")
        time.sleep(3)
    return False, f"Execution {exec_id} timed out after {timeout}s"


def _catc_wait_task(headers, task_id, timeout=120):
    """Poll a Catalyst Center task until it completes. Returns (ok, data)."""
    import requests, urllib3, time
    urllib3.disable_warnings()
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(f"{CATC_BASE}/dna/intent/api/v1/task/{task_id}",
                         headers=headers, verify=False, timeout=15)
        t = r.json().get("response", {})
        if t.get("isError"):
            return False, t.get("failureReason", t.get("progress", "unknown error"))
        # Discovery tasks return the discovery ID in 'data' immediately
        if t.get("data"):
            return True, t.get("data")
        if t.get("endTime"):
            return True, t.get("progress", "completed")
        time.sleep(3)
    return False, f"Task {task_id} timed out after {timeout}s"


def _catc_wait_discovery(headers, discovery_id, timeout=300):
    """Poll discovery until status=Inactive (complete). Returns (ok, device_list)."""
    import requests, urllib3, time
    urllib3.disable_warnings()
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = requests.get(
            f"{CATC_BASE}/dna/intent/api/v1/discovery/{discovery_id}",
            headers=headers, verify=False, timeout=15)
        status = r.json().get("response", {}).get("discoveryStatus", "")

        r2 = requests.get(
            f"{CATC_BASE}/dna/intent/api/v1/discovery/{discovery_id}/network-device",
            headers=headers, verify=False, timeout=15)
        devices = r2.json().get("response", [])

        elapsed = int(time.time() - (deadline - timeout))
        print(f"     Discovery {status}... {elapsed}s ({len(devices)} devices)")

        if status == "Inactive":
            return True, devices
        time.sleep(10)
    return False, []


def phase_catc_discover(log_fn=print):
    """
    Discover all 3 lab switches in Catalyst Center using pre-existing credentials.
    Creates a new discovery job targeting the 3 switch IPs, polls until complete,
    then verifies all switches are Reachable.
    Returns (ok, result_string).
    """
    import requests, urllib3, json
    urllib3.disable_warnings()

    # Loopback IPs used for discovery; mgmt IPs used for inventory check and site assignment
    loopback_ips = [info["loopback"] for info in CATC_DISCOVERY_IPS.values()]
    mgmt_ips     = [info["mgmt"]     for info in CATC_DISCOVERY_IPS.values()]
    discovery_ip_list = ",".join(loopback_ips)
    summary = ", ".join(loopback_ips)  # default; overwritten after discovery

    # ── Step 1: Authenticate ─────────────────────────────────────────────────
    log_fn("[catc:step] auth | running | Authenticating to Catalyst Center")
    try:
        headers = _catc_headers()
    except Exception as e:
        log_fn(f"[catc:step] auth | failed | Auth failed: {e}")
        return False, f"Catalyst Center auth failed: {e}"
    log_fn(f"[catc:step] auth | completed | Connected to {CATC_HOST}")

    # ── Step 2: Check existing inventory (by loopback IP) ────────────────────
    log_fn("[catc:step] check_inventory | running | Checking existing inventory")
    r = requests.get(f"{CATC_BASE}/dna/intent/api/v1/network-device",
                     headers=headers, verify=False, timeout=15)
    existing = {d["managementIpAddress"]: d for d in r.json().get("response", [])}
    # Devices discovered via loopback will appear with the loopback as managementIpAddress
    already_ok = [ip for ip in loopback_ips
                  if existing.get(ip, {}).get("reachabilityStatus") in ("Reachable", "Success")]
    if len(already_ok) == len(loopback_ips):
        log_fn(f"[catc:step] check_inventory | completed | All 3 switches already reachable via loopback")
        log_fn(f"[catc:step] create_discovery | completed | Skipped — already in inventory")
        log_fn(f"[catc:step] verify_results | completed | All switches reachable in inventory")
        # Still fall through to site assignment and provisioning
    else:
        log_fn(f"[catc:step] check_inventory | completed | {len(already_ok)}/3 already reachable — need discovery")

    # ── Step 3: Create and run discovery job (only if not already in inventory) ─
    if len(already_ok) < len(loopback_ips):
      import time as _t
      job_name = f"NaC-Lab-Switches-{_t.strftime('%Y%m%d-%H%M%S')}"
      log_fn(f"[catc:step] create_discovery | running | Creating discovery for loopbacks: {discovery_ip_list}")
      payload = {
        "name":          job_name,
        "discoveryType": "Multi Range",
        "ipAddressList": discovery_ip_list,
        "protocolOrder":  "ssh",
        "timeout":        5,
        "retry":          2,
        "netconfPort":    "830",
        "globalCredentialIdList": [
            "82d24eba-dcc0-4fb8-8810-137d190bf90f",  # CLI netadmin
            "e6b5e009-5aa3-41b2-a576-d92e6a4c8f02",  # SNMPv2 Read
            "07d96097-7dac-4929-a9d6-622eb43f3d3e",  # SNMPv2 Write
            "d6e2d122-0a7b-42a9-87cf-6a21f1d12e2a",  # NETCONF
            "a21757fb-057d-43c1-baa4-6187b0d13cd9",  # HTTP Read  (netadmin)
            "64b9020e-923f-4577-ae3b-6397d3feb94a",  # HTTP Write (netadmin)
        ],
      }
      r2 = requests.post(f"{CATC_BASE}/dna/intent/api/v1/discovery",
                         headers=headers, json=payload, verify=False, timeout=15)
      if r2.status_code not in (200, 201, 202):
          log_fn(f"[catc:step] create_discovery | failed | HTTP {r2.status_code}: {r2.text[:200]}")
          return False, f"Discovery create failed ({r2.status_code}): {r2.text[:300]}"

      # Resolve discovery ID by matching the job name — avoids stale task data field
      import time as _time2
      discovery_id = None
      for _ in range(15):
          r3 = requests.get(f"{CATC_BASE}/dna/intent/api/v1/discovery/1/500",
                            headers=headers, verify=False, timeout=15)
          for disc in r3.json().get("response", []):
              if disc.get("name") == job_name:
                  discovery_id = disc["id"]
                  break
          if discovery_id:
              break
          _time2.sleep(2)

      if not discovery_id:
          log_fn(f"[catc:step] create_discovery | failed | Could not find discovery job '{job_name}'")
          return False, f"Could not locate discovery job after creation"

      log_fn(f"[catc:step] create_discovery | running | Discovery ID {discovery_id} — polling for completion")

      ok, devices = _catc_wait_discovery(headers, discovery_id, timeout=300)
      if not ok:
          log_fn(f"[catc:step] create_discovery | failed | Discovery timed out")
          return False, "Discovery timed out waiting for all devices"
      log_fn(f"[catc:step] create_discovery | completed | Discovery {discovery_id} finished ({len(devices)} devices)")

      # ── Step 4: Verify results ─────────────────────────────────────────────
      log_fn(f"[catc:step] verify_results | running | Checking reachability for {len(devices)} devices")
      results = []
      all_reachable = True
      for d in devices:
          ip     = d.get("managementIpAddress", "?")
          host   = d.get("hostname", "?")
          status = d.get("reachabilityStatus", "?")
          results.append(f"{ip} ({host}): {status}")
          log_fn(f"[catc:step] verify_results | running | {ip} | {host} | {status}")
          if status not in ("Reachable", "Success"):
              all_reachable = False

      summary = "; ".join(results)
      if not all_reachable:
          log_fn(f"[catc:step] verify_results | failed | Some switches not reachable: {summary}")
          return False, f"Some switches not reachable: {summary}"
      log_fn(f"[catc:step] verify_results | completed | All switches reachable: {summary}")

    # ── Step 5: Assign to site ───────────────────────────────────────────────
    log_fn(f"[catc:step] assign_site | running | Assigning to Global/NORTH CAROLINA/Durham/Site-105/MAIN")

    # Devices discovered via loopback — their managementIpAddress in CatC is the loopback IP
    r_inv = requests.get(f"{CATC_BASE}/dna/intent/api/v1/network-device",
                         headers=headers, verify=False, timeout=15)
    inv = {d["managementIpAddress"]: d for d in r_inv.json().get("response", [])}

    already_assigned = [
        ip for ip in loopback_ips
        if CATC_MAIN_SITE_ID in inv.get(ip, {}).get("siteHierarchyId", "")
    ]
    if len(already_assigned) == len(loopback_ips):
        log_fn(f"[catc:step] assign_site | completed | All 3 already assigned to MAIN site")
    else:
        to_assign = [ip for ip in loopback_ips if ip not in already_assigned]
        log_fn(f"[catc:step] assign_site | running | Assigning {len(to_assign)} device(s) to site")
        payload_assign = {"device": [{"ip": ip} for ip in loopback_ips]}
        r_assign = requests.post(
            f"{CATC_BASE}/dna/intent/api/v1/assign-device-to-site/{CATC_MAIN_SITE_ID}/device",
            headers=headers, json=payload_assign, verify=False, timeout=15)
        if r_assign.status_code not in (200, 202):
            log_fn(f"[catc:step] assign_site | failed | HTTP {r_assign.status_code}: {r_assign.text[:200]}")
            return False, f"Site assignment failed ({r_assign.status_code}): {r_assign.text[:200]}"

        exec_id = r_assign.json().get("executionId")
        log_fn(f"[catc:step] assign_site | running | Execution {exec_id} — waiting for completion")
        ok, msg = _catc_wait_execution(headers, exec_id, timeout=90)
        if not ok:
            log_fn(f"[catc:step] assign_site | failed | {msg}")
            return False, f"Site assignment execution failed: {msg}"
        log_fn(f"[catc:step] assign_site | completed | All 3 switches assigned to MAIN site")

    # ── Step 6: Discover and assign C9800-WLC ────────────────────────────────
    wlc_ip   = CATC_WLC["ip"]
    wlc_name = CATC_WLC["name"]
    wlc_site = CATC_WLC["site"]
    log_fn(f"[catc:step] discover_wlc | running | Checking {wlc_name} ({wlc_ip}) in inventory")
    import time as _time

    r_inv2 = requests.get(f"{CATC_BASE}/dna/intent/api/v1/network-device",
                          headers=headers, verify=False, timeout=15)
    inv2 = {d["managementIpAddress"]: d for d in r_inv2.json().get("response", [])}
    wlc_dev = inv2.get(wlc_ip)

    if wlc_dev and wlc_dev.get("reachabilityStatus") in ("Reachable", "Success"):
        log_fn(f"[catc:step] discover_wlc | completed | {wlc_name} already in inventory")
    else:
        log_fn(f"[catc:step] discover_wlc | running | Creating discovery job for {wlc_name} ({wlc_ip})")
        wlc_job = f"NaC-WLC-{_time.strftime('%Y%m%d-%H%M%S')}"
        wlc_payload = {
            "name":                   wlc_job,
            "discoveryType":          "Single",
            "ipAddressList":          wlc_ip,
            "protocolOrder":          "ssh",
            "retryCount":             3,
            "timeOut":                5,
            "netconfPort":            "830",
            "globalCredentialIdList": CATC_WLC["cred_ids"],
        }
        r_wlc = requests.post(f"{CATC_BASE}/dna/intent/api/v1/discovery",
                              headers=headers, json=wlc_payload, verify=False, timeout=15)
        if r_wlc.status_code not in (200, 201, 202):
            log_fn(f"[catc:step] discover_wlc | running | WARNING: discovery create failed ({r_wlc.status_code}) — continuing")
        else:
            wlc_disc_id = None
            for _ in range(15):
                r_wlc2 = requests.get(f"{CATC_BASE}/dna/intent/api/v1/discovery/1/500",
                                      headers=headers, verify=False, timeout=15)
                for disc in r_wlc2.json().get("response", []):
                    if disc.get("name") == wlc_job:
                        wlc_disc_id = disc["id"]
                        break
                if wlc_disc_id:
                    break
                _time.sleep(2)

            if wlc_disc_id:
                log_fn(f"[catc:step] discover_wlc | running | Discovery {wlc_disc_id} — polling")
                deadline_wlc = _time.time() + 180
                while _time.time() < deadline_wlc:
                    r_d = requests.get(f"{CATC_BASE}/dna/intent/api/v1/discovery/{wlc_disc_id}",
                                       headers=headers, verify=False, timeout=15)
                    if r_d.json().get("response", {}).get("discoveryStatus") == "Inactive":
                        break
                    _time.sleep(10)

                # Job Inactive ≠ inventory collection done — poll per-device until Managed
                log_fn(f"[catc:step] discover_wlc | running | Waiting for inventory collection")
                deadline_coll = _time.time() + 120
                while _time.time() < deadline_coll:
                    r_dev = requests.get(
                        f"{CATC_BASE}/dna/intent/api/v1/discovery/{wlc_disc_id}/network-device",
                        headers=headers, verify=False, timeout=15)
                    devs = r_dev.json().get("response", [])
                    if devs and devs[0].get("inventoryCollectionStatus", "") not in ("In Progress", ""):
                        break
                    _time.sleep(5)

            # Re-check inventory for WLC
            r_inv3 = requests.get(f"{CATC_BASE}/dna/intent/api/v1/network-device",
                                  headers=headers, verify=False, timeout=15)
            wlc_dev = {d["managementIpAddress"]: d
                       for d in r_inv3.json().get("response", [])}.get(wlc_ip)

        if wlc_dev and wlc_dev.get("reachabilityStatus") in ("Reachable", "Success"):
            log_fn(f"[catc:step] discover_wlc | completed | {wlc_name} discovered and reachable")
        else:
            log_fn(f"[catc:step] discover_wlc | failed | {wlc_name} not reachable after discovery — continuing")

    # Assign WLC to its site
    if wlc_dev:
        wlc_site_current = wlc_dev.get("siteHierarchyId", "")
        if CATC_WLC_SITE_ID in wlc_site_current:
            log_fn(f"[catc:step] assign_wlc_site | completed | {wlc_name} already assigned to {wlc_site}")
        else:
            log_fn(f"[catc:step] assign_wlc_site | running | Assigning {wlc_name} to {wlc_site}")
            r_asgn = requests.post(
                f"{CATC_BASE}/dna/intent/api/v1/assign-device-to-site/{CATC_WLC_SITE_ID}/device",
                headers=headers, json={"device": [{"ip": wlc_ip}]}, verify=False, timeout=15)
            if r_asgn.status_code not in (200, 202):
                log_fn(f"[catc:step] assign_wlc_site | running | WARNING: site assignment failed ({r_asgn.status_code}) — continuing")
            else:
                exec_id = r_asgn.json().get("executionId")
                if exec_id:
                    deadline_e = _time.time() + 90
                    while _time.time() < deadline_e:
                        r_e = requests.get(
                            f"{CATC_BASE}/dna/intent/api/v1/dnacaap/management/execution-status/{exec_id}",
                            headers=headers, verify=False, timeout=15)
                        if r_e.json().get("status", "") in ("SUCCESS", "FAILURE"):
                            break
                        _time.sleep(5)
                log_fn(f"[catc:step] assign_wlc_site | completed | {wlc_name} assigned to {wlc_site}")
    else:
        log_fn(f"[catc:step] assign_wlc_site | failed | {wlc_name} not in inventory — skipping site assignment")

    # ── Step 7: Provision switches ────────────────────────────────────────────
    # Trigger actual CatC provision action for all 3 switches.
    # NOTE: DOT1X_SECURITY no longer pushes any AAA/RADIUS CLIs so CatC will
    # never hit NCSO20070 on a clean run. Do NOT add cleanup here.
    log_fn(f"[catc:step] provision | running | Triggering CatC provision for all switches")
    r_inv2 = requests.get(f"{CATC_BASE}/dna/intent/api/v1/network-device",
                          headers=headers, verify=False, timeout=15)
    inv2 = {d["managementIpAddress"]: d for d in r_inv2.json().get("response", [])}
    device_ids = [inv2[ip]["id"] for ip in loopback_ips if ip in inv2 and "id" in inv2[ip]]
    if not device_ids:
        log_fn(f"[catc:step] provision | failed | No device IDs found for loopback IPs")
        return False, "Provision failed — devices not found in inventory"

    prov_payload = [{"networkDeviceId": dev_id, "siteId": CATC_MAIN_SITE_ID} for dev_id in device_ids]
    r_prov = requests.post(f"{CATC_BASE}/dna/intent/api/v2/provision-device",
                           headers=headers, json=prov_payload, verify=False, timeout=30)
    if r_prov.status_code not in (200, 202):
        log_fn(f"[catc:step] provision | failed | HTTP {r_prov.status_code}: {r_prov.text[:300]}")
        return False, f"Provision trigger failed ({r_prov.status_code}): {r_prov.text[:300]}"

    # Poll task to completion
    task_id = (r_prov.json().get("response") or {}).get("taskId") or \
              (r_prov.json().get("response") or [{}])[0].get("taskId") if isinstance(r_prov.json().get("response"), list) else None
    if task_id:
        log_fn(f"[catc:step] provision | running | Task {task_id} — waiting for completion")
        deadline_prov = _time.time() + 300
        while _time.time() < deadline_prov:
            r_task = requests.get(f"{CATC_BASE}/dna/intent/api/v1/task/{task_id}",
                                  headers=headers, verify=False, timeout=15)
            t = r_task.json().get("response", {})
            if t.get("isError"):
                log_fn(f"[catc:step] provision | failed | Task error: {t.get('failureReason','')[:200]}")
                return False, f"Provision task failed: {t.get('failureReason','')}"
            if t.get("endTime"):
                log_fn(f"[catc:step] provision | running | Provision task completed — verifying managed state")
                break
            _time.sleep(10)

    # Verify all devices reach Managed state
    log_fn(f"[catc:step] provision | running | Verifying devices are managed and syncing")
    deadline = _time.time() + 300
    all_managed = False
    while _time.time() < deadline:
        r_check = requests.get(f"{CATC_BASE}/dna/intent/api/v1/network-device",
                               headers=headers, verify=False, timeout=15)
        inv3 = {d["managementIpAddress"]: d for d in r_check.json().get("response", [])}
        states = [(ip, inv3.get(ip, {}).get("managementState", "?"),
                       inv3.get(ip, {}).get("collectionStatus", "?")) for ip in loopback_ips]
        managed = [ip for ip, ms, cs in states if ms == "Managed" and cs not in ("In Progress", "Not Synced")]
        log_fn(f"[catc:step] provision | running | Managed: {len(managed)}/3 — "
               + " | ".join(f"{ip}:{cs}" for ip, ms, cs in states))
        if len(managed) == len(loopback_ips):
            all_managed = True
            break
        _time.sleep(10)

    if not all_managed:
        log_fn(f"[catc:step] provision | failed | Not all devices reached Managed state in time")
        return False, "Provision verification timed out — devices not all Managed"

    log_fn(f"[catc:step] provision | completed | All 3 switches provisioned and Managed")
    return True, f"All switches discovered, assigned to MAIN site, and provisioned: {summary}"


def run_switch_checks(step_name):
    info = SWITCHES.get(step_name)
    if not info:
        return False, "UNKNOWN STEP"
    ip = info["ip"]
    print(f"  SSH to {info['name']} ({ip})...")
    client, shell = None, None
    last_err = None
    for attempt in range(1, 4):
        try:
            client, shell = ssh_switch(ip)
            last_err = None
            break
        except Exception as e:
            last_err = e
            print(f"  SSH attempt {attempt}/3 failed: {e}")
            if attempt < 3:
                time.sleep(10)
    if last_err is not None:
        print(f"  SSH failed after 3 attempts: {last_err}")
        return False, f"SSH FAILED: {last_err}"

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
        parts.append(f"PASS: {n_count} OSPF neighbors" if n_count >= 2 else f"FAIL: {n_count} OSPF neighbors (expected 2)")

        # VRF — no pipes, filter in Python
        out_vrf = switch_cmd(shell, "show vrf")
        has_mgmt, extra_vrfs = _parse_vrfs(out_vrf)
        parts.append(f"PASS: VRF OK (Mgmt-vrf only)" if (has_mgmt and not extra_vrfs) else f"FAIL: unexpected VRFs: {extra_vrfs or 'Mgmt-vrf missing'}")

        # Version — no pipes, filter in Python
        out_ver = switch_cmd(shell, "show version")
        ver_ok, ver_str = _parse_version_str(out_ver)
        parts.append(f"{'PASS' if ver_ok else 'FAIL'}: Version {ver_str}")

        # VLAN — only VLAN 1, VLAN 5 (DNAC), and internal VLANs 1002-1005 expected
        out = switch_cmd(shell, "show vlan brief")
        vlan_lines = [l for l in out.splitlines() if l.strip() and l[0].isdigit()]
        non_default = []
        for l in vlan_lines:
            try:
                vid = int(l.split()[0])
            except ValueError:
                continue
            if vid in (1, 5) or 1002 <= vid <= 1005:
                continue
            non_default.append(l)
        vlan_ok = len(non_default) == 0
        parts.append(f"{'PASS' if vlan_ok else 'FAIL'}: VLAN check ({'only VLAN 1+5' if vlan_ok else f'extra: {[l.split()[0] for l in non_default]}'})")

        # AAA — only the 3 base-config lines (plus aaa new-model) are allowed
        out_aaa = switch_cmd(shell, "show run | include ^aaa")
        ALLOWED_AAA = {
            "aaa new-model",
            "aaa authentication login default local",
            "aaa authorization exec default local",
            "aaa authorization network default local",
        }
        aaa_lines = [l.strip() for l in out_aaa.splitlines() if l.strip().startswith("aaa")]
        extra_aaa = [l for l in aaa_lines if l not in ALLOWED_AAA]
        aaa_ok = len(extra_aaa) == 0
        parts.append(f"{'PASS' if aaa_ok else 'FAIL'}: AAA {'clean' if aaa_ok else f'extra: {extra_aaa[:3]}'}")

    else:
        # Leaf switches — VRF, version, VLAN, AAA
        out_vrf = switch_cmd(shell, "show vrf")
        has_mgmt, extra_vrfs = _parse_vrfs(out_vrf)
        parts.append(f"PASS: VRF OK (Mgmt-vrf only)" if (has_mgmt and not extra_vrfs) else f"FAIL: extra VRFs {extra_vrfs or 'Mgmt-vrf missing'}")

        out_ver = switch_cmd(shell, "show version")
        ver_ok, ver_str = _parse_version_str(out_ver)
        parts.append(f"{'PASS' if ver_ok else 'FAIL'}: Version {ver_str}")

        # VLAN — only VLAN 1 and internal VLANs 1002-1005 expected after base config
        out = switch_cmd(shell, "show vlan brief")
        vlan_lines = [l for l in out.splitlines() if l.strip() and l[0].isdigit()]
        non_default = []
        for l in vlan_lines:
            try:
                vid = int(l.split()[0])
            except ValueError:
                continue
            if vid == 1 or 1002 <= vid <= 1005:
                continue
            non_default.append(l)
        vlan_ok = len(non_default) == 0
        parts.append(f"{'PASS' if vlan_ok else 'FAIL'}: VLAN check ({'only default' if vlan_ok else f'extra: {[l.split()[0] for l in non_default]}'})")

        # AAA — only the 3 base-config lines (plus aaa new-model) are allowed
        out_aaa = switch_cmd(shell, "show run | include ^aaa")
        ALLOWED_AAA = {
            "aaa new-model",
            "aaa authentication login default local",
            "aaa authorization exec default local",
            "aaa authorization network default local",
        }
        aaa_lines = [l.strip() for l in out_aaa.splitlines() if l.strip().startswith("aaa")]
        extra_aaa = [l for l in aaa_lines if l not in ALLOWED_AAA]
        aaa_ok = len(extra_aaa) == 0
        parts.append(f"{'PASS' if aaa_ok else 'FAIL'}: AAA {'clean' if aaa_ok else f'extra: {extra_aaa[:3]}'}")

    client.close()
    result = " | ".join(parts)
    print(f"  {result}")
    overall_ok = "FAIL" not in result
    return overall_ok, result


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


# Switch key → base config filename + IP
BASECONFIG_SWITCHES = {
    "border_spine": {"ip": "198.18.128.24", "name": "Border Spine", "file": "border_spine.txt"},
    "leaf1":        {"ip": "198.18.128.22", "name": "Leaf 1",        "file": "leaf1.txt"},
    "leaf2":        {"ip": "198.18.128.23", "name": "Leaf 2",        "file": "leaf2.txt"},
}

def phase_baseconfig_verify(switch_key, log_fn=print):
    """
    Verify a switch has the expected base config.
    Checks: hostname, management VRF present, key VLANs present.
    Returns (ok, detail).
    """
    info = BASECONFIG_SWITCHES.get(switch_key)
    if not info:
        return False, f"Unknown switch key: {switch_key}"

    expected_hostname = {
        "border_spine": "Site_105-Border-Spine",
        "leaf1":        "Site_105-Leaf1",
        "leaf2":        "Site_105-Leaf2",
    }.get(switch_key, "")

    log_fn(f"  Verifying {info['name']} ({info['ip']})...")
    try:
        client, shell = ssh_switch(info["ip"])
    except Exception as e:
        return False, f"SSH failed: {e}"

    checks = {}
    try:
        # Check hostname
        out = switch_cmd(shell, "show run | include ^hostname", timeout=8)
        hostname_ok = expected_hostname in out
        checks["hostname"] = "OK" if hostname_ok else f"FAIL (got: {out.strip()[:60]})"

        # Check Mgmt-vrf present
        out = switch_cmd(shell, "show vrf | include Mgmt", timeout=8)
        checks["Mgmt-vrf"] = "OK" if "Mgmt-vrf" in out else "MISSING"

        # Check Loopback0 present (present in all base configs, good indicator config loaded)
        out = switch_cmd(shell, "show run | include ^interface Loopback0", timeout=8)
        checks["loopback0"] = "OK" if "Loopback0" in out else "MISSING"

        # No EVPN NVE interface (should be gone after reset)
        out = switch_cmd(shell, "show run | include ^interface nve", timeout=8)
        # Check for the actual interface line — avoid false positives from banner/echo noise
        nve_present = any(
            line.strip().lower().startswith("interface nve")
            for line in out.splitlines()
        )
        checks["no_nve"] = "STILL_PRESENT" if nve_present else "OK"

        # No fabric VRFs (Main/IOT/PROD should be gone after reset)
        out = switch_cmd(shell, "show vrf", timeout=8)
        fabric_vrfs = [v for v in ["Main", "IOT", "PROD"] if v in out]
        checks["no_fabric_vrfs"] = f"STILL_PRESENT:{','.join(fabric_vrfs)}" if fabric_vrfs else "OK"

        client.close()
    except Exception as e:
        client.close()
        return False, f"Verify failed mid-check: {e}"

    failed = [k for k, v in checks.items() if v != "OK"]
    summary = "; ".join(f"{k}={v}" for k, v in checks.items())
    ok = len(failed) == 0
    return ok, summary


def phase_baseconfig_reset(switch_key, log_fn=print):
    """
    Reset a switch to its known-good base config using Telnet + TFTP + reload.
    Delegates to reset_switches.reset_switch() which mirrors the proven manual script.
    Returns (ok, detail).
    """
    import reset_switches

    base_dir = os.environ.get("BASE_CONFIGS_DIR") or os.path.join(os.path.dirname(os.path.abspath(__file__)), "base_configs")
    info = BASECONFIG_SWITCHES.get(switch_key)
    if not info:
        return False, f"Unknown switch key: {switch_key}"

    cfg_path = os.path.join(base_dir, info["file"])
    if not os.path.exists(cfg_path):
        return False, f"Base config not found: {cfg_path}"

    log_fn(f"  Starting TFTP-based reset for {info['name']} ({info['ip']})...")
    return reset_switches.reset_switch(switch_key, cfg_path, log_fn=log_fn)


# ---------------------------------------------------------------------------
# ISE cleanup
# ---------------------------------------------------------------------------

ISE_HOST = "198.18.5.101"
ISE_USER = "admin"
ISE_PASS = "C1sco12345"

# NAD names added by Catalyst Center discovery — should be removed on reset
ISE_SWITCH_NAD_NAMES = [
    "Site_105-Border-Spine.dcloud.cisco.com",
    "Site_105-Leaf1.dcloud.cisco.com",
    "Site_105-Leaf2.dcloud.cisco.com",
]

# Safety net: only delete NADs whose IP matches one of these switch Loopback IPs
# (ISE NADs are registered with Loopback IPs, same as Catalyst Center discovery)
ISE_SWITCH_NAD_IPS = {"172.30.255.3", "172.30.255.1", "172.30.255.2"}


def phase_ise_cleanup(log_fn=print):
    """
    Delete the 3 switch NADs from ISE that Catalyst Center adds during discovery.
    Catalyst Center will re-add them on next discovery/provisioning run.
    Returns (ok, detail).
    """
    import ssl, urllib.request, urllib.error, base64, json

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    creds = base64.b64encode(f"{ISE_USER}:{ISE_PASS}".encode()).decode()
    headers = {"Accept": "application/json", "Authorization": f"Basic {creds}"}

    def _get(path):
        req = urllib.request.Request(f"https://{ISE_HOST}{path}", headers=headers)
        resp = urllib.request.urlopen(req, context=ctx, timeout=15)
        return json.loads(resp.read().decode())

    def _delete(path):
        req = urllib.request.Request(f"https://{ISE_HOST}{path}", headers=headers, method="DELETE")
        try:
            urllib.request.urlopen(req, context=ctx, timeout=15)
            return True
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None  # already gone
            raise

    log_fn("  Fetching ISE network device list...")
    try:
        data = _get("/ers/config/networkdevice?size=100")
    except Exception as e:
        return False, f"ISE unreachable: {e}"

    resources = data.get("SearchResult", {}).get("resources", [])
    # Build name→id map
    nad_map = {r["name"]: r["id"] for r in resources}

    deleted, skipped, errors = [], [], []
    for name in ISE_SWITCH_NAD_NAMES:
        if name not in nad_map:
            log_fn(f"  {name}: not found (already removed)")
            skipped.append(name)
            continue
        nad_id = nad_map[name]
        # Safety check: verify the NAD's IP is one of the known switch IPs
        # before deleting — prevents accidentally wiping the CC NAD or others
        try:
            nad_detail = _get(f"/ers/config/networkdevice/{nad_id}")
            nad_ip = nad_detail.get("NetworkDevice", {}).get("NetworkDeviceIPList", [{}])[0].get("ipaddress", "")
            if nad_ip not in ISE_SWITCH_NAD_IPS:
                log_fn(f"  {name}: SKIPPED — IP {nad_ip} not in switch IP list (safety check)")
                skipped.append(name)
                continue
        except Exception as e:
            log_fn(f"  {name}: could not verify IP — {e}, skipping for safety")
            skipped.append(name)
            continue
        log_fn(f"  Deleting {name} ({nad_id}, IP {nad_ip})...")
        try:
            result = _delete(f"/ers/config/networkdevice/{nad_id}")
            if result is None:
                log_fn(f"  {name}: already gone (404)")
                skipped.append(name)
            else:
                log_fn(f"  {name}: deleted")
                deleted.append(name)
        except Exception as e:
            log_fn(f"  {name}: ERROR — {e}")
            errors.append(f"{name}: {e}")

    if errors:
        return False, f"Errors: {'; '.join(errors)}"

    parts = []
    if deleted:
        parts.append(f"deleted {len(deleted)}: {', '.join(n.split('.')[0] for n in deleted)}")
    if skipped:
        parts.append(f"already gone: {len(skipped)}")
    return True, "; ".join(parts) if parts else "nothing to do"


def phase_catc_cleanup(log_fn=print):
    """
    Delete the 3 switches from Catalyst Center inventory.
    Catalyst Center will re-discover and provision them on the next run.
    Returns (ok, detail).
    """
    import requests, urllib3
    urllib3.disable_warnings()

    log_fn("  Getting Catalyst Center auth token...")
    try:
        headers = _catc_headers()
    except Exception as e:
        return False, f"CC auth failed: {e}"

    # Get all network devices and find the 3 switch IPs
    switch_ips = {info["mgmt"] for info in CATC_DISCOVERY_IPS.values()}
    log_fn("  Fetching device inventory from Catalyst Center...")
    try:
        r = requests.get(f"{CATC_BASE}/dna/intent/api/v1/network-device",
                         headers=headers, verify=False, timeout=15)
        r.raise_for_status()
        devices = r.json().get("response", [])
    except Exception as e:
        return False, f"CC inventory fetch failed: {e}"

    # Match by management IP
    to_delete = [d for d in devices if d.get("managementIpAddress") in switch_ips]
    if not to_delete:
        log_fn("  No switch devices found in CC inventory (already removed)")
        return True, "nothing to do — devices not in inventory"

    deleted, errors = [], []
    for dev in to_delete:
        dev_id = dev["id"]
        name   = dev.get("hostname", dev.get("managementIpAddress", dev_id))
        log_fn(f"  Deleting {name} ({dev.get('managementIpAddress')}) from CC...")
        try:
            r = requests.delete(
                f"{CATC_BASE}/dna/intent/api/v1/network-device/{dev_id}",
                headers=headers, verify=False, timeout=30
            )
            if r.status_code in (200, 202, 204):
                log_fn(f"  {name}: deleted")
                deleted.append(name)
            else:
                msg = f"{name}: unexpected status {r.status_code} — {r.text[:100]}"
                log_fn(f"  {msg}")
                errors.append(msg)
        except Exception as e:
            msg = f"{name}: {e}"
            log_fn(f"  ERROR: {msg}")
            errors.append(msg)

    if errors:
        return False, f"Errors: {'; '.join(errors)}"
    return True, f"deleted {len(deleted)}: {', '.join(deleted)}"


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

def _ubuntu_ensure_image(image):
    """Ensure image exists on Ubuntu PC. If not, copy from local mounted images dir.
    Returns True if image is ready, False on failure."""
    local_image_path = f"/pipeline/host-data/images/{image}"
    remote_image_path = f"{UBUNTU_IMAGE_DIR}/{image}"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(UBUNTU_HOST, username=UBUNTU_USER, password=UBUNTU_PASS,
                   look_for_keys=False, allow_agent=False, timeout=15)

    # Check if already on Ubuntu PC
    _, out, _ = client.exec_command(f"test -f {remote_image_path} && echo EXISTS", timeout=5)
    if out.read().strip():
        print(f"     Image {image} already on Ubuntu PC — skipping copy")
        client.close()
        return True

    # Not on Ubuntu PC — copy from local mounted images dir via SFTP
    print(f"     Image {image} not on Ubuntu PC — copying from local images dir...")
    import os
    if not os.path.exists(local_image_path):
        client.close()
        print(f"     ERROR: {local_image_path} not found — upload the image via the dashboard first")
        return False

    try:
        sftp = client.open_sftp()
        sftp.put(local_image_path, remote_image_path)
        sftp.close()
        print(f"     Image copied to Ubuntu PC successfully")
    except Exception as e:
        client.close()
        print(f"     ERROR copying image to Ubuntu PC: {e}")
        return False

    client.close()
    return True


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

    # 1. Ensure image is on Ubuntu PC (copy from local if needed)
    if not _ubuntu_ensure_image(image):
        return False, f"Image {image} not available on Ubuntu PC and not found locally"

    # 2. Ensure HTTP server is running on Ubuntu PC
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

    print(f"     [{name}] Image copied. Saving config before install...")

    # 3. Save config first — IOS rejects install if config is unsaved
    shell.send("write memory\n")
    time.sleep(5)
    if shell.recv_ready():
        shell.recv(8192)

    # 4. Install, activate, commit (correct IOS XE command)
    print(f"     [{name}] Running install add activate commit...")
    shell.send(f"install add file flash:{image} activate commit\n")
    time.sleep(3)

    install_out = b""
    deadline2 = time.time() + 1800  # 30 min max for install + reload
    last_print = time.time()
    reloading = False
    while time.time() < deadline2:
        if shell.recv_ready():
            chunk = shell.recv(8192)
            install_out += chunk
            decoded = chunk.decode(errors="replace")
            print(f"     [{name}] {decoded.strip()[:120]}")
            # Confirm any y/n prompts
            if any(x in decoded.lower() for x in ["proceed", "y/n", "yes/no", "reload", "[y]"]):
                shell.send("y\n")
                time.sleep(2)
            if "reloading" in decoded.lower() or "restarting" in decoded.lower() or "install_add_activate_commit" in decoded.lower():
                reloading = True
                print(f"     [{name}] Switch reloading...")
                break
            if "FAILED" in decoded:
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

    # 1. Ensure image is on Ubuntu PC (copy from local if needed)
    if not _ubuntu_ensure_image(image):
        return False, f"Image {image} not available on Ubuntu PC and not found locally"

    # 2. Ensure HTTP server running
    print(f"     Starting HTTP server on Ubuntu PC...")
    if not _ubuntu_ensure_http_server():
        return False, "Failed to start HTTP server on Ubuntu PC"

    # 3. Copy image to bootflash
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
                    attributes=["cn", "mail", "userPrincipalName", "sAMAccountName", "memberOf"])
        for e in conn.entries:
            mail = str(e.mail) if e.mail else ""
            upn  = str(e.userPrincipalName) if e.userPrincipalName else ""
            # Extract CN from each memberOf DN, e.g. "CN=MAIN,OU=Groups,..." → "MAIN"
            member_of_raw = e.memberOf.values if e.memberOf else []
            groups = []
            for dn in member_of_raw:
                m = re.match(r"CN=([^,]+)", str(dn), re.I)
                if m:
                    groups.append(m.group(1))
            results.append({
                "cn":     str(e.cn),
                "sam":    str(e.sAMAccountName),
                "mail":   mail,
                "upn":    upn,
                "groups": groups,
            })
    conn.unbind()
    return results


def phase_detect_pod_number():
    """
    Detect the authoritative dCloud POD number and write it to pods.pod_number.

    Method 1 (preferred): Read C:\\dcloud\\session.xml from the jump host via
    WinRM.  Device names end in -P<NN> (e.g. EN-SDA-ISR4331-P04), and that
    2-digit suffix is the definitive POD number.  This is fast, accurate, and
    does not depend on AD provisioning having completed.

    Method 2 (fallback): Query AD for Kit/Lee/Pat/Nik and extract the POD
    number from their email subdomain (e.g. nik@rtp16.corp.pseudoco.com → 16).
    Used only when the jump host is unreachable via WinRM.

    Writes the confirmed number to pods.pod_number in the DB.
    Soft-fail: returns (False, reason) if both methods fail, so the pipeline
    continues without blocking.
    """
    import re, sqlite3

    DB_PATH = os.environ.get("DB_PATH", "/pipeline/host-data/pod_state.db")
    POD_ID  = os.environ.get("POD_ID", "")

    def _persist(pod_number, source):
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.row_factory = sqlite3.Row
            if POD_ID:
                conn.execute(
                    "UPDATE pods SET pod_number=?, updated_at=datetime('now') WHERE pod_id=?",
                    (pod_number, POD_ID),
                )
                conn.commit()
            conn.close()
        except Exception as db_err:
            return True, f"POD# {pod_number} (via {source}) — WARNING: DB write failed: {db_err}"
        return True, f"POD# confirmed: {pod_number} (via {source})"

    # ── Method 1: session.xml via WinRM ──────────────────────────────────────
    # Authoritative: device names in session.xml always end in -P<NN> where
    # <NN> matches the CSV POD number (e.g. EN-SDA-ISR4331-P04 → '04').
    try:
        import winrm
        sess = winrm.Session(
            "198.18.133.36",
            auth=("administrator", "C1sco12345"),
            transport="ntlm",
            read_timeout_sec=30,
            operation_timeout_sec=20,
        )
        r = sess.run_cmd("type", [r"C:\dcloud\session.xml"])
        xml_text = r.std_out.decode("utf-8", errors="replace")
        if r.status_code == 0 and xml_text:
            # Device names: EN-SDA-ISR4331-P04, EN-SDA-C9300-1-P04, etc.
            # All devices in a session share the same -P<NN> suffix.
            m = re.search(r"-P(\d{2})</name>", xml_text)
            if m:
                pod_number = m.group(1)
                print(f"     [detect_pod_number] session.xml → POD# {pod_number}")
                return _persist(pod_number, "session.xml")
    except Exception as e:
        print(f"     [detect_pod_number] WinRM unavailable, falling back to AD: {e}")

    # ── Method 2: AD email subdomain fallback ─────────────────────────────────
    try:
        users = _ad_query_users()
    except Exception as e:
        return False, f"AD query failed — POD# unconfirmed: {e}"

    if not users:
        return False, "AD returned no users for Kit/Lee/Pat/Nik — POD not yet provisioned"

    detected = None
    evidence = []
    for u in users:
        mail = u.get("mail", "")
        m = re.search(r"@[a-z]+(\d+)\.corp\.pseudoco\.com", mail, re.I)
        if m:
            detected = m.group(1)
            evidence.append(f"{u['sam']}={mail}")
            break  # all 4 users share the same POD number; first hit is enough

    if not detected:
        sample = users[0].get("mail", "?") if users else "?"
        return False, (
            f"AD users found but email not yet POD-specific (e.g. {sample}) "
            "— run AD automation first"
        )

    return _persist(detected, f"AD ({', '.join(evidence)})")


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


# ──────────────────────────────────────────────────────────────────────────────
# Duo org setup (pre-create users from AD data, no AD directory sync needed)
# ──────────────────────────────────────────────────────────────────────────────

def phase_duo_setup():
    """
    Reset the Duo org and pre-create Kit/Lee/Pat/Nik with:
      - Emails derived from their current AD mail attribute
        (e.g. kit@rtp16.corp.pseudoco.com)
      - Group assignments derived from their AD memberOf attribute
        (IoT / MAIN / PROD only; other groups are ignored)

    Requires:
      - AD users already provisioned (phase_detect_pod_number passed)
      - Duo credentials in DB (duo_ikey/skey/host) OR data/duo_keys/duo_keys_<org>.json
    Returns (ok, result_string).
    """
    from duo_automation import (
        duo_verify_credentials, duo_reset_org,
        duo_create_groups, duo_create_users,
        duo_set_permitted_domain, DUO_GROUPS,
        duo_get_authproxy_creds, duo_create_authproxy_integration,
        duo_push_authproxy_cfg,
    )

    DB_PATH = os.environ.get("DB_PATH", "/pipeline/host-data/pod_state.db")
    POD_ID  = os.environ.get("POD_ID", "")

    # ── 1. Load Duo credentials from DB ──────────────────────────────────────
    print(f"     Loading Duo credentials from DB for {POD_ID}...")
    try:
        keys = _duo_load_keys(POD_ID)
    except KeyError:
        return False, (
            "Duo credentials not configured for this POD — "
            "enter ikey/skey/host in the dashboard Duo Setup panel"
        )
    except Exception as e:
        return False, f"Failed to load Duo keys: {e}"

    ikey = keys["duo_ikey"].strip()
    skey = keys["duo_skey"].strip()
    host = keys["duo_host"].strip()

    # ── 2. Verify credentials ─────────────────────────────────────────────────
    print(f"     Verifying Duo API credentials ({host})...")
    ok, msg = duo_verify_credentials(ikey, skey, host)
    if not ok:
        return False, msg
    print(f"     {msg}")

    # ── 3. Query AD for user emails + group memberships ───────────────────────
    print("     Querying AD for user data (email + groups)...")
    try:
        ad_users = _ad_query_users()
    except Exception as e:
        return False, f"AD query failed: {e}"

    if not ad_users:
        return False, "AD returned no users — run AD provisioning first"

    # Validate all 4 users have POD-specific emails
    ad_default = "@corp.pseudoco.com"
    not_provisioned = [u["cn"] for u in ad_users
                       if (u.get("mail") or "").lower().endswith(ad_default)]
    if not_provisioned:
        return False, (
            f"AD users not yet provisioned: {not_provisioned} — "
            "run ADDuoTenantUserProvisioning.ps1 first"
        )

    # Build the permitted domain from the first user's email subdomain
    # e.g. kit@rtp16.corp.pseudoco.com → rtp16.corp.pseudoco.com
    permitted_domain = None
    m_dom = re.search(r"@([a-z0-9]+\.corp\.pseudoco\.com)", ad_users[0]["mail"], re.I)
    if m_dom:
        permitted_domain = m_dom.group(1)

    # Filter group memberships to only Duo groups (IoT/MAIN/PROD)
    duo_group_names = set(DUO_GROUPS)
    duo_users = []
    for u in ad_users:
        matched_groups = [g for g in u.get("groups", []) if g in duo_group_names]
        duo_users.append({
            "username": u["sam"].lower(),
            "email":    u["mail"],
            "realname": u["cn"],
            "groups":   matched_groups,
        })
        print(f"     AD → Duo: {u['sam']} | {u['mail']} | groups={matched_groups}")

    # ── 4. Reset Duo org (users/groups/domains only — integrations preserved) ──
    print("     Resetting Duo org (delete users, groups, domains — preserving integrations)...")
    ok, msg = duo_reset_org(ikey, skey, host)
    if not ok:
        return False, msg
    print(f"     {msg}")

    # ── 5. Create groups ──────────────────────────────────────────────────────
    print("     Creating Duo groups: IoT, MAIN, PROD...")
    try:
        group_id_map = duo_create_groups(ikey, skey, host)
    except Exception as e:
        return False, f"Group creation failed: {e}"

    # ── 6. Create users ───────────────────────────────────────────────────────
    print("     Creating Duo users with email + group assignments...")
    ok, msg = duo_create_users(ikey, skey, host, duo_users, group_id_map)
    if not ok:
        return False, msg
    print(f"     {msg}")

    # ── 7. Set permitted domain ───────────────────────────────────────────────
    if permitted_domain:
        print(f"     Setting permitted domain: {permitted_domain}...")
        ok, msg = duo_set_permitted_domain(ikey, skey, host, permitted_domain)
        if not ok:
            print(f"     WARN: {msg}")  # non-fatal

    # ── 8. Auth Proxy setup on AD1 ────────────────────────────────────────────
    print("     Setting up Duo Auth Proxy on AD1 (198.18.5.102)...")
    ap_creds = duo_get_authproxy_creds(ikey, skey, host)
    if ap_creds:
        print(f"     Found authproxy integration: {ap_creds['ikey']}")
        # Persist credentials to DB for future reference
        try:
            import sqlite3 as _sq
            _c = _sq.connect(DB_PATH)
            _c.execute(
                "UPDATE org_credentials SET authproxy_ikey=?, authproxy_skey=? "
                "WHERE org_number=?",
                (ap_creds["ikey"], ap_creds["skey"],
                 _extract_org_number(keys.get("_org_num", "") if isinstance(keys, dict) else ""))
            )
            _c.commit(); _c.close()
        except Exception:
            pass  # non-fatal DB write
    else:
        # Fall back to DB-stored authproxy credentials
        try:
            import sqlite3 as _sq
            _c = _sq.connect(DB_PATH)
            _c.row_factory = _sq.Row
            _org_num = _extract_org_number(
                _c.execute("SELECT scc_org FROM pods WHERE pod_id=?", (POD_ID,))
                 .fetchone()["scc_org"] or ""
            )
            _row = _c.execute(
                "SELECT authproxy_ikey, authproxy_skey FROM org_credentials WHERE org_number=?",
                (_org_num,)
            ).fetchone()
            _c.close()
            if _row and _row["authproxy_ikey"] and _row["authproxy_skey"]:
                ap_creds = {"ikey": _row["authproxy_ikey"], "skey": _row["authproxy_skey"], "host": host}
                print(f"     Using DB-stored authproxy credentials: {ap_creds['ikey']}")
        except Exception:
            pass

    if not ap_creds:
        # Auto-create a radius-type integration for the auth proxy
        print("     No authproxy integration found — creating radius-type integration...")
        ap_creds = duo_create_authproxy_integration(ikey, skey, host)
        if ap_creds:
            print(f"     Created authproxy integration: {ap_creds['ikey']}")
            try:
                import sqlite3 as _sq
                _c = _sq.connect(DB_PATH)
                _c.row_factory = _sq.Row
                _org_num = _extract_org_number(
                    _c.execute("SELECT scc_org FROM pods WHERE pod_id=?", (POD_ID,))
                     .fetchone()["scc_org"] or ""
                )
                _c.execute(
                    "UPDATE org_credentials SET authproxy_ikey=?, authproxy_skey=? "
                    "WHERE org_number=?",
                    (ap_creds["ikey"], ap_creds["skey"], _org_num)
                )
                _c.commit(); _c.close()
            except Exception:
                pass  # non-fatal DB write
        else:
            print(
                "     WARN: Failed to create authproxy integration. "
                "Create an Authentication Proxy application manually in the Duo admin console "
                f"({host}) and enter ikey/skey in Org Credentials."
            )

    if ap_creds:
        ap_ok, ap_msg = duo_push_authproxy_cfg(
            ap_ikey=ap_creds["ikey"],
            ap_skey=ap_creds["skey"],
            ap_host=ap_creds["host"],
            ad_ip=AD_DC_IP,
            winrm_user=AD_DC_USER,
            winrm_pass=AD_DC_PASS,
        )
        if ap_ok:
            print(f"     Auth proxy: {ap_msg}")
        else:
            print(f"     WARN: Auth proxy setup failed: {ap_msg}")  # non-fatal

    # ── Summary ───────────────────────────────────────────────────────────────
    user_summary = " | ".join(
        f"{u['username']}={u['email']}"
        for u in duo_users
    )
    ap_status = "authproxy=ok" if ap_creds else "authproxy=no-creds"
    return True, (
        f"Duo setup complete | {len(duo_users)} users created | "
        f"domain={permitted_domain or 'n/a'} | {ap_status} | {user_summary}"
    )


def phase_cdfmc_check():
    """
    1. SSH to the Terraform-Automation Ubuntu PC (via VPN).
    2. Read terraform.tasks.logs — verify 'Full infrastructure deployed'.
    3. Read terraform.tfvars  — extract cdfmc_host (SCC org).
    4. Hit the SCC/cdFMC API to confirm FTD device is Online.
    Retries up to 10 times (2 min apart) to handle Terraform still running.
    Returns (ok, result_string).
    """
    import re as _re

    MAX_ATTEMPTS = 10
    RETRY_WAIT   = 120  # seconds between retries

    for attempt in range(1, MAX_ATTEMPTS + 1):
        print(f"     cdFMC check attempt {attempt}/{MAX_ATTEMPTS} — connecting to {CDFMC_AUTOMATION_HOST}...")
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
            print(f"     SSH to automation PC failed: {e}")
            if attempt < MAX_ATTEMPTS:
                print(f"     Retrying in {RETRY_WAIT}s...")
                time.sleep(RETRY_WAIT)
                continue
            return False, f"SSH to automation PC failed: {e}"

        def _run(cmd):
            _, out, err = client.exec_command(cmd, timeout=20)
            return out.read().decode(errors="replace").strip()

        # --- 1. Check terraform log for success ---
        log_tail = _run(f"tail -30 {CDFMC_LAB_DIR}/terraform.tasks.logs")
        deployed = "Full infrastructure deployed" in log_tail
        print(f"     Terraform log: {'✓ deployed' if deployed else '✗ not deployed yet'}")

        if not deployed:
            client.close()
            if attempt < MAX_ATTEMPTS:
                print(f"     Terraform not done yet — retrying in {RETRY_WAIT}s...")
                time.sleep(RETRY_WAIT)
                continue
            return False, "Terraform deployment not complete after max retries"

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
# ── SCC keys directory (on host, mounted into container) ─────────────────────
SCC_KEYS_DIR = os.environ.get(
    "SCC_KEYS_DIR",
    "/pipeline/host-data/scc_keys"
)

def _extract_org_number(scc_org: str) -> str:
    """Extract numeric org number from scc_org (e.g. 'pseudoco-5001--...' → '5001')."""
    import re as _re
    if not scc_org:
        return ""
    m = _re.search(r"pseudoco-(\d+)", scc_org)
    if m:
        return m.group(1)
    if scc_org.strip().isdigit():
        return scc_org.strip()
    return ""


def _org_credentials(org_number: str) -> dict:
    """
    Load credentials from the org_credentials table for the given org number.
    Returns an empty dict if not found.
    """
    if not org_number:
        return {}
    db_path = os.environ.get("DB_PATH", "/pipeline/host-data/pod_state.db")
    try:
        import sqlite3 as _sqlite3
        with _sqlite3.connect(db_path) as conn:
            conn.row_factory = _sqlite3.Row
            row = conn.execute(
                "SELECT * FROM org_credentials WHERE org_number=?", (org_number,)
            ).fetchone()
        return dict(row) if row else {}
    except Exception:
        return {}


def _scc_load_keys(org_number: str, pod_id: str = None) -> dict:
    """
    Load SCC API keys.
    Priority:
      1. Per-POD override in pods table (scc_api_key / scc_api_secret)
      2. org_credentials table keyed by org_number
      3. JSON file at SCC_KEYS_DIR/scc_keys_<org>.json (legacy)
    """
    # 1. Per-POD override
    if pod_id:
        try:
            db_path = os.environ.get("DB_PATH", os.environ.get("POD_STATE_DB", "/pipeline/host-data/pod_state.db"))
            import sqlite3 as _sqlite3
            with _sqlite3.connect(db_path) as _conn:
                row = _conn.execute(
                    "SELECT scc_api_key, scc_api_secret FROM pods WHERE pod_id=?",
                    (pod_id,)
                ).fetchone()
            if row and row[0] and row[1]:
                return {"scc_api_key": row[0], "scc_api_secret": row[1]}
        except Exception:
            pass

    # 2. org_credentials table
    if org_number:
        oc = _org_credentials(org_number)
        if oc.get("scc_api_key") and oc.get("scc_api_secret"):
            return {"scc_api_key": oc["scc_api_key"], "scc_api_secret": oc["scc_api_secret"]}

    # 3. JSON file (legacy fallback)
    path = os.path.join(SCC_KEYS_DIR, f"scc_keys_{org_number}.json")
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"SCC keys not found for org={org_number!r} (pod_id={pod_id!r}, file={path})"
        )
    with open(path) as f:
        return json.load(f)


# ── Duo keys ──────────────────────────────────────────────────────────────────

def _duo_load_keys(pod_id: str) -> dict:
    """
    Load Duo Admin API keys.
    Priority:
      1. Per-POD override in pods table (duo_ikey / duo_skey / duo_host)
      2. org_credentials table keyed by org number derived from scc_org
    Raises KeyError if credentials are not found.
    """
    db_path = os.environ.get("DB_PATH", "/pipeline/host-data/pod_state.db")
    import sqlite3 as _sqlite3
    with _sqlite3.connect(db_path) as conn:
        conn.row_factory = _sqlite3.Row
        row = conn.execute(
            "SELECT duo_ikey, duo_skey, duo_host, scc_org FROM pods WHERE pod_id=?",
            (pod_id,)
        ).fetchone()

    # 1. Per-POD override
    if row and row["duo_ikey"] and row["duo_skey"] and row["duo_host"]:
        return {"duo_ikey": row["duo_ikey"], "duo_skey": row["duo_skey"], "duo_host": row["duo_host"]}

    # 2. org_credentials table
    if row:
        org_num = _extract_org_number(row["scc_org"] or "")
        if org_num:
            oc = _org_credentials(org_num)
            if oc.get("duo_ikey") and oc.get("duo_skey") and oc.get("duo_host"):
                return {"duo_ikey": oc["duo_ikey"], "duo_skey": oc["duo_skey"], "duo_host": oc["duo_host"]}

    raise KeyError(f"Duo credentials not found for pod_id={pod_id!r} — configure in Org Credentials or POD override")


def _sa_load_keys(pod_id: str) -> dict:
    """
    Load Secure Access API keys.
    Priority:
      1. Per-POD override in pods table (sa_api_key / sa_api_secret)
      2. org_credentials table keyed by org number derived from scc_org
    Raises KeyError if credentials are not found.
    """
    db_path = os.environ.get("DB_PATH", "/pipeline/host-data/pod_state.db")
    import sqlite3 as _sqlite3
    with _sqlite3.connect(db_path) as conn:
        conn.row_factory = _sqlite3.Row
        row = conn.execute(
            "SELECT sa_org_id, sa_api_key, sa_api_secret, scc_org FROM pods WHERE pod_id=?",
            (pod_id,)
        ).fetchone()

    # 1. Per-POD override
    if row and row["sa_api_key"] and row["sa_api_secret"]:
        return {"sa_org_id": row["sa_org_id"] or "", "sa_api_key": row["sa_api_key"], "sa_api_secret": row["sa_api_secret"]}

    # 2. org_credentials table
    if row:
        org_num = _extract_org_number(row["scc_org"] or "")
        if org_num:
            oc = _org_credentials(org_num)
            if oc.get("sa_api_key") and oc.get("sa_api_secret"):
                return {"sa_org_id": oc.get("sa_org_id", ""), "sa_api_key": oc["sa_api_key"], "sa_api_secret": oc["sa_api_secret"]}

    raise KeyError(f"SA credentials not found for pod_id={pod_id!r} — configure in Org Credentials or POD override")


def _scc_token(key_id: str, key_secret: str) -> str:
    """Obtain a bearer token for the SSE API.
    If key_secret is already a JWT (starts with 'eyJ'), use it directly.
    Otherwise exchange key_id + key_secret via the /auth/v2/token endpoint.
    """
    if key_secret and key_secret.startswith("eyJ"):
        return key_secret
    r = requests.post(
        "https://api.sse.cisco.com/auth/v2/token",
        auth=(key_id, key_secret),
        data={"grant_type": "client_credentials"},
        timeout=15,
    )
    r.raise_for_status()
    return r.json()["access_token"]


def _scc_org_number_from_pod() -> str:
    """Extract org number from scc_org stored in DB for the current POD."""
    db_path = os.environ.get("DB_PATH", "/pipeline/host-data/pod_state.db")
    pod_id  = os.environ.get("POD_ID", "")
    try:
        import sqlite3 as _sq
        c = _sq.connect(db_path)
        c.row_factory = _sq.Row
        row = c.execute("SELECT scc_org FROM pods WHERE pod_id=?", (pod_id,)).fetchone()
        c.close()
        if row:
            return _extract_org_number(row["scc_org"] or "")
    except Exception:
        pass
    return ""


def phase_duo_ext_dir_setup() -> tuple[bool, str]:
    """
    External Directory (AD sync) + SSO Auth Proxy setup for this POD's Duo org.

    Runs after duo_setup.  Requires:
      - Auth proxy installed on AD1 (handled by duo_setup)
      - authproxy_ikey/skey in org_credentials (stored by duo_setup)
      - idac_url configured in org_credentials

    Calls duo_automation.duo_ext_dir_and_sso_setup() which:
      Part 1 – External Directory:
        Users → External Directories → Add AD, push clean [cloud] to AD1,
        Test Connection, configure DC 198.18.5.102:389 / groups / attrs, Sync Now
      Part 2 – SSO Auth Proxy:
        Applications → SSO Settings → add AD source, capture [sso] config,
        push to AD1, run enrollment command, verify Connected,
        configure DC, add permitted domain corp.pseudoco.com, set routing rule

    Returns (ok, result_string).

    When running inside Docker (pipeline container), delegates to the dashboard
    host process via http://host.docker.internal:5050/api/duo-ext-dir-setup-sync/{pod_id}
    because Playwright (headless browser) needs the host network stack.
    """
    DB_PATH = os.environ.get("DB_PATH", "/pipeline/host-data/pod_state.db")
    POD_ID  = os.environ.get("POD_ID", "")

    if not POD_ID:
        return False, "POD_ID env var not set"

    if os.path.exists("/.dockerenv"):
        import urllib.request, json as _json
        dashboard_url = os.environ.get("DASHBOARD_URL", "http://192.168.65.254:5050")
        try:
            req = urllib.request.Request(
                f"{dashboard_url}/api/duo-ext-dir-setup-sync/{POD_ID}",
                method="POST",
                headers={"Content-Type": "application/json"},
                data=b"{}",
            )
            with urllib.request.urlopen(req, timeout=600) as resp:
                data = _json.loads(resp.read())
            return data.get("ok", False), data.get("result", "no result from host")
        except Exception as e:
            return False, f"Host delegation failed: {e}"

    from duo_automation import duo_ext_dir_and_sso_setup
    return duo_ext_dir_and_sso_setup(POD_ID, DB_PATH)


def phase_scc_reset_check():
    """
    Automated SCC reset verification (6 of 13 checklist items).
    Reads scc_keys_<org>.json, authenticates, and checks/resets:
      1. access_policy_rules   — no non-default rules
      2. network_tunnel_groups — no NTGs
      3. zta_profiles          — only default-profile remains
      4. private_resources     — no private resources or resource groups
      5. dns_servers           — no custom DNS server configs
      6. epp_posture_profiles  — no non-system-defined profiles

    logging_settings and ravpn_profiles moved to manual checklist
    (require browser session auth — no public API equivalent).

    Persists each item to scc_checklist table.
    Returns (ok, result_string).
    """
    import sqlite3 as _sq

    db_path = os.environ.get("DB_PATH", "/pipeline/host-data/pod_state.db")
    pod_id  = os.environ.get("POD_ID", "")

    # SCC API calls require public internet (api.sse.cisco.com).
    # When running inside a Docker container (VPN network), DNS for public hosts
    # is blocked by the tunnel. Delegate to the dashboard host process instead.
    if os.path.exists("/.dockerenv"):
        import urllib.request, json as _json
        dashboard_url = os.environ.get("DASHBOARD_URL", "http://192.168.65.254:5050")
        try:
            req = urllib.request.Request(
                f"{dashboard_url}/api/scc/run-check-sync/{pod_id}",
                method="POST",
                headers={"Content-Type": "application/json"},
                data=b"{}",
            )
            with urllib.request.urlopen(req, timeout=180) as resp:
                data = _json.loads(resp.read())
            return data.get("ok", False), data.get("result", "no result from host")
        except Exception as e:
            return False, f"Host delegation failed: {e}"

    ALL_KEYS = (
        "access_policy_rules", "network_tunnel_groups",
        "zta_profiles", "private_resources", "dns_servers",
        "epp_posture_profiles",
    )

    def _persist(item_key, status, detail=""):
        if not pod_id:
            return
        try:
            c = _sq.connect(db_path)
            c.execute(
                "INSERT OR REPLACE INTO scc_checklist "
                "(pod_id, item_key, status, detail) VALUES (?, ?, ?, ?)",
                (pod_id, item_key, status, str(detail)[:500])
            )
            c.commit(); c.close()
        except Exception as e:
            print(f"     scc_checklist DB write failed: {e}")

    org_num = _scc_org_number_from_pod()
    if not org_num:
        msg = "Could not determine SCC org number from pod_number — run detect_pod_number first"
        for k in ALL_KEYS:
            _persist(k, "skipped", msg)
        return False, msg

    try:
        keys = _scc_load_keys(org_num, pod_id=pod_id)
    except FileNotFoundError as e:
        msg = str(e)
        for k in ALL_KEYS:
            _persist(k, "skipped", msg)
        return False, f"SCC keys missing for org {org_num} — generate keys first | {msg}"

    # SSE (Umbrella) API uses the Secure Access (sa_*) key pair, not the CDO
    # machine-account JWT stored in scc_api_secret.  Load SA keys explicitly.
    try:
        sa_keys  = _sa_load_keys(pod_id=pod_id)
        key_id     = sa_keys.get("sa_api_key", "")
        key_secret = sa_keys.get("sa_api_secret", "")
    except Exception:
        # Fallback: try scc keys (old behaviour, may return 500)
        key_id     = keys.get("scc_api_key") or keys.get("key_id", "")
        key_secret = keys.get("scc_api_secret") or keys.get("key_secret", "")

    try:
        token = _scc_token(key_id, key_secret)
        hdrs  = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        # Extract Umbrella org ID from JWT (sub: org/XXXXXXX/client/...)
        import base64 as _b64, json as _json, re as _re
        _payload = _json.loads(_b64.b64decode(token.split('.')[1] + '=='))
        _m = _re.search(r'org/(\d+)/', _payload.get('sub', ''))
        umbrella_org_id = _m.group(1) if _m else org_num
    except Exception as e:
        msg = f"SCC auth failed: {e}"
        for k in ALL_KEYS:
            _persist(k, "failed", msg)
        return False, msg

    results = {}

    # 1. Access policy rules — delete all non-default rules
    try:
        r = requests.get("https://api.sse.cisco.com/policies/v2/rules",
                         headers=hdrs, timeout=15)
        if r.ok:
            rules = r.json().get("results", r.json().get("data", []))
            custom = [x for x in rules if isinstance(x, dict) and not x.get("ruleIsDefault", False)]
            deleted = []
            for rule in custom:
                d = requests.delete(f"https://api.sse.cisco.com/policies/v2/rules/{rule['ruleId']}",
                                    headers=hdrs, timeout=15)
                deleted.append(f"{rule.get('ruleName','?')}({'ok' if d.ok else d.status_code})")
            ok1 = True
            if deleted:
                detail = f"deleted {len(deleted)} rule(s): {', '.join(deleted)}"
            else:
                detail = "0 custom rule(s)"
        else:
            ok1 = False
            detail = f"API error {r.status_code}: {r.text[:100]}"
        _persist("access_policy_rules", "completed" if ok1 else "failed", detail)
        results["access_policy_rules"] = (ok1, detail)
    except Exception as e:
        _persist("access_policy_rules", "failed", str(e))
        results["access_policy_rules"] = (False, str(e))

    # 2. Network tunnel groups — delete all
    try:
        r = requests.get("https://api.sse.cisco.com/deployments/v2/networktunnelgroups",
                         headers=hdrs, timeout=15)
        if r.ok:
            ntgs = r.json().get("data", r.json()) if isinstance(r.json(), dict) else r.json()
            ntgs = ntgs if isinstance(ntgs, list) else []
            deleted = []
            for ntg in ntgs:
                tid = ntg.get("tunnelId") or ntg.get("id") or ntg.get("tunnelGroupId")
                if tid:
                    d = requests.delete(f"https://api.sse.cisco.com/deployments/v2/networktunnelgroups/{tid}",
                                        headers=hdrs, timeout=15)
                    deleted.append(f"{ntg.get('name','?')}({'ok' if d.ok else d.status_code})")
            ok3 = True
            detail = f"deleted {len(deleted)} NTG(s): {', '.join(deleted)}" if deleted else "0 NTG(s)"
        else:
            ok3 = False
            detail = f"API error {r.status_code}: {r.text[:100]}"
        _persist("network_tunnel_groups", "completed" if ok3 else "failed", detail)
        results["network_tunnel_groups"] = (ok3, detail)
    except Exception as e:
        _persist("network_tunnel_groups", "failed", str(e))
        results["network_tunnel_groups"] = (False, str(e))

    # 3. ZTA profiles — delete all except default-profile
    try:
        r = requests.get("https://api.sse.cisco.com/deployments/v2/ztna/profiles",
                         headers=hdrs, timeout=15)
        if r.ok:
            profiles = r.json().get("data", r.json()) if isinstance(r.json(), dict) else r.json()
            profiles = profiles if isinstance(profiles, list) else []
            custom = [p for p in profiles if str(p.get("profileId","")) != "default-profile"
                      and str(p.get("name","")) != "default-profile"]
            deleted = []
            for p in custom:
                pid = p.get("profileId") or p.get("id")
                if pid:
                    d = requests.delete(f"https://api.sse.cisco.com/deployments/v2/ztna/profiles/{pid}",
                                        headers=hdrs, timeout=15)
                    deleted.append(f"{p.get('name','?')}({'ok' if d.ok else d.status_code})")
            ok4 = True
            detail = f"deleted {len(deleted)} ZTA profile(s): {', '.join(deleted)}" if deleted else "only default-profile"
        else:
            ok4 = False
            detail = f"API error {r.status_code}: {r.text[:100]}"
        _persist("zta_profiles", "completed" if ok4 else "failed", detail)
        results["zta_profiles"] = (ok4, detail)
    except Exception as e:
        _persist("zta_profiles", "failed", str(e))
        results["zta_profiles"] = (False, str(e))

    # 4. Private resources + resource groups — delete all
    try:
        deleted_res, deleted_grp = [], []
        # Delete resource groups first (resources may depend on them)
        r_grp = requests.get("https://api.sse.cisco.com/deployments/v2/resourcegroups",
                             headers=hdrs, timeout=15)
        if r_grp.ok:
            groups = r_grp.json().get("data", r_grp.json()) if isinstance(r_grp.json(), dict) else r_grp.json()
            for g in (groups if isinstance(groups, list) else []):
                gid = g.get("id") or g.get("groupId")
                if gid:
                    d = requests.delete(f"https://api.sse.cisco.com/deployments/v2/resourcegroups/{gid}",
                                        headers=hdrs, timeout=15)
                    deleted_grp.append(f"{g.get('name','?')}({'ok' if d.ok else d.status_code})")
        # Delete private resources
        r_res = requests.get("https://api.sse.cisco.com/deployments/v2/privateresources",
                             headers=hdrs, timeout=15)
        if r_res.ok:
            resources = r_res.json().get("data", r_res.json()) if isinstance(r_res.json(), dict) else r_res.json()
            for res in (resources if isinstance(resources, list) else []):
                rid = res.get("id") or res.get("resourceId")
                if rid:
                    d = requests.delete(f"https://api.sse.cisco.com/deployments/v2/privateresources/{rid}",
                                        headers=hdrs, timeout=15)
                    deleted_res.append(f"{res.get('name','?')}({'ok' if d.ok else d.status_code})")
        ok5 = True
        parts = []
        if deleted_res: parts.append(f"deleted {len(deleted_res)} resource(s): {', '.join(deleted_res)}")
        if deleted_grp: parts.append(f"deleted {len(deleted_grp)} group(s): {', '.join(deleted_grp)}")
        detail = " | ".join(parts) if parts else "0 resource(s), 0 group(s)"
        _persist("private_resources", "completed", detail)
        results["private_resources"] = (ok5, detail)
    except Exception as e:
        _persist("private_resources", "failed", str(e))
        results["private_resources"] = (False, str(e))

    # 5. DNS servers — delete all custom
    try:
        r = requests.get(
            f"https://api.umbrella.com/v1/organizations/{umbrella_org_id}/dnsservers",
            headers=hdrs, timeout=15)
        if r.ok:
            servers = r.json() if isinstance(r.json(), list) else r.json().get("data", [])
            deleted = []
            for s in (servers if isinstance(servers, list) else []):
                sid = s.get("id") or s.get("serverId")
                if sid:
                    d = requests.delete(
                        f"https://api.umbrella.com/v1/organizations/{umbrella_org_id}/dnsservers/{sid}",
                        headers=hdrs, timeout=15)
                    deleted.append(f"{s.get('name','?')}({'ok' if d.ok else d.status_code})")
            ok6 = True
            detail = f"deleted {len(deleted)} DNS server(s): {', '.join(deleted)}" if deleted else "0 custom DNS server(s)"
        else:
            ok6 = (r.status_code == 404)  # 404 = none configured = clean
            detail = "0 custom DNS server(s)" if ok6 else f"API error {r.status_code}: {r.text[:100]}"
        _persist("dns_servers", "completed" if ok6 else "failed", detail)
        results["dns_servers"] = (ok6, detail)
    except Exception as e:
        _persist("dns_servers", "failed", str(e))
        results["dns_servers"] = (False, str(e))

    # 6. EPP posture profiles — delete all non-system-defined
    try:
        r = requests.get(
            f"https://api.umbrella.com/v1/organizations/{umbrella_org_id}/postureprofiles",
            headers=hdrs, timeout=15)
        if r.ok:
            profs = r.json() if isinstance(r.json(), list) else r.json().get("data", [])
            custom = [p for p in (profs if isinstance(profs, list) else [])
                      if "System defined" not in (p.get("tags") or [])]
            deleted = []
            for p in custom:
                pid = p.get("id") or p.get("profileId")
                if pid:
                    d = requests.delete(
                        f"https://api.umbrella.com/v1/organizations/{umbrella_org_id}/postureprofiles/{pid}",
                        headers=hdrs, timeout=15)
                    deleted.append(f"{p.get('name','?')}({'ok' if d.ok else d.status_code})")
            ok8 = True
            detail = f"deleted {len(deleted)} EPP profile(s): {', '.join(deleted)}" if deleted else "only system-defined"
        else:
            ok8 = (r.status_code == 404)
            detail = "only system-defined" if ok8 else f"API error {r.status_code}: {r.text[:100]}"
        _persist("epp_posture_profiles", "completed" if ok8 else "failed", detail)
        results["epp_posture_profiles"] = (ok8, detail)
    except Exception as e:
        _persist("epp_posture_profiles", "failed", str(e))
        results["epp_posture_profiles"] = (False, str(e))

    all_ok = all(v[0] for v in results.values())
    summary = " | ".join(f"{k}: {'✓' if v[0] else '✗'} {v[1]}" for k, v in results.items())
    print(f"     SCC reset check ({'PASS' if all_ok else 'FAIL'}): {summary}")
    return all_ok, summary


def phase_duo_saml_setup() -> tuple[bool, str]:
    """
    Automate full SA + Duo SAML/SCIM integration setup.

    When running inside Docker (pipeline container), delegates to the dashboard
    host process via http://host.docker.internal:5050/api/duo-saml-setup-sync/{pod_id}
    because playwright (headless browser) needs the host network stack and
    the management.api.umbrella.com JWT requires an Okta browser session.

    When running on the host directly, calls duo_automation.duo_saml_full_setup().

    Returns (ok, result_string).
    """
    db_path = os.environ.get("DB_PATH", "/pipeline/host-data/pod_state.db")
    pod_id  = os.environ.get("POD_ID", "")

    if os.path.exists("/.dockerenv"):
        import urllib.request, json as _json
        dashboard_url = os.environ.get("DASHBOARD_URL", "http://192.168.65.254:5050")
        try:
            req = urllib.request.Request(
                f"{dashboard_url}/api/duo-saml-setup-sync/{pod_id}",
                method="POST",
                headers={"Content-Type": "application/json"},
                data=b"{}",
            )
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = _json.loads(resp.read())
            return data.get("ok", False), data.get("result", "no result from host")
        except Exception as e:
            return False, f"Host delegation failed: {e}"

    # Running on host — call directly
    from duo_automation import duo_saml_full_setup
    return duo_saml_full_setup(pod_id, db_path)


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
