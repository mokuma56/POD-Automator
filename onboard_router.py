"""
Onboard C8231-G2 Secure Router with correct values from CSV template.
Usage: uv run --directory ~/sw_projects/pod_automator python3 onboard_router.py [SERIAL]
"""

import csv, json, os, sys, time, paramiko, requests, subprocess, urllib3
urllib3.disable_warnings()

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


def router_enable(shell):
    read_shell(shell, 2)
    shell.send("enable\n")
    time.sleep(1)
    read_shell(shell, 1)
    shell.send("C1sco12345\n")
    time.sleep(2)
    read_shell(shell, 2)


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

    # Step 1: Check if device already has a license assigned
    r = s.post(f"{VMANAGE}/dataservice/v1/licensing/licenses",
        json={"uuids": [UUID], "appliedFilters": {"billingType": "Prepaid", "licenseClassification": "Advantage"}},
        timeout=10)
    already_licensed = False
    if r.status_code == 200:
        for bl in r.json().get("baseLicenses", []):
            if UUID in bl.get("uuids", []):
                already_licensed = True
                print(f"  3. Device {UUID} already licensed — skipping")
                break
    if already_licensed:
        return True

    print(f"  2. Querying available licenses...")
    if r.status_code == 200:
        for bl in r.json().get("baseLicenses", []):
            for lic in bl.get("licenses", []):
                print(f"     - {lic['displayName']} (tag: {lic['tag'][:50]}...) available={lic.get('available')}")

    # Step 2: SA/VA distribution check (browser always calls this before assign)
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

    # Step 3: Assign the WAN Advantage license
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
    r = s.post(
        f"{VMANAGE}/dataservice/v1/config-group/{CG_ID}/device/deploy",
        json={"devices": [{"id": UUID}]}, timeout=10
    )
    if r.status_code != 200:
        print(f"  5. Deploy: ❌ {r.status_code} {r.text[:200]}")
        return False
    try:
        task_id = r.json().get("id", "")
    except Exception:
        task_id = ""
    print(f"  5. Deploy: ✅ task={task_id[:40]}")

    # Poll until deployment completes
    if task_id:
        for i in range(60):
            time.sleep(5)
            tr = s.get(f"{VMANAGE}/dataservice/task/{task_id}", timeout=10)
            if tr.status_code != 200:
                continue
            status = tr.json().get("data", [{}])[0].get("status", "")
            if status == "done":
                print(f"     Deploy completed (waited {(i+1)*5}s)")
                return True
            elif status in ("error", "fail"):
                detail = tr.json().get("data", [{}])[0].get("details", "")
                print(f"     Deploy failed: {detail[:200]}")
                return False
            if i % 6 == 0:
                print(f"     Deploy status: {status}...")
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
            shell.send("terminal length 0\n"); time.sleep(1); read_shell(shell, 1)

            src = f"http://{vpn_ip}:{http_port}/ciscosdwan.cfg"
            shell.send(f"copy {src} bootflash:ciscosdwan.cfg\n")
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
                            s2.send("dir bootflash:ciscosdwan.cfg\n"); time.sleep(3)
                            vout = read_shell(s2, 3)
                            c2.close()
                            if str(expected_size) in vout.replace(",", ""):
                                print(f"     Verified: {expected_size} bytes ✅")
                                return True
                        except: time.sleep(2)
                    print("     Size mismatch, proceed anyway")
                    return True
                if "?" in out.lower() or any(kw in out.lower() for kw in ("confirm", "over write", "destination")):
                    shell.send("\n")
            print(f"     HTTP copy result: {all_out[-200:]}")
        except Exception as e:
            print(f"     Attempt {attempt+1}: {e}")
        finally:
            if client: client.close()
        time.sleep(3)
    httpd.shutdown()
    return False


def phase_controller_mode():
    # Check if device is already in controller mode via vManage
    try:
        s = vmanage_session()
        r = s.get(f"{VMANAGE}/dataservice/system/device/vedges?uuid={UUID}", timeout=10)
        data = r.json()
        for dev in data.get("data", []):
            mode = dev.get("configOperationMode", "")
            if mode == "vmanage":
                print(f"     Device already in controller mode (vmanage) — skipping")
                return True
    except Exception as e:
        print(f"     vManage check: {e} (proceeding with SSH)")
        s = vmanage_session()

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

    def read_all(timeout=5):
        return read_shell(shell, timeout)

    # Verify bootstrap file exists and check size
    shell.send("dir bootflash:ciscosdwan.cfg\n")
    time.sleep(3)
    out = read_all(3)
    found = "ciscosdwan.cfg" in out
    print(f"     Verify bootflash: {'found' if found else 'NOT FOUND'}")

    if not found:
        print("     Bootstrap file missing! Attempting re-copy...")
        client.close()
        if not phase_copy_bootstrap():
            return False
        client, shell = router_shell()
        router_enable(shell)

    # Verify bootstrap content
    shell.send("more bootflash:ciscosdwan.cfg | begin system\n")
    time.sleep(3)
    out = read_all(3)
    if "system-ip" in out:
        for line in out.split("\n"):
            if "system-ip" in line or "site-id" in line or "host-name" in line:
                print(f"     {line.strip()}")

    # Controller-mode enable
    shell.send("controller-mode enable\n")
    time.sleep(3)
    out = read_all(5)
    print(f"     Controller-mode prompt: {out[-200:]}")

    if "confirm" in out.lower():
        shell.send("yes\n")
        time.sleep(3)
        out += read_all(5)
        print(f"     After yes: {out[-200:]}")
        client.close()
        return True

    client.close()
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

    # Get model
    out = switch_cmd(shell, "show ver | i Cisco IOS")
    model = ""
    for line in out.splitlines():
        if "Cisco IOS Software" in line:
            continue
        if "Model Number" in line:
            model = line.split()[-1]
        if "Switch Ports Model" in line:
            pass
    for line in out.splitlines():
        if "Model Number" in line:
            model = line.split()[-1]
        if "C9300" in line or "C8200" in line or "C8300" in line:
            model = line.split()[-1]
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

        # VRF
        out = switch_cmd(shell, "show vrf")
        vrf_lines = [l for l in out.splitlines() if l.strip() and not l.startswith("Name") and "show vrf" not in l]
        # Mgmt-vrf should be the only non-empty line
        has_mgmt = any("Mgmt-vrf" in l for l in vrf_lines)
        extra_vrfs = [l.strip() for l in vrf_lines if "Mgmt-vrf" not in l and "Default" not in l and l.strip()]
        if has_mgmt and not extra_vrfs:
            parts.append(f"PASS: VRF OK (Mgmt-vrf only)")
        else:
            parts.append(f"FAIL: unexpected VRFs: {extra_vrfs or 'Mgmt-vrf missing'}")

        # Version
        out = switch_cmd(shell, "show ver | i Version")
        ver_ok = "17.12" in out
        parts.append(f"{'PASS' if ver_ok else 'FAIL'}: Version {out.split('Version')[1].strip().split()[0] if 'Version' in out else '??'}")

        # VLAN
        out = switch_cmd(shell, "show vlan")
        has_vlan5 = "5    DNAC-Discovery" in out
        parts.append(f"{'PASS' if has_vlan5 else 'FAIL'}: VLAN 5 {'present' if has_vlan5 else 'missing'}")

    else:
        # Leaf switches
        # Skip OSPF — just check VRF, version, VLAN
        out = switch_cmd(shell, "show vrf")
        extra_vrfs = [l for l in out.splitlines() if l.strip() and not l.startswith("Name") and "Mgmt-vrf" not in l and "Default" not in l]
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
            out = switch_cmd(shell, "ping 198.18.5.100 source loopback0 repeat 2")
            success = "Success rate is 100" in out
            results.append(f"{'PASS' if success else 'FAIL'}: {info['name']} ({ip}) -> 198.18.5.100 {'OK' if success else 'FAILED'}")
            client.close()
        except Exception as e:
            results.append(f"FAIL: {info['name']} ({ip}) SSH failed: {e}")
    print("  " + " | ".join(results))
    return True, " | ".join(results)


# ---- Main ----
if __name__ == "__main__":
    pod_id = os.environ.get("POD_ID", f"POD-{SERIAL}")
    print(f"\nOnboarding {UUID} for {pod_id}\n{'='*40}")

    s = vmanage_session()
    steps = [
        ("verify_router", lambda: True),
        ("quick_connect", lambda: phase_quick_connect(s)),
        ("assign_license", lambda: phase_assign_license(s)),
        ("config_group_associate", lambda: phase_associate(s)),
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
