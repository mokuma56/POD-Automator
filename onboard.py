#!/usr/bin/env python3
"""
SD-WAN Secure Router Onboarding Pipeline for Cisco One Experience Lab

Full pipeline: Onboard → License → Associate → Set Vars → Deploy → Bootstrap → Copy → Controller-Mode

Usage:
  uv run --directory ~/sw_projects/pod_automator python3 onboard.py [--serial SERIAL] [--phase N]

Environment:
  VMANAGE, VMANAGE_USER, VMANAGE_PASS  (defaults: 198.18.133.10, admin, C1sco12345)
  ROUTER_IP, ROUTER_USER, ROUTER_PASS  (defaults: 198.18.133.25, admin, C1sco12345)
  JUMP_HOST, JUMP_USER, JUMP_PASS      (defaults: 198.18.133.36, demouser, C1sco12345)
"""

import csv, json, os, sys, time, subprocess, paramiko, requests, urllib3
urllib3.disable_warnings()

# ── Config ──────────────────────────────────────────────────────────────────
VMANAGE_HOST = os.getenv("VMANAGE", "198.18.133.10")
VMANAGE_USER = os.getenv("VMANAGE_USER", "admin")
VMANAGE_PASS = os.getenv("VMANAGE_PASS", "C1sco12345")
ROUTER_IP = os.getenv("ROUTER_IP", "198.18.133.25")
ROUTER_USER = os.getenv("ROUTER_USER", "admin")
ROUTER_PASS = os.getenv("ROUTER_PASS", "C1sco12345")
JUMP_HOST = os.getenv("JUMP_HOST", "198.18.133.36")
JUMP_USER = os.getenv("JUMP_USER", "demouser")
JUMP_PASS = os.getenv("JUMP_PASS", "C1sco12345")

SERIAL = "FJC300412NA"
UUID = f"C8231-G2-{SERIAL}"
CG_ID = "ae290e0f-7bc4-40f7-9bfa-23b1e7b2a71a"
POD_DIR = os.path.expanduser("~/sw_projects/pod_automator")
CSV_PATH = os.path.join(POD_DIR, "PseudocoBranches_Config-Group-Template.csv")
BOOTSTRAP_PATH = os.path.join(POD_DIR, "data", "bootstrap", "ciscosdwan.cfg")

WAN_LICENSE_TAG = "regid.2024-11.com.cisco.C8K_MEDIUM_WAN_A,1.0_7c756381-d4d6-4b30-b27d-7601feb51248"
WAN_LICENSE_SA = "dCloud Cisco Internal Account"
WAN_LICENSE_VA = "dCloud-Pseudoco-Campus"

INT_FIELDS = {"site_id", "pseudo_commit_timer", "VPN102-BGP-REMOTE-AS", "VPN101-BGP-REMOTE-AS",
              "VPN10-BGP-REMOTE-AS", "VPN10-DIS-BGP-REMOTE-AS"}
BOOL_FIELDS = {"ipv6_strict_control"}
HEADER_MAP = {"System IP": "system_ip", "Host Name": "host_name", "Site Id": "site_id",
              "Dual Stack IPv6 Default": "ipv6_strict_control", "Rollback Timer (sec)": "pseudo_commit_timer"}

SWITCHES = [
    ("Border Spine", "198.18.128.24"),
    ("Leaf 1", "198.18.128.22"),
    ("Leaf 2", "198.18.128.23"),
]

# ── vManage session ─────────────────────────────────────────────────────────
s = requests.Session()
s.auth = (VMANAGE_USER, VMANAGE_PASS)
s.verify = False

def _xsrf():
    r = s.get(f"https://{VMANAGE_HOST}/dataservice/client/token", timeout=10)
    token = r.text.strip()
    s.headers.update({"X-XSRF-TOKEN": token, "Content-Type": "application/json"})
    s.cookies.set("XSRF-TOKEN", token)
    return token

def _get(path, timeout=15):
    return s.get(f"https://{VMANAGE_HOST}{path}", timeout=timeout)

def _post(path, data, timeout=15):
    _xsrf()
    return s.post(f"https://{VMANAGE_HOST}{path}", json=data, timeout=timeout)

def _put(path, data, timeout=15):
    _xsrf()
    return s.put(f"https://{VMANAGE_HOST}{path}", json=data, timeout=timeout)

# ── Read CSV template ───────────────────────────────────────────────────────
def _read_csv():
    with open(CSV_PATH) as f:
        reader = csv.DictReader(f)
        for row in reader:
            if SERIAL in row.get("Device ID", ""):
                return row
        f.seek(0); next(reader)
        return next(reader)

# ── Phases ──────────────────────────────────────────────────────────────────

def phase_onboard():
    """Quick Connect onboard — set system-ip, site-id, host-name."""
    print("[1/8] Onboard...")
    csv_row = _read_csv()
    payload = {
        "deviceList": [{
            "deviceId": UUID,
            "serialNumber": SERIAL,
            "systemIp": csv_row["System IP"],
            "siteId": csv_row["Site Id"],
            "hostName": csv_row["Host Name"],
            "board": True,
        }]
    }
    r = _post("/dataservice/template/config/quickConnect/submitDevices", payload)
    ok = r.status_code == 200
    print(f"  {'OK' if ok else 'FAIL'} {r.status_code}")
    if not ok: print(f"  {r.text[:200]}")
    return ok

def phase_license():
    """Assign WAN Advantage license."""
    print("[2/8] License...")

    r = _post("/dataservice/v1/licensing/sa-va-distribution", {
        "appliedFilters": {"billingType": "Prepaid", "licenseClassification": "Advantage"},
        "baseLicenses": [{
            "displayName": "WAN Advantage for C8000 Secure Router, Medium",
            "tag": WAN_LICENSE_TAG, "platformClass": "c8kg2be",
            "uuids": [UUID],
        }]
    })
    if r.status_code == 200:
        for bl in r.json().get("baseLicenses", []):
            for sm in bl.get("savaMap", []):
                print(f"  SA/VA: {sm['saName']} / {sm['vaName']} → avail={sm['available']}")

    r = _post("/dataservice/v1/licensing/assign-licenses", {
        "baseLicenses": [{
            "assignLicenses": [{
                "allocated": 1,
                "saName": WAN_LICENSE_SA,
                "vaName": WAN_LICENSE_VA,
                "billingType": "Prepaid",
                "displayName": "WAN Advantage for C8000 Secure Router, Medium",
                "tag": WAN_LICENSE_TAG,
            }],
            "uuids": [UUID],
        }],
        "tenantLicenses": [],
    })
    ok = r.status_code == 200
    print(f"  {'OK' if ok else 'FAIL'} {r.status_code}")
    if not ok: print(f"  {r.text[:200]}")
    return ok

def phase_associate():
    """Associate device to config group."""
    print("[3/8] Associate CG...")
    r = _post(f"/dataservice/v1/config-group/{CG_ID}/device/associate",
              {"devices": [{"id": UUID}]})
    ok = r.status_code == 200
    print(f"  {'OK' if ok else 'FAIL'} {r.status_code}")
    return ok

def phase_set_variables():
    """Set config group variables from CSV template."""
    print("[4/8] Set variables...")
    csv_row = _read_csv()
    r = _get(f"/dataservice/v1/config-group/{CG_ID}/device/variables")
    if r.status_code != 200:
        print(f"  FAIL {r.status_code}")
        return False
    variables = []
    for dev in r.json().get("devices", []):
        if dev.get("device-id") == UUID:
            for var in dev.get("variables", []):
                vn = var["name"]
                val = None
                for ck, cv in csv_row.items():
                    mn = HEADER_MAP.get(ck, ck)
                    if mn == vn and cv.strip():
                        rv = cv.strip()
                        if vn in INT_FIELDS:
                            try: val = int(rv)
                            except: val = rv
                        elif vn in BOOL_FIELDS: val = rv.upper() == "TRUE"
                        else: val = rv
                        break
                if val is not None:
                    variables.append({"name": vn, "value": val})
                elif "value" in var and var.get("value") is not None:
                    variables.append({"name": vn, "value": var["value"]})
            break
    r = _put(f"/dataservice/v1/config-group/{CG_ID}/device/variables",
             {"solution": "sdwan", "devices": [{"device-id": UUID, "variables": variables}]})
    ok = r.status_code == 200
    print(f"  {'OK' if ok else 'FAIL'} ({len(variables)} vars)")
    return ok

def phase_deploy():
    """Deploy config group to device."""
    print("[5/8] Deploy...")
    r = _post(f"/dataservice/v1/config-group/{CG_ID}/device/deploy",
              {"devices": [{"id": UUID}]})
    ok = r.status_code == 200
    print(f"  {'OK' if ok else 'FAIL'} {r.status_code}")
    if ok:
        task_id = r.json().get("id", "")
        if task_id:
            for i in range(36):
                time.sleep(5)
                tr = _get(f"/dataservice/task/{task_id}")
                if tr.status_code == 200:
                    st = tr.json().get("data", [{}])[0].get("status", "")
                    if i % 6 == 0: print(f"    status={st}")
                    if st == "done": print(f"    Completed ({(i+1)*5}s)"); break
                    if st in ("error", "fail"): print(f"    {tr.text[:200]}"); break
        else:
            time.sleep(10)
    return ok

def phase_bootstrap():
    """Generate bootstrap config."""
    print("[6/8] Generate bootstrap...")
    r = _get(f"/dataservice/system/device/bootstrap/device/{UUID}?configtype=cloudinit&inclDefRootCert=true",
             timeout=30)
    ok = r.status_code == 200
    if ok:
        raw = r.json().get("bootstrapConfig", r.text)
        os.makedirs(os.path.dirname(BOOTSTRAP_PATH), exist_ok=True)
        with open(BOOTSTRAP_PATH, "w") as f: f.write(raw)
        print(f"  OK ({len(raw)} bytes)")
    else:
        print(f"  FAIL {r.status_code}")
    return ok

def phase_tftp_copy():
    """SCP bootstrap to jump host, TFTP to router bootflash."""
    print("[7/8] Copy bootstrap to router...")
    local = BOOTSTRAP_PATH
    remote = f"C:\\\\TFTP-ROOT\\\\ciscosdwan.cfg"

    r = subprocess.run(["sshpass", "-p", JUMP_PASS, "scp", "-o", "StrictHostKeyChecking=no",
                        "-o", "ConnectTimeout=10", local, f"{JUMP_USER}@{JUMP_HOST}:{remote}"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        print(f"  SCP FAIL: {r.stderr[:100]}")
        return False
    print(f"  SCP OK")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ROUTER_IP, username=ROUTER_USER, password=ROUTER_PASS,
                       look_for_keys=False, allow_agent=False, timeout=15)
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(2)
        if shell.recv_ready(): shell.recv(65535)
        shell.send("enable\n"); time.sleep(1)
        if shell.recv_ready(): shell.recv(65535)
        shell.send(f"{ROUTER_PASS}\n"); time.sleep(2)
        if shell.recv_ready(): shell.recv(65535)

        src = f"tftp://{JUMP_HOST}/ciscosdwan.cfg"
        shell.send(f"copy {src} bootflash:ciscosdwan.cfg\n")

        text = ""
        for i in range(30):
            time.sleep(2)
            while shell.recv_ready():
                text += shell.recv(65535).decode(errors="replace")
            if "bytes copied" in text.lower():
                break
            if "?" in text or "over write" in text.lower() or "confirm" in text.lower():
                shell.send("\n")

        ok = "bytes copied" in text.lower()
        print(f"  {'OK' if ok else 'FAIL'}")
        if ok:
            for line in text.splitlines():
                if "bytes copied" in line:
                    print(f"    {line.strip()}")
        return ok
    except Exception as e:
        print(f"  TFTP FAIL: {e}")
        return False
    finally:
        client.close()

def phase_controller_mode():
    """Enable controller-mode on router."""
    print("[8/8] Controller-mode enable...")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(ROUTER_IP, username=ROUTER_USER, password=ROUTER_PASS,
                       look_for_keys=False, allow_agent=False, timeout=15)
        shell = client.invoke_shell(width=200, height=50)
        time.sleep(2)
        if shell.recv_ready(): shell.recv(65535)
        shell.send("enable\n"); time.sleep(1)
        if shell.recv_ready(): shell.recv(65535)
        shell.send(f"{ROUTER_PASS}\n"); time.sleep(2)
        if shell.recv_ready(): shell.recv(65535)

        shell.send("controller-mode enable\n"); time.sleep(5)
        out = b""
        while shell.recv_ready():
            out += shell.recv(65535); time.sleep(0.5)
        text = out.decode(errors="replace")
        if "confirm" in text.lower():
            shell.send("yes\n"); time.sleep(5)

        print(f"  Controller-mode enabled — router rebooting into SD-WAN mode")
        return True
    except Exception as e:
        print(f"  FAIL: {e}")
        return False
    finally:
        client.close()

def phase_verify_online(max_wait=600):
    """Poll until control connections are established."""
    print(f"\n  Waiting for router to come online (up to {max_wait}s)...")
    start = time.time()
    while time.time() - start < max_wait:
        elapsed = int(time.time() - start)
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ROUTER_IP, username=ROUTER_USER, password=ROUTER_PASS,
                           look_for_keys=False, allow_agent=False, timeout=10)
            shell = client.invoke_shell(width=200, height=50)
            time.sleep(3)
            if shell.recv_ready(): shell.recv(65535)
            shell.send("show sdwan control connections\n"); time.sleep(3)
            out = b""
            while shell.recv_ready():
                out += shell.recv(65535); time.sleep(0.5)
            text = out.decode(errors="replace")
            tunnels = text.lower().count("up")
            if tunnels >= 3:
                print(f"  Router online! {tunnels} control tunnels ({elapsed}s)")
                client.close()
                return True
            client.close()
            print(f"\r  {elapsed}s: {tunnels} tunnels", end="", flush=True)
        except:
            print(f"\r  {elapsed}s: waiting...", end="", flush=True)
        time.sleep(15)
    print(f"\n  Not online after {max_wait}s")
    return False

def check_switches():
    """Verify switch state and connectivity."""
    print("\n── Switch checks ──")
    for name, ip in SWITCHES:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(ip, username="netadmin", password="C1sco12345",
                           look_for_keys=False, allow_agent=False, timeout=15)
            shell = client.invoke_shell(width=200, height=50)
            time.sleep(2)
            if shell.recv_ready(): shell.recv(65535)
            shell.send("enable\n"); time.sleep(1)
            if shell.recv_ready(): shell.recv(65535)
            shell.send("C1sco12345\n"); time.sleep(2)
            if shell.recv_ready(): shell.recv(65535)

            shell.send("show ver | include Model Number\n"); time.sleep(3)
            out = b""
            while shell.recv_ready():
                out += shell.recv(65535); time.sleep(0.5)
            model = ""
            for l in out.decode(errors="replace").splitlines():
                if "Model Number" in l: model = l.split()[-1]

            shell.send("ping 198.18.5.100 source loopback0 repeat 2\n"); time.sleep(5)
            out = b""
            while shell.recv_ready():
                out += shell.recv(65535); time.sleep(0.5)
            ping = "✓" if "Success rate is 100" in out.decode(errors="replace") else "✗"

            client.close()
            print(f"  {name:15s} {model:15s} ping {ping}")
        except Exception as e:
            print(f"  {name:15s} SSH FAIL: {e}")

# ── Main ────────────────────────────────────────────────────────────────────
PHASES = [
    ("onboard",          phase_onboard),
    ("license",          phase_license),
    ("associate",        phase_associate),
    ("set_variables",    phase_set_variables),
    ("deploy",           phase_deploy),
    ("bootstrap",        phase_bootstrap),
    ("tftp_copy",        phase_tftp_copy),
    ("controller_mode",  phase_controller_mode),
]

def main():
    start_phase = 1
    if "--phase" in sys.argv:
        idx = sys.argv.index("--phase")
        start_phase = int(sys.argv[idx + 1])
    if "--serial" in sys.argv:
        idx = sys.argv.index("--serial")
        global SERIAL, UUID
        SERIAL = sys.argv[idx + 1]
        UUID = f"C8231-G2-{SERIAL}"

    print(f"{'='*50}")
    print(f"SD-WAN Onboarding Pipeline")
    print(f"  Router:    {ROUTER_IP} ({SERIAL})")
    print(f"  vManage:   {VMANAGE_HOST}")
    print(f"  Jump Host: {JUMP_HOST}")
    print(f"  Config:    {CG_ID}")
    print(f"{'='*50}\n")

    for i, (name, fn) in enumerate(PHASES, 1):
        if i < start_phase:
            continue
        t0 = time.time()
        ok = fn()
        elapsed = time.time() - t0
        status = "✅" if ok else "❌"
        print(f"  {status} ({elapsed:.0f}s)\n")
        if not ok:
            print(f"Pipeline paused at phase {name}")
            sys.exit(1)

    print(f"{'='*50}")
    print("Pipeline complete! Waiting for router to come online...")
    print(f"{'='*50}\n")

    if phase_verify_online():
        check_switches()
        print(f"\n{'='*50}")
        print("All done! Router online, switches verified.")
        print(f"{'='*50}")

if __name__ == "__main__":
    main()
