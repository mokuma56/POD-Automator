"""
Record HAR + live-print vManage API calls during manual onboarding.
User does the process in Chrome; every API call prints to terminal in real-time.
"""
import json
from playwright.sync_api import sync_playwright
from urllib.parse import urlparse, parse_qs

HAR_PATH = "/Users/maokuma/sw_projects/pod_automator/data/live.har"

api_seen = set()

def on_response(response):
    url = response.url
    if "/dataservice/" not in url:
        return
    method = response.request.method
    status = response.status
    path = url.split("/dataservice/")[1] if "/dataservice/" in url else url

    # Only show write ops + bootstrap + quickconnect + associate + licensing
    if not any(kw in path.lower() for kw in [
        "quickconnect", "submitdevices", "licensing", "license",
        "config-group", "associate", "bootstrap", "deploy", "variable",
    ]):
        return

    uid = f"{method} {path}"
    if uid in api_seen:
        return
    api_seen.add(uid)

    body = ""
    post_data = response.request.post_data
    if post_data:
        try:
            parsed = json.loads(post_data)
            body = json.dumps(parsed, indent=2)
        except:
            body = post_data[:200]

    print(f"\n{'='*60}")
    print(f"{method} {path}")
    print(f"Status: {status}")
    if body:
        print(f"Body:\n{body}")
    print(f"{'='*60}")


with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)
    context = browser.new_context(
        record_har_path=HAR_PATH,
        viewport={"width": 1400, "height": 900},
        ignore_https_errors=True,
    )
    page = context.new_page()
    page.on("response", on_response)

    page.goto("https://198.18.133.10", wait_until="networkidle")
    print(f"\nOpened vManage at https://198.18.133.10")
    print(f"HAR: {HAR_PATH}")
    print(f"\n{'='*60}")
    print(f"  LOG IN AND DO THE FULL ONBOARD PROCESS MANUALLY")
    print(f"  From scratch: Quick Connect → License → CG Associate")
    print(f"  → Variables → Deploy → Generate Bootstrap")
    print(f"  ")
    print(f"  CLOSE THE BROWSER when done → HAR saved + summary")
    print(f"{'='*60}\n")

    try:
        page.wait_for_event("close", timeout=0)
    except KeyboardInterrupt:
        pass
    except:
        pass

    context.close()
    browser.close()

    with open(HAR_PATH) as f:
        har = json.load(f)
    entries = har.get("log", {}).get("entries", [])
    print(f"\n\nTotal requests: {len(entries)}")
    print(f"Full HAR saved to {HAR_PATH}")
