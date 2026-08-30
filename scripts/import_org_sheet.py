#!/usr/bin/env python3
"""Import the XAR org inventory from XAR-Vs-SEC-Tasks-List.xlsx into org_credentials.

Two tabs feed one row per org, keyed on the trailing number of "PseudoCo-NNN":

  "SCC   SA Orgs"  -> SCC / Secure Access identity, API keys, cdFMC, status flags
  "Meraki Orgs"    -> Meraki org id and its activation flags

The pxGrid Cloud login is the XAR Gmail account: the "Gmail Account" column is the
sign-in address and "Gmail Sub-Account" is the pxGrid deployment name (the code uses
pxgrid_cloud_account as the deployment name, not as a second login).

Run --dry-run first; it prints every change without touching the database.

The spreadsheet is the source of truth. A non-empty cell overwrites what is already
stored, so divergences are reported rather than silently kept or silently lost. Blank
cells never overwrite — that would erase working values for orgs the sheet has not
caught up with.
"""
import argparse
import base64
import concurrent.futures as cf
import json
import os
import re
import sqlite3
import sys
from datetime import datetime, timezone

import openpyxl
import requests

SHEET = os.environ.get(
    "XAR_SHEET",
    os.path.expanduser(
        "~/Library/CloudStorage/OneDrive-Cisco/"
        "Cross-Architecture Integration Experience Lab - Documents/"
        "XAR-Vs-SEC-Tasks-List.xlsx"
    ),
)
DB = os.environ.get("POD_DB", "data/pod_state.db")

# The lab's shared Gmail password. Passed in rather than hardcoded so it never
# lands in the repo; see .env / --gmail-password.
GMAIL_PASSWORD_ENV = "XAR_GMAIL_PASSWORD"

# Columns the sheet fills that org_credentials does not already have.
NEW_COLUMNS = {
    "cdfmc_host":              "TEXT",
    "cdfmc_api_token":         "TEXT",
    "cdfmc_registered":        "TEXT",
    "sa_activated":            "TEXT",
    "zta_internet_activated":  "TEXT",
    "encryption_enabled":      "TEXT",
    "csadc_enabled":           "TEXT",
    "org_notes":               "TEXT",
    "meraki_org_id":           "TEXT",
    "meraki_sso_saml_user":    "TEXT",
    "meraki_sdwan_activation": "TEXT",
    "meraki_duo_activated":    "TEXT",
}

# sheet column index -> org_credentials column, per tab.
SCC_MAP = {
    1:  "scc_org_uuid",
    2:  "sa_org_id",
    3:  "sa_api_key",
    4:  "sa_api_secret",
    5:  "pxgrid_cloud_email",
    6:  "pxgrid_cloud_account",
    7:  "sa_activated",
    8:  "zta_internet_activated",
    9:  "encryption_enabled",
    10: "csadc_enabled",
    11: "cdfmc_registered",
    12: "cdfmc_host",
    13: "cdfmc_api_token",
    14: "org_notes",
}
MERAKI_MAP = {
    1: "meraki_org_id",
    2: "meraki_sso_saml_user",
    3: "meraki_sdwan_activation",
    4: "meraki_duo_activated",
}

# Secrets, so the diff prints a fingerprint instead of the value.
SECRET = {"sa_api_key", "sa_api_secret", "cdfmc_api_token", "pxgrid_cloud_password"}


def cell(v):
    """Excel gives ints for numeric ids; everything here is stored as text."""
    if v is None:
        return ""
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v).strip()


def org_number(name):
    """'PseudoCo-502' -> '502'. Returns None for footers and stray rows."""
    m = re.match(r"^PseudoCo-(\d+)$", (name or "").strip(), re.I)
    return m.group(1) if m else None


def redact(col, val):
    if col in SECRET and val:
        return f"<{len(val)} chars ending {val[-4:]}>"
    return val


def verify_org_ids(recs, log=print):
    """Ask Secure Access which org each API key actually belongs to.

    The sheet is maintained by hand and has been wrong: PseudoCo-507 listed
    8383149 while its own key authenticates against 8388847. A wrong sa_org_id
    points every SCC/SGT operation at another tenant, so trust the token over
    the cell. The org id is the middle field of the JWT's `sub` claim,
    "org/{orgId}/client/{keyId}".

    Mutates recs in place and returns (corrected, unverified).
    """
    def check(item):
        num, rec = item
        k, s = rec.get("sa_api_key", ""), rec.get("sa_api_secret", "")
        if not k or not s:
            return num, None, "no API key in sheet"
        b = base64.b64encode(f"{k}:{s}".encode()).decode()
        try:
            r = requests.post(
                "https://api.sse.cisco.com/auth/v2/token",
                headers={"Authorization": f"Basic {b}",
                         "Content-Type": "application/x-www-form-urlencoded"},
                data={"grant_type": "client_credentials"}, timeout=30)
            if r.status_code != 200:
                return num, None, f"HTTP {r.status_code} (key rotated or revoked?)"
            p = r.json()["access_token"].split(".")[1]
            p += "=" * (-len(p) % 4)
            sub = json.loads(base64.urlsafe_b64decode(p)).get("sub", "")
            return num, (sub.split("/")[1] if "/" in sub else None), None
        except Exception as e:              # network, JSON shape, malformed JWT
            return num, None, f"{type(e).__name__}: {e}"

    corrected, unverified = [], []
    with cf.ThreadPoolExecutor(max_workers=8) as ex:
        for num, api_org, err in ex.map(check, sorted(recs.items(), key=lambda x: int(x[0]))):
            if err:
                unverified.append((num, err))
                continue
            sheet_org = recs[num].get("sa_org_id", "")
            if api_org and sheet_org and api_org != sheet_org:
                corrected.append((num, sheet_org, api_org))
                recs[num]["sa_org_id"] = api_org
    log(f"org id check: {len(recs) - len(unverified) - len(corrected)} confirmed, "
        f"{len(corrected)} corrected, {len(unverified)} unverified")
    for num, sheet_org, api_org in corrected:
        log(f"  ! org {num}: sheet says {sheet_org}, API says {api_org} "
            f"— using {api_org}; FIX THE SPREADSHEET")
    for num, err in unverified:
        log(f"  ? org {num}: {err} — sheet value used as-is")
    return corrected, unverified


def read_tab(wb, tab, colmap):
    """{org_number: {db_column: value}} for the non-empty cells of one tab."""
    out = {}
    for row in wb[tab].iter_rows(min_row=2, values_only=True):
        num = org_number(cell(row[0]) if row else "")
        if not num:
            continue
        rec = {}
        for idx, col in colmap.items():
            if idx < len(row):
                v = cell(row[idx])
                if v:
                    rec[col] = v
        out[num] = rec
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true", help="print changes, write nothing")
    ap.add_argument("--db", default=DB)
    ap.add_argument("--sheet", default=SHEET)
    ap.add_argument("--gmail-password", default=os.environ.get(GMAIL_PASSWORD_ENV, ""),
                    help=f"XAR Gmail password (or set ${GMAIL_PASSWORD_ENV})")
    ap.add_argument("--no-verify", action="store_true",
                    help="skip the Secure Access org-id check (offline use)")
    args = ap.parse_args()

    if not os.path.exists(args.sheet):
        sys.exit(f"spreadsheet not found: {args.sheet}")

    wb = openpyxl.load_workbook(args.sheet, data_only=True, read_only=True)
    scc = read_tab(wb, "SCC   SA Orgs", SCC_MAP)
    mer = read_tab(wb, "Meraki Orgs", MERAKI_MAP)

    merged = {}
    for num in sorted(set(scc) | set(mer), key=int):
        rec = dict(scc.get(num, {}))
        rec.update(mer.get(num, {}))
        # Only orgs with a pxGrid login get the shared password; writing it to an
        # org with no Gmail account would imply a credential that does not exist.
        if args.gmail_password and rec.get("pxgrid_cloud_email"):
            rec["pxgrid_cloud_password"] = args.gmail_password
        merged[num] = rec

    print(f"sheet:  {args.sheet}")
    print(f"        modified {datetime.fromtimestamp(os.path.getmtime(args.sheet)):%Y-%m-%d %H:%M}")
    print(f"db:     {args.db}")
    print(f"orgs in sheet: {len(merged)}")
    if not args.gmail_password:
        print(f"NOTE: no password given (--gmail-password / ${GMAIL_PASSWORD_ENV}); "
              "pxgrid_cloud_password left untouched")
    print()

    if not args.no_verify:
        verify_org_ids(merged)
        print()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row
    have = {r[1] for r in conn.execute("PRAGMA table_info(org_credentials)")}

    adding = [(c, t) for c, t in NEW_COLUMNS.items() if c not in have]
    for col, typ in adding:
        print(f"  + column org_credentials.{col} {typ}")
        if not args.dry_run:
            conn.execute(f"ALTER TABLE org_credentials ADD COLUMN {col} {typ}")
    if adding:
        print()

    existing = {r["org_number"]: dict(r)
                for r in conn.execute("SELECT * FROM org_credentials")}

    n_new = n_upd = n_same = 0
    conflicts = []
    for num, rec in merged.items():
        cur = existing.get(num)
        if cur is None:
            n_new += 1
            print(f"NEW org {num}: {len(rec)} fields")
            if not args.dry_run:
                cols = ["org_number"] + list(rec)
                conn.execute(
                    f"INSERT INTO org_credentials ({','.join(cols)}) "
                    f"VALUES ({','.join('?' * len(cols))})",
                    [num] + list(rec.values()))
            continue

        changes = {c: v for c, v in rec.items() if (cur.get(c) or "").strip() != v}
        if not changes:
            n_same += 1
            continue
        n_upd += 1
        print(f"org {num}:")
        for c, v in sorted(changes.items()):
            old = (cur.get(c) or "").strip()
            if old:
                # Overwriting a value that was already set: worth a second look.
                conflicts.append((num, c, old, v))
                print(f"    ~ {c}: {redact(c, old)!r}  ->  {redact(c, v)!r}")
            else:
                print(f"    + {c}: {redact(c, v)!r}")
        if not args.dry_run:
            conn.execute(
                f"UPDATE org_credentials SET {','.join(f'{c}=?' for c in changes)},"
                f" updated_at=? WHERE org_number=?",
                list(changes.values()) + [datetime.now(timezone.utc)
                                          .strftime("%Y-%m-%d %H:%M:%S"), num])

    in_db_only = sorted(set(existing) - set(merged), key=lambda x: int(x) if x.isdigit() else 0)

    print(f"\n{'DRY RUN — ' if args.dry_run else ''}"
          f"{n_new} new, {n_upd} updated, {n_same} already correct")
    if in_db_only:
        print(f"in DB but not in sheet (left alone): {', '.join(in_db_only)}")
    if conflicts:
        print(f"\n{len(conflicts)} value(s) OVERWRITTEN that were already set:")
        for num, c, old, v in conflicts:
            print(f"  org {num}  {c}: {redact(c, old)} -> {redact(c, v)}")

    if not args.dry_run:
        conn.commit()
        print("\ncommitted")
    conn.close()


if __name__ == "__main__":
    main()
