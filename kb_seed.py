"""
KB seeder and ingestion helpers.

Usage:
  uv run python3 kb_seed.py seed       # seed from AGENTS.md + curated articles
  uv run python3 kb_seed.py articles   # seed curated articles only
  uv run python3 kb_seed.py ingest     # ingest a file passed as argv[2]
  uv run python3 kb_seed.py clear      # wipe all published+draft articles (careful)

Also importable:
  ingest_text(title, text, tags, category, db_path, chunk_size)
      -> splits text into chunks, adds each as a published KB article
  ingest_file(path, title, tags, category, db_path)
      -> reads a file and calls ingest_text
"""

import re
import sys
from pathlib import Path

import kb

AGENTS_MD = Path(__file__).parent.parent.parent / ".config" / "opencode" / "AGENTS.md"
# fallback if running from a different cwd
if not AGENTS_MD.exists():
    AGENTS_MD = Path.home() / ".config" / "opencode" / "AGENTS.md"

DB_PATH = kb.DB_PATH

# ---------------------------------------------------------------------------
# Chunking
# ---------------------------------------------------------------------------

def _chunk_text(text: str, chunk_size: int = 800, overlap: int = 100) -> list[str]:
    """
    Split text into overlapping chunks by paragraph boundaries.
    Tries to keep chunks under chunk_size characters.
    """
    paragraphs = re.split(r"\n{2,}", text.strip())
    chunks, current = [], ""
    for para in paragraphs:
        para = para.strip()
        if not para:
            continue
        if len(current) + len(para) + 2 <= chunk_size:
            current = (current + "\n\n" + para).strip()
        else:
            if current:
                chunks.append(current)
            # If a single paragraph is huge, hard-split it
            if len(para) > chunk_size:
                words = para.split()
                sub = ""
                for w in words:
                    if len(sub) + len(w) + 1 > chunk_size:
                        if sub:
                            chunks.append(sub.strip())
                        sub = w
                    else:
                        sub += " " + w
                current = sub.strip()
            else:
                current = para
    if current:
        chunks.append(current)
    # Add overlap: prepend last N chars of previous chunk
    if overlap > 0 and len(chunks) > 1:
        overlapped = [chunks[0]]
        for i in range(1, len(chunks)):
            tail = chunks[i - 1][-overlap:]
            overlapped.append(tail + "\n\n" + chunks[i])
        return overlapped
    return chunks


# ---------------------------------------------------------------------------
# Public ingest API
# ---------------------------------------------------------------------------

def ingest_text(title: str, text: str, tags: str = "", category: str = "documentation",
                db_path=None, chunk_size: int = 800, status: str = "published") -> list[int]:
    """
    Chunk text and add each chunk as a KB article.
    Returns list of inserted article IDs.
    """
    db_path = db_path or DB_PATH
    kb.ensure_kb_table(db_path)
    chunks = _chunk_text(text, chunk_size=chunk_size)
    ids = []
    for i, chunk in enumerate(chunks):
        chunk_title = title if len(chunks) == 1 else f"{title} (part {i+1}/{len(chunks)})"
        aid = kb.add_article(
            db_path=db_path,
            title=chunk_title,
            body=chunk,
            tags=tags,
            category=category,
            status=status,
        )
        ids.append(aid)
        print(f"  [{aid}] {chunk_title[:70]}")
    return ids


def ingest_file(path: str, title: str = "", tags: str = "", category: str = "documentation",
                db_path=None) -> list[int]:
    """Read a file and ingest it into the KB."""
    p = Path(path)
    if not p.exists():
        print(f"File not found: {path}")
        return []
    text = p.read_text(encoding="utf-8", errors="replace")
    title = title or p.stem.replace("-", " ").replace("_", " ").title()
    return ingest_text(title=title, text=text, tags=tags, category=category, db_path=db_path)


# ---------------------------------------------------------------------------
# AGENTS.md seeder
# ---------------------------------------------------------------------------

# Map AGENTS.md section headings → KB category + tags
_SECTION_MAP = {
    "License Assignment":        ("pipeline-failure", "license,vmanage,sdwan"),
    "Bootstrap":                 ("sdwan", "bootstrap,router"),
    "Config Register":           ("sdwan", "config-register,bootstrap,router,known-issue"),
    "TFTP Copy":                 ("sdwan", "tftp,bootstrap,copy"),
    "VPN":                       ("infrastructure", "vpn,openconnect"),
    "Onboard API":               ("sdwan", "vmanage,api,onboard"),
    "Full Pipeline":             ("sdwan", "pipeline,workflow"),
    "Run command":               ("sdwan", "cli,run"),
    "Multi-POD":                 ("infrastructure", "docker,multi-pod"),
    "Dashboard":                 ("dashboard", "dashboard,features"),
    "Upgrade Logic":             ("upgrade", "upgrade,switch,router"),
    "Known JS Pitfall":          ("dashboard", "javascript,bug"),
    "Generate Lab Details PDF":  ("dashboard", "pdf,lab-cards"),
    "Switch Recheck":            ("pipeline-failure", "switch,recheck"),
    "Base Config Corrections":   ("infrastructure", "switch,config,known-issue"),
    "Current State":             ("infrastructure", "status"),
    "Key Infrastructure":        ("infrastructure", "ips,credentials,infra"),
    "Relevant Files":            ("infrastructure", "files,codebase"),
}


def _default_meta(heading: str):
    for key, (cat, tags) in _SECTION_MAP.items():
        if key.lower() in heading.lower():
            return cat, tags
    return "general", "lab,cisco,sdwan"


def seed_from_agents_md(db_path=None, agents_md=None):
    """
    Parse AGENTS.md by ### headings and insert each section as a KB article.
    Skips sections already in the KB (matched by title prefix).
    """
    db_path = db_path or DB_PATH
    agents_md = Path(agents_md) if agents_md else AGENTS_MD
    if not agents_md.exists():
        print(f"AGENTS.md not found at {agents_md}")
        return

    kb.ensure_kb_table(db_path)
    existing_titles = {a["title"] for a in kb.list_articles(db_path, status=None, limit=1000)}

    text = agents_md.read_text(encoding="utf-8")
    # Only parse the pod_automator section
    match = re.search(r"<!-- pod_automator -->(.*?)<!-- /pod_automator -->", text, re.DOTALL)
    if match:
        text = match.group(1)

    # Split by ### headings
    sections = re.split(r"(?m)^### ", text)
    added = 0
    for section in sections:
        section = section.strip()
        if not section:
            continue
        lines = section.splitlines()
        heading = lines[0].strip()
        body = "\n".join(lines[1:]).strip()
        if not body:
            continue
        title = f"Lab KB: {heading}"
        if title in existing_titles:
            print(f"  skip (exists): {title[:70]}")
            continue
        category, tags = _default_meta(heading)
        aid = kb.add_article(
            db_path=db_path,
            title=title,
            body=f"### {heading}\n\n{body}",
            tags=tags,
            category=category,
            status="published",
        )
        print(f"  [{aid}] {title[:70]}")
        added += 1

    print(f"\nSeeded {added} articles from AGENTS.md")


# ---------------------------------------------------------------------------
# Curated articles
# ---------------------------------------------------------------------------

CURATED_ARTICLES = [
    {
        "title": "Verify SDA Fabric Operations Commands",
        "category": "sda-fabric",
        "tags": "sda,fabric,lisp,bgp,ise,dhcp,verify,troubleshooting",
        "body": """\
### Verify SDA Fabric Operations Commands

Use these commands to verify the health of an SDA fabric after deployment or troubleshooting.

---

## Control Plane (LISP)

Run on Leaf switches unless noted.

    show lisp instance-id 4100 ipv4 map-cache        ! Main VRF — entries resolving?
    show lisp instance-id 4099 ipv4 map-cache        ! PROD
    show lisp instance-id 4101 ipv4 map-cache        ! IOT
    show lisp site                                    ! Border Spine only — registered EIDs
    show lisp instance-id 4100 ipv4 database         ! Leaf — what endpoints are registered

Look for `complete` entries in the map-cache with a valid locator (172.30.255.3).
A `Negative cache` entry means the map-server has no registration for that prefix.
`show lisp site` on Border Spine should show EIDs registered from Leaf1 (172.30.255.1) and Leaf2 (172.30.255.2).

---

## BGP (Border Spine <-> Router)

Run on Border Spine.

    show bgp vpnv4 unicast all summary               ! all 3 VRF peers up? (192.168.255.0/.2/.4)
    show ip route vrf Main                           ! 198.18.5.0/24 present via 192.168.255.0?
    show ip route vrf PROD
    show ip route vrf IOT

Expected BGP neighbors: 192.168.255.0 (Main), 192.168.255.2 (PROD), 192.168.255.4 (IOT).
All should show a numeric prefix count in State/PfxRcd — not Idle or Active.
Each VRF table must contain 198.18.5.0/24 (DHCP server route) — if missing, relay traffic has no return path.

---

## Authentication / ISE (Leaf Switches)

Run on Leaf1 or Leaf2.

    show authentication sessions                     ! any active sessions?
    show authentication sessions interface Gi1/0/1   ! is the client authenticated?
    show authentication sessions interface Gi1/0/3
    show access-session                              ! SGT assigned?

Look for Status: Authorized and a valid VLAN/Domain. If Unauthorized, dot1x/MAB has not completed.
If show authentication sessions shows no sessions on Gi1/0/1 or Gi1/0/3, verify the port has
`source template DefaultWiredDot1xClosedAuth` applied — this was the root cause of DHCP failure in this lab.

---

## DHCP Relay

Run on Leaf switches.

    show ip helper-address                           ! no 'global', no source-interface
    show ip dhcp snooping statistics                 ! packets forwarded vs dropped

Correct relay config:
- Helper address: 198.18.5.102
- NO 'global' keyword — relay must stay in VRF (LISP resolves the path)
- NO 'ip dhcp relay source-interface Loopback0' — giaddr must be the SVI IP (e.g. 10.10.255.1)
  so the DHCP server reply can route back via OMP

---

## Fabric Edge (Leaf)

    show vlan brief                                  ! VLANs 10, 101, 102 active
    show ip interface brief | include Vlan           ! SVIs up/up
    ping vrf Main 198.18.5.102 repeat 3             ! relay path reachable?

All three SVIs (Vlan10, Vlan101, Vlan102) must be up/up with anycast IPs (10.10.255.1, 10.101.255.1, 10.102.255.1).

---

## Quick Health Check — Border Spine

    show ip bgp vpnv4 all summary | include 192.168.255
    show ip route vrf Main | include 198.18.5
    show lisp site summary

---

## Key Points

Two most telling commands:
- `show authentication sessions` on a leaf — confirms clients are hitting ISE and authorized into the correct VRF
- `show lisp site` on Border Spine — confirms endpoints are registered in the LISP control plane
""",
    },
]


def seed_curated_articles(db_path=None):
    """Insert curated hand-written KB articles (skips if title already exists)."""
    db_path = db_path or DB_PATH
    kb.ensure_kb_table(db_path)
    existing_titles = {a["title"] for a in kb.list_articles(db_path, status=None, limit=1000)}
    added = 0
    for art in CURATED_ARTICLES:
        if art["title"] in existing_titles:
            print(f"  skip (exists): {art['title'][:70]}")
            continue
        aid = kb.add_article(
            db_path=db_path,
            title=art["title"],
            body=art["body"],
            tags=art["tags"],
            category=art["category"],
            status="published",
        )
        print(f"  [{aid}] {art['title'][:70]}")
        added += 1
    print(f"Seeded {added} curated article(s)")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "seed"

    if cmd == "seed":
        print(f"Seeding KB from {AGENTS_MD} ...")
        seed_from_agents_md()
        print(f"\nSeeding curated articles ...")
        seed_curated_articles()

    elif cmd == "articles":
        print("Seeding curated articles ...")
        seed_curated_articles()

    elif cmd == "ingest":
        if len(sys.argv) < 3:
            print("Usage: kb_seed.py ingest <file> [title] [tags] [category]")
            sys.exit(1)
        fpath  = sys.argv[2]
        title  = sys.argv[3] if len(sys.argv) > 3 else ""
        tags   = sys.argv[4] if len(sys.argv) > 4 else ""
        cat    = sys.argv[5] if len(sys.argv) > 5 else "documentation"
        print(f"Ingesting {fpath} ...")
        ids = ingest_file(fpath, title=title, tags=tags, category=cat)
        print(f"Added {len(ids)} article(s): {ids}")

    elif cmd == "clear":
        confirm = input("Type YES to delete all KB articles: ")
        if confirm == "YES":
            with kb._conn(DB_PATH) as c:
                c.execute("DELETE FROM knowledge_base")
                c.commit()
            print("Cleared.")
        else:
            print("Aborted.")

    elif cmd == "status":
        kb.ensure_kb_table()
        arts = kb.list_articles(status=None)
        print(f"Knowledge base: {len(arts)} articles")
        for a in arts:
            print(f"  [{a['status']:9}] {a['id']:3}. {a['title'][:70]}")

    else:
        print(f"Unknown command: {cmd}")
        print("Commands: seed | ingest <file> | clear | status")
