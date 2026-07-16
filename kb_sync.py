from __future__ import annotations
"""
kb_sync.py - Shared Knowledge Base sync for POD Automator.

Pulls articles from the public POD-Automator-KB GitHub repo and imports
any new ones into the local SQLite knowledge base.  Existing articles
(matched by exact title) are never overwritten so local edits are safe.

Also handles pushing a published article back to the shared KB repo via
the GitHub Contents API - no git CLI required on the proctor's machine.
Images referenced in the article body (!/api/kb/image/...) are pushed to
the images/ folder in the KB repo and URLs are rewritten to raw.githubusercontent
so they render for all proctors who pull the article.

Usage (CLI):
  uv run python3 kb_sync.py pull          # pull + import new articles (default)
  uv run python3 kb_sync.py status        # show local vs remote article counts
  uv run python3 kb_sync.py push <id>     # push one article by local DB id
                                           # (requires GITHUB_KB_TOKEN env var
                                            #  or token stored in data/kb_token.txt)

Called automatically by update.sh on every Check-for-Updates run.
"""

import json
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

import kb as _kb

# ── Config ────────────────────────────────────────────────────────────────────
KB_REPO        = "mokuma56/POD-Automator-KB"
KB_REPO_URL    = f"https://github.com/{KB_REPO}.git"
KB_RAW_URL     = f"https://raw.githubusercontent.com/{KB_REPO}/main/articles.json"
KB_API_CONTENT = f"https://api.github.com/repos/{KB_REPO}/contents/articles.json"
KB_RAW_IMG_BASE = f"https://raw.githubusercontent.com/{KB_REPO}/main/images"

SCRIPT_DIR    = Path(__file__).parent
DB_PATH       = SCRIPT_DIR / "data" / "pod_state.db"
TOKEN_FILE    = SCRIPT_DIR / "data" / "kb_token.txt"
KB_IMAGES_DIR = SCRIPT_DIR / "data" / "kb_images"


# ── Token helpers ─────────────────────────────────────────────────────────────

def _load_token() -> str:
    """Return GitHub token from env var or token file. Empty string if not set."""
    t = os.environ.get("GITHUB_KB_TOKEN", "").strip()
    if t:
        return t
    if TOKEN_FILE.exists():
        t = TOKEN_FILE.read_text().strip()
        if t:
            return t
    return ""


def save_token(token: str):
    """Persist token to data/kb_token.txt (mode 600)."""
    TOKEN_FILE.write_text(token.strip())
    TOKEN_FILE.chmod(0o600)


# ── Pull ──────────────────────────────────────────────────────────────────────

def pull(db_path=None, verbose=True) -> dict:
    """
    Fetch articles.json from the shared KB repo and import any new articles.
    Returns {"imported": int, "skipped": int, "error": str|None}
    """
    db_path = db_path or DB_PATH
    _kb.ensure_kb_table(db_path)

    # Fetch remote articles.json
    try:
        req = urllib.request.Request(
            KB_RAW_URL,
            headers={"User-Agent": "POD-Automator-KB-Sync/1.0",
                     "Cache-Control": "no-cache"}
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            remote_articles = json.loads(resp.read().decode())
    except Exception as e:
        msg = f"Could not fetch KB articles from GitHub: {e}"
        if verbose: print(f"[kb-sync] ERROR: {msg}")
        return {"imported": 0, "skipped": 0, "error": msg}

    if not isinstance(remote_articles, list):
        msg = "articles.json is not a JSON array"
        if verbose: print(f"[kb-sync] ERROR: {msg}")
        return {"imported": 0, "skipped": 0, "error": msg}

    # Get existing articles (title -> id+body) for upsert logic
    existing = {
        a["title"]: a
        for a in _kb.list_articles(db_path, status=None, limit=10000)
    }

    imported = skipped = updated = 0
    for art in remote_articles:
        title = (art.get("title") or "").strip()
        body  = (art.get("body")  or "").strip()
        if not title or not body:
            skipped += 1
            continue
        if title in existing:
            local = existing[title]
            if (local.get("body") or "").strip() != body:
                _kb.update_article(
                    db_path=db_path,
                    article_id=local["id"],
                    body=body,
                    tags=art.get("tags", local.get("tags", "")),
                    category=art.get("category", local.get("category", "General")),
                    status="published",
                )
                if verbose: print(f"[kb-sync] updated: {title[:70]}")
                updated += 1
            else:
                skipped += 1
            continue
        _kb.add_article(
            db_path=db_path,
            title=title,
            body=body,
            tags=art.get("tags", ""),
            category=art.get("category", "General"),
            status="published",
        )
        if verbose: print(f"[kb-sync] imported: {title[:70]}")
        imported += 1

    if verbose:
        print(f"[kb-sync] done - {imported} imported, {updated} updated, {skipped} skipped")

    return {"imported": imported, "updated": updated, "skipped": skipped, "error": None}


# ── Image push helper ─────────────────────────────────────────────────────────

def _push_image_to_repo(filename: str, headers: dict) -> str | None:
    """
    Push a single image from data/kb_images/<filename> to images/<filename>
    in the KB repo.  Returns the raw.githubusercontent URL on success, or
    None if the file doesn't exist / upload fails.
    Silently skips if the image already exists at that path.
    """
    import base64
    local_path = KB_IMAGES_DIR / filename
    if not local_path.exists():
        return None

    image_bytes = local_path.read_bytes()
    content_b64 = base64.b64encode(image_bytes).decode()

    api_url = f"https://api.github.com/repos/{KB_REPO}/contents/images/{filename}"

    # Check if file already exists (get its SHA so we can update/skip)
    existing_sha = None
    try:
        req = urllib.request.Request(api_url, headers=headers)
        with urllib.request.urlopen(req, timeout=10) as resp:
            meta = json.loads(resp.read().decode())
            existing_sha = meta.get("sha")
    except urllib.error.HTTPError as e:
        if e.code != 404:
            return None  # unexpected error
    except Exception:
        return None

    payload_dict: dict = {
        "message": f"kb: add image {filename}",
        "content": content_b64,
    }
    if existing_sha:
        # File already in repo - skip re-upload, just return the URL
        return f"{KB_RAW_IMG_BASE}/{filename}"

    payload = json.dumps(payload_dict).encode()
    try:
        req = urllib.request.Request(
            api_url, data=payload,
            headers={**headers, "Content-Type": "application/json"},
            method="PUT"
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp.read()
        return f"{KB_RAW_IMG_BASE}/{filename}"
    except Exception:
        return None


# ── Push ──────────────────────────────────────────────────────────────────────

def push_article(article_id: int, token: str = "", db_path=None) -> dict:
    """
    Push a single published article to the shared KB repo via GitHub Contents API.
    Any images referenced as ![alt](/api/kb/image/<filename>) are pushed to the
    images/ folder in the repo and the URLs are rewritten to raw.githubusercontent
    so they render for all proctors.

    Returns {"ok": bool, "message": str, "commit_sha": str|None}
    """
    import base64
    db_path = db_path or DB_PATH
    token = token or _load_token()
    if not token:
        return {"ok": False, "message": "No GitHub token - set one in KB Settings", "commit_sha": None}

    art = _kb.get_article(db_path, article_id)
    if not art:
        return {"ok": False, "message": f"Article {article_id} not found", "commit_sha": None}
    if art.get("status") != "published":
        return {"ok": False, "message": "Only published articles can be contributed", "commit_sha": None}

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "POD-Automator-KB-Sync/1.0",
    }

    # 1. Push any locally referenced images and rewrite URLs
    body = art.get("body", "")
    local_img_pattern = re.compile(r'!\[([^\]]*)\]\(/api/kb/image/([^)]+)\)')

    def _replace_image(m):
        alt, filename = m.group(1), m.group(2)
        raw_url = _push_image_to_repo(filename, headers)
        if raw_url:
            return f"![{alt}]({raw_url})"
        return m.group(0)  # leave unchanged if push failed

    body_for_remote = local_img_pattern.sub(_replace_image, body)

    # 2. Fetch current articles.json (need SHA for update)
    try:
        req = urllib.request.Request(KB_API_CONTENT, headers=headers)
        with urllib.request.urlopen(req, timeout=15) as resp:
            file_meta = json.loads(resp.read().decode())
        current_sha = file_meta["sha"]
        current_articles = json.loads(base64.b64decode(file_meta["content"]).decode())
    except urllib.error.HTTPError as e:
        return {"ok": False, "message": f"GitHub API error fetching file: {e.code} {e.reason}", "commit_sha": None}
    except Exception as e:
        return {"ok": False, "message": f"Could not fetch articles.json: {e}", "commit_sha": None}

    # 3. Build the article record (no id/embedding - portable across installs)
    new_record = {
        "title":      art["title"],
        "body":       body_for_remote,
        "tags":       art.get("tags", ""),
        "category":   art.get("category", "General"),
        "status":     "published",
        "created_at": art.get("created_at", ""),
    }

    # Avoid duplicate titles
    existing_titles = {a.get("title") for a in current_articles}
    if new_record["title"] in existing_titles:
        return {"ok": False,
                "message": f"An article with this title already exists in the shared KB: '{new_record['title']}'",
                "commit_sha": None}

    updated_articles = current_articles + [new_record]

    # 4. Commit updated articles.json
    new_content = base64.b64encode(
        json.dumps(updated_articles, indent=2, ensure_ascii=False).encode()
    ).decode()

    payload = json.dumps({
        "message": f"kb: add article '{new_record['title'][:60]}'",
        "content": new_content,
        "sha": current_sha,
    }).encode()

    try:
        req = urllib.request.Request(
            KB_API_CONTENT, data=payload, headers={**headers, "Content-Type": "application/json"},
            method="PUT"
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            result = json.loads(resp.read().decode())
        sha = result.get("commit", {}).get("sha", "")
        return {"ok": True,
                "message": f"Article contributed successfully (commit {sha[:7]})",
                "commit_sha": sha}
    except urllib.error.HTTPError as e:
        body_err = e.read().decode()
        return {"ok": False, "message": f"GitHub API error pushing: {e.code} - {body_err[:200]}", "commit_sha": None}
    except Exception as e:
        return {"ok": False, "message": f"Push failed: {e}", "commit_sha": None}


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "pull"

    if cmd == "pull":
        result = pull()
        sys.exit(0 if result["error"] is None else 1)

    elif cmd == "status":
        _kb.ensure_kb_table()
        local = _kb.list_articles(status=None, limit=10000)
        print(f"Local KB: {len(local)} articles")
        try:
            req = urllib.request.Request(KB_RAW_URL, headers={"User-Agent": "POD-Automator"})
            with urllib.request.urlopen(req, timeout=10) as r:
                remote = json.loads(r.read())
            print(f"Shared KB ({KB_REPO}): {len(remote)} articles")
            local_titles = {a["title"] for a in local}
            new_remote = [a for a in remote if a.get("title") not in local_titles]
            if new_remote:
                print(f"  {len(new_remote)} article(s) available to import:")
                for a in new_remote:
                    print(f"    - {a['title'][:70]}")
            else:
                print("  Local KB is up to date with shared KB")
        except Exception as e:
            print(f"Could not reach shared KB: {e}")

    elif cmd == "push":
        if len(sys.argv) < 3:
            print("Usage: kb_sync.py push <article_id>")
            sys.exit(1)
        aid = int(sys.argv[2])
        tok = _load_token()
        if not tok:
            tok = input("GitHub token (public_repo scope): ").strip()
        result = push_article(aid, token=tok)
        print(f"{'OK' if result['ok'] else 'FAIL'}: {result['message']}")
        sys.exit(0 if result["ok"] else 1)

    else:
        print(f"Unknown command: {cmd}")
        print("Commands: pull | status | push <id>")
        sys.exit(1)

