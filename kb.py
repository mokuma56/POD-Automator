"""
Knowledge Base module for POD Automator.

Stores articles in SQLite with sentence-transformer embeddings for semantic
search. Uses a local Ollama model to answer questions grounded in the KB.

Schema (added to existing pod_state.db):
  knowledge_base(id, title, body, tags, category, status, embedding, created_at, updated_at)
    status: 'draft' | 'published'

Public API:
  ensure_kb_table(db_path)
  add_article(db_path, title, body, tags, category, status) -> id
  update_article(db_path, id, **fields)
  publish_article(db_path, id)
  delete_article(db_path, id)
  get_article(db_path, id) -> dict
  list_articles(db_path, status, category, limit) -> [dict]
  search(db_path, query, top_k, status) -> [dict]   # semantic search
  ask(db_path, question, top_k, model) -> dict       # RAG answer via Ollama
  auto_draft(db_path, step_name, error_text, pod_id) -> id  # called on pipeline failure
  reembed_all(db_path)                               # rebuild all embeddings
"""

import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "data" / "pod_state.db"
OLLAMA_MODEL = "llama3.2"
EMBED_MODEL = "all-MiniLM-L6-v2"

_embedder = None


def _get_embedder():
    global _embedder
    if _embedder is None:
        from sentence_transformers import SentenceTransformer
        _embedder = SentenceTransformer(EMBED_MODEL)
    return _embedder


def _embed(text: str) -> list:
    return _get_embedder().encode(text, normalize_embeddings=True).tolist()


def _cosine(a: list, b: list) -> float:
    import numpy as np
    a, b = np.array(a), np.array(b)
    denom = (np.linalg.norm(a) * np.linalg.norm(b))
    return float(np.dot(a, b) / denom) if denom else 0.0


def _conn(db_path):
    c = sqlite3.connect(str(db_path))
    c.row_factory = sqlite3.Row
    return c


def ensure_kb_table(db_path=None):
    db_path = db_path or DB_PATH
    with _conn(db_path) as c:
        c.execute("""
            CREATE TABLE IF NOT EXISTS knowledge_base (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                title       TEXT NOT NULL,
                body        TEXT NOT NULL,
                tags        TEXT DEFAULT '',
                category    TEXT DEFAULT 'general',
                status      TEXT DEFAULT 'draft',
                embedding   TEXT DEFAULT NULL,
                created_at  TEXT DEFAULT (datetime('now')),
                updated_at  TEXT DEFAULT (datetime('now'))
            )
        """)
        c.commit()


def add_article(db_path=None, title="", body="", tags="", category="general",
                status="draft", compute_embedding=True) -> int:
    db_path = db_path or DB_PATH
    ensure_kb_table(db_path)
    emb = json.dumps(_embed(f"{title}\n{body}")) if compute_embedding else None
    with _conn(db_path) as c:
        cur = c.execute(
            "INSERT INTO knowledge_base (title, body, tags, category, status, embedding) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (title, body, tags, category, status, emb)
        )
        c.commit()
        return cur.lastrowid


def update_article(db_path=None, article_id=None, **fields) -> bool:
    db_path = db_path or DB_PATH
    if not article_id:
        return False
    allowed = {"title", "body", "tags", "category", "status"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return False
    # Recompute embedding if title or body changed
    if "title" in updates or "body" in updates:
        row = get_article(db_path, article_id)
        if row:
            new_title = updates.get("title", row["title"])
            new_body = updates.get("body", row["body"])
            updates["embedding"] = json.dumps(_embed(f"{new_title}\n{new_body}"))
    updates["updated_at"] = "datetime('now')"
    set_clause = ", ".join(
        f"{k}=datetime('now')" if k == "updated_at" else f"{k}=?"
        for k in updates if k != "updated_at"
    ) + ", updated_at=datetime('now')"
    vals = [v for k, v in updates.items() if k != "updated_at"]
    vals.append(article_id)
    with _conn(db_path) as c:
        c.execute(f"UPDATE knowledge_base SET {set_clause} WHERE id=?", vals)
        c.commit()
    return True


def publish_article(db_path=None, article_id=None) -> bool:
    return update_article(db_path, article_id, status="published")


def delete_article(db_path=None, article_id=None) -> bool:
    db_path = db_path or DB_PATH
    with _conn(db_path) as c:
        c.execute("DELETE FROM knowledge_base WHERE id=?", (article_id,))
        c.commit()
    return True


def get_article(db_path=None, article_id=None) -> Optional[dict]:
    db_path = db_path or DB_PATH
    with _conn(db_path) as c:
        row = c.execute("SELECT * FROM knowledge_base WHERE id=?", (article_id,)).fetchone()
        return dict(row) if row else None


def list_articles(db_path=None, status=None, category=None, limit=100) -> list:
    db_path = db_path or DB_PATH
    ensure_kb_table(db_path)
    clauses, vals = [], []
    if status:
        clauses.append("status=?"); vals.append(status)
    if category:
        clauses.append("category=?"); vals.append(category)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with _conn(db_path) as c:
        rows = c.execute(
            f"SELECT id, title, tags, category, status, created_at, updated_at "
            f"FROM knowledge_base {where} ORDER BY updated_at DESC LIMIT ?",
            vals + [limit]
        ).fetchall()
        return [dict(r) for r in rows]


def search(db_path=None, query="", top_k=5, status="published") -> list:
    """Semantic search — returns top_k articles sorted by cosine similarity."""
    db_path = db_path or DB_PATH
    ensure_kb_table(db_path)
    q_emb = _embed(query)
    clause = "WHERE embedding IS NOT NULL"
    if status:
        clause += f" AND status='{status}'"
    with _conn(db_path) as c:
        rows = c.execute(
            f"SELECT id, title, body, tags, category, status, embedding FROM knowledge_base {clause}"
        ).fetchall()
    if not rows:
        return []
    scored = []
    for r in rows:
        try:
            emb = json.loads(r["embedding"])
            score = _cosine(q_emb, emb)
            scored.append({**dict(r), "score": score, "embedding": None})
        except Exception:
            pass
    scored.sort(key=lambda x: x["score"], reverse=True)
    return scored[:top_k]


def ask(db_path=None, question="", top_k=4, model=None) -> dict:
    """
    RAG: semantic search -> build context -> query Ollama.
    Returns {"answer": str, "sources": [{"id", "title", "score"}], "model": str}
    """
    import ollama as _ollama
    db_path = db_path or DB_PATH
    model = model or OLLAMA_MODEL
    hits = search(db_path, question, top_k=top_k, status="published")

    if not hits:
        context = "No relevant knowledge base articles found."
    else:
        context = "\n\n---\n\n".join(
            f"Article: {h['title']}\n{h['body']}" for h in hits
        )

    prompt = f"""You are a lab assistant for a Cisco SD-WAN dCloud lab. 
Answer the proctor's question using ONLY the knowledge base articles provided below.
If the answer is not in the articles, say so clearly.

Knowledge Base:
{context}

Question: {question}

Answer:"""

    try:
        resp = _ollama.chat(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1}
        )
        answer = resp["message"]["content"].strip()
        ollama_ok = True
    except Exception as e:
        answer = f"Ollama unavailable ({e}). Top matching article: {hits[0]['title'] if hits else 'none'}"
        ollama_ok = False

    return {
        "answer": answer,
        "sources": [{"id": h["id"], "title": h["title"], "score": round(h["score"], 3)} for h in hits],
        "model": model,
        "ollama_ok": ollama_ok,
    }


def auto_draft(db_path=None, step_name="", error_text="", pod_id="") -> int:
    """
    Called automatically when a pipeline step fails.
    Creates a draft KB article pre-filled with step name, error, and POD context.
    Proctors can review and publish via the dashboard.
    """
    db_path = db_path or DB_PATH
    title = f"Pipeline failure: {step_name}" + (f" (POD {pod_id})" if pod_id else "")
    body = f"""## Step
`{step_name}`

## POD
{pod_id or 'unknown'}

## Error / Output
```
{error_text[:2000]}
```

## Resolution
_TODO: Fill in the resolution steps._

## Root Cause
_TODO: Fill in the root cause._
"""
    return add_article(
        db_path=db_path,
        title=title,
        body=body,
        tags=f"pipeline,{step_name},auto-draft",
        category="pipeline-failure",
        status="draft",
    )


def reembed_all(db_path=None):
    """Recompute embeddings for all articles (e.g. after changing embed model)."""
    db_path = db_path or DB_PATH
    with _conn(db_path) as c:
        rows = c.execute("SELECT id, title, body FROM knowledge_base").fetchall()
    print(f"Re-embedding {len(rows)} articles...")
    for r in rows:
        emb = json.dumps(_embed(f"{r['title']}\n{r['body']}"))
        with _conn(db_path) as c:
            c.execute("UPDATE knowledge_base SET embedding=? WHERE id=?", (emb, r["id"]))
            c.commit()
        print(f"  [{r['id']}] {r['title'][:60]}")
    print("Done.")


def ollama_status(model=None) -> dict:
    """Check if Ollama is running and the model is available."""
    import ollama as _ollama
    model = model or OLLAMA_MODEL
    try:
        models = [m["model"] for m in _ollama.list()["models"]]
        available = any(model in m for m in models)
        return {"running": True, "model": model, "available": available, "models": models}
    except Exception as e:
        return {"running": False, "model": model, "available": False, "error": str(e)}


if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "reembed":
        reembed_all()
    elif cmd == "status":
        ensure_kb_table()
        arts = list_articles(status=None)
        print(f"Knowledge base: {len(arts)} articles")
        for a in arts:
            print(f"  [{a['status']:9}] {a['id']:3}. {a['title'][:70]}")
    elif cmd == "ask":
        q = " ".join(sys.argv[2:]) or "What is the config register issue?"
        result = ask(question=q)
        print(f"\nAnswer ({result['model']}):\n{result['answer']}")
        print(f"\nSources: {result['sources']}")
