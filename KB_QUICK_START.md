# Proctor Knowledge Base — Quick Start

The POD Automator includes a shared **Proctor Knowledge Base** — a searchable library
of troubleshooting notes, pipeline fixes, and infrastructure tips contributed by the
proctor team. Articles are automatically synced across every proctor's installation.

---

## Finding the KB

1. Open the dashboard at **http://localhost:5050**
2. Click any POD row to open the detail panel
3. Click the **Knowledge Base** tab

---

## Searching for an Answer

Type any keyword or full question into the **Search bar** and press Enter or click Search.

- Results are ranked by relevance — you don't need to know the exact wording
- Try the symptom: `router no config`, `switch vlan leftover`, `ISE pxgrid`, `bootstrap 0x2142`
- The search is **semantic** — it understands meaning, not just keywords

---

## Writing a New Article

Captured a fix during the session? Write it down before you forget.

1. Click **+ New Article** (top right of the KB tab)
2. Fill in the form:

   | Field | What to put |
   |-------|-------------|
   | **Title** | Short and specific — use the symptom as the title. E.g. *Router boots with no config — config register 0x2142* |
   | **Body** | Your notes. Include: what happened, what you tried, what fixed it. Exact CLI commands and error messages are gold. |
   | **Tags** | Comma-separated keywords: `sdwan, bootstrap, config-register` |
   | **Category** | Pick the best fit — `sdwan`, `switches`, `infrastructure`, `troubleshooting`, `procedure`, `general` |

3. Click **Save** — the article is published immediately and searchable

---

## Sharing Your Article with All Proctors

Once saved, your article lives only on your machine. To share it with the team:

1. Find your article in the list
2. Click the **🌐 Contribute** button on the right side of the article row
3. Wait 2–3 seconds — the button turns green: **✓ Contributed!**

That's it. Your article is now committed to the shared KB repo at
**https://github.com/mokuma56/POD-Automator-KB**

Every other proctor gets it on their next **⬆ Check for Updates**.

> No GitHub account or token needed — the shared write access is pre-configured in the tool.

---

## Getting the Latest Articles from the Team

Articles are pulled automatically in two ways:

- **On dashboard startup** — silently in the background
- **On every Check for Updates** — as part of the update sequence

To pull manually from the command line:
```bash
cd ~/POD-Automator
uv run python3 kb_sync.py pull
```

To see how many new articles are available:
```bash
uv run python3 kb_sync.py status
```

---

## Tips for Good Articles

**Do:**
- Use the error message or symptom as the title
- Include the exact CLI command that revealed the problem
- Include the exact fix — not just "I rebooted it"
- Note which POD/device it happened on
- Add tags so others can find it

**Don't:**
- Write vague titles like "Issue with router"
- Leave the body empty or with just one line
- Duplicate an existing article — search first

**Example of a good article:**

> **Title:** Bootstrap delivery fails — router drops to ROMMON after controller-mode enable
>
> **Body:**
> Symptom: Router reboots into SD-WAN controller mode but shows no config.
> `show bootvar` shows Configuration register is 0x2142 — means router ignores
> startup-config on boot.
>
> Root cause: Config register was left at 0x2142 from a previous manual operation.
>
> Fix:
> ```
> conf t
> config-register 0x2102
> end
> write mem
> reload
> ```
>
> **Tags:** sdwan, bootstrap, config-register, rommon
> **Category:** troubleshooting

---

## Shared KB Repository

All contributed articles are visible at:
**https://github.com/mokuma56/POD-Automator-KB**

The repo is public — you can browse articles directly, see who contributed what,
and view the full history.

---

## Questions?

Reach the lab team through the usual channels. For dashboard issues, use the
**⬆ Check for Updates** button first — most fixes are already pushed.
