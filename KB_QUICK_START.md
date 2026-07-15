# Proctor Knowledge Base — Quick Start

The POD Automator includes a shared **Proctor Knowledge Base** — a searchable library
of troubleshooting notes, pipeline fixes, and infrastructure tips contributed by the
proctor team. Articles are automatically synced across every proctor's installation.

---

## Finding the KB

1. Open the dashboard at **http://localhost:5050**
2. Click the **📚 KB** card in the top row — the KB opens as a full-screen panel

---

## Searching for an Answer

Type any keyword or full question into the **Search bar** and press Enter or click Search.

- Results are ranked by relevance — you don't need to know the exact wording
- Try the symptom: `router no config`, `switch vlan leftover`, `ISE pxgrid`, `bootstrap 0x2142`
- The search is **semantic** — it understands meaning, not just keywords

---

## Writing a New Article

Captured a fix during the session? Write it down before you forget.

1. Click **+ New Article** (top right of the KB panel)
2. Fill in the form:

   | Field | What to put |
   |-------|-------------|
   | **Title** | Short and specific — use the symptom as the title. E.g. *Router boots with no config — config register 0x2142* |
   | **Body** | Your notes. Include: what happened, what you tried, what fixed it. Exact CLI commands and error messages are gold. |
   | **Tags** | Comma-separated keywords: `sdwan, bootstrap, config-register` |
   | **Category** | Pick the lab section this relates to (see list below) |

3. Click **Save** — the article is published immediately and searchable

### Categories

| Category | Use for |
|----------|---------|
| SDA Fabric Provisioning | SDA fabric issues and tips |
| EVPN Fabric Provisioning | EVPN fabric issues and tips |
| EVPN Catalyst Center Discovery | CatC discovery and provisioning |
| Configure & Test WLC | Wireless LAN controller setup |
| Macro / Micro Segmentation | Segmentation policy issues |
| Enable SGTs | SGT configuration and propagation |
| Connect Infrastructure | Infrastructure connectivity |
| Connect DUO IDP | Duo identity provider setup |
| Secure Private Access Configuration | RA VPN and private access |
| Secure Internet Access Configure | SIA / internet policy |
| Secure SD-WAN Local Enforcement | SD-WAN enforcement issues |
| Secure Firewall - SGT Enforcement | FTD/cdFMC and SGT enforcement |
| Experience Insights Integration | ThousandEyes integration |
| NDFC - DC Fabric Deployment | Data center fabric via NDFC |
| Install Thousandeyes Agents on Leaf Switches | TE agent deployment |
| General | Anything that doesn't fit above |

---

## Adding Screenshots to an Article

A picture is worth a thousand words — attach screenshots directly to articles.

1. Open or create an article
2. Click **📷 Add Screenshot** below the body text area
3. Select a PNG, JPG, GIF, or WebP file from your machine
4. The image is uploaded and a markdown reference is inserted into the body automatically
5. Save the article — the image is stored locally and displayed inline when viewing

> When you **Contribute** an article, all its screenshots are automatically pushed
> to the shared KB repo so every other proctor sees them too.

---

## Sharing Your Article with All Proctors

Once saved, your article lives only on your machine. To share it with the team:

1. Find your article in the list
2. Click the **🌐 Contribute** button on the right side of the article row

### First-time setup — entering your token

The first time you click Contribute, a **token prompt** will appear. You need a
GitHub token to write to the shared KB repo. Your proctor lead will give you this token.

1. Paste the token into the field
2. Click **Save & Contribute**
3. The token is saved locally — you will **never be asked again** on this machine

> The token is stored in `data/kb_token.txt` on your local machine only.
> It is never committed to git or shared with anyone.

### After the token is saved

The button turns green: **✓ Contributed!**

Your article (and any screenshots) are now committed to the shared KB repo at
**https://github.com/mokuma56/POD-Automator-KB**

Every other proctor gets it on their next **⬆ Check for Updates**.

---

## Getting the Latest Articles from the Team

Articles and images are pulled automatically in two ways:

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
- Attach a screenshot of the error or the fix in action

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
> **Category:** Secure SD-WAN Local Enforcement

---

## Shared KB Repository

All contributed articles and screenshots are visible at:
**https://github.com/mokuma56/POD-Automator-KB**

The repo is public — you can browse articles directly, see who contributed what,
and view the full history including all images.

---

## Questions?

Reach the lab team through the usual channels. For dashboard issues, use the
**⬆ Check for Updates** button first — most fixes are already pushed.
