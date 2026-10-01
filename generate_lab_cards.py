"""
generate_lab_cards.py
Generates a Cisco-branded PDF with 4 lab detail cards per page (2x2 grid).
Called from dashboard.py via /api/generate-lab-pdf
"""

import io
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.pdfgen import canvas
from reportlab.lib.utils import simpleSplit

# ── Print-friendly light theme ─────────────────────────────────────────────
# Cards are printed and handed to students: white paper, dark text, and blue
# used only for thin accents, so a sheet costs little ink and reads easily.
C_BG          = colors.white                 # page background (left unfilled)
C_CARD_BG     = colors.white                 # card background
C_CARD_BORDER = colors.HexColor("#b8c4d0")   # card outline
C_ACCENT      = colors.HexColor("#049fd9")   # Cisco blue — accent bar, pills
C_TITLE       = colors.HexColor("#0b2a4a")   # card title / POD number
C_LABEL       = colors.HexColor("#5b6b7b")   # field label color
C_VALUE       = colors.HexColor("#111827")   # field value color
C_DIVIDER     = colors.HexColor("#e1e7ee")   # row divider
C_ROW_ALT     = colors.HexColor("#f4f7fa")   # alternating row tint (near-white)
C_TAGLINE     = colors.HexColor("#374151")   # CE credits tagline
C_MUTED       = colors.HexColor("#8a97a5")   # page header / footer text
C_CUT         = colors.HexColor("#c8d0d8")   # dashed cut guides
C_HDR_TINT    = colors.HexColor("#e8f5fb")   # summary table header row

# ── Page / Card Geometry ───────────────────────────────────────────────────
PAGE_W, PAGE_H = landscape(letter)           # 11 x 8.5 inches
MARGIN         = 0.32 * inch
GUTTER         = 0.22 * inch
COLS, ROWS     = 2, 2
CARD_W = (PAGE_W - 2 * MARGIN - GUTTER) / COLS
CARD_H = (PAGE_H - 2 * MARGIN - GUTTER) / ROWS

# ── Typography ─────────────────────────────────────────────────────────────
FONT_REG   = "Helvetica"
FONT_BOLD  = "Helvetica-Bold"
FONT_OBLIQ = "Helvetica-Oblique"
# Credentials in monospace so students can tell 0/O and 1/l/I apart.
FONT_MONO  = "Courier-Bold"


def _card_origin(idx):
    """Return (x, y) bottom-left of card at position idx (0-3, left-to-right, top-to-bottom)."""
    col = idx % COLS
    row = idx // COLS
    x = MARGIN + col * (CARD_W + GUTTER)
    # Row 0 = top row → higher y value
    y = PAGE_H - MARGIN - (row + 1) * CARD_H - row * GUTTER
    return x, y


def _draw_card(c: canvas.Canvas, idx: int, pod: dict):
    """Draw a single lab details card."""
    x, y = _card_origin(idx)
    w, h = CARD_W, CARD_H

    PAD = 0.18 * inch

    # ── Card outline ──────────────────────────────────────────────────────
    c.setStrokeColor(C_CARD_BORDER)
    c.setFillColor(C_CARD_BG)
    c.setLineWidth(0.8)
    c.roundRect(x, y, w, h, radius=6, stroke=1, fill=1)

    # Thin Cisco-blue accent bar across the top
    ACCENT_H = 0.07 * inch
    c.setFillColor(C_ACCENT)
    c.roundRect(x, y + h - ACCENT_H, w, ACCENT_H, radius=3, stroke=0, fill=1)

    # ── Title ─────────────────────────────────────────────────────────────
    TITLE_Y = y + h - 0.40 * inch
    c.setFillColor(C_ACCENT)
    c.setFont(FONT_BOLD, 8)
    c.drawString(x + PAD, TITLE_Y + 2, "CISCO")
    c.setFillColor(C_TITLE)
    c.setFont(FONT_BOLD, 13)
    c.drawCentredString(x + w / 2, TITLE_Y, "Cisco One Experience Lab")

    # ── POD / Session pills (outlined, no fill) ───────────────────────────
    PILL_H = 0.30 * inch
    PILL_Y = TITLE_Y - 0.18 * inch - PILL_H
    raw_id = pod.get('pod_id', '')
    # use AD-confirmed pod_number if available, fall back to pod_id
    pod_num = pod.get('pod_number', '') or raw_id.replace('POD-', '')
    pills = [(f"POD {pod_num}", 13, 1.15 * inch),
             (f"Session {pod.get('session_id') or '—'}", 10, 1.55 * inch)]
    px = x + PAD
    c.setStrokeColor(C_ACCENT)
    c.setLineWidth(1.1)
    for label, size, pw in pills:
        c.roundRect(px, PILL_Y, pw, PILL_H, radius=PILL_H / 2, stroke=1, fill=0)
        c.setFillColor(C_TITLE)
        c.setFont(FONT_BOLD, size)
        c.drawCentredString(px + pw / 2, PILL_Y + (PILL_H - size * 0.72) / 2, label)
        px += pw + 0.10 * inch

    # ── Field rows ────────────────────────────────────────────────────────
    FIELD_START_Y = PILL_Y - 0.10 * inch
    ROW_H = 0.285 * inch
    LABEL_W = 1.05 * inch

    # (label, value, monospace?) — anything a student must type is monospace
    fields = [
        ("SCC Org #",    _fmt_scc(pod.get("scc_org", "")), False),
        ("CCO ID",       pod.get("assigned_to") or "",     False),
        ("VPN Host",     pod.get("vpn_host", ""),          True),
        ("Username",     pod.get("vpn_username", ""),      True),
        ("Password",     pod.get("vpn_password", ""),      True),
        ("Jump Host",    "RDP: 198.18.133.36",              True),
        ("JH User",      r"corp.pseudoco.com\demouser",    True),
        ("JH Password",  "C1sco12345",                      True),
    ]

    for i, (label, value, mono) in enumerate(fields):
        ry = FIELD_START_Y - (i + 1) * ROW_H
        # Stop drawing if we'd go below card bottom + tagline room
        if ry < y + 0.30 * inch:
            break

        if i % 2 == 1:
            c.setFillColor(C_ROW_ALT)
            c.rect(x + PAD / 2, ry, w - PAD, ROW_H, stroke=0, fill=1)

        c.setStrokeColor(C_DIVIDER)
        c.setLineWidth(0.5)
        c.line(x + PAD / 2, ry, x + w - PAD / 2, ry)

        text_y = ry + (ROW_H - 9) / 2 + 1

        c.setFillColor(C_LABEL)
        c.setFont(FONT_REG, 8.5)
        c.drawString(x + PAD, text_y, label)

        font, size = (FONT_MONO, 10.5) if mono else (FONT_BOLD, 10)
        c.setFillColor(C_VALUE)
        c.setFont(font, size)
        max_val_w = w - PAD - LABEL_W - PAD
        c.drawString(x + PAD + LABEL_W, text_y,
                     _truncate(c, str(value), font, size, max_val_w))

    # ── CE Credits tagline ────────────────────────────────────────────────
    c.setFillColor(C_TAGLINE)
    c.setFont(FONT_OBLIQ, 8)
    c.drawCentredString(x + w / 2, y + 0.12 * inch,
                        "Complete this lab to earn 10 Cisco Continuing Education (CE) Credits")


def _draw_page_header(c: canvas.Canvas, page_num: int, total_pages: int):
    """Small grey header line — no filled strip."""
    c.setFillColor(C_MUTED)
    c.setFont(FONT_REG, 7)
    c.drawString(MARGIN, PAGE_H - 0.20 * inch, "CISCO CONFIDENTIAL — FOR PROCTOR USE ONLY")
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.20 * inch, f"Page {page_num} of {total_pages}")


def _draw_cut_guides(c: canvas.Canvas):
    """Dashed lines through the gutters so the sheet cuts cleanly into 4 cards."""
    c.saveState()
    c.setStrokeColor(C_CUT)
    c.setLineWidth(0.5)
    c.setDash(4, 3)
    mid_x = MARGIN + CARD_W + GUTTER / 2
    mid_y = PAGE_H - MARGIN - CARD_H - GUTTER / 2
    c.line(mid_x, MARGIN / 2, mid_x, PAGE_H - MARGIN / 2 - 0.12 * inch)
    c.line(MARGIN / 2, mid_y, PAGE_W - MARGIN / 2, mid_y)
    c.restoreState()


def _fmt_scc(scc_org: str) -> str:
    """Extract short org identifier from full SCC org string."""
    if not scc_org:
        return ""
    import re
    m = re.search(r'pseudoco-(\d+)--', scc_org)
    if m:
        return f"pseudoco-{m.group(1)}"
    return scc_org[:40]


def _truncate(c: canvas.Canvas, text: str, font: str, size: float, max_w: float) -> str:
    """Truncate text with ellipsis if wider than max_w."""
    if c.stringWidth(text, font, size) <= max_w:
        return text
    while text and c.stringWidth(text + "…", font, size) > max_w:
        text = text[:-1]
    return text + "…"


def _draw_summary_page(c: canvas.Canvas, pods: list, page_num: int, total_pages: int):
    """Draw a single proctor summary page — one row per POD."""
    _draw_page_header(c, page_num, total_pages)

    # Title block
    TITLE_Y = PAGE_H - 0.22 * inch - 0.55 * inch
    c.setFillColor(C_TITLE)
    c.setFont(FONT_BOLD, 16)
    title = "Cisco One Experience Lab — Proctor Summary"
    c.drawCentredString(PAGE_W / 2, TITLE_Y, title)

    # Accent line under title
    c.setStrokeColor(C_ACCENT)
    c.setLineWidth(1.5)
    c.line(MARGIN, TITLE_Y - 0.08 * inch, PAGE_W - MARGIN, TITLE_Y - 0.08 * inch)

    # ── Table geometry ────────────────────────────────────────────────────
    TABLE_TOP  = TITLE_Y - 0.22 * inch
    ROW_H      = 0.30 * inch
    HDR_H      = 0.34 * inch
    COL_PAD    = 0.10 * inch
    TABLE_W    = PAGE_W - 2 * MARGIN

    # Column definitions: (header label, proportional width)
    cols = [
        ("POD #",       0.08),
        ("Session #",   0.12),
        ("CCO ID",      0.14),
        ("VPN Host",    0.30),
        ("VPN Username",0.18),
        ("VPN Password",0.18),
    ]
    total_w = sum(w for _, w in cols)
    col_widths = [TABLE_W * (w / total_w) for _, w in cols]
    col_headers = [h for h, _ in cols]

    # Column x positions
    col_x = [MARGIN]
    for cw in col_widths[:-1]:
        col_x.append(col_x[-1] + cw)

    # ── Header row ────────────────────────────────────────────────────────
    c.setFillColor(C_HDR_TINT)
    c.roundRect(MARGIN, TABLE_TOP - HDR_H, TABLE_W, HDR_H, radius=5, stroke=0, fill=1)

    c.setFillColor(C_TITLE)
    c.setFont(FONT_BOLD, 9)
    for i, header in enumerate(col_headers):
        c.drawString(col_x[i] + COL_PAD, TABLE_TOP - HDR_H + (HDR_H - 9) / 2 + 1, header)

    # ── Data rows ─────────────────────────────────────────────────────────
    row_fields = [
        lambda p: ("POD-" + p.get("pod_number")) if p.get("pod_number") else p.get("pod_id", ""),
        lambda p: p.get("session_id", ""),
        lambda p: p.get("assigned_to", "") or "—",
        lambda p: p.get("vpn_host", ""),
        lambda p: p.get("vpn_username", ""),
        lambda p: p.get("vpn_password", ""),
    ]

    for r, pod in enumerate(pods):
        ry = TABLE_TOP - HDR_H - (r + 1) * ROW_H

        # Alternating row background
        if r % 2 == 1:
            c.setFillColor(C_ROW_ALT)
            c.rect(MARGIN, ry, TABLE_W, ROW_H, stroke=0, fill=1)

        # Row divider
        c.setStrokeColor(C_DIVIDER)
        c.setLineWidth(0.4)
        c.line(MARGIN, ry + ROW_H, MARGIN + TABLE_W, ry + ROW_H)

        text_y = ry + (ROW_H - 9) / 2 + 1

        for i, fn in enumerate(row_fields):
            val = str(fn(pod))
            # POD column bold; host/username/password monospace like the cards
            font = FONT_BOLD if i == 0 else FONT_MONO if i >= 3 else FONT_REG
            c.setFillColor(C_TITLE if i == 0 else C_VALUE)
            c.setFont(font, 9)
            val_str = _truncate(c, val, font, 9, col_widths[i] - COL_PAD * 2)
            c.drawString(col_x[i] + COL_PAD, text_y, val_str)

    # Table outer border
    total_rows = len(pods)
    table_h = HDR_H + total_rows * ROW_H
    c.setStrokeColor(C_CARD_BORDER)
    c.setLineWidth(1.2)
    c.roundRect(MARGIN, TABLE_TOP - table_h, TABLE_W, table_h, radius=5, stroke=1, fill=0)

    # Vertical column dividers
    c.setStrokeColor(C_DIVIDER)
    c.setLineWidth(0.4)
    for i in range(1, len(col_x)):
        c.line(col_x[i], TABLE_TOP - table_h, col_x[i], TABLE_TOP)

    # Footer note
    c.setFillColor(C_MUTED)
    c.setFont(FONT_OBLIQ, 7.5)
    note = "Proctor reference only — do not distribute to participants"
    c.drawCentredString(PAGE_W / 2, MARGIN, note)


def generate_pdf(pods: list) -> bytes:
    """
    Generate the lab detail PDF.

    pods: list of dicts with keys:
        pod_id, session_id, scc_org, assigned_to,
        vpn_host, vpn_username, vpn_password
    Returns raw PDF bytes.
    """
    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=landscape(letter))
    c.setTitle("Cisco One Experience Lab — Lab Details")
    c.setAuthor("Cisco One Experience Lab Automator")

    per_page = COLS * ROWS  # 4
    card_pages = (len(pods) + per_page - 1) // per_page
    total_pages = card_pages + 1  # +1 for summary page

    for page_start in range(0, len(pods), per_page):
        page_pods = pods[page_start: page_start + per_page]

        _draw_page_header(c, page_start // per_page + 1, total_pages)
        _draw_cut_guides(c)

        for i, pod in enumerate(page_pods):
            _draw_card(c, i, pod)

        c.showPage()

    # Final page — proctor summary table
    _draw_summary_page(c, pods, total_pages, total_pages)

    c.save()
    return buf.getvalue()


if __name__ == "__main__":
    # Quick local test
    test_pods = [
        {"pod_id": "POD-11", "session_id": "1329155", "scc_org": "pseudoco-11--abc123",
         "assigned_to": "jsmith", "vpn_host": "dcloud-rtp-anyconnect.cisco.com",
         "vpn_username": "v3137user1", "vpn_password": "abc123"},
        {"pod_id": "POD-12", "session_id": "1329156", "scc_org": "pseudoco-12--def456",
         "assigned_to": "", "vpn_host": "dcloud-sjc-anyconnect.cisco.com",
         "vpn_username": "v3976user1", "vpn_password": "xyz789"},
        {"pod_id": "POD-13", "session_id": "1329157", "scc_org": "pseudoco-13--ghi012",
         "assigned_to": "mjones", "vpn_host": "dcloud-rtp-anyconnect.cisco.com",
         "vpn_username": "v3360user1", "vpn_password": "pass001"},
        {"pod_id": "POD-14", "session_id": "1329158", "scc_org": "",
         "assigned_to": "", "vpn_host": "dcloud-rtp-anyconnect.cisco.com",
         "vpn_username": "v3716user1", "vpn_password": "pass002"},
        {"pod_id": "POD-15", "session_id": "1329159", "scc_org": "pseudoco-15--jkl345",
         "assigned_to": "tdavis", "vpn_host": "dcloud-sjc-anyconnect.cisco.com",
         "vpn_username": "v913user1", "vpn_password": "pass003"},
        {"pod_id": "POD-16", "session_id": "1329160", "scc_org": "pseudoco-16--mno678",
         "assigned_to": "", "vpn_host": "dcloud-rtp-anyconnect.cisco.com",
         "vpn_username": "v3053user1", "vpn_password": "pass004"},
    ]
    import sys
    out = sys.argv[1] if len(sys.argv) > 1 else "/tmp/lab_details_test.pdf"
    pdf_bytes = generate_pdf(test_pods)
    with open(out, "wb") as f:
        f.write(pdf_bytes)
    print(f"Written {len(pdf_bytes):,} bytes → {out}")
