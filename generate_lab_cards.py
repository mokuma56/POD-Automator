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

# ── Cisco Dark Theme Colors ────────────────────────────────────────────────
C_BG          = colors.HexColor("#0d1117")   # page background
C_CARD_BG     = colors.HexColor("#0d1b2e")   # card background
C_CARD_BORDER = colors.HexColor("#00bceb")   # Cisco blue border/accent
C_HEADER_BG   = colors.HexColor("#00bceb")   # title bar background
C_HEADER_TEXT = colors.HexColor("#0d1117")   # title bar text (dark on blue)
C_LABEL       = colors.HexColor("#8ab4c8")   # field label color
C_VALUE       = colors.HexColor("#ffffff")   # field value color
C_DIVIDER     = colors.HexColor("#1a3a52")   # row divider
C_TAGLINE     = colors.HexColor("#ffcc00")   # CE credits tagline
C_SUBHEADER   = colors.HexColor("#00bceb")   # section subheader
C_ROW_ALT     = colors.HexColor("#0f2236")   # alternating row tint
C_POD_NUM     = colors.HexColor("#00bceb")   # POD number accent

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

    PAD = 0.14 * inch

    # ── Card shadow / border glow ──────────────────────────────────────────
    c.setStrokeColor(C_CARD_BORDER)
    c.setFillColor(C_CARD_BG)
    c.setLineWidth(1.5)
    c.roundRect(x, y, w, h, radius=8, stroke=1, fill=1)

    # ── Header bar ────────────────────────────────────────────────────────
    HEADER_H = 0.48 * inch
    c.setFillColor(C_HEADER_BG)
    # Clip rounded top — draw a rect for the top portion, then overlay
    # We draw the rounded rect for full card above, so just fill header area
    # using a clipping trick: draw the header rect with rounded top corners only
    c.roundRect(x, y + h - HEADER_H, w, HEADER_H, radius=8, stroke=0, fill=1)
    # Square off the bottom of header so it butts cleanly against card body
    c.rect(x, y + h - HEADER_H, w, HEADER_H / 2, stroke=0, fill=1)

    # Cisco wordmark (text treatment)
    c.setFillColor(C_HEADER_TEXT)
    c.setFont(FONT_BOLD, 8)
    c.drawString(x + PAD, y + h - HEADER_H + 0.07 * inch, "CISCO")

    # Card title
    c.setFont(FONT_BOLD, 11)
    title = "Cisco One Experience Lab"
    title_w = c.stringWidth(title, FONT_BOLD, 11)
    c.drawString(x + (w - title_w) / 2, y + h - HEADER_H * 0.58, title)

    # ── POD number badge ──────────────────────────────────────────────────
    BADGE_Y = y + h - HEADER_H - 0.34 * inch
    BADGE_H = 0.28 * inch
    BADGE_W = 1.1 * inch

    # POD badge
    c.setFillColor(C_POD_NUM)
    c.roundRect(x + PAD, BADGE_Y, BADGE_W, BADGE_H, radius=4, stroke=0, fill=1)
    c.setFillColor(C_HEADER_TEXT)
    c.setFont(FONT_BOLD, 10)
    # POD badge — use AD-confirmed pod_number if available, fall back to pod_id
    raw_id = pod.get('pod_id', '')
    pod_num = pod.get('pod_number', '') or raw_id.replace('POD-', '')
    pod_label = f"POD {pod_num}"
    pod_lw = c.stringWidth(pod_label, FONT_BOLD, 10)
    c.drawString(x + PAD + (BADGE_W - pod_lw) / 2,
                 BADGE_Y + (BADGE_H - 10) / 2 + 1, pod_label)

    # Session badge — identical style to POD badge
    SESSION_X  = x + PAD + BADGE_W + 0.08 * inch
    c.setFillColor(C_POD_NUM)
    c.roundRect(SESSION_X, BADGE_Y, BADGE_W, BADGE_H, radius=4, stroke=0, fill=1)
    c.setFillColor(C_HEADER_TEXT)
    c.setFont(FONT_BOLD, 10)
    sess_label = f"Session {pod.get('session_id','—')}"
    sess_lw = c.stringWidth(sess_label, FONT_BOLD, 10)
    c.drawString(SESSION_X + (BADGE_W - sess_lw) / 2,
                 BADGE_Y + (BADGE_H - 10) / 2 + 1, sess_label)

    # ── Field rows ────────────────────────────────────────────────────────
    FIELD_START_Y = BADGE_Y - 0.10 * inch
    ROW_H = 0.245 * inch
    LABEL_W = 1.05 * inch

    fields = [
        ("SCC Org #",    _fmt_scc(pod.get("scc_org", ""))),
        ("CCO ID",       pod.get("assigned_to") or ""),
        ("VPN Host",     pod.get("vpn_host", "")),
        ("Username",     pod.get("vpn_username", "")),
        ("Password",     pod.get("vpn_password", "")),
        ("Jump Host",    "RDP: 198.18.133.35"),
        ("JH User",      r"corp.pseudoco.com\demouser"),
        ("JH Password",  "C1sco12345"),
    ]

    for i, (label, value) in enumerate(fields):
        ry = FIELD_START_Y - (i + 1) * ROW_H
        # Stop drawing if we'd go below card bottom + tagline room
        if ry < y + 0.30 * inch:
            break

        # Alternating row tint
        if i % 2 == 1:
            c.setFillColor(C_ROW_ALT)
            c.rect(x + 2, ry, w - 4, ROW_H, stroke=0, fill=1)

        # Divider line
        c.setStrokeColor(C_DIVIDER)
        c.setLineWidth(0.4)
        c.line(x + PAD, ry + ROW_H, x + w - PAD, ry + ROW_H)

        text_y = ry + (ROW_H - 8) / 2 + 1

        # Label
        c.setFillColor(C_LABEL)
        c.setFont(FONT_BOLD, 7.5)
        c.drawString(x + PAD, text_y, label + ":")

        # Value — truncate if too long
        c.setFillColor(C_VALUE)
        c.setFont(FONT_REG, 8.5)
        max_val_w = w - PAD - LABEL_W - PAD
        val_str = _truncate(c, str(value), FONT_REG, 8.5, max_val_w)
        c.drawString(x + PAD + LABEL_W, text_y, val_str)

    # ── CE Credits tagline ────────────────────────────────────────────────
    c.setFillColor(C_TAGLINE)
    c.setFont(FONT_OBLIQ, 7.5)
    tagline = "Complete this lab to earn 10 Cisco Continuing Education (CE) Credits"
    tl_w = c.stringWidth(tagline, FONT_OBLIQ, 7.5)
    c.drawString(x + (w - tl_w) / 2, y + 0.10 * inch, tagline)

    # Bottom border accent line
    c.setStrokeColor(C_CARD_BORDER)
    c.setLineWidth(1.5)
    c.line(x + 12, y + 0.27 * inch, x + w - 12, y + 0.27 * inch)


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
    # Page background
    c.setFillColor(C_BG)
    c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

    # Page header strip
    c.setFillColor(colors.HexColor("#060d16"))
    c.rect(0, PAGE_H - 0.22 * inch, PAGE_W, 0.22 * inch, stroke=0, fill=1)
    c.setFillColor(C_LABEL)
    c.setFont(FONT_REG, 6.5)
    c.drawString(MARGIN, PAGE_H - 0.15 * inch, "CISCO CONFIDENTIAL — FOR PROCTOR USE ONLY")
    c.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.15 * inch, f"Page {page_num} of {total_pages}")

    # Title block
    TITLE_Y = PAGE_H - 0.22 * inch - 0.55 * inch
    c.setFillColor(C_CARD_BORDER)
    c.setFont(FONT_BOLD, 16)
    title = "Cisco One Experience Lab — Proctor Summary"
    c.drawCentredString(PAGE_W / 2, TITLE_Y, title)

    # Accent line under title
    c.setStrokeColor(C_CARD_BORDER)
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
    c.setFillColor(C_HEADER_BG)
    c.roundRect(MARGIN, TABLE_TOP - HDR_H, TABLE_W, HDR_H, radius=5, stroke=0, fill=1)

    c.setFillColor(C_HEADER_TEXT)
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
        if r % 2 == 0:
            c.setFillColor(C_CARD_BG)
        else:
            c.setFillColor(C_ROW_ALT)
        c.rect(MARGIN, ry, TABLE_W, ROW_H, stroke=0, fill=1)

        # Row divider
        c.setStrokeColor(C_DIVIDER)
        c.setLineWidth(0.4)
        c.line(MARGIN, ry + ROW_H, MARGIN + TABLE_W, ry + ROW_H)

        text_y = ry + (ROW_H - 9) / 2 + 1

        for i, fn in enumerate(row_fields):
            val = str(fn(pod))
            # POD column gets Cisco blue bold treatment
            if i == 0:
                c.setFillColor(C_POD_NUM)
                c.setFont(FONT_BOLD, 9)
            else:
                c.setFillColor(C_VALUE)
                c.setFont(FONT_REG, 9)
            val_str = _truncate(c, val, FONT_BOLD if i == 0 else FONT_REG, 9,
                                col_widths[i] - COL_PAD * 2)
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
    c.setFillColor(C_TAGLINE)
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

        # Page background
        c.setFillColor(C_BG)
        c.rect(0, 0, PAGE_W, PAGE_H, stroke=0, fill=1)

        # Page header strip
        c.setFillColor(colors.HexColor("#060d16"))
        c.rect(0, PAGE_H - 0.22 * inch, PAGE_W, 0.22 * inch, stroke=0, fill=1)
        c.setFillColor(C_LABEL)
        c.setFont(FONT_REG, 6.5)
        c.drawString(MARGIN, PAGE_H - 0.15 * inch, "CISCO CONFIDENTIAL — FOR PROCTOR USE ONLY")
        page_num = page_start // per_page + 1
        c.drawRightString(PAGE_W - MARGIN, PAGE_H - 0.15 * inch, f"Page {page_num} of {total_pages}")

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
    pdf_bytes = generate_pdf(test_pods)
    with open("/tmp/lab_details_test.pdf", "wb") as f:
        f.write(pdf_bytes)
    print(f"Written {len(pdf_bytes):,} bytes → /tmp/lab_details_test.pdf")
