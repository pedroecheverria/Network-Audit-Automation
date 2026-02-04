import os
import re
import json
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta, date
from collections import Counter, defaultdict

# PDF
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image,
    PageBreak
)
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors
from reportlab.lib.units import cm

# Charts
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


# CONFIG (LAB)
GITEA_BASE = "http://TU_IP:PUERTO"
OWNER = "TU_OWNER"
REPO = "TU_REPO"

TOKEN_FILE = "TU_TOKEN_FILE-PATH"

# Real mode window (only applies when DEMO_TIMELINE=0)
DAYS_WINDOW = int(os.environ.get("DAYS_WINDOW", "30"))

# Demo mode (opcional: Yo lo use para test)
DEMO_TIMELINE = os.environ.get("DEMO_TIMELINE", "0") == "1"
DEMO_TIMELINE_START = os.environ.get("DEMO_TIMELINE_START", "2026-01-20")
DEMO_TODAY = os.environ.get("DEMO_TODAY", "2026-02-03")

OUT_DIR = "FILE_PATH" # File donde quieres que se guarden los reportes con las imagenes. 

# Mail (opcional)
MAIL_TO = os.environ.get("MAIL_TO", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "")
SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASS = os.environ.get("SMTP_PASS", "")
SMTP_STARTTLS = os.environ.get("SMTP_STARTTLS", "1") == "1"


# Helpers
def read_token() -> str:
    with open(TOKEN_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()

def api_get(path: str, params: dict | None = None):
    token = read_token()
    url = f"{GITEA_BASE}{path}"
    if params:
        url += "?" + urllib.parse.urlencode(params)

    req = urllib.request.Request(url, headers={
        "Authorization": f"token {token}",
        "Accept": "application/json"
    })
    with urllib.request.urlopen(req, timeout=25) as r:
        return json.loads(r.read().decode("utf-8", errors="replace"))

def parse_dt(s: str | None):
    if not s:
        return None
    s = s.replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None

def parse_date_yyyy_mm_dd(s: str) -> date:
    return datetime.strptime(s, "%Y-%m-%d").date()

def ensure_outdir():
    os.makedirs(OUT_DIR, exist_ok=True)

def paginate_issues(state: str = "all"):
    items_all = []
    page = 1
    limit = 50

    while True:
        items = api_get(f"/api/v1/repos/{OWNER}/{REPO}/issues", {
            "state": state,
            "page": page,
            "limit": limit,
            "sort": "created",
            "direction": "desc"
        })
        if not items:
            break
        items_all.extend(items)
        if len(items) < limit:
            break
        page += 1

    return items_all

def severity_from_issue(issue: dict) -> str:
    labels = issue.get("labels") or []
    for lb in labels:
        name = (lb.get("name") or "").lower().strip()
        if name.startswith("severity::"):
            lvl = name.split("severity::", 1)[1].strip().upper()
            if lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                return lvl

    title = (issue.get("title") or "").strip()
    if title.startswith("[") and "]" in title:
        lvl = title[1:title.index("]")].strip().upper()
        if lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            return lvl

    return "UNKNOWN"

def safe(s: str) -> str:
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def extract_device_from_body(body: str) -> str:
    """
    Expects: **Node:** `Edge_Router`
    """
    if not body:
        return ""
    m = re.search(r"\*\*Node:\*\*\s*`([^`]+)`", body)
    if m:
        return m.group(1).strip()

    # fallback: "Node: Edge_Router"
    m = re.search(r"\bNode:\s*([A-Za-z0-9_.-]+)", body)
    if m:
        return m.group(1).strip()

    return ""

def extract_top_reason_from_body(body: str) -> str:
    """
    Expects:
    **Reasons**:
    - reason 1
    - reason 2

    Or fallback:
    Reasons:
      • reason 1
    """
    if not body:
        return ""

    m = re.search(r"\*\*Reasons\*\*:\s*\n-\s*(.+)", body)
    if m:
        first = m.group(1).strip().split("\n")[0].strip()
        return first

    m = re.search(r"\bReasons:\s*\n\s*•\s*(.+)", body)
    if m:
        first = m.group(1).strip().split("\n")[0].strip()
        return first

    return ""


# Charts (readable)
def make_donut(counts: dict, out_png: str, title: str):
    labels = list(counts.keys())
    sizes = [counts[k] for k in labels]
    total = sum(sizes)

    if total <= 0:
        labels = ["No data"]
        sizes = [1]

    fig, ax = plt.subplots(figsize=(5.0, 3.6))
    wedges, texts, autotexts = ax.pie(
        sizes,
        labels=None,
        autopct=lambda pct: f"{pct:.0f}%" if pct >= 8 else "",
        startangle=90,
        pctdistance=0.78
    )

    centre_circle = plt.Circle((0, 0), 0.62, fc="white")
    ax.add_artist(centre_circle)

    ax.set_title(title, fontsize=12, pad=10)
    ax.axis("equal")

    ax.legend(
        wedges,
        [f"{lab} ({counts.get(lab, 0)})" for lab in labels],
        loc="center left",
        bbox_to_anchor=(1.02, 0.5),
        fontsize=10,
        frameon=False
    )

    for t in autotexts:
        t.set_fontsize(11)

    fig.tight_layout()
    fig.savefig(out_png, dpi=200, bbox_inches="tight")
    plt.close(fig)

def make_timeline_two_series(series_critical: dict, series_high: dict, out_png: str, title: str):
    all_dates = sorted(set(series_critical.keys()) | set(series_high.keys()))
    if not all_dates:
        all_dates = [datetime.now(timezone.utc).date()]

    vals_c = [series_critical.get(d, 0) for d in all_dates]
    vals_h = [series_high.get(d, 0) for d in all_dates]

    fig, ax = plt.subplots(figsize=(10.5, 3.8))
    ax.plot(all_dates, vals_c, marker="o", linewidth=2, label="CRITICAL")
    ax.plot(all_dates, vals_h, marker="o", linewidth=2, label="HIGH")

    ax.set_title(title, fontsize=12, pad=10)
    ax.set_xlabel("Date", fontsize=11)
    ax.set_ylabel("Incidents", fontsize=11)
    ax.tick_params(axis="both", labelsize=10)

    ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.35)
    ax.legend(fontsize=10, frameon=False, loc="upper left")

    fig.autofmt_xdate(rotation=35)
    fig.tight_layout()
    fig.savefig(out_png, dpi=200, bbox_inches="tight")
    plt.close(fig)


# Timeline builders
def build_timeline_real(highcrit_issues: list[dict], window_start_date: date):
    critical_daily = defaultdict(int)
    high_daily = defaultdict(int)

    for it in highcrit_issues:
        created = parse_dt(it.get("created_at"))
        if not created:
            continue
        d = created.date()
        if d < window_start_date:
            continue

        sev = severity_from_issue(it)
        if sev == "CRITICAL":
            critical_daily[d] += 1
        elif sev == "HIGH":
            high_daily[d] += 1

    return critical_daily, high_daily

def build_timeline_demo(highcrit_issues: list[dict], start_date: date, end_date: date):
    critical_daily = defaultdict(int)
    high_daily = defaultdict(int)

    if end_date < start_date:
        start_date, end_date = end_date, start_date

    days = max(1, (end_date - start_date).days + 1)

    def sort_key(it):
        sev = severity_from_issue(it)
        sev_rank = 0 if sev == "CRITICAL" else 1
        created = parse_dt(it.get("created_at")) or datetime(1970, 1, 1, tzinfo=timezone.utc)
        return (sev_rank, created)

    ordered = sorted(
        [it for it in highcrit_issues if severity_from_issue(it) in ("HIGH", "CRITICAL")],
        key=sort_key
    )

    for idx, it in enumerate(ordered):
        assigned_day = start_date + timedelta(days=(idx % days))
        sev = severity_from_issue(it)
        if sev == "CRITICAL":
            critical_daily[assigned_day] += 1
        elif sev == "HIGH":
            high_daily[assigned_day] += 1

    return critical_daily, high_daily


# Email
def send_email_with_attachment(pdf_path: str, subject: str, body: str):
    if not (MAIL_TO and MAIL_FROM and SMTP_HOST):
        return False, "MAIL_TO/MAIL_FROM/SMTP_HOST not set (skipping email)."

    import smtplib
    from email.message import EmailMessage

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = MAIL_FROM
    msg["To"] = MAIL_TO
    msg.set_content(body)

    with open(pdf_path, "rb") as f:
        data = f.read()
    msg.add_attachment(data, maintype="application", subtype="pdf", filename=os.path.basename(pdf_path))

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=25) as s:
        if SMTP_STARTTLS:
            s.starttls()
        if SMTP_USER:
            s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

    return True, "Email sent."


# PDF Styling
def build_styles():
    base = getSampleStyleSheet()

    title = ParagraphStyle(
        "CLevelTitle",
        parent=base["Title"],
        fontSize=20,
        leading=24,
        spaceAfter=8
    )
    subtitle = ParagraphStyle(
        "CLevelSubtitle",
        parent=base["Normal"],
        fontSize=11,
        leading=14,
        textColor=colors.HexColor("#333333"),
        spaceAfter=10
    )
    h2 = ParagraphStyle(
        "CLevelH2",
        parent=base["Heading2"],
        fontSize=14,
        leading=18,
        spaceBefore=10,
        spaceAfter=8
    )
    normal = ParagraphStyle(
        "CLevelNormal",
        parent=base["Normal"],
        fontSize=10.5,
        leading=14
    )
    small = ParagraphStyle(
        "CLevelSmall",
        parent=base["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#444444")
    )
    note = ParagraphStyle(
        "CLevelNote",
        parent=base["Normal"],
        fontSize=9,
        leading=12,
        textColor=colors.HexColor("#555555"),
        backColor=colors.HexColor("#F5F6F8"),
        borderPadding=6,
        spaceBefore=8,
        spaceAfter=8
    )
    return {"title": title, "subtitle": subtitle, "h2": h2, "normal": normal, "small": small, "note": note}


# Report builder
def build_report():
    ensure_outdir()
    styles = build_styles()

    issues_all = paginate_issues("all")
    now_real = datetime.now(timezone.utc)

    if DEMO_TIMELINE:
        today = parse_date_yyyy_mm_dd(DEMO_TODAY)
        demo_start = parse_date_yyyy_mm_dd(DEMO_TIMELINE_START)
    else:
        today = now_real.date()
        demo_start = None

    status_counter = Counter()
    sev_counter = Counter()
    high_status = Counter()
    critical_status = Counter()

    highcrit_issues = []
    for it in issues_all:
        state = (it.get("state") or "").lower()
        status_counter[state] += 1

        sev = severity_from_issue(it)
        sev_counter[sev] += 1

        if sev == "HIGH":
            high_status[state] += 1
        elif sev == "CRITICAL":
            critical_status[state] += 1

        if sev in ("HIGH", "CRITICAL"):
            highcrit_issues.append(it)

    # Charts
    donut_share_png = os.path.join(OUT_DIR, "donut_high_vs_critical.png")
    donut_high_status_png = os.path.join(OUT_DIR, "donut_high_open_closed.png")
    donut_critical_status_png = os.path.join(OUT_DIR, "donut_critical_open_closed.png")
    timeline_png = os.path.join(OUT_DIR, "timeline_critical_high.png")

    donut_counts = {
        "CRITICAL": sev_counter.get("CRITICAL", 0),
        "HIGH": sev_counter.get("HIGH", 0),
    }

    make_donut(donut_counts, donut_share_png, "Severity distribution (HIGH vs CRITICAL)")
    make_donut(
        {"Open": high_status.get("open", 0), "Closed": high_status.get("closed", 0)},
        donut_high_status_png,
        "HIGH incidents — Open vs Closed"
    )
    make_donut(
        {"Open": critical_status.get("open", 0), "Closed": critical_status.get("closed", 0)},
        donut_critical_status_png,
        "CRITICAL incidents — Open vs Closed"
    )

    # Timeline
    if DEMO_TIMELINE:
        critical_daily, high_daily = build_timeline_demo(highcrit_issues, demo_start, today)
        timeline_title = f"Incident trend over time (DEMO) — {demo_start.isoformat()} to {today.isoformat()}"
    else:
        window_start = (now_real - timedelta(days=DAYS_WINDOW)).date()
        critical_daily, high_daily = build_timeline_real(highcrit_issues, window_start)
        timeline_title = f"Incident trend over time — last {DAYS_WINDOW} days"

    make_timeline_two_series(critical_daily, high_daily, timeline_png, timeline_title)

    # PDF output
    pdf_name = f"network_change_incidents_report_{today.isoformat()}.pdf"
    pdf_path = os.path.join(OUT_DIR, pdf_name)

    doc = SimpleDocTemplate(
        pdf_path,
        pagesize=A4,
        leftMargin=2.0*cm,
        rightMargin=2.0*cm,
        topMargin=1.8*cm,
        bottomMargin=1.8*cm,
        title="Network Change Incidents Report"
    )

    elements = []

    # Cover
    elements.append(Paragraph("Network Change Incidents Report", styles["title"]))
    elements.append(Paragraph(
        f"<b>Repository:</b> {OWNER}/{REPO} &nbsp;&nbsp;&nbsp; "
        f"<b>Generated (UTC):</b> {now_real.strftime('%Y-%m-%d %H:%M:%S')}",
        styles["subtitle"]
    ))

    total = sum(status_counter.values())
    open_n = status_counter.get("open", 0)
    closed_n = status_counter.get("closed", 0)
    high_n = sev_counter.get("HIGH", 0)
    crit_n = sev_counter.get("CRITICAL", 0)

    exec_summary = (
        "This report summarizes <b>security-relevant network configuration changes</b> detected via "
        "automated change monitoring and ticketing. It highlights backlog, severity distribution, "
        "and recent trends of <b>HIGH</b> and <b>CRITICAL</b> incidents requiring review."
    )
    elements.append(Paragraph(exec_summary, styles["normal"]))
    elements.append(Spacer(1, 10))

    # Summary table
    elements.append(Paragraph("Key metrics", styles["h2"]))
    summary_data = [
        ["Total issues", str(total)],
        ["Open", str(open_n)],
        ["Closed", str(closed_n)],
        ["HIGH", str(high_n)],
        ["CRITICAL", str(crit_n)],
    ]

    tbl = Table(summary_data, colWidths=[7.0*cm, 3.0*cm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#E9EDF2")),
        ("TEXTCOLOR", (0,0), (-1,-1), colors.HexColor("#111111")),
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#B8C0CC")),
        ("FONTSIZE", (0,0), (-1,-1), 10.5),
        ("ALIGN", (1,0), (1,-1), "RIGHT"),
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.white, colors.HexColor("#FAFBFC")]),
        ("LEFTPADDING", (0,0), (-1,-1), 8),
        ("RIGHTPADDING", (0,0), (-1,-1), 8),
        ("TOPPADDING", (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
    ]))
    elements.append(tbl)
    elements.append(Spacer(1, 14))

    # Charts
    elements.append(Paragraph("Visual overview", styles["h2"]))

    img1 = Image(donut_share_png, width=5.7*cm, height=4.1*cm)
    img2 = Image(donut_high_status_png, width=5.7*cm, height=4.1*cm)
    img3 = Image(donut_critical_status_png, width=5.7*cm, height=4.1*cm)

    row = Table([[img1, img2, img3]], colWidths=[6.2*cm, 6.2*cm, 6.2*cm])
    row.setStyle(TableStyle([
        ("VALIGN", (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
        ("LEFTPADDING", (0,0), (-1,-1), 0),
        ("RIGHTPADDING", (0,0), (-1,-1), 0),
        ("TOPPADDING", (0,0), (-1,-1), 0),
        ("BOTTOMPADDING", (0,0), (-1,-1), 0),
    ]))
    elements.append(row)
    elements.append(Spacer(1, 10))

    elements.append(Image(timeline_png, width=17.0*cm, height=6.4*cm))
    elements.append(Spacer(1, 10))

    # Page 2
    elements.append(PageBreak())
    elements.append(Paragraph("Latest HIGH/CRITICAL incidents", styles["h2"]))
    elements.append(Paragraph(
        "Top 15 most recent HIGH/CRITICAL incidents (device + top reason).",
        styles["small"]
    ))
    elements.append(Spacer(1, 6))

    def issue_created(it):
        dt = parse_dt(it.get("created_at"))
        return dt if dt else datetime(1970, 1, 1, tzinfo=timezone.utc)

    def sev_rank(it):
        return 0 if severity_from_issue(it) == "CRITICAL" else 1

    highcrit_sorted = sorted(
        highcrit_issues,
        key=lambda it: (sev_rank(it), -issue_created(it).timestamp())
    )[:15]

    rows = [[
        Paragraph("<b>Severity</b>", styles["small"]),
        Paragraph("<b>State</b>", styles["small"]),
        Paragraph("<b>Created (UTC)</b>", styles["small"]),
        Paragraph("<b>Device</b>", styles["small"]),
        Paragraph("<b>Top reason</b>", styles["small"]),
    ]]

    for it in highcrit_sorted:
        sev = severity_from_issue(it)
        state = (it.get("state") or "").upper()
        created = issue_created(it).strftime("%Y-%m-%d %H:%M")

        body_txt = it.get("body") or ""
        device = extract_device_from_body(body_txt) or "(unknown)"
        reason = extract_top_reason_from_body(body_txt) or "(no reason parsed)"

        rows.append([
            Paragraph(safe(sev), styles["small"]),
            Paragraph(safe(state), styles["small"]),
            Paragraph(safe(created), styles["small"]),
            Paragraph(safe(device), styles["small"]),
            Paragraph(safe(reason), styles["small"]),
        ])

    # widths: Reason is largest
    t2 = Table(rows, colWidths=[2.0*cm, 2.0*cm, 3.2*cm, 3.2*cm, 7.2*cm])
    t2.setStyle(TableStyle([
        ("GRID", (0,0), (-1,-1), 0.5, colors.HexColor("#B8C0CC")),
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#E9EDF2")),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
        ("LEFTPADDING", (0,0), (-1,-1), 6),
        ("RIGHTPADDING", (0,0), (-1,-1), 6),
        ("TOPPADDING", (0,0), (-1,-1), 4),
        ("BOTTOMPADDING", (0,0), (-1,-1), 4),
    ]))
    elements.append(t2)

    # DEMO note at bottom
    if DEMO_TIMELINE:
        elements.append(Spacer(1, 10))
        demo_note = (
            "<b>DEMO note:</b> The timeline shown in this report is generated for demonstration purposes only "
            "to illustrate how weekly/biweekly reporting and trending would look. "
            "In production, the trend must be built from real timestamps (e.g., Gitea <i>created_at</i> / <i>closed_at</i>) "
            "or from commit timestamps in the Oxidized Git repository."
        )
        elements.append(Paragraph(demo_note, styles["note"]))

    doc.build(elements)

    return {
        "pdf": pdf_path,
        "total": total,
        "open": open_n,
        "closed": closed_n,
        "high": high_n,
        "critical": crit_n,
        "demo": DEMO_TIMELINE,
        "today": today.isoformat(),
        "demo_start": (demo_start.isoformat() if demo_start else "")
    }


def main():
    info = build_report()
    print(f"[OK] PDF generated: {info['pdf']}")

    subject = f"Network Change Incidents Report - {OWNER}/{REPO}"
    body = (
        f"Attached is the latest report.\n\n"
        f"Total issues: {info['total']}\n"
        f"Open: {info['open']} | Closed: {info['closed']}\n"
        f"HIGH: {info['high']} | CRITICAL: {info['critical']}\n"
    )
    if info["demo"]:
        body += f"Timeline mode: DEMO ({info['demo_start']} to {info['today']})\n"
    else:
        body += "Timeline mode: REAL\n"

    ok, msg = send_email_with_attachment(info["pdf"], subject, body)
    print(f"[MAIL] {msg}")


if __name__ == "__main__":
    main()

