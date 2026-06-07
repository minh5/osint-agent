import json
import logging
from datetime import datetime
from pathlib import Path

import config
from models.shared import PipelineState

logger = logging.getLogger(__name__)


# ── Colour palette ────────────────────────────────────────────────────────────
_RED    = (0.85, 0.15, 0.15)
_ORANGE = (0.90, 0.45, 0.05)
_GREEN  = (0.10, 0.60, 0.25)
_DARK   = (0.10, 0.10, 0.15)
_MID    = (0.35, 0.35, 0.40)
_LIGHT  = (0.94, 0.94, 0.96)
_WHITE  = (1.00, 1.00, 1.00)
_ACCENT = (0.18, 0.36, 0.72)


def _risk_colour(level: str):
    l = (level or "").lower()
    if l == "high":   return _RED
    if l == "medium": return _ORANGE
    return _GREEN


def _write_pdf(pdf_path: Path, state: PipelineState, analysis: dict) -> None:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.enums import TA_LEFT, TA_CENTER
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether,
    )
    from reportlab.lib import colors

    primary  = state.classifications[0] if state.classifications else None
    target   = primary.value if primary else "unknown"
    ts       = datetime.now().strftime("%Y-%m-%d %H:%M")
    risk_lvl = (analysis.get("overall_risk_level") or "low").upper()
    risk_scr = analysis.get("overall_risk_score", 0)
    risk_col = colors.Color(*_risk_colour(risk_lvl))

    known       = analysis.get("what_is_known", {}) or {}
    remediation = analysis.get("remediation",   {}) or {}

    doc = SimpleDocTemplate(
        str(pdf_path),
        pagesize=A4,
        leftMargin=18*mm, rightMargin=18*mm,
        topMargin=16*mm,  bottomMargin=16*mm,
    )
    W = A4[0] - 36*mm  # usable width

    # ── Styles ────────────────────────────────────────────────────────────────
    def style(name, **kw) -> ParagraphStyle:
        base = dict(fontName="Helvetica", fontSize=10, leading=14,
                    textColor=colors.Color(*_DARK), spaceAfter=2)
        base.update(kw)
        return ParagraphStyle(name, **base)

    S = {
        "h1":     style("h1",  fontName="Helvetica-Bold", fontSize=20, leading=24,
                         textColor=colors.Color(*_ACCENT), spaceAfter=2),
        "meta":   style("meta", fontSize=9, textColor=colors.Color(*_MID)),
        "h2":     style("h2",  fontName="Helvetica-Bold", fontSize=13, leading=17,
                         textColor=colors.Color(*_ACCENT), spaceBefore=10, spaceAfter=4),
        "h3":     style("h3",  fontName="Helvetica-Bold", fontSize=10, leading=14,
                         textColor=colors.Color(*_DARK), spaceBefore=6, spaceAfter=2),
        "body":   style("body", leading=15),
        "bullet": style("bullet", leftIndent=12, bulletIndent=0, leading=15),
        "check":  style("check", fontName="Helvetica", fontSize=9, leading=14,
                         leftIndent=12, textColor=colors.Color(*_DARK)),
        "small":  style("small", fontSize=8, textColor=colors.Color(*_MID)),
    }

    def hr():
        return HRFlowable(width="100%", thickness=0.5,
                          color=colors.Color(*_LIGHT), spaceAfter=6, spaceBefore=2)

    def h2(text):
        return Paragraph(text, S["h2"])

    def h3(text):
        return Paragraph(text, S["h3"])

    def body(text):
        return Paragraph(text, S["body"])

    def bullet(text):
        return Paragraph(f"• &nbsp;{text}", S["bullet"])

    def checkbox(text):
        return Paragraph(f"☐ &nbsp;{text}", S["check"])

    def space(h=4):
        return Spacer(1, h*mm)

    # ── Build story ───────────────────────────────────────────────────────────
    story = []

    # Title block
    story += [
        Paragraph("Privacy OSINT Report", S["h1"]),
        Paragraph(f"Target: <b>{target}</b> &nbsp;·&nbsp; Generated: {ts}", S["meta"]),
        space(3),
    ]

    # Risk score banner
    banner_data = [[
        Paragraph("RISK SCORE", style("rs_label", fontName="Helvetica-Bold",
                  fontSize=8, textColor=colors.white, alignment=TA_CENTER)),
        Paragraph(f"{risk_scr}/100", style("rs_score", fontName="Helvetica-Bold",
                  fontSize=22, textColor=colors.white, alignment=TA_CENTER)),
        Paragraph(risk_lvl, style("rs_level", fontName="Helvetica-Bold",
                  fontSize=14, textColor=colors.white, alignment=TA_CENTER)),
    ]]
    banner = Table(banner_data, colWidths=[W*0.25, W*0.35, W*0.40])
    banner.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), risk_col),
        ("VALIGN",     (0,0), (-1,-1), "MIDDLE"),
        ("ALIGN",      (0,0), (-1,-1), "CENTER"),
        ("TOPPADDING", (0,0), (-1,-1), 8),
        ("BOTTOMPADDING", (0,0), (-1,-1), 8),
        ("ROUNDEDCORNERS", [4]),
    ]))
    story += [banner, space(5)]

    # Identity summary
    summary = analysis.get("identity_summary")
    if summary:
        story += [h2("What the Internet Knows About You"), body(summary), space(2)]

    # What is known sub-sections
    sections = [
        ("handles_and_usernames", "Usernames & Handles"),
        ("platforms_with_accounts", "Accounts Found"),
        ("physical_data", "Physical Data Exposed"),
        ("credentials_exposed", "Credentials in Circulation"),
        ("google_footprint", "Google Footprint"),
        ("breach_history", "Breach History"),
    ]
    for key, title in sections:
        items = known.get(key) or []
        if items:
            block = [h3(title)]
            for item in items:
                block.append(bullet(item))
            block.append(space(2))
            story.append(KeepTogether(block))

    # Top risks
    top_risks = analysis.get("top_risks") or []
    if top_risks:
        story += [hr(), h2("Top Risks")]
        for risk in top_risks:
            story.append(bullet(f'<font color="#{int(_RED[0]*255):02x}{int(_RED[1]*255):02x}{int(_RED[2]*255):02x}">⚠</font> &nbsp;{risk}'))
        story.append(space(2))

    # Findings context
    findings = analysis.get("findings_context") or []
    if findings:
        story += [hr(), h2("What Each Finding Means")]
        for f in findings:
            name = f.get("name", "")
            what = f.get("what_it_is", "")
            why  = f.get("why_it_matters", "")
            how  = f.get("how_to_remove", "")
            block = [h3(name)]
            if what: block.append(body(f"<b>What it is:</b> {what}"))
            if why:  block.append(body(f"<b>Why it matters:</b> {why}"))
            if how:  block.append(body(f"<b>How to remove:</b> {how}"))
            block.append(space(2))
            story.append(KeepTogether(block))

    # Remediation
    story += [hr(), h2("What To Do")]
    rem_sections = [
        ("do_today",      "Do Today"),
        ("do_this_week",  "Do This Week"),
        ("ongoing",       "Ongoing"),
    ]
    for key, title in rem_sections:
        items = remediation.get(key) or []
        if items:
            block = [h3(title)]
            for item in items:
                block.append(checkbox(item))
            block.append(space(2))
            story.append(KeepTogether(block))

    # Tool summary table
    story += [hr(), h2("Tool Results")]
    tool_rows = []
    def _tr(label, result_obj, value_fn):
        if result_obj and result_obj.success:
            tool_rows.append([label, value_fn(result_obj.data)])

    _tr("HIBP",       state.hibp_result,       lambda d: f"{d.get('breach_count',0)} breaches")
    _tr("Blackbird",  state.blackbird_result,  lambda d: f"{d.get('found_count',0)} accounts")
    _tr("Maigret",    state.sherlock_result,   lambda d: f"{d.get('found_count',0)} profiles / {d.get('platforms_checked',0)} platforms")
    _tr("Holehe",     state.holehe_result,     lambda d: f"{d.get('found_count',0)} registrations / {d.get('platforms_checked',0)} platforms")
    _tr("GHunt",      state.ghunt_result,      lambda d: "Found" if d.get("found") else "Not found")
    _tr("LeakRadar",  state.leakradar_result,  lambda d: f"{d.get('total_results',0)} results")
    _tr("SpiderFoot", state.spiderfoot_result, lambda d: f"{d.get('element_count',0)} elements")
    _tr("Broker scan",state.broker_result,     lambda d: f"{d.get('brokers_found_count',0)} brokers, score {d.get('exposure_score',0)}/100")
    _tr("AI Audit",   state.ai_audit_result,   lambda d: f"{d.get('high_risk_count',0)} high-risk platforms")

    if tool_rows:
        tbl = Table(
            [[Paragraph(r, style("tc", fontName="Helvetica-Bold", fontSize=9)),
              Paragraph(v, style("tv", fontSize=9))]
             for r, v in tool_rows],
            colWidths=[W*0.30, W*0.70],
        )
        tbl.setStyle(TableStyle([
            ("BACKGROUND",    (0,0), (-1,0),  colors.Color(*_ACCENT)),
            ("ROWBACKGROUNDS",(0,0), (-1,-1), [colors.Color(*_LIGHT), colors.white]),
            ("TEXTCOLOR",     (0,0), (-1,-1), colors.Color(*_DARK)),
            ("FONTNAME",      (0,0), (0,-1),  "Helvetica-Bold"),
            ("FONTSIZE",      (0,0), (-1,-1), 9),
            ("TOPPADDING",    (0,0), (-1,-1), 4),
            ("BOTTOMPADDING", (0,0), (-1,-1), 4),
            ("LEFTPADDING",   (0,0), (-1,-1), 6),
            ("GRID",          (0,0), (-1,-1), 0.3, colors.Color(*_LIGHT)),
        ]))
        story.append(tbl)

    story += [space(4), Paragraph("Generated by osint-agent · local processing · no data stored", S["small"])]

    doc.build(story)


def write_report(state: PipelineState) -> str:
    output_dir = Path(config.get("RESULTS_OUTPUT_PATH"))
    output_dir.mkdir(parents=True, exist_ok=True)

    primary    = state.classifications[0] if state.classifications else None
    input_type = primary.type if primary else "unknown"
    timestamp  = datetime.now().strftime("%Y-%m-%d_%H-%M")
    base_name  = f"{timestamp}_{input_type}"

    json_path = output_dir / f"{base_name}_results.json"
    md_path   = output_dir / f"{base_name}_report.md"
    pdf_path  = output_dir / f"{base_name}_report.pdf"

    json_path.write_text(json.dumps(state.model_dump(), indent=2, default=str))

    analysis    = state.analysis_result or {}
    known       = analysis.get("what_is_known", {}) or {}
    remediation = analysis.get("remediation",   {}) or {}

    # ── Markdown ──────────────────────────────────────────────────────────────
    lines = [
        "# Privacy OSINT Report",
        "",
        f"**Generated:** {timestamp}",
        f"**Target:** {primary.value if primary else 'unknown'}",
        f"**Risk Score:** {analysis.get('overall_risk_score', 'N/A')}/100 — {analysis.get('overall_risk_level', 'N/A').upper()}",
        "",
        "---",
        "",
        "## What the Internet Knows About You",
        "",
        analysis.get("identity_summary", "No analysis available."),
        "",
    ]

    for key, title in [
        ("handles_and_usernames",  "Usernames & Handles"),
        ("platforms_with_accounts","Accounts Found"),
        ("physical_data",          "Physical Data Exposed"),
        ("credentials_exposed",    "Credentials in Circulation"),
        ("google_footprint",       "Google Footprint"),
        ("breach_history",         "Breach History"),
    ]:
        items = known.get(key) or []
        if items:
            lines += [f"### {title}", ""]
            for item in items:
                lines.append(f"- {item}")
            lines.append("")

    if analysis.get("top_risks"):
        lines += ["---", "", "## Top Risks", ""]
        for risk in analysis["top_risks"]:
            lines.append(f"- {risk}")
        lines.append("")

    findings = analysis.get("findings_context") or []
    if findings:
        lines += ["---", "", "## What Each Finding Means", ""]
        for f in findings:
            name         = f.get("name", "")
            what         = f.get("what_it_is", "")
            why          = f.get("why_it_matters", "")
            how          = f.get("how_to_remove", "")
            lines += [f"### {name}", ""]
            if what: lines.append(f"**What it is:** {what}  ")
            if why:  lines.append(f"**Why it matters:** {why}  ")
            if how:  lines.append(f"**How to remove:** {how}")
            lines.append("")

    lines += ["---", "", "## What To Do", ""]
    for key, title in [("do_today","Do Today"),("do_this_week","Do This Week"),("ongoing","Ongoing")]:
        items = remediation.get(key) or []
        if items:
            lines += [f"### {title}", ""]
            for action in items:
                lines.append(f"- [ ] {action}")
            lines.append("")

    lines += ["---", "", "## Raw Tool Results", ""]
    if state.hibp_result       and state.hibp_result.success:
        lines.append(f"- **HIBP:** {state.hibp_result.data.get('breach_count',0)} breaches")
    if state.blackbird_result  and state.blackbird_result.success:
        lines.append(f"- **Blackbird:** {state.blackbird_result.data.get('found_count',0)} accounts found")
    if state.sherlock_result   and state.sherlock_result.success:
        lines.append(f"- **Maigret:** {state.sherlock_result.data.get('found_count',0)} profiles found across {state.sherlock_result.data.get('platforms_checked',0)} platforms")
    if state.ghunt_result      and state.ghunt_result.success:
        lines.append(f"- **GHunt:** {'Found' if state.ghunt_result.data.get('found') else 'Not found'}")
    if state.holehe_result     and state.holehe_result.success:
        lines.append(f"- **Holehe:** {state.holehe_result.data.get('found_count',0)} registrations found")
    if state.broker_result     and state.broker_result.success:
        lines.append(f"- **Broker scan:** {state.broker_result.data.get('brokers_found_count',0)} brokers, exposure score {state.broker_result.data.get('exposure_score',0)}/100")
    if state.leakradar_result  and state.leakradar_result.success:
        lines.append(f"- **LeakRadar:** {state.leakradar_result.data.get('total_results',0)} results")
    if state.spiderfoot_result and state.spiderfoot_result.success:
        lines.append(f"- **SpiderFoot:** {state.spiderfoot_result.data.get('element_count',0)} elements")
    if state.ai_audit_result   and state.ai_audit_result.success:
        lines.append(f"- **AI Audit:** {state.ai_audit_result.data.get('high_risk_count',0)} high-risk platforms")

    lines += ["", f"Full results: `{json_path}`"]

    md_content = "\n".join(lines)
    md_path.write_text(md_content)

    # ── PDF ───────────────────────────────────────────────────────────────────
    try:
        _write_pdf(pdf_path, state, analysis)
        logger.info("PDF written to %s", pdf_path)
    except Exception as exc:
        logger.warning("PDF generation failed: %s", exc)
        pdf_path = None

    # ── stdout ────────────────────────────────────────────────────────────────
    print(md_content)
    print(f"\nFull results saved to: {json_path}")
    print(f"Report saved to:       {md_path}")
    if pdf_path:
        print(f"PDF saved to:          {pdf_path}")

    logger.info("report written to %s", md_path)
    return str(md_path)
