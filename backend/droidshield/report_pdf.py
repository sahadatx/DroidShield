"""Bounded, escaped ReportLab PDF rendering from a frozen report allowlist."""

import io
from pathlib import Path
from threading import RLock
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    HRFlowable,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)

_FONT_LOCK = RLock()


def _fonts():
    with _FONT_LOCK:
        if "DSBody" not in pdfmetrics.getRegisteredFontNames():
            root = Path(__file__).parent / "report_fonts"
            pdfmetrics.registerFont(TTFont("DSBody", str(root / "FreeSans.ttf"), shapable=True))
            pdfmetrics.registerFont(TTFont("DSBold", str(root / "FreeSansBold.ttf"), shapable=True))
            pdfmetrics.registerFontFamily(
                "DSBody", normal="DSBody", bold="DSBold", italic="DSBody", boldItalic="DSBold"
            )


def _safe(value):
    text = str(value) if value is not None else "Not recorded"
    text = "".join(
        character if ord(character) >= 32 or character == "\n" else " " for character in text
    )
    return escape(text).replace("\n", "<br/>")


def render_pdf(envelope: dict) -> bytes:
    _fonts()
    payload = envelope["report"]
    styles = getSampleStyleSheet()
    for style in styles.byName.values():
        style.fontName = "DSBody"
        style.fontSize = 9
        style.leading = 13
        style.textColor = colors.HexColor("#223147")
        style.shaping = 1
    styles["Title"].fontName = "DSBold"
    styles["Title"].fontSize = 27
    styles["Title"].leading = 33
    styles["Title"].alignment = TA_LEFT
    styles["Heading1"].fontName = "DSBold"
    styles["Heading1"].fontSize = 16
    styles["Heading1"].leading = 21
    styles["Heading1"].spaceBefore = 15
    styles["Heading1"].spaceAfter = 9
    styles["Heading2"].fontName = "DSBold"
    styles["Heading2"].fontSize = 11
    styles["Heading2"].leading = 15
    styles.add(
        ParagraphStyle(
            "Muted",
            parent=styles["BodyText"],
            textColor=colors.HexColor("#617085"),
            fontSize=8,
            leading=11,
        )
    )
    styles.add(ParagraphStyle("SmallCell", parent=styles["BodyText"], fontSize=7.4, leading=10))
    body = []

    def paragraph(value, style="BodyText"):
        return Paragraph(_safe(value), styles[style])

    def section(title):
        body.append(paragraph(title, "Heading1"))

    def field(label, value):
        body.append(Paragraph(f"<b>{_safe(label)}</b><br/>{_safe(value)}", styles["BodyText"]))
        body.append(Spacer(1, 5))

    def table(rows, widths):
        data = [[paragraph(value, "SmallCell") for value in row] for row in rows]
        result = LongTable(
            data, colWidths=widths, repeatRows=1, hAlign="LEFT", splitByRow=1, splitInRow=1
        )
        result.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e4f3f2")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.HexColor("#133f43")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ("LINEBELOW", (0, 0), (-1, 0), 0.7, colors.HexColor("#6daba6")),
                    ("LINEBELOW", (0, 1), (-1, -1), 0.3, colors.HexColor("#d8e0e6")),
                ]
            )
        )
        body.append(result)
        body.append(Spacer(1, 8))

    body.append(paragraph(payload["branding_name"], "Heading2"))
    body.append(Spacer(1, 24 * mm))
    body.append(paragraph(payload["title"], "Title"))
    body.append(paragraph("Mobile Application Security Assessment", "Heading2"))
    body.append(Spacer(1, 9 * mm))
    table(
        [
            ["CLIENT", "APPLICATION"],
            [payload["client"]["name"], payload["project"]["application_name"]],
        ],
        [84 * mm, 84 * mm],
    )
    field("Assessment", payload["assessment"]["name"])
    field("Report version", payload["version"])
    field("Prepared by", payload["author"]["name"])
    field("Approved at (UTC)", envelope["release"]["approved_at"])
    field("Classification", "Confidential - authorized client recipients only")
    body.append(Spacer(1, 14 * mm))
    body.append(paragraph(payload["alignment_notice"], "Muted"))
    body.append(PageBreak())
    section("Executive summary")
    body.append(paragraph(payload["executive_summary"]))
    section("Risk summary")
    table(
        [
            ["Critical", "High", "Medium", "Low", "Informational"],
            [
                str(payload["risk_summary"][key])
                for key in ("critical", "high", "medium", "low", "info")
            ],
        ],
        [33.6 * mm] * 5,
    )
    body.append(
        paragraph(
            f"Confirmed findings included: {len(payload['findings'])}. Findings excluded by verification or selected severity: {payload['excluded_findings_count']}.",
            "Muted",
        )
    )
    section("Scope and authorization")
    field("Application identifier", payload["project"]["package_id"])
    field(
        "Platform / artifact format",
        f"{payload['project'].get('platform', 'Not recorded')} / {payload['assessment'].get('artifact_format') or 'No application artifact'}",
    )
    field(
        "Scope snapshot source",
        str(payload["scope"].get("source", "not_recorded")).replace("_", " ").title(),
    )
    field("Authorization revision", payload["scope"].get("authorization_revision"))
    field(
        "Testing window (UTC)",
        f"{payload['scope'].get('valid_from') or 'Not recorded'} to {payload['scope'].get('valid_until') or 'Not recorded'}",
    )
    field("Artifact SHA-256", payload["assessment"]["artifact_sha256"])
    field("Authorization record", payload["scope"]["authorization_id"])
    field(
        "Approved targets", "\n".join(payload["scope"]["approved_targets"]) or "No targets recorded"
    )
    field(
        "Assessment targets", "\n".join(payload["scope"]["tested_targets"]) or "No targets recorded"
    )
    field("Exclusions", "\n".join(payload["scope"]["exclusions"]) or "None recorded")
    section("Methodology and limitations")
    body.append(paragraph(payload["limitations"]))
    for limitation in payload["engine_limitations"]:
        body.append(paragraph(limitation, "Muted"))
    body.append(
        paragraph(
            "Manual and external-tool observations are analyst supplied. A recorded Pass applies only to its documented environment, artifact and procedure. Untested controls are visible below.",
            "Muted",
        )
    )
    section("Coverage matrix")
    coverage = payload["coverage"]
    cases = coverage.get("cases", [])
    rows = [["TEST / MAPPING", "PLATFORM", "STATUS"]]
    for case in cases:
        snapshot = case.get("case_snapshot", case)
        title = case.get(
            "title", snapshot.get("title", snapshot.get("test_title", case.get("case_id", "Test")))
        )
        mapping = [
            f"{reference['id']} ({reference['version']})"
            for reference in snapshot.get("references", [])
            if reference.get("framework") in {"MASVS", "MOBILE-TOP-10"}
        ]
        execution = case.get("execution") or {}
        platform = execution.get("platform") or " / ".join(
            snapshot.get("platforms", ["android", "ios"])
        )
        rows.append(
            [
                f"{title}\n{', '.join(mapping) if isinstance(mapping, list) else mapping}",
                platform,
                str(case.get("status", "not_run")).replace("_", " ").title(),
            ]
        )
    if len(rows) == 1:
        rows.append(["No coverage records available", "-", "Not Run"])
    body.append(
        paragraph(
            "; ".join(
                f"{framework['id']} {framework['version']}"
                for framework in coverage.get("frameworks", [])
            ),
            "Muted",
        )
    )
    table(rows, [115 * mm, 26 * mm, 27 * mm])
    if payload["remediation_roadmap"]:
        body.append(PageBreak())
        section("Prioritized remediation roadmap")
        table(
            [["PRIORITY / FINDING", "SEVERITY", "STATUS"]]
            + [
                [
                    f"{item['priority']}. {item['title']}",
                    item["severity"].title(),
                    item["status"].replace("_", " ").title(),
                ]
                for item in payload["remediation_roadmap"]
            ],
            [115 * mm, 26 * mm, 27 * mm],
        )
        body.append(
            paragraph(
                "Priority follows assessed severity; the client should agree owners and due dates based on exposure and business impact. No due dates are implied by the report.",
                "Muted",
            )
        )
    if payload["template"] in {"technical", "combined"}:
        section("Technical findings")
        if not payload["findings"]:
            body.append(
                paragraph(
                    "No confirmed findings match the selected severity filter. This does not establish that the application is free of vulnerabilities."
                )
            )
        for index, item in enumerate(payload["findings"], 1):
            body.append(paragraph(f"{index}. {item['title']}", "Heading2"))
            field(
                "Severity / remediation",
                f"{item['severity'].title()} / {item['remediation_status'].replace('_', ' ').title()}",
            )
            if item["cvss_vector"]:
                field("CVSS base score / vector", f"{item['cvss_score']} / {item['cvss_vector']}")
            field("Affected component", item["affected_component"])
            field("Description", item["description"])
            field("Impact", item["impact"])
            field("Reproduction steps / proof of concept", item["reproduction_steps"])
            if item["remediation"]:
                field("Remediation", item["remediation"])
            field(
                "MASVS / CWE",
                ", ".join(item["masvs_mapping"] + item["cwe_mapping"]) or "No mapping recorded",
            )
            for evidence in item["evidence"]:
                body.append(paragraph(f"Evidence: {evidence['title']}", "Heading2"))
                field(
                    "Provenance",
                    f"{evidence['platform']} / {evidence['tool']} {evidence['tool_version']} / {evidence['environment']}",
                )
                field("Evidence SHA-256", evidence["sha256"])
                body.append(paragraph(evidence["text"]))
            body.append(
                HRFlowable(
                    width="100%",
                    thickness=0.5,
                    color=colors.HexColor("#d8e0e6"),
                    spaceBefore=10,
                    spaceAfter=10,
                )
            )
    section("Retesting results")
    if payload["retests"]:
        table(
            [["FINDING / ARTIFACT", "RESULT", "REVIEWED (UTC)"]]
            + [
                [
                    f"{item['finding_id']}\n{item['new_artifact_sha256'] or item.get('new_release_ref') or 'No artifact recorded'}",
                    item["result"].replace("_", " ").title(),
                    item["reviewed_at"],
                ]
                for item in payload["retests"]
            ],
            [104 * mm, 27 * mm, 37 * mm],
        )
        for item in payload["retests"]:
            field(
                "Retest method / notes",
                f"{item['method']} / {item['notes'] or 'No additional notes'}",
            )
            for proof in item.get("new_evidence", []):
                field(f"Retest evidence: {proof['title']}", proof["text"])
                body.append(paragraph(f"Evidence SHA-256: {proof['sha256']}", "Muted"))
    else:
        body.append(
            paragraph(
                "No approved retest results were available when this report version was frozen."
            )
        )
    body.append(PageBreak())
    section("Appendix and provenance")
    field("Tool versions", json_text(payload["tool_versions"]))
    for framework in coverage.get("frameworks", []):
        field(f"{framework['id']} {framework['version']}", framework["url"])
    field("Report snapshot SHA-256", envelope["snapshot_sha256"])
    field("Assessment reviewer", payload["assessment"]["reviewer_id"])
    field("Report reviewer", envelope["release"]["reviewer_id"])
    body.append(paragraph(payload["alignment_notice"], "Muted"))
    output = io.BytesIO()
    document = SimpleDocTemplate(
        output,
        pagesize=A4,
        leftMargin=21 * mm,
        rightMargin=21 * mm,
        topMargin=22 * mm,
        bottomMargin=22 * mm,
        title=payload["title"],
        author=payload["author"]["name"],
        pageCompression=1,
    )

    def page(canvas, doc):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#21a89a"))
        canvas.setLineWidth(2)
        canvas.line(21 * mm, 282 * mm, 189 * mm, 282 * mm)
        canvas.setFont("DSBody", 7)
        canvas.setFillColor(colors.HexColor("#617085"))
        canvas.drawString(
            21 * mm, 14 * mm, f"DroidShield | Confidential | Version {payload['version']}"
        )
        canvas.drawRightString(189 * mm, 14 * mm, f"Page {doc.page}")
        canvas.restoreState()

    document.build(body, onFirstPage=page, onLaterPages=page)
    return output.getvalue()


def json_text(value):
    import json

    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True)
        if value
        else "No automated engine versions recorded; see coverage provenance for manual tools."
    )
