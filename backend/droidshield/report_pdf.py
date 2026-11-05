"""Bounded, escaped ReportLab PDF rendering from a frozen report allowlist."""

import base64
import binascii
import hashlib
import io
import warnings
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
    Image,
    LongTable,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)

_FONT_LOCK = RLock()
MAX_PDF_SCREENSHOTS = 10
MAX_PDF_SCREENSHOT_FILE_BYTES = 2 * 1024**2
MAX_PDF_SCREENSHOT_BYTES = 4 * 1024**2
MAX_PDF_SCREENSHOT_PIXELS = 8_000_000
MAX_PDF_SCREENSHOT_SIDE = 6_000
MAX_NORMALIZED_SCREENSHOT_BYTES = 6 * 1024**2


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


def _group_digest(value):
    digest = str(value)
    return " ".join(digest[index : index + 16] for index in range(0, len(digest), 16))


def _normalize_screenshots(envelope, report):
    expected = {}
    for finding in report.get("findings", []):
        for evidence in finding.get("evidence", []):
            attachment = evidence.get("attachment")
            if attachment and attachment.get("pdf_inclusion") == "embedded":
                expected[evidence["id"]] = attachment
    for retest in report.get("retests", []):
        for evidence in retest.get("new_evidence", []):
            attachment = evidence.get("attachment")
            if attachment and attachment.get("pdf_inclusion") == "embedded":
                expected[evidence["id"]] = attachment
    encoded_images = envelope.get("pdf_images", {})
    if not isinstance(encoded_images, dict) or encoded_images.keys() != expected.keys():
        raise ValueError("PDF screenshot assets do not match the approved snapshot")
    if len(expected) > MAX_PDF_SCREENSHOTS:
        raise ValueError("PDF screenshot count exceeds the fixed limit")
    raw_total = sum(item.get("file_size", 0) for item in expected.values())
    if raw_total > MAX_PDF_SCREENSHOT_BYTES:
        raise ValueError("PDF screenshot bytes exceed the fixed limit")

    from PIL import Image as PILImage

    PILImage.MAX_IMAGE_PIXELS = MAX_PDF_SCREENSHOT_PIXELS
    normalized = {}
    normalized_total = 0
    for evidence_id, metadata in expected.items():
        if (
            metadata.get("media_type") != "image/png"
            or not isinstance(metadata.get("file_size"), int)
            or metadata["file_size"] < 1
            or metadata["file_size"] > MAX_PDF_SCREENSHOT_FILE_BYTES
            or not isinstance(metadata.get("sha256"), str)
            or len(metadata["sha256"]) != 64
        ):
            raise ValueError("PDF screenshot metadata is invalid")
        try:
            raw = base64.b64decode(encoded_images[evidence_id], validate=True)
        except (binascii.Error, ValueError, TypeError) as exc:
            raise ValueError("PDF screenshot encoding is invalid") from exc
        if (
            len(raw) != metadata["file_size"]
            or hashlib.sha256(raw).hexdigest() != metadata["sha256"]
        ):
            raise ValueError("PDF screenshot integrity check failed")
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("error", PILImage.DecompressionBombWarning)
                with PILImage.open(io.BytesIO(raw), formats=["PNG"]) as image:
                    if (
                        image.format != "PNG"
                        or getattr(image, "n_frames", 1) != 1
                        or image.width < 1
                        or image.height < 1
                        or image.width > MAX_PDF_SCREENSHOT_SIDE
                        or image.height > MAX_PDF_SCREENSHOT_SIDE
                        or image.width * image.height > MAX_PDF_SCREENSHOT_PIXELS
                    ):
                        raise ValueError("PDF screenshot dimensions are unsupported")
                    image.verify()
                with PILImage.open(io.BytesIO(raw), formats=["PNG"]) as source:
                    source.load()
                    rgba = source.convert("RGBA")
                    clean = PILImage.new("RGB", rgba.size, "white")
                    clean.paste(rgba, mask=rgba.getchannel("A"))
                    clean.thumbnail((1600, 1200), PILImage.Resampling.LANCZOS)
                    output = io.BytesIO()
                    clean.save(output, format="PNG", optimize=False)
                    clean_bytes = output.getvalue()
                    normalized_total += len(clean_bytes)
                    if normalized_total > MAX_NORMALIZED_SCREENSHOT_BYTES:
                        raise ValueError("Normalized PDF screenshots exceed the fixed limit")
                    normalized[evidence_id] = (clean_bytes, clean.width, clean.height)
        except (
            OSError,
            SyntaxError,
            PILImage.DecompressionBombError,
            PILImage.DecompressionBombWarning,
        ) as exc:
            raise ValueError("PDF screenshot could not be safely decoded") from exc
    return normalized


def render_pdf(envelope: dict) -> bytes:
    _fonts()
    payload = envelope["report"]
    screenshot_images = _normalize_screenshots(envelope, payload)
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
                attachment = evidence.get("attachment")
                if attachment:
                    inclusion = attachment.get("pdf_inclusion")
                    if inclusion == "embedded":
                        image_bytes, image_width, image_height = screenshot_images[evidence["id"]]
                        scale = min(166 * mm / image_width, 100 * mm / image_height, 1)
                        field("Screenshot evidence ID", evidence["id"])
                        field("Source screenshot SHA-256", _group_digest(attachment["sha256"]))
                        body.append(
                            paragraph(
                                "Sanitized screenshot normalized for this PDF; source image metadata was stripped.",
                                "Muted",
                            )
                        )
                        body.append(
                            Image(
                                io.BytesIO(image_bytes),
                                width=image_width * scale,
                                height=image_height * scale,
                                hAlign="LEFT",
                            )
                        )
                        body.append(Spacer(1, 8))
                    elif inclusion == "omitted_limit":
                        body.append(
                            paragraph(
                                f"Screenshot evidence {evidence['id']} was not embedded because the PDF image limits were reached. Its protected evidence record remains available in the workspace.",
                                "Muted",
                            )
                        )
                    elif inclusion == "duplicate_reference":
                        body.append(
                            paragraph(
                                f"Screenshot evidence {evidence['id']} is shown at its first report reference.",
                                "Muted",
                            )
                        )
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
                attachment = proof.get("attachment")
                if attachment and attachment.get("pdf_inclusion") == "embedded":
                    image_bytes, image_width, image_height = screenshot_images[proof["id"]]
                    scale = min(166 * mm / image_width, 100 * mm / image_height, 1)
                    field("Retest screenshot evidence ID", proof["id"])
                    field("Source screenshot SHA-256", _group_digest(attachment["sha256"]))
                    body.append(
                        paragraph(
                            "Sanitized retest screenshot normalized for this PDF; source image metadata was stripped.",
                            "Muted",
                        )
                    )
                    body.append(
                        Image(
                            io.BytesIO(image_bytes),
                            width=image_width * scale,
                            height=image_height * scale,
                            hAlign="LEFT",
                        )
                    )
                    body.append(Spacer(1, 8))
    else:
        body.append(
            paragraph(
                "No approved retest results were available when this report version was frozen."
            )
        )
    body.append(PageBreak())
    section("Appendix and provenance")
    field("Tool versions", json_text(payload["tool_versions"]))
    screenshot_summary = payload.get("pdf_screenshots", {})
    if screenshot_summary:
        field(
            "Screenshot embedding",
            f"{screenshot_summary.get('embedded_count', 0)} embedded; "
            f"{screenshot_summary.get('omitted_by_limit', 0)} omitted by image limits; "
            f"{screenshot_summary.get('excluded_by_template', 0)} excluded by executive template",
        )
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
