"""Deliverable review, frozen client boundaries, export integrity and scoring."""

import hashlib
import io
import json
import struct
import unicodedata
import zlib
from datetime import UTC, datetime
from uuid import UUID

import pytest
from pypdf import PdfReader
from sqlalchemy import select
from sqlalchemy.orm import Session

from droidshield.cvss_scoring import score_cvss, validate_cvss
from droidshield.models import Assessment, AssessmentEvidence, AuditEvent, Finding
from droidshield.report_api import router
from droidshield.report_models import ReportExport
from tests.test_api import PREFIX, expect, grant, make_assessment, make_project
from tests.test_api import api as _api

api = _api
V4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
V31 = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
BODY = {
    "title": "Client mobile security assessment",
    "executive_summary": "Testing identified one confirmed issue requiring remediation.",
    "limitations": "Manual assessment of the documented application and account scope. Runtime coverage was not complete.",
}


@pytest.fixture
def reporting(api, tmp_path):
    if "/api/v1/reports" not in api.client.app.openapi()["paths"]:
        api.client.app.include_router(router)
    api.client.app.state.settings.storage_root = tmp_path / "private"
    return api


def completed(api, *, role="analyst"):
    project = make_project(api, role=role)
    assessment = make_assessment(api, project, role=role)
    with Session(api.engine) as session:
        item = session.get(Assessment, UUID(assessment["id"]))
        item.status = "completed"
        item.completed_at = datetime.now(UTC)
        item.reviewer_id = api.users["admin"]
        for title, status in (
            ("Confirmed issue", "confirmed"),
            ("Secret candidate must stay internal", "unreviewed"),
        ):
            session.add(
                Finding(
                    workspace_id=item.workspace_id,
                    project_id=item.project_id,
                    assessment_id=item.id,
                    title=title,
                    description="A verified application condition.",
                    affected_component="Application API",
                    category="authorization",
                    severity="high",
                    verification_status=status,
                    remediation_status="open",
                    cvss_vector=V31,
                    cvss_score=9.8,
                    masvs_mapping=["MASVS-AUTH-1"],
                    cwe_mapping=["CWE-862"],
                    reproduction_steps="1. Use the approved test account.\n2. Observe the documented condition.",
                    impact="Unauthorized disclosure is possible.",
                    remediation="Enforce object ownership on the server.",
                    evidence_provenance={},
                    created_by=api.users[role],
                )
            )
        session.commit()
    return project, assessment


def new_report(api, assessment, role="analyst", **changes):
    return expect(
        api.post(f"/assessments/{assessment['id']}/reports", {**BODY, **changes}, role=role), 201
    )


def test_report_library_filters_title_project_assessment_status_and_template(reporting):
    project, assessment = completed(reporting)
    report = new_report(reporting, assessment, template="technical")
    other_client = make_project(reporting, role="analyst")["client_id"]
    page = expect(
        reporting.get(
            "/reports",
            params={
                "q": "Client mobile",
                "client_id": project["client_id"],
                "project_id": project["id"],
                "assessment_id": assessment["id"],
                "status": "awaiting_review",
                "template": "technical",
            },
        )
    )
    assert page["total"] == 1
    assert page["items"][0]["id"] == report["id"]
    assert expect(reporting.get("/reports", params={"client_id": other_client}))["total"] == 0
    expect(
        reporting.get("/reports", role="other_admin", params={"client_id": project["client_id"]}),
        404,
    )
    expect(reporting.get("/reports", params={"template": "unknown"}), 422)


def _tiny_png():
    signature = b"\x89PNG\r\n\x1a\n"

    def chunk(kind, content):
        payload = kind + content
        return struct.pack(">I", len(content)) + payload + struct.pack(">I", zlib.crc32(payload))

    header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    return (
        signature
        + chunk(b"IHDR", header)
        + chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00\xff"))
        + chunk(b"IEND", b"")
    )


@pytest.mark.parametrize(
    "vector,score",
    [
        (V4, 10.0),
        (V31, 9.8),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", 0.0),
    ],
)
def test_exact_cvss_scoring(vector, score):
    assert score_cvss(vector)["score"] == score
    validate_cvss(vector, score)


@pytest.mark.parametrize(
    "vector,score",
    [
        (V4, 9.9),
        (None, 3.1),
        (V31, None),
        (V31 + "/E:F", 9.8),
        (V4 + "/AV:N", 10),
        (V4.replace("AT:N", "AT:X"), 10),
        ("CVSS:2.0/AV:N", 1.0),
        (V31, float("nan")),
    ],
)
def test_rejects_unvalidated_or_nonbase_cvss(vector, score):
    with pytest.raises(ValueError):
        validate_cvss(vector, score)


def test_report_reviewer_release_client_scope_and_json_integrity(reporting):
    api = reporting
    project, assessment = completed(api)
    report = new_report(api, assessment)
    assert report["status"] == "awaiting_review"
    assert (
        api.post(f"/reports/{report['id']}/exports", {"format": "json"}, role="analyst").status_code
        == 409
    )
    assert (
        api.post(
            f"/reports/{report['id']}/release", {"decision": "approve"}, role="analyst"
        ).status_code
        == 403
    )
    detail = expect(api.get(f"/reports/{report['id']}", role="analyst"))
    snapshot = detail["snapshot"]
    assert [f["title"] for f in snapshot["findings"]] == ["Confirmed issue"]
    assert snapshot["excluded_findings_count"] == 1
    assert "not_run" in json.dumps(snapshot["coverage"])
    assert "certification" in snapshot["alignment_notice"]
    assert api.get(f"/reports/{report['id']}", role="other_admin").status_code == 404
    assert api.get(f"/reports/{report['id']}", role="viewer").status_code == 404
    assert expect(api.get("/reports", role="other_admin"))["total"] == 0
    approved = expect(api.post(f"/reports/{report['id']}/release", {"decision": "approve"}))
    assert approved["reviewer_id"] == str(api.users["admin"])
    output = expect(
        api.post(
            f"/reports/{report['id']}/exports", {"format": "json"}, role="analyst", key="export-one"
        ),
        201,
    )
    assert output == expect(
        api.post(
            f"/reports/{report['id']}/exports", {"format": "json"}, role="analyst", key="export-one"
        ),
        201,
    )
    response = api.get(f"/report-exports/{output['id']}/download", role="analyst")
    assert response.status_code == 200
    assert hashlib.sha256(response.content).hexdigest() == output["sha256"]
    assert response.headers["x-content-sha256"] == output["sha256"]
    assert response.json()["report"] == snapshot
    assert (
        api.get(f"/report-exports/{output['id']}/download", role="other_admin").status_code == 404
    )
    assert "storage_ref" not in output
    grant(api, project, "viewer")
    assert api.get(f"/report-exports/{output['id']}/download", role="viewer").status_code == 200
    assert (
        api.post(f"/reports/{report['id']}/exports", {"format": "json"}, role="viewer").status_code
        == 403
    )
    with Session(api.engine) as session:
        events = session.scalars(select(AuditEvent)).all()
        assert "executive_summary" not in json.dumps([event.source_metadata for event in events])


def test_report_snapshot_references_screenshot_without_embedding_its_bytes(reporting):
    api = reporting
    _, assessment = completed(api)
    with Session(api.engine) as session:
        issue = session.scalar(
            select(Finding).where(
                Finding.assessment_id == UUID(assessment["id"]),
                Finding.verification_status == "confirmed",
            )
        )
        finding_id = str(issue.id)
    png = _tiny_png()
    evidence_response = api.client.post(
        PREFIX + f"/assessments/{assessment['id']}/evidence-attachments",
        data={
            "title": "Sanitized access-control proof",
            "sanitized": "true",
            "platform": "android",
            "tool": "Manual review",
            "tool_version": "1.0",
            "environment": "Dedicated client test lab",
            "finding_id": finding_id,
            "release_ref": "backend-release-2026-10-31",
        },
        files={"file": ("proof.png", png, "image/png")},
        headers=api.headers("analyst", "report-screenshot-evidence"),
    )
    evidence = expect(evidence_response, 201)
    with Session(api.engine) as session:
        issue = session.get(Finding, UUID(finding_id))
        issue.evidence_provenance = {"source": "manual", "evidence_ids": [evidence["id"]]}
        session.commit()

    report = new_report(api, assessment)
    report_detail = expect(api.get(f"/reports/{report['id']}", role="analyst"))
    snapshot = report_detail["snapshot"]
    proof = snapshot["findings"][0]["evidence"][0]
    assert proof["attachment"] == {
        "sha256": hashlib.sha256(png).hexdigest(),
        "file_size": len(png),
        "media_type": "image/png",
        "display_name": "screenshot.png",
        "pdf_inclusion": "embedded",
    }
    assert snapshot["pdf_screenshots"]["embedded_count"] == 1
    assert (
        hashlib.sha256(
            json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        == report_detail["snapshot_sha256"]
    )
    assert evidence["id"] == proof["id"]
    assert "Protected screenshot attachment" in proof["text"]
    assert png.hex() not in json.dumps(snapshot)
    expect(api.post(f"/reports/{report['id']}/release", {"decision": "approve"}, role="admin"))
    output = expect(
        api.post(f"/reports/{report['id']}/exports", {"format": "pdf"}, role="analyst"), 201
    )
    pdf = api.get(f"/report-exports/{output['id']}/download", role="analyst")
    assert pdf.status_code == 200
    reader = PdfReader(io.BytesIO(pdf.content))
    assert sum(len(page.images) for page in reader.pages) == 1
    text = "\n".join(page.extract_text() for page in reader.pages)
    assert "Sanitized screenshot" in text
    assert proof["attachment"]["sha256"] in unicodedata.normalize("NFKC", "".join(text.split()))

    executive = new_report(api, assessment, template="executive")
    executive_snapshot = expect(api.get(f"/reports/{executive['id']}", role="analyst"))["snapshot"]
    assert executive_snapshot["findings"][0]["evidence"][0]["attachment"]["pdf_inclusion"] == (
        "template_excluded"
    )
    expect(api.post(f"/reports/{executive['id']}/release", {"decision": "approve"}, role="admin"))
    executive_export = expect(
        api.post(f"/reports/{executive['id']}/exports", {"format": "pdf"}, role="analyst"),
        201,
    )
    executive_pdf = api.get(f"/report-exports/{executive_export['id']}/download", role="analyst")
    executive_reader = PdfReader(io.BytesIO(executive_pdf.content))
    assert sum(len(page.images) for page in executive_reader.pages) == 0


def test_pdf_export_rejects_tampered_screenshot_evidence(reporting):
    from droidshield.storage import Storage

    api = reporting
    _, assessment = completed(api)
    with Session(api.engine) as session:
        issue = session.scalar(
            select(Finding).where(
                Finding.assessment_id == UUID(assessment["id"]),
                Finding.verification_status == "confirmed",
            )
        )
        finding_id = str(issue.id)
    png = _tiny_png()
    evidence_response = api.client.post(
        PREFIX + f"/assessments/{assessment['id']}/evidence-attachments",
        data={
            "title": "Sanitized access-control proof",
            "sanitized": "true",
            "platform": "android",
            "tool": "Manual review",
            "tool_version": "1.0",
            "environment": "Dedicated client test lab",
            "finding_id": finding_id,
            "release_ref": "backend-release-2026-10-31",
        },
        files={"file": ("proof.png", png, "image/png")},
        headers=api.headers("analyst", "report-screenshot-tamper-evidence"),
    )
    evidence = expect(evidence_response, 201)
    with Session(api.engine) as session:
        issue = session.get(Finding, UUID(finding_id))
        issue.evidence_provenance = {"source": "manual", "evidence_ids": [evidence["id"]]}
        session.commit()
    report = new_report(api, assessment)
    expect(api.post(f"/reports/{report['id']}/release", {"decision": "approve"}, role="admin"))
    with Session(api.engine) as session:
        record = session.get(AssessmentEvidence, UUID(evidence["id"]))
        storage_ref = record.attachment.storage_ref
    storage = Storage(api.client.app.state.settings.storage_root / "evidence-attachments")
    path = storage._path(storage_ref)
    path.chmod(0o600)
    path.write_bytes(b"x" * len(png))
    response = api.client.post(
        PREFIX + f"/reports/{report['id']}/exports",
        json={"format": "pdf"},
        headers=api.headers("analyst", "tampered-report-screenshot-export"),
    )
    assert response.status_code == 503
    assert expect(api.get(f"/reports/{report['id']}/exports", role="analyst"))["total"] == 0


def test_independent_author_cannot_approve_own_report_and_versions_freeze(reporting):
    api = reporting
    _, assessment = completed(api, role="admin")
    report = new_report(api, assessment, role="admin")
    assert api.post(f"/reports/{report['id']}/release", {"decision": "approve"}).status_code == 403
    original = expect(api.get(f"/reports/{report['id']}"))["snapshot"]
    with Session(api.engine) as session:
        finding = session.scalar(
            select(Finding).where(
                Finding.assessment_id == UUID(assessment["id"]),
                Finding.verification_status == "confirmed",
            )
        )
        finding.title = "Later edit to finding"
        session.commit()
    second = new_report(api, assessment, role="admin")
    assert second["version"] == 2
    assert expect(api.get(f"/reports/{report['id']}"))["snapshot"] == original
    assert (
        expect(api.get(f"/reports/{second['id']}"))["snapshot"]["findings"][0]["title"]
        == "Later edit to finding"
    )


def test_requires_human_completed_assessment_and_declared_limitations(reporting):
    api = reporting
    project = make_project(api)
    assessment = make_assessment(api, project)
    assert api.post(f"/assessments/{assessment['id']}/reports", BODY).status_code == 409
    assert (
        api.post(
            f"/assessments/{assessment['id']}/reports", {**BODY, "limitations": ""}
        ).status_code
        == 422
    )
    assert api.post("/cvss/score", {"vector": V4}).json()["score"] == 10
    assert api.post("/cvss/score", {"vector": "secret invalid vector"}).status_code == 422


def test_pdf_escapes_narratives_and_paginates_long_content(reporting):
    api = reporting
    _, assessment = completed(api)
    report = new_report(
        api,
        assessment,
        title="Report <b>literal</b> & clients",
        executive_summary="Executive summary & <script>alert('x')</script>\n"
        + "Long narrative with reviewed evidence. " * 200,
        limitations="Testing coverage সীমিত।\n" + "A" * 1000,
    )
    expect(api.post(f"/reports/{report['id']}/release", {"decision": "approve"}))
    output = expect(
        api.post(f"/reports/{report['id']}/exports", {"format": "pdf"}, role="analyst"), 201
    )
    response = api.get(f"/report-exports/{output['id']}/download", role="analyst")
    assert response.content.startswith(b"%PDF-")
    reader = PdfReader(io.BytesIO(response.content))
    assert len(reader.pages) >= 4
    text = unicodedata.normalize("NFKC", "\n".join(page.extract_text() for page in reader.pages))
    assert "<script>" in text
    assert "<b>literal</b>" in text
    assert "Technical findings" in text
    assert "Retesting results" in text
    assert "Not Run" in text
    assert "MASVS-STORAGE-1 (2.1.0)" in text
    assert "M1 (2024)" in text
    assert hashlib.sha256(response.content).hexdigest() == output["sha256"]


def test_download_detects_tampered_export(reporting):
    api = reporting
    _, assessment = completed(api)
    report = new_report(api, assessment)
    expect(api.post(f"/reports/{report['id']}/release", {"decision": "approve"}))
    output = expect(
        api.post(f"/reports/{report['id']}/exports", {"format": "json"}, role="analyst"), 201
    )
    with Session(api.engine) as session:
        record = session.get(ReportExport, UUID(output["id"]))
        path = (
            api.client.app.state.settings.storage_root
            / "reports"
            / "objects"
            / (record.storage_ref[4:] + ".apk")
        )
        path.chmod(0o600)
        path.write_bytes(b"tampered")
    assert api.get(f"/report-exports/{output['id']}/download", role="analyst").status_code == 409


def test_execution_scope_and_detached_evidence_are_frozen(reporting):
    from droidshield import delivery, services
    from droidshield.delivery_schemas import EvidenceCreate
    from droidshield.models import User
    from tests.test_api import make_authorization

    api = reporting
    project, assessment = completed(api)
    permit = make_authorization(api, project)
    with Session(api.engine) as session:
        item = session.get(Assessment, UUID(assessment["id"]))
        item.authorization_id = UUID(permit["id"])
        item.configuration_snapshot = {
            "requested_targets": ["https://api.example.test/v1"],
            "manual": {
                "approved_targets": ["https://api.example.test/v1"],
                "exclusions": ["https://api.example.test/v1/excluded"],
                "authorization_id": permit["id"],
                "authorization_revision": 2,
                "valid_from": permit["valid_from"],
                "valid_until": permit["valid_until"],
            },
        }
        item.status = "needs_review"
        actor = session.get(User, api.users["analyst"])
        ctx = services.Context(session, actor, "report-evidence-fixture")
        proof = delivery.create_evidence(
            ctx,
            item.id,
            EvidenceCreate(
                title="Reviewed object ownership result",
                content="Sanitized reproducible observation with a test account only.",
                sanitized=True,
                platform="android",
                tool="Burp Suite",
                tool_version="recorded-version",
                environment="Dedicated authorized QA account",
            ),
            api.client.app.state.settings,
        )
        issue = session.scalar(
            select(Finding).where(
                Finding.assessment_id == item.id, Finding.verification_status == "confirmed"
            )
        )
        issue.evidence_provenance = {"source": "manual", "evidence_ids": [str(proof.id)]}
        item.status = "completed"
        session.commit()
    report = new_report(api, assessment)
    payload = expect(api.get(f"/reports/{report['id']}", role="analyst"))["snapshot"]
    assert payload["scope"]["source"] == "manual_execution_snapshot"
    assert payload["scope"]["exclusions"] == ["https://api.example.test/v1/excluded"]
    assert payload["scope"]["authorization_revision"] == 2
    assert payload["project"]["platform"] == "android"
    assert payload["findings"][0]["evidence"][0]["text"].startswith("Sanitized reproducible")
    assert "artifact_ref" not in json.dumps(payload)


def test_report_narratives_reject_credentials(reporting):
    api = reporting
    _, assessment = completed(api)
    response = api.post(
        f"/assessments/{assessment['id']}/reports",
        {**BODY, "executive_summary": "Captured Authorization: Bearer super-secret-credential"},
        role="analyst",
    )
    assert response.status_code == 422
    assert "super-secret-credential" not in response.text


def test_api_retests_preserve_release_references_without_fabricated_hashes(reporting):
    from droidshield.models import Retest

    api = reporting
    _, assessment = completed(api)
    with Session(api.engine) as session:
        issue = session.scalar(
            select(Finding).where(
                Finding.assessment_id == UUID(assessment["id"]),
                Finding.verification_status == "confirmed",
            )
        )
        session.add(
            Retest(
                workspace_id=issue.workspace_id,
                project_id=issue.project_id,
                finding_id=issue.id,
                original_assessment_id=issue.assessment_id,
                new_artifact_id=None,
                method="api",
                operator_id=api.users["analyst"],
                environment={
                    "original_release_ref": "backend-2026-10-01",
                    "new_release_ref": "backend-2026-10-28",
                    "artifact_sha256": None,
                },
                previous_evidence=[],
                new_evidence=[],
                result="inconclusive",
                notes="Service release recorded; the observed condition remains inconclusive.",
                reviewer_id=api.users["admin"],
                reviewed_at=datetime.now(UTC),
                review_decision="approve",
            )
        )
        session.commit()
    report = new_report(api, assessment)
    frozen = expect(api.get(f"/reports/{report['id']}", role="analyst"))["snapshot"]
    assert frozen["retests"][0]["new_artifact_sha256"] is None
    assert frozen["retests"][0]["new_release_ref"] == "backend-2026-10-28"
    assert frozen["retests"][0]["original_release_ref"] == "backend-2026-10-01"


@pytest.mark.parametrize("mobile", [False, True])
def test_new_retest_evidence_never_contaminates_original_finding(reporting, mobile):
    from droidshield import delivery, services
    from droidshield.delivery_schemas import EvidenceCreate
    from droidshield.models import AppArtifact, User
    from tests.test_api import make_authorization

    api = reporting
    project, assessment = completed(api)
    permit = make_authorization(
        api, project, approved_targets=["https://api.example.test/v1", "package:com.example.store"]
    )
    with Session(api.engine) as session:
        item = session.get(Assessment, UUID(assessment["id"]))
        item.authorization_id = UUID(permit["id"])
        issue = session.scalar(
            select(Finding).where(
                Finding.assessment_id == item.id, Finding.verification_status == "confirmed"
            )
        )
        actor = session.get(User, api.users["analyst"])
        ctx = services.Context(session, actor, "report-retest-evidence-fixture")
        old_artifact = new_artifact = None
        if mobile:
            artifacts = [
                AppArtifact(
                    workspace_id=item.workspace_id,
                    project_id=item.project_id,
                    sha256=character * 64,
                    storage_ref=f"fixture:{character}",
                    original_filename="fixture.apk",
                    file_size=10,
                    metadata_json={"package_name": project["package_id"]},
                    created_by=actor.id,
                )
                for character in ("a", "b")
            ]
            session.add_all(artifacts)
            session.flush()
            old_artifact, new_artifact = artifacts
            item.artifact_id = issue.artifact_id = old_artifact.id
            item.assessment_type = "static"
        item.status = "needs_review"
        evidence_fields = {
            "sanitized": True,
            "platform": "android",
            "tool": "Manual verification",
            "tool_version": "1",
            "environment": "Dedicated QA environment",
            "finding_id": issue.id,
        }
        original = delivery.create_evidence(
            ctx,
            item.id,
            EvidenceCreate(
                **evidence_fields,
                title="Original observed condition",
                content="Original release observation reviewed before completion.",
                artifact_id=old_artifact.id if mobile else None,
                release_ref=None if mobile else "api-release-original",
            ),
            api.client.app.state.settings,
        )
        issue.evidence_provenance = {"source": "manual", "evidence_ids": [str(original.id)]}
        item.status = "completed"
        later = delivery.create_evidence(
            ctx,
            item.id,
            EvidenceCreate(
                **evidence_fields,
                title="New retest observation",
                content="New release observation captured only for retesting.",
                artifact_id=new_artifact.id if mobile else None,
                release_ref=None if mobile else "api-release-new",
            ),
            api.client.app.state.settings,
        )
        session.commit()
        later_id = str(later.id)
    report = new_report(api, assessment)
    frozen = expect(api.get(f"/reports/{report['id']}", role="analyst"))["snapshot"]
    assert [proof["title"] for proof in frozen["findings"][0]["evidence"]] == [
        "Original observed condition"
    ]
    assert later_id not in json.dumps(frozen["findings"])


def test_new_idempotency_key_reuses_same_immutable_format(reporting):
    api = reporting
    _, assessment = completed(api)
    report = new_report(api, assessment)
    expect(api.post(f"/reports/{report['id']}/release", {"decision": "approve"}))
    first = expect(
        api.post(
            f"/reports/{report['id']}/exports",
            {"format": "json"},
            role="analyst",
            key="export-first",
        ),
        201,
    )
    second = expect(
        api.post(
            f"/reports/{report['id']}/exports",
            {"format": "json"},
            role="analyst",
            key="export-second",
        ),
        201,
    )
    assert first == second
    assert expect(api.get(f"/reports/{report['id']}/exports", role="analyst"))["total"] == 1


def test_provably_uncommitted_export_file_is_cleaned_on_database_failure(reporting, monkeypatch):
    from droidshield import reports, services
    from droidshield.models import User

    api = reporting
    _, assessment = completed(api)
    report = new_report(api, assessment)
    expect(api.post(f"/reports/{report['id']}/release", {"decision": "approve"}))
    with Session(api.engine) as session:
        actor = session.get(User, api.users["analyst"])
        ctx = services.Context(session, actor, "report-failing-flush")
        flush = session.flush

        def fail_export_flush(*args, **kwargs):
            if any(isinstance(value, ReportExport) for value in session.new):
                raise RuntimeError("simulated database write failure")
            return flush(*args, **kwargs)

        monkeypatch.setattr(session, "flush", fail_export_flush)
        with pytest.raises(RuntimeError, match="simulated database write failure"):
            reports.export(ctx, UUID(report["id"]), "json", api.client.app.state.settings)
        session.rollback()
    root = api.client.app.state.settings.storage_root / "reports"
    assert list((root / "objects").iterdir()) == []
    assert list((root / "staging").iterdir()) == []


def test_pdf_resource_failure_publishes_no_export_or_file(reporting, monkeypatch):
    from droidshield import report_render

    api = reporting
    _, assessment = completed(api)
    report = new_report(api, assessment)
    expect(api.post(f"/reports/{report['id']}/release", {"decision": "approve"}))

    def timeout(_):
        raise report_render.RenderError("report_render_timeout")

    monkeypatch.setattr(report_render, "render", timeout)
    response = api.post(f"/reports/{report['id']}/exports", {"format": "pdf"}, role="analyst")
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "report_export_unavailable"
    assert expect(api.get(f"/reports/{report['id']}/exports", role="analyst"))["total"] == 0
    assert expect(api.get(f"/reports/{report['id']}", role="analyst"))["status"] == "approved"
    assert not (api.client.app.state.settings.storage_root / "reports").exists()
