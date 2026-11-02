"""Evidence-backed analyst delivery, review separation and retest regression."""

import hashlib
import io
import struct
import zlib
from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from droidshield.auth import hash_password
from droidshield.cvss_scoring import score_cvss
from droidshield.models import (
    AnalysisJob,
    AppArtifact,
    AssessmentEvidence,
    AuditEvent,
    EvidenceAttachment,
    Finding,
    Retest,
    User,
)
from droidshield.models import (
    TestExecution as Execution,
)
from droidshield.storage import Storage
from tests.test_api import (
    PREFIX,
    expect,
    grant,
    make_assessment,
    make_authorization,
    make_project,
)
from tests.test_api import (
    api as _api,
)

api = _api
VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"


@pytest.fixture
def delivery_api(api, tmp_path):
    api.client.app.state.settings.storage_root = tmp_path / "protected"
    return api


def manual(api, *, platform="android", artifact=False):
    project = make_project(api, role="analyst", platform=platform)
    targets = (
        [f"{'bundle' if platform == 'ios' else 'package'}:{project['package_id']}"]
        if artifact
        else ["https://api.example.test/v1"]
    )
    permit = make_authorization(api, project, approved_targets=targets)
    version = add_artifact(api, project, platform=platform) if artifact else None
    assessment = make_assessment(
        api,
        project,
        permit,
        targets=targets,
        role="analyst",
        assessment_type="full" if artifact else "api",
        artifact_id=version["id"] if version else None,
    )
    started = expect(
        api.post(
            f"/assessments/{assessment['id']}/manual-start",
            {
                "revision": assessment["revision"],
                "platform": platform,
                "environment": "Dedicated client test lab",
                "tools": [{"name": "Manual review", "version": "1.0"}],
                "limitations": "No production data or state-changing operations were used.",
            },
            role="analyst",
        )
    )
    return project, permit, started, version


def add_artifact(api, project, *, platform="android", content=b"trusted test version one"):
    store = Storage(api.client.app.state.settings.storage_root)
    staged = store.stage(io.BytesIO(content), 1000)
    reference = store.publish(staged)
    staged.close()
    with Session(api.engine) as session:
        item = AppArtifact(
            workspace_id=UUID(project["workspace_id"]),
            project_id=UUID(project["id"]),
            sha256=hashlib.sha256(content).hexdigest(),
            storage_ref=reference,
            original_filename="client.ipa" if platform == "ios" else "client.apk",
            file_size=len(content),
            metadata_json={
                "package_name": project["package_id"],
                "platform": platform,
                "artifact_format": "ipa" if platform == "ios" else "apk",
            },
            created_by=api.users["analyst"],
        )
        session.add(item)
        session.commit()
        return {"id": str(item.id), "sha256": item.sha256}


def add_evidence(
    api,
    assessment,
    *,
    artifact_id=None,
    platform="android",
    release_ref=None,
    content="Observed the approved test account receiving a protected object owned by another approved account.",
):
    if (
        assessment["assessment_type"] == "api"
        and assessment["status"] != "completed"
        and release_ref is None
    ):
        release_ref = "backend-release-1"
    return expect(
        api.post(
            f"/assessments/{assessment['id']}/evidence",
            {
                "title": "Controlled test observation",
                "content": content,
                "sanitized": True,
                "platform": platform,
                "tool": "Manual review",
                "tool_version": "1.0",
                "environment": "Dedicated client test lab",
                "artifact_id": artifact_id,
                "release_ref": release_ref,
            },
            role="analyst",
        ),
        201,
    )


def tiny_png():
    signature = b"\x89PNG\r\n\x1a\n"

    def chunk(kind, content):
        payload = kind + content
        return struct.pack(">I", len(content)) + payload + struct.pack(">I", zlib.crc32(payload))

    header = struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0)
    pixels = zlib.compress(b"\x00\xff\x00\x00\xff")
    return signature + chunk(b"IHDR", header) + chunk(b"IDAT", pixels) + chunk(b"IEND", b"")


def add_finding(api, assessment, evidence_ids=()):
    calculated = score_cvss(VECTOR)
    return expect(
        api.post(
            f"/assessments/{assessment['id']}/findings",
            {
                "title": "Missing object authorization",
                "description": "Approved secondary accounts can access another account's protected object.",
                "affected_component": "Authorized object detail endpoint",
                "category": "api_authorization",
                "severity": calculated["severity"],
                "reproduction_steps": "Sign in with both approved accounts, create owned objects, then compare permitted access.",
                "impact": "Protected account-specific records can be disclosed to a different approved test account.",
                "remediation": "Enforce ownership and role authorization for each requested object on the server.",
                "cvss_vector": VECTOR,
                "cvss_score": calculated["score"],
                "masvs_mapping": ["MASVS-AUTH-1"],
                "cwe_mapping": ["CWE-639"],
                "evidence_ids": list(evidence_ids),
            },
            role="analyst",
        ),
        201,
    )


def record_case(
    api,
    assessment,
    evidence,
    finding=None,
    *,
    status="pass",
    case_id="DS-API-01",
    revision=None,
    platform="android",
):
    return api.client.put(
        f"/api/v1/assessments/{assessment['id']}/coverage/{case_id}",
        headers=api.headers("analyst"),
        json={
            "revision": revision,
            "status": status,
            "platform": platform,
            "environment": "Dedicated client test lab",
            "tool": "Manual review",
            "tool_version": "1.0",
            "notes": "Approved account and object ownership were independently checked.",
            "evidence_ids": [evidence["id"]] if evidence else [],
            "finding_ids": [finding["id"]] if finding else [],
        },
    )


def complete(api, assessment):
    finished = expect(
        api.post(
            f"/assessments/{assessment['id']}/manual-finish",
            {
                "revision": assessment["revision"],
                "summary": "The approved test procedures were performed and their evidence has been attached.",
            },
            role="analyst",
        )
    )
    return expect(
        api.post(
            f"/assessments/{assessment['id']}/review",
            {
                "revision": finished["revision"],
                "decision": "complete",
                "notes": "Evidence, authorization scope and explicit untested limitations were reviewed.",
            },
        )
    )


def confirm(api, finding):
    return expect(
        api.post(
            f"/findings/{finding['id']}/review",
            {
                "revision": finding["revision"],
                "decision": "confirmed",
                "notes": "The approved test accounts, object ownership and evidence support this finding.",
            },
        )
    )


def retest_body(permit, evidence, *, artifact=None, result="pass", platform="android"):
    return {
        "new_artifact_id": artifact["id"] if artifact else None,
        "authorization_id": permit["id"],
        "method": "manual" if artifact else "api",
        "platform": platform,
        "environment": "Dedicated updated client test lab",
        "tool": "Manual review",
        "tool_version": "1.0",
        "evidence_ids": [evidence["id"]],
        "result": result,
        "notes": "Ownership enforcement was checked again with approved test accounts.",
        **(
            {}
            if artifact
            else {
                "original_release_ref": "backend-release-1",
                "new_release_ref": "backend-release-2",
            }
        ),
    }


def test_manual_api_coverage_review_and_release_retest(delivery_api):
    api = delivery_api
    project, permit, assessment, _ = manual(api)
    assert assessment["execution_mode"] == "analyst_record"
    coverage = expect(api.get(f"/assessments/{assessment['id']}/coverage"))
    assert coverage["summary"]["not_run"] == len(coverage["cases"])
    evidence = add_evidence(api, assessment)
    issue = add_finding(api, assessment, [evidence["id"]])
    assert issue["verification_status"] == "unreviewed"
    expect(record_case(api, assessment, evidence, issue, status="fail"))
    issue = confirm(api, issue)
    completed = complete(api, assessment)
    assert completed["status"] == "completed"
    assert completed["reviewer_id"] == str(api.users["admin"])
    assert expect(api.get("/overview"))["open_findings"] == 1
    new_evidence = add_evidence(
        api,
        completed,
        release_ref="backend-release-2",
        content="The new backend release rejects cross-account access with HTTP 403 for both approved test objects.",
    )
    request = retest_body(permit, new_evidence)
    attempt = expect(
        api.post(f"/findings/{issue['id']}/retests", request, role="analyst", key="api-retest-1"),
        201,
    )
    assert attempt["new_artifact_id"] is None
    assert attempt["environment"]["artifact_sha256"] is None
    assert attempt["environment"]["new_release_ref"] == "backend-release-2"
    assert expect(api.get(f"/findings/{issue['id']}"))["remediation_status"] == "retest_required"
    pending_retests = expect(
        api.get(
            "/retests",
            params={
                "project_id": project["id"],
                "assessment_id": assessment["id"],
                "method": "api",
                "result": "pass",
                "review_status": "awaiting_review",
            },
        )
    )
    assert pending_retests["total"] == 1
    assert pending_retests["items"][0]["id"] == attempt["id"]
    replay = expect(
        api.post(f"/findings/{issue['id']}/retests", request, role="analyst", key="api-retest-1"),
        201,
    )
    assert replay["id"] == attempt["id"]
    current = expect(api.get(f"/findings/{issue['id']}"))
    reviewed = expect(
        api.post(
            f"/retests/{attempt['id']}/review",
            {
                "revision": attempt["revision"],
                "finding_revision": current["revision"],
                "decision": "approve",
                "notes": "The new release and sanitized denial evidence demonstrate the fix.",
            },
        )
    )
    assert reviewed["review_decision"] == "approve"
    assert expect(api.get(f"/findings/{issue['id']}"))["remediation_status"] == "fixed"
    approved_retests = expect(api.get("/retests", params={"review_status": "approved"}))
    assert approved_retests["total"] == 1
    assert expect(api.get("/overview"))["open_findings"] == 0
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(AnalysisJob)) == 0
        assert session.scalar(select(func.count()).select_from(Retest)) == 1
    assert expect(api.get("/retests"))["total"] == 1
    assert expect(api.get(f"/projects/{project['id']}/versions"))["total"] == 0


@pytest.mark.parametrize("platform", ["android", "ios"])
def test_mobile_retest_requires_different_build_and_review(delivery_api, platform):
    api = delivery_api
    project, permit, assessment, original = manual(api, platform=platform, artifact=True)
    evidence = add_evidence(api, assessment, artifact_id=original["id"], platform=platform)
    issue = add_finding(api, assessment, [evidence["id"]])
    expect(record_case(api, assessment, evidence, issue, status="fail", platform=platform))
    issue = confirm(api, issue)
    completed = complete(api, assessment)
    next_artifact = add_artifact(
        api, project, platform=platform, content=b"trusted test version two"
    )
    next_evidence = add_evidence(api, completed, artifact_id=next_artifact["id"], platform=platform)
    body = retest_body(permit, next_evidence, artifact=next_artifact, platform=platform)
    expect(
        api.post(
            f"/findings/{issue['id']}/retests",
            {**body, "new_artifact_id": original["id"]},
            role="analyst",
        ),
        409,
    )
    attempt = expect(api.post(f"/findings/{issue['id']}/retests", body, role="analyst"), 201)
    assert attempt["environment"]["artifact_sha256"] == next_artifact["sha256"]
    expect(api.post(f"/findings/{issue['id']}/retests", body, role="analyst"), 409)
    current = expect(api.get(f"/findings/{issue['id']}"))
    expect(
        api.post(
            f"/retests/{attempt['id']}/review",
            {
                "revision": 1,
                "finding_revision": current["revision"],
                "decision": "approve",
                "notes": "The new build evidence and affected component were independently reviewed.",
            },
            role="analyst",
        ),
        403,
    )
    assert expect(api.get(f"/findings/{issue['id']}"))["remediation_status"] != "fixed"
    expect(
        api.post(
            f"/retests/{attempt['id']}/review",
            {
                "revision": 1,
                "finding_revision": current["revision"],
                "decision": "reject",
                "notes": "More proof of the original reproduction path is needed for this test.",
            },
        )
    )
    assert expect(api.get(f"/findings/{issue['id']}"))["remediation_status"] == "retest_required"


def test_evidence_is_redacted_private_and_integrity_checked(delivery_api):
    api = delivery_api
    _, _, assessment, _ = manual(api)
    secret = "Bearer never-persist-this-secret-value"
    data = add_evidence(
        api,
        assessment,
        content=f"Approved login observation. Authorization: {secret}\nThe response was HTTP 403 with no protected object.",
    )
    assert data["redaction_count"] >= 1
    assert "artifact_ref" not in data and "content" not in data
    response = api.get(f"/evidence/{data['id']}/content")
    assert response.status_code == 200
    assert secret not in response.text
    assert "[REDACTED]" in response.text
    assert hashlib.sha256(response.content).hexdigest() == data["sha256"]
    assert response.headers["content-disposition"].startswith("attachment;")
    with Session(api.engine) as session:
        record = session.get(AssessmentEvidence, UUID(data["id"]))
        store = Storage(api.client.app.state.settings.storage_root / "evidence")
        path = store._path(record.artifact_ref)
        assert path.stat().st_mode & 0o777 == 0o400
        path.chmod(0o600)
        path.write_bytes(b"tampered evidence")
        assert secret not in repr(session.scalars(select(AuditEvent)).all())
    expect(api.get(f"/evidence/{data['id']}/content"), 503)
    expect(api.get(f"/evidence/{data['id']}", role="other_admin"), 404)


def test_screenshot_evidence_is_private_bounded_and_integrity_checked(delivery_api):
    api = delivery_api
    _, _, assessment, _ = manual(api)
    fields = {
        "title": "Login flow screenshot",
        "sanitized": "true",
        "platform": "android",
        "tool": "Manual review",
        "tool_version": "1.0",
        "environment": "Dedicated client test lab",
    }
    password = "Screenshot-evidence-test-password!"
    with Session(api.engine) as session:
        session.get(User, api.users["analyst"]).password_hash = hash_password(password)
        session.commit()
    login = api.client.post(
        PREFIX + "/auth/login",
        json={"email": "analyst@example.com", "password": password},
    )
    assert login.status_code == 200
    headers = {
        "X-CSRF-Token": login.json()["csrf_token"],
        "Idempotency-Key": "screenshot-evidence-1",
    }
    response = api.client.post(
        PREFIX + f"/assessments/{assessment['id']}/evidence-attachments",
        data=fields,
        files={"file": ("login.png", tiny_png(), "image/png")},
        headers=headers,
    )
    record = expect(response, 201)
    assert record["attachment"]["media_type"] == "image/png"
    assert record["attachment"]["display_name"] == "screenshot.png"
    assert record["attachment"]["sha256"] == hashlib.sha256(tiny_png()).hexdigest()
    assert "storage_ref" not in record["attachment"]

    downloaded = api.get(f"/evidence/{record['id']}/content")
    assert downloaded.status_code == 200
    assert downloaded.content == tiny_png()
    assert downloaded.headers["content-type"] == "application/octet-stream"
    assert downloaded.headers["x-content-type-options"] == "nosniff"
    assert downloaded.headers["cache-control"] == "no-store"
    assert downloaded.headers["x-content-sha256"] == record["attachment"]["sha256"]
    assert (
        'attachment; filename="DroidShield-evidence-' in downloaded.headers["content-disposition"]
    )

    listed = expect(api.get(f"/assessments/{assessment['id']}/evidence?limit=100"))
    assert listed["items"][0]["attachment"]["sha256"] == record["attachment"]["sha256"]
    expect(api.get(f"/evidence/{record['id']}/content", role="other_admin"), 404)
    replay = api.client.post(
        PREFIX + f"/assessments/{assessment['id']}/evidence-attachments",
        data=fields,
        files={"file": ("login.png", tiny_png(), "image/png")},
        headers=headers,
    )
    assert expect(replay, 201)["id"] == record["id"]

    with Session(api.engine) as session:
        item = session.get(EvidenceAttachment, UUID(record["id"]))
        store = Storage(api.client.app.state.settings.storage_root / "evidence-attachments")
        path = store._path(item.storage_ref)
        assert path.stat().st_mode & 0o777 == 0o400
        path.chmod(0o600)
        path.write_bytes(b"tampered screenshot")
    expect(api.get(f"/evidence/{record['id']}/content"), 503)


def test_screenshot_evidence_rejects_non_png_and_requires_sanitization(delivery_api):
    api = delivery_api
    _, _, assessment, _ = manual(api)
    fields = {
        "title": "Invalid screenshot",
        "sanitized": "true",
        "platform": "android",
        "tool": "Manual review",
        "tool_version": "1.0",
        "environment": "Dedicated client test lab",
    }
    invalid = api.client.post(
        PREFIX + f"/assessments/{assessment['id']}/evidence-attachments",
        data=fields,
        files={"file": ("capture.png", b"not a PNG", "image/png")},
        headers=api.headers("analyst", "invalid-screenshot-1"),
    )
    expect(invalid, 422)
    unconfirmed = api.client.post(
        PREFIX + f"/assessments/{assessment['id']}/evidence-attachments",
        data={**fields, "sanitized": "false"},
        files={"file": ("capture.png", tiny_png(), "image/png")},
        headers=api.headers("analyst", "invalid-screenshot-2"),
    )
    expect(unconfirmed, 422)


def test_scope_roles_stale_revisions_and_self_review(delivery_api):
    api = delivery_api
    project, permit, assessment, _ = manual(api)
    grant(api, project, "viewer")
    evidence = add_evidence(api, assessment)
    issue = add_finding(api, assessment)
    expect(
        api.post(
            f"/findings/{issue['id']}/review",
            {
                "revision": issue["revision"],
                "decision": "confirmed",
                "notes": "No evidence has yet been linked to support this candidate.",
            },
        ),
        409,
    )
    expect(
        api.patch(
            f"/findings/{issue['id']}",
            {"revision": 99, "evidence_ids": [evidence["id"]]},
            role="analyst",
        ),
        409,
    )
    updated = expect(
        api.patch(
            f"/findings/{issue['id']}",
            {"revision": issue["revision"], "evidence_ids": [evidence["id"]]},
            role="analyst",
        )
    )
    expect(
        api.patch(
            f"/findings/{issue['id']}",
            {"revision": updated["revision"], "title": "Unauthorized change"},
            role="viewer",
        ),
        403,
    )
    expect(api.get(f"/assessments/{assessment['id']}/coverage", role="other_admin"), 404)
    issue = confirm(api, updated)
    assert (
        expect(
            api.patch(
                f"/findings/{issue['id']}",
                {
                    "revision": issue["revision"],
                    "impact": "Additional independently verified impact details were recorded.",
                },
                role="analyst",
            )
        )["verification_status"]
        == "unreviewed"
    )
    expect(record_case(api, assessment, None, status="pass"), 422)
    result = expect(record_case(api, assessment, None, status="blocked"))
    expect(record_case(api, assessment, None, status="blocked"), 409)
    expect(record_case(api, assessment, None, status="blocked", revision=result["revision"]))
    revoke = expect(
        api.post(
            f"/authorizations/{permit['id']}/revoke",
            {
                "revision": permit["revision"],
                "reason": "The testing authorization has been withdrawn.",
            },
        )
    )
    assert revoke["status"] == "revoked"
    expect(
        api.post(
            f"/assessments/{assessment['id']}/manual-finish",
            {
                "revision": assessment["revision"],
                "summary": "The earlier tests have been documented for review.",
            },
            role="analyst",
        ),
        409,
    )


def test_cross_assessment_evidence_cannot_confirm_or_populate_coverage(delivery_api):
    api = delivery_api
    _, _, first, _ = manual(api)
    _, _, second, _ = manual(api)
    wrong = add_evidence(api, second)
    expect(
        api.post(
            f"/assessments/{first['id']}/findings",
            {**finding_payload(), "evidence_ids": [wrong["id"]]},
            role="analyst",
        ),
        404,
    )
    expect(record_case(api, first, wrong), 404)
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(Finding)) == 0
        assert session.scalar(select(func.count()).select_from(Execution)) == 0


def finding_payload():
    calculated = score_cvss(VECTOR)
    return {
        "title": "Controlled test candidate",
        "description": "The approved test demonstrated a candidate security issue.",
        "affected_component": "Approved test component",
        "category": "manual",
        "severity": calculated["severity"],
        "reproduction_steps": "Perform the approved controlled test and observe the denied access condition.",
        "impact": "A protected test object may be disclosed across approved test accounts.",
        "remediation": "Enforce the documented ownership and access constraints on the server.",
        "cvss_vector": VECTOR,
        "cvss_score": calculated["score"],
    }


def test_draft_queue_and_expired_scope_do_not_start_manual_execution(delivery_api):
    api = delivery_api
    project = make_project(api, role="analyst")
    permit = make_authorization(api, project)
    assessment = make_assessment(api, project, permit, role="analyst")
    now = datetime.now(UTC)
    from droidshield.models import Authorization

    with Session(api.engine) as session:
        session.get(Authorization, UUID(permit["id"])).valid_until = now - timedelta(seconds=1)
        session.commit()
    body = {
        "revision": 1,
        "platform": "android",
        "environment": "Controlled test lab",
        "tools": [{"name": "Burp", "version": "documented external"}],
        "limitations": "This records approved analyst work; no network operation is executed.",
    }
    expect(api.post(f"/assessments/{assessment['id']}/manual-start", body, role="analyst"), 409)
    assert expect(api.get(f"/assessments/{assessment['id']}"))["status"] == "draft"
    with Session(api.engine) as session:
        session.get(Authorization, UUID(permit["id"])).valid_until = now + timedelta(hours=1)
        session.commit()
    expect(api.post(f"/assessments/{assessment['id']}/queue", {"revision": 1}, role="analyst"))
    expect(
        api.post(
            f"/assessments/{assessment['id']}/manual-start", {**body, "revision": 2}, role="analyst"
        ),
        409,
    )


def test_methodology_pins_all_masvs_controls_without_inventing_execution(delivery_api):
    api = delivery_api
    result = expect(api.get("/methodology"))
    controls = {
        reference["id"]
        for case in result["cases"]
        for reference in case["references"]
        if reference["framework"] == "MASVS"
    }
    assert len(controls) == 24
    assert {item["version"] for item in result["frameworks"]} == {"2.1.0", "2024", "2008-09"}
    assert {
        "storage",
        "authentication",
        "api_authorization",
        "business_logic",
        "resilience",
        "privacy",
    } <= {case["category"] for case in result["cases"]}


@pytest.mark.parametrize(
    "result,expected",
    [
        ("fail", "open"),
        ("inconclusive", "retest_required"),
        ("not_reproducible", "retest_required"),
    ],
)
def test_only_reviewed_pass_closes_finding(delivery_api, result, expected):
    api = delivery_api
    _, permit, assessment, _ = manual(api)
    evidence = add_evidence(api, assessment)
    issue = confirm(api, add_finding(api, assessment, [evidence["id"]]))
    expect(record_case(api, assessment, evidence, issue, status="fail"))
    completed = complete(api, assessment)
    new_evidence = add_evidence(api, completed, release_ref="backend-release-2")
    attempt = expect(
        api.post(
            f"/findings/{issue['id']}/retests",
            retest_body(permit, new_evidence, result=result),
            role="analyst",
        ),
        201,
    )
    current = expect(api.get(f"/findings/{issue['id']}"))
    expect(
        api.post(
            f"/retests/{attempt['id']}/review",
            {
                "revision": attempt["revision"],
                "finding_revision": current["revision"],
                "decision": "approve",
                "notes": "The evidence was independently checked against the original reproduction.",
            },
        )
    )
    assert expect(api.get(f"/findings/{issue['id']}"))["remediation_status"] == expected


def test_api_retest_release_evidence_and_current_authorization_are_required(delivery_api):
    api = delivery_api
    _, permit, assessment, _ = manual(api)
    evidence = add_evidence(api, assessment)
    issue = confirm(api, add_finding(api, assessment, [evidence["id"]]))
    expect(record_case(api, assessment, evidence, issue, status="fail"))
    completed = complete(api, assessment)
    new_evidence = add_evidence(api, completed, release_ref="wrong-release")
    body = retest_body(permit, new_evidence)
    expect(api.post(f"/findings/{issue['id']}/retests", body, role="analyst"), 409)
    expect(
        api.post(
            f"/findings/{issue['id']}/retests",
            {**body, "original_release_ref": "backend-release-2"},
            role="analyst",
        ),
        422,
    )
    expect(
        api.post(
            f"/findings/{issue['id']}/retests",
            {**body, "evidence_ids": [evidence["id"]]},
            role="analyst",
        ),
        409,
    )
    expect(
        api.post(
            f"/authorizations/{permit['id']}/revoke",
            {
                "revision": permit["revision"],
                "reason": "The approved test window has been closed by the client.",
            },
        )
    )
    expect(
        api.post(
            f"/findings/{issue['id']}/retests",
            {**body, "new_release_ref": "wrong-release"},
            role="analyst",
        ),
        409,
    )
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(Retest)) == 0
    assert expect(api.get(f"/findings/{issue['id']}"))["remediation_status"] == "open"


def test_self_review_and_completed_record_edits_are_rejected(delivery_api):
    api = delivery_api
    _, _, assessment, _ = manual(api)
    evidence = add_evidence(api, assessment)
    issue = expect(
        api.post(
            f"/assessments/{assessment['id']}/findings",
            {**finding_payload(), "evidence_ids": [evidence["id"]]},
        ),
        201,
    )
    expect(
        api.post(
            f"/findings/{issue['id']}/review",
            {
                "revision": 1,
                "decision": "confirmed",
                "notes": "Attempting to review one's own authored finding is not permitted.",
            },
        ),
        409,
    )
    expect(
        api.post(
            f"/findings/{issue['id']}/review",
            {
                "revision": 1,
                "decision": "confirmed",
                "notes": "Analysts cannot grant final reviewer approval to a finding.",
            },
            role="analyst",
        ),
        403,
    )
    edited = expect(
        api.patch(
            f"/findings/{issue['id']}",
            {
                "revision": 1,
                "impact": "The independently confirmed impact affects another approved test account.",
            },
            role="analyst",
        )
    )
    # Both the original author and final editor are kept out of self approval.
    expect(
        api.post(
            f"/findings/{issue['id']}/review",
            {
                "revision": edited["revision"],
                "decision": "confirmed",
                "notes": "The original author remains ineligible to approve the authored finding.",
            },
        ),
        409,
    )


def test_idempotent_evidence_replay_and_changed_payload_conflict(delivery_api):
    api = delivery_api
    project, _, assessment, _ = manual(api)
    payload = {
        "title": "Idempotent evidence",
        "content": "The controlled access check returned HTTP 403 to the secondary test account.",
        "sanitized": True,
        "platform": "android",
        "tool": "Manual review",
        "tool_version": "1.0",
        "environment": "Controlled client test lab",
    }
    first = expect(
        api.post(
            f"/assessments/{assessment['id']}/evidence",
            payload,
            role="analyst",
            key="evidence-replay",
        ),
        201,
    )
    second = expect(
        api.post(
            f"/assessments/{assessment['id']}/evidence",
            payload,
            role="analyst",
            key="evidence-replay",
        ),
        201,
    )
    assert first["id"] == second["id"]
    expect(
        api.post(
            f"/assessments/{assessment['id']}/evidence",
            {
                **payload,
                "content": "A different observation should not reuse the same operation key.",
            },
            role="analyst",
            key="evidence-replay",
        ),
        409,
    )
    grant(api, project, "viewer")
    expect(api.post(f"/assessments/{assessment['id']}/evidence", payload, role="viewer"), 403)
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(AssessmentEvidence)) == 1
        audit = session.scalars(
            select(AuditEvent).where(AuditEvent.action == "evidence.created")
        ).all()
        assert len(audit) == 1
        assert "HTTP 403" not in repr(audit[0].source_metadata)


@pytest.mark.parametrize(
    "change",
    [
        {"cvss_score": 0.1},
        {"cvss_vector": "CVSS:4.0/AV:N"},
        {"description": "password=never-store-this-secret"},
        {"verification_status": "confirmed"},
    ],
)
def test_untrusted_manual_finding_inputs_are_rejected_without_side_effects(delivery_api, change):
    api = delivery_api
    _, _, assessment, _ = manual(api)
    response = api.post(
        f"/assessments/{assessment['id']}/findings", {**finding_payload(), **change}, role="analyst"
    )
    expect(response, 422)
    assert "never-store-this-secret" not in response.text
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(Finding)) == 0


def test_prior_finding_editor_cannot_launder_self_review_through_another_edit(delivery_api):
    api = delivery_api
    _, _, assessment, _ = manual(api)
    proof = add_evidence(api, assessment)
    issue = add_finding(api, assessment, [proof["id"]])
    edited = expect(
        api.patch(
            f"/findings/{issue['id']}",
            {
                "revision": issue["revision"],
                "impact": "Administrator-authored impact that must receive an independent reviewer decision.",
            },
        )
    )
    edited = expect(
        api.patch(
            f"/findings/{issue['id']}",
            {"revision": edited["revision"], "title": issue["title"]},
            role="analyst",
        )
    )
    assert str(api.users["admin"]) in edited["evidence_provenance"]["contributors"]
    expect(
        api.post(
            f"/findings/{issue['id']}/review",
            {
                "revision": edited["revision"],
                "decision": "confirmed",
                "notes": "A different administrator must assess the earlier administrator-authored content.",
            },
        ),
        409,
    )
    assert expect(api.get(f"/findings/{issue['id']}"))["verification_status"] == "unreviewed"


def test_prior_coverage_operator_cannot_launder_assessment_review(delivery_api):
    api = delivery_api
    _, _, assessment, _ = manual(api)
    body = {
        "status": "blocked",
        "platform": "android",
        "environment": "Dedicated test lab",
        "tool": "Manual review",
        "tool_version": "1.0",
        "notes": "The required second account was unavailable during the approved test window.",
        "evidence_ids": [],
        "finding_ids": [],
    }
    path = f"/api/v1/assessments/{assessment['id']}/coverage/DS-API-01"
    result = expect(api.client.put(path, json=body, headers=api.headers()))
    result = expect(
        api.client.put(
            path, json={**body, "revision": result["revision"]}, headers=api.headers("analyst")
        )
    )
    assert str(api.users["admin"]) in result["contributors"]
    finished = expect(
        api.post(
            f"/assessments/{assessment['id']}/manual-finish",
            {
                "revision": assessment["revision"],
                "summary": "The blocked test and account limitation have been documented for review.",
            },
            role="analyst",
        )
    )
    expect(
        api.post(
            f"/assessments/{assessment['id']}/review",
            {
                "revision": finished["revision"],
                "decision": "complete",
                "notes": "A previous coverage operator cannot approve their own underlying test decision.",
            },
        ),
        409,
    )
    assert expect(api.get(f"/assessments/{assessment['id']}"))["status"] == "needs_review"


def test_manual_starter_cannot_complete_another_analysts_submission(delivery_api):
    api = delivery_api
    project = make_project(api, role="analyst")
    permit = make_authorization(api, project)
    assessment = make_assessment(api, project, permit, role="analyst")
    started = expect(
        api.post(
            f"/assessments/{assessment['id']}/manual-start",
            {
                "revision": 1,
                "platform": "android",
                "environment": "Dedicated test lab",
                "tools": [{"name": "Manual review", "version": "1.0"}],
                "limitations": "The test accounts were unavailable; this engagement records explicit limitations.",
            },
        )
    )
    expect(record_case(api, started, None, status="blocked"))
    finished = expect(
        api.post(
            f"/assessments/{assessment['id']}/manual-finish",
            {
                "revision": started["revision"],
                "summary": "The execution was blocked by missing approved accounts and submitted for review.",
            },
            role="analyst",
        )
    )
    expect(
        api.post(
            f"/assessments/{assessment['id']}/review",
            {
                "revision": finished["revision"],
                "decision": "complete",
                "notes": "The manual starter must not approve another analyst's later submission.",
            },
        ),
        409,
    )


def test_retest_evidence_author_cannot_approve_own_proof(delivery_api):
    api = delivery_api
    _, permit, assessment, _ = manual(api)
    evidence = add_evidence(api, assessment)
    issue = confirm(api, add_finding(api, assessment, [evidence["id"]]))
    expect(record_case(api, assessment, evidence, issue, status="fail"))
    completed = complete(api, assessment)
    new_evidence = expect(
        api.post(
            f"/assessments/{completed['id']}/evidence",
            {
                "title": "New backend release denial",
                "content": "The new backend release denies cross-account access to the original approved test object.",
                "sanitized": True,
                "platform": "android",
                "tool": "Manual",
                "tool_version": "1.0",
                "environment": "Controlled test lab",
                "release_ref": "backend-release-2",
            },
        ),
        201,
    )
    attempt = expect(
        api.post(
            f"/findings/{issue['id']}/retests", retest_body(permit, new_evidence), role="analyst"
        ),
        201,
    )
    current = expect(api.get(f"/findings/{issue['id']}"))
    expect(
        api.post(
            f"/retests/{attempt['id']}/review",
            {
                "revision": attempt["revision"],
                "finding_revision": current["revision"],
                "decision": "approve",
                "notes": "An evidence author must not approve the fix based on their own proof.",
            },
        ),
        409,
    )
    assert expect(api.get(f"/findings/{issue['id']}"))["remediation_status"] == "retest_required"


def test_api_finding_requires_pinned_original_release_and_exact_artifact_none(delivery_api):
    api = delivery_api
    project, _, assessment, _ = manual(api)
    artifact = add_artifact(api, project)
    wrong = add_evidence(api, assessment, artifact_id=artifact["id"])
    expect(
        api.post(
            f"/assessments/{assessment['id']}/findings",
            {**finding_payload(), "evidence_ids": [wrong["id"]]},
            role="analyst",
        ),
        404,
    )
    no_release = expect(
        api.post(
            f"/assessments/{assessment['id']}/evidence",
            {
                "title": "Missing baseline release",
                "content": "A controlled test account received a protected object from another approved test account.",
                "sanitized": True,
                "platform": "android",
                "tool": "Manual",
                "tool_version": "1.0",
                "environment": "Controlled test lab",
            },
            role="analyst",
        ),
        201,
    )
    issue = add_finding(api, assessment, [no_release["id"]])
    expect(
        api.post(
            f"/findings/{issue['id']}/review",
            {
                "revision": issue["revision"],
                "decision": "confirmed",
                "notes": "Missing release provenance cannot become an implicitly pinned API baseline.",
            },
        ),
        409,
    )
    assert expect(api.get(f"/findings/{issue['id']}"))["verification_status"] == "unreviewed"


def test_authorization_expiry_blocks_fresh_evidence_and_coverage_results(delivery_api):
    api = delivery_api
    _, permit, assessment, _ = manual(api)
    from droidshield.models import Authorization

    with Session(api.engine) as session:
        session.get(Authorization, UUID(permit["id"])).valid_until = datetime.now(UTC) - timedelta(
            seconds=1
        )
        session.commit()
    expect(record_case(api, assessment, None, status="blocked"), 409)
    expect(
        api.post(
            f"/assessments/{assessment['id']}/evidence",
            {
                "title": "No active test permission",
                "content": "A new observation cannot be attributed to an expired active testing window.",
                "sanitized": True,
                "platform": "android",
                "tool": "Manual",
                "tool_version": "1.0",
                "environment": "Controlled test lab",
                "release_ref": "backend-release-1",
            },
            role="analyst",
        ),
        409,
    )
    with Session(api.engine) as session:
        assert session.scalar(select(func.count()).select_from(AssessmentEvidence)) == 0
        assert session.scalar(select(func.count()).select_from(Execution)) == 0


def test_retest_rejects_invented_original_release_or_proof_outside_authorization(delivery_api):
    api = delivery_api
    project, permit, assessment, _ = manual(api)
    evidence = add_evidence(api, assessment)
    issue = confirm(api, add_finding(api, assessment, [evidence["id"]]))
    expect(record_case(api, assessment, evidence, issue, status="fail"))
    completed = complete(api, assessment)
    new_evidence = add_evidence(api, completed, release_ref="backend-release-2")
    body = retest_body(permit, new_evidence)
    expect(
        api.post(
            f"/findings/{issue['id']}/retests",
            {**body, "original_release_ref": "invented-release"},
            role="analyst",
        ),
        409,
    )
    later_permit = make_authorization(api, project, valid_from=datetime.now(UTC).isoformat())
    expect(
        api.post(
            f"/findings/{issue['id']}/retests",
            {**body, "authorization_id": later_permit["id"]},
            role="analyst",
        ),
        409,
    )
    assert expect(api.get(f"/findings/{issue['id']}"))["remediation_status"] == "open"
