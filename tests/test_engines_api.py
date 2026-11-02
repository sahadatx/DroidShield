"""Cross-layer checks for engine routing, safe reads and the same-origin app."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from droidshield import worker
from droidshield.models import AnalysisJob
from tests.dex_factory import dex_apk
from tests.test_api import expect, grant, make_assessment, make_authorization, make_project, queue
from tests.test_uploads import upload
from tests.test_uploads import upload_api as _upload_api

upload_api = _upload_api


def test_real_dex_upload_queue_worker_result_and_scoped_finding_reads(upload_api):
    api = upload_api
    project = make_project(api)
    target = "package:com.example.store"
    permit = make_authorization(api, project, approved_targets=[target])
    draft = make_assessment(
        api, project, permit, targets=[target], assessment_type="static", engine="dex"
    )
    assert draft["engine"] == "dex"
    expect(upload(api, draft, content=dex_apk(package_name="com.example.store")), 201)
    current = expect(api.get(f"/assessments/{draft['id']}"))
    queued = expect(queue(api, current))
    assert queued["engine"] == "dex"
    assert worker.run_once(api.client.app.state.settings, api.engine)
    result = expect(api.get(f"/assessments/{draft['id']}/analysis"))
    assert result["schema_version"] == 2
    assert result["engine_version"] == "droidshield-dex-1"
    assert result["dex_summary"]["dex_files"] == 1
    assert result["dex_summary"]["analyzed_methods"] == 2
    assert "_dex_summary" not in result["metadata"]
    assert any(item["rule_id"] == "DEX_SECRET_LITERAL" for item in result["indicators"])
    assert "do-not-expose" not in str(result)
    assert "AKIA0123456789ABCDEF" not in str(result)
    records = expect(
        api.get(
            "/findings", params={"project_id": project["id"], "verification_status": "unreviewed"}
        )
    )
    assert records["total"] >= 9
    finding = expect(api.get(f"/findings/{records['items'][0]['id']}"))
    assert finding["verification_status"] == "unreviewed"
    assert finding["evidence_provenance"]["source"] == "static_dex"
    assert finding["evidence_provenance"]["artifact_sha256"] == result["artifact_sha256"]
    assert "storage_ref" not in str(finding)
    assert expect(api.get("/findings", role="viewer"))["total"] == 0
    expect(api.get(f"/findings/{finding['id']}", role="viewer"), 404)
    expect(api.get(f"/findings/{finding['id']}", role="other_admin"), 404)
    grant(api, project, "viewer")
    assert expect(api.get("/findings", role="viewer"))["total"] == records["total"]
    expect(api.get(f"/findings/{finding['id']}", role="viewer"))
    with Session(api.engine) as session:
        job = session.scalar(
            select(AnalysisJob).where(AnalysisJob.assessment_id == UUID(draft["id"]))
        )
        assert job.tool_versions == {"static_dex": "droidshield-dex-1"}
        assert "dex_max_files" in job.configuration_snapshot["execution"]


def test_capabilities_are_authenticated_and_expose_no_secrets_or_device_serials(upload_api):
    api = upload_api
    assert api.client.get("/api/v1/capabilities").status_code == 401
    settings = api.client.app.state.settings
    settings.mobsf_url = "http://127.0.0.1:8788"
    from pydantic import SecretStr

    settings.mobsf_api_key = SecretStr("never-return-this-key")
    settings.lab_devices = [
        {
            "id": "lab",
            "label": "Test lab",
            "serial": "emulator-5560",
            "avd_name": "DroidShield_Test",
            "android_version": "11",
        }
    ]
    capabilities = expect(api.get("/capabilities"))
    assert capabilities["engines"]["mobsf"]["configured"]
    assert capabilities["dynamic"]["devices"] == [
        {"id": "lab", "label": "Test lab", "android_version": "11"}
    ]
    assert "never-return-this-key" not in str(capabilities)
    assert "emulator-5560" not in str(capabilities)
    assert "127.0.0.1:8788" not in str(capabilities)
    assert "mobsf_api_key" not in settings.model_dump()


def test_same_origin_frontend_has_protective_headers_and_no_artifact_mount(upload_api):
    client = upload_api.client
    root = client.get("/")
    assert root.status_code == 200
    assert 'src="/assets/app.js?v=' in root.text
    assert "connect-src 'self'" in root.headers["content-security-policy"]
    assert root.headers["cache-control"] == "no-store"
    assert client.get("/assets/app.js").status_code == 200
    assert client.get("/assets/styles.css").status_code == 200
    # Only named distribution assets are public, even if protected files are
    # accidentally configured under the web directory later.
    assert client.get("/assets/index.html").status_code == 404
    assert client.get("/assets/artifacts/object.apk").status_code == 404
    assert client.get("/assets/../../var/droidshield.db").status_code == 404
    assert client.get("/var/droidshield.db").status_code == 404
    assert client.get("/artifacts/").status_code == 404
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "content-security-policy" not in docs.headers


def test_engine_selection_is_validated_and_updates_only_draft_static_assessments(upload_api):
    api = upload_api
    project = make_project(api)
    for kind, engine in (("api", "dex"), ("dynamic", "mobsf"), ("static", "arbitrary")):
        expect(
            api.post(
                "/assessments",
                {
                    "project_id": project["id"],
                    "name": "Invalid",
                    "assessment_type": kind,
                    "engine": engine,
                    "requested_targets": ["package:com.example.store"],
                },
            ),
            422,
        )
    draft = make_assessment(
        api, project, targets=["package:com.example.store"], assessment_type="static"
    )
    updated = expect(
        api.patch(f"/assessments/{draft['id']}", {"revision": draft["revision"], "engine": "dex"})
    )
    assert updated["engine"] == "dex"
    expect(
        api.patch(f"/assessments/{draft['id']}", {"revision": updated["revision"], "engine": None}),
        422,
    )
