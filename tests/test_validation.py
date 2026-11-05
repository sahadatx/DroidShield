"""Contract checks for untrusted form fields and safe response serialization."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from pydantic import ValidationError

from droidshield.delivery_schemas import FindingUpdate
from droidshield.schemas import (
    ArtifactCreate,
    ArtifactOut,
    AssessmentCancel,
    AssessmentCreate,
    AssessmentOut,
    AssessmentQueue,
    AssessmentSubmit,
    AssessmentUpdate,
    AuthorizationCreate,
    AuthorizationRevoke,
    AuthorizationVerify,
    ClientCreate,
    ClientUpdate,
    MeOut,
    ProjectCreate,
    ProjectMemberAdd,
    ProjectUpdate,
    validate_target,
)


def project_data(**changes):
    return {
        "client_id": uuid4(),
        "name": "Store assessment",
        "application_name": "Store",
        "package_id": "com.example.store",
        **changes,
    }


def authorization_data(**changes):
    start = datetime(2026, 10, 28, tzinfo=UTC)
    return {
        "approved_targets": ["package:com.example.store", "https://api.example.test/v1"],
        "exclusions": [],
        "evidence_ref": "approval:engagement-001",
        "valid_from": start,
        "valid_until": start + timedelta(days=7),
        **changes,
    }


def artifact_data(**changes):
    return {
        "sha256": "A" * 64,
        "file_size": 1024,
        "original_filename": "store.apk",
        **changes,
    }


def test_client_trims_strings_and_preserves_optional_contact_fields():
    client = ClientCreate(
        client_type="individual",
        name="  Authorized Client  ",
        contact_email="  Contact@Example.COM  ",
        website="HTTPS://EXAMPLE.COM:443",
        notes="Engagement reference only",
    )
    assert client.name == "Authorized Client"
    assert client.contact_email == "Contact@example.com"
    assert client.website == "https://example.com/"
    assert client.phone is None
    assert client.status == "active"


@pytest.mark.parametrize("name", ["", "   ", "n" * 201])
def test_client_requires_a_bounded_nonblank_name(name):
    with pytest.raises(ValidationError):
        ClientCreate(name=name)


@pytest.mark.parametrize("email", ["bad-address", "a@@example.com", "name@example"])
def test_client_rejects_invalid_optional_email(email):
    with pytest.raises(ValidationError):
        ClientCreate(name="Client", contact_email=email)


@pytest.mark.parametrize(
    "website", ["ftp://example.com", "https://user:secret@example.com", "https://bad host.test"]
)
def test_urls_reject_unsupported_schemes_embedded_secrets_and_invalid_hosts(website):
    with pytest.raises(ValidationError):
        ClientCreate(name="Client", website=website)


def test_archived_create_requires_reason_for_clients_and_projects():
    with pytest.raises(ValidationError):
        ClientCreate(name="Client", status="archived")
    with pytest.raises(ValidationError):
        ProjectCreate(**project_data(status="archived", archive_reason=" "))
    assert ClientCreate(
        name="Client", status="archived", archive_reason="Engagement closed"
    ).archive_reason
    assert ProjectCreate(
        **project_data(status="archived", archive_reason="Engagement closed")
    ).archive_reason


@pytest.mark.parametrize("field", ["client_type", "name", "status"])
def test_client_patch_cannot_clear_required_fields(field):
    with pytest.raises(ValidationError):
        ClientUpdate(**{"revision": 1, field: None})


@pytest.mark.parametrize("field", ["name", "application_name", "package_id", "framework", "status"])
def test_project_patch_cannot_clear_required_fields(field):
    with pytest.raises(ValidationError):
        ProjectUpdate(**{"revision": 1, field: None})


def test_patch_distinguishes_omitted_optional_value_from_explicit_clear():
    patch = ClientUpdate(revision=2, contact_email=None)
    assert patch.model_dump(exclude_unset=True) == {"revision": 2, "contact_email": None}
    # The service validates archive_reason against the merged database state.
    assert ClientUpdate(revision=2, status="archived").status == "archived"


@pytest.mark.parametrize("revision", [0, -1, None, True, 1.1, "1"])
def test_mutating_commands_require_a_positive_integer_revision(revision):
    for schema, extra in (
        (ClientUpdate, {}),
        (ProjectUpdate, {}),
        (AuthorizationVerify, {}),
        (AuthorizationRevoke, {"reason": "Authorization withdrawn"}),
        (AssessmentQueue, {}),
        (AssessmentUpdate, {}),
        (AssessmentSubmit, {}),
        (AssessmentCancel, {"reason": "Operator cancelled"}),
    ):
        with pytest.raises(ValidationError):
            schema(revision=revision, **extra)


def test_finding_retest_due_date_requires_an_aware_timestamp_and_can_be_cleared():
    due = FindingUpdate(revision=1, retest_due_at="2026-11-05T12:00:00+06:00")
    assert due.retest_due_at == datetime(2026, 11, 5, 6, tzinfo=UTC)
    assert FindingUpdate(revision=1, retest_due_at=None).retest_due_at is None
    with pytest.raises(ValidationError):
        FindingUpdate(revision=1, retest_due_at="2026-11-05T12:00:00")


@pytest.mark.parametrize(
    "package_id",
    ["store", "com.1store", ".com.store", "com..store", "com.store-name", "com.store/"],
)
def test_projects_reject_invalid_android_package_syntax(package_id):
    with pytest.raises(ValidationError):
        ProjectCreate(**project_data(package_id=package_id))


def test_project_keeps_framework_choices_explicit_and_client_immutable():
    assert ProjectCreate(**project_data()).framework == "unknown"
    assert (
        ProjectCreate(**project_data(package_id="Com.Example_1.App")).package_id
        == "Com.Example_1.App"
    )
    with pytest.raises(ValidationError):
        ProjectCreate(**project_data(framework="ionic"))
    with pytest.raises(ValidationError):
        ProjectUpdate(revision=1, client_id=uuid4())


@pytest.mark.parametrize(
    ("target", "expected"),
    [
        (" package:com.example.store ", "package:com.example.store"),
        ("HTTPS://API.EXAMPLE.TEST:443/v1", "https://api.example.test/v1"),
        ("https://api.example.test", "https://api.example.test/"),
        ("https://[2001:db8::1]:8443/v1", "https://[2001:db8::1]:8443/v1"),
    ],
)
def test_targets_have_a_stable_exact_canonical_form(target, expected):
    assert validate_target(target) == expected


@pytest.mark.parametrize(
    "target",
    [
        "*",
        "package:com.example.*",
        "package:store",
        "http://api.example.test",
        "https://user:token@api.example.test/v1",
        "https://api.example.test/v1?token=secret",
        "https://api.example.test/v1#fragment",
        "https://api.example.test/../admin",
        "https://api.example.test/%2e%2e/admin",
        "https://api.example.test/v[12]",
        "https://api.example.test\\@another.test",
        "https://api.exa\nmple.test",
        "https://api.example.test:65536",
        "https://api.example.test:0",
        "https://*.example.test",
    ],
)
def test_scope_rejects_broad_targets_credentials_and_url_parser_ambiguity(target):
    with pytest.raises(ValueError):
        validate_target(target)


@pytest.mark.parametrize("path", ["/v1//admin", "/v1/admin;parameter=ignored", "/v1/ａｄｍｉｎ"])
def test_scope_rejects_ambiguous_path_normalization(path):
    with pytest.raises(ValueError):
        validate_target("https://api.example.test" + path)


@pytest.mark.parametrize("field", ["valid_from", "valid_until"])
def test_authorizations_require_explicit_timezone(field):
    with pytest.raises(ValidationError):
        AuthorizationCreate(**authorization_data(**{field: datetime(2026, 10, 28)}))


def test_authorization_window_is_ordered_by_instant_and_serialized_in_utc():
    auth = AuthorizationCreate(
        **authorization_data(
            valid_from="2026-10-28T12:00:00+06:00", valid_until="2026-10-28T07:00:00Z"
        )
    )
    assert auth.valid_from == datetime(2026, 10, 28, 6, tzinfo=UTC)
    with pytest.raises(ValidationError):
        AuthorizationCreate(
            **authorization_data(
                valid_from="2026-10-28T12:00:00+06:00", valid_until="2026-10-28T06:00:00Z"
            )
        )


def test_authorization_requires_nonempty_unique_approved_targets():
    with pytest.raises(ValidationError):
        AuthorizationCreate(**authorization_data(approved_targets=[]))
    with pytest.raises(ValidationError):
        AuthorizationCreate(
            **authorization_data(
                approved_targets=[
                    "https://api.example.test",
                    "HTTPS://API.EXAMPLE.TEST:443/",
                ]
            )
        )
    with pytest.raises(ValidationError):
        AuthorizationCreate(
            **authorization_data(approved_targets=["package:com.example.store"] * 101)
        )


@pytest.mark.parametrize(
    "reference",
    [
        "",
        "Client approves all testing",
        "/etc/passwd",
        "../approval.pdf",
        "file:///approval.pdf",
        "https://example.test/approval",
        "approval\nsecret",
    ],
)
def test_authorization_evidence_is_an_internal_reference(reference):
    with pytest.raises(ValidationError):
        AuthorizationCreate(**authorization_data(evidence_ref=reference))


def test_client_cannot_submit_verification_or_execution_metadata():
    with pytest.raises(ValidationError):
        AuthorizationCreate(**authorization_data(status="verified", verified_by=uuid4()))
    with pytest.raises(ValidationError):
        AssessmentCreate(
            project_id=uuid4(),
            name="API",
            assessment_type="api",
            requested_targets=["https://api.example.test/v1"],
            status="running",
        )


def test_assessment_contract_requires_explicit_exact_scope():
    base = {"project_id": uuid4(), "name": "API", "assessment_type": "api"}
    with pytest.raises(ValidationError):
        AssessmentCreate(**base, requested_targets=[])
    with pytest.raises(ValidationError):
        AssessmentCreate(**base, requested_targets=["https://api.example.test/*"])
    assessment = AssessmentCreate(**base, requested_targets=["https://api.example.test/v1"])
    assert (
        assessment.authorization_id is None
    )  # It is a draft; the queue service enforces authorization.


def test_assessment_patch_can_link_or_clear_records_without_clearing_required_fields():
    authorization_id = uuid4()
    assert (
        AssessmentUpdate(revision=1, authorization_id=authorization_id).authorization_id
        == authorization_id
    )
    assert AssessmentUpdate(revision=1, artifact_id=None).model_dump(exclude_unset=True) == {
        "revision": 1,
        "artifact_id": None,
    }
    for field in ("name", "requested_targets"):
        with pytest.raises(ValidationError):
            AssessmentUpdate(**{"revision": 1, field: None})
    with pytest.raises(ValidationError):
        AssessmentUpdate(revision=1, requested_targets=[])
    with pytest.raises(ValidationError):
        AssessmentUpdate(
            revision=1, requested_targets=["https://api.example.test", "https://api.example.test/"]
        )
    with pytest.raises(ValidationError):
        AssessmentUpdate(revision=1, project_id=uuid4())


def test_artifact_claims_are_bounded_and_do_not_accept_a_storage_location():
    artifact = ArtifactCreate(**artifact_data(version_code=0))
    assert artifact.sha256 == "a" * 64
    assert ArtifactCreate(**artifact_data(version_code=2**63 - 1)).version_code == 2**63 - 1
    with pytest.raises(ValidationError):
        ArtifactCreate(**artifact_data(storage_ref="/tmp/untrusted.apk"))
    with pytest.raises(ValidationError):
        ArtifactCreate(**artifact_data(metadata_json={"token": "secret"}))


@pytest.mark.parametrize(
    "changes",
    [
        {"sha256": "z" * 64},
        {"sha256": "a" * 63},
        {"file_size": 0},
        {"file_size": 2 * 1024**3 + 1},
        {"version_code": -1},
        {"version_code": 2**63},
        {"version_code": True},
        {"original_filename": "../app.apk"},
        {"original_filename": "C:\\temp\\app.apk"},
        {"original_filename": "app.zip"},
        {"original_filename": "app\x00.apk"},
    ],
)
def test_invalid_artifact_claims_are_rejected(changes):
    with pytest.raises(ValidationError):
        ArtifactCreate(**artifact_data(**changes))


@pytest.mark.parametrize(
    "field", ["password", "payment_card", "api_key", "token", "workspace_id", "created_by"]
)
def test_client_schema_rejects_unrelated_sensitive_or_server_owned_fields(field):
    with pytest.raises(ValidationError):
        ClientCreate(**{"name": "Client", field: "not-collected"})


def test_membership_add_accepts_only_user_id():
    assert ProjectMemberAdd(user_id=uuid4()).user_id
    with pytest.raises(ValidationError):
        ProjectMemberAdd(user_id=uuid4(), role="ADMIN")


def test_artifact_response_allowlist_hides_storage_and_raw_metadata():
    artifact = SimpleNamespace(
        id=uuid4(),
        workspace_id=uuid4(),
        project_id=uuid4(),
        created_by=uuid4(),
        created_at=datetime(2026, 10, 28),
        version_name="1.0",
        version_code=1,
        sha256="a" * 64,
        original_filename="store.apk",
        file_size=1024,
        build_type="release",
        storage_ref="protected/raw.apk",
        metadata_json={"secret": "hidden"},
    )
    output = ArtifactOut.model_validate(artifact).model_dump(mode="json")
    assert "storage_ref" not in output
    assert "metadata_json" not in output
    assert output["created_at"].endswith("Z")


def test_assessment_response_reads_only_requested_scope_from_snapshot():
    assessment = SimpleNamespace(
        id=uuid4(),
        workspace_id=uuid4(),
        created_by=uuid4(),
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
        revision=1,
        project_id=uuid4(),
        artifact_id=None,
        authorization_id=None,
        name="API draft",
        assessment_type="api",
        status="draft",
        configuration_snapshot={
            "requested_targets": ["https://api.example.test/v1"],
            "secret": "hidden",
        },
        tool_versions={"token": "hidden"},
        reviewer_id=None,
        started_at=None,
        completed_at=None,
        cancelled_at=None,
        failure_reason=None,
        cancellation_reason=None,
    )
    output = AssessmentOut.model_validate(assessment).model_dump()
    assert output["requested_targets"] == ["https://api.example.test/v1"]
    assert "configuration_snapshot" not in output
    assert "tool_versions" not in output


def test_identity_response_never_serializes_authentication_material():
    user = SimpleNamespace(
        id=uuid4(),
        workspace_id=uuid4(),
        email="analyst@example.test",
        full_name="Analyst",
        role="SECURITY_ANALYST",
        status="active",
        password_hash="hidden",
        access_token="hidden",
    )
    assert set(MeOut.model_validate(user).model_dump()) == {
        "id",
        "workspace_id",
        "workspace_name",
        "email",
        "full_name",
        "role",
        "status",
    }
