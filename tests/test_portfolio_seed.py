"""Portfolio records must obey the same protected-read contracts as real intake."""

from copy import deepcopy

import pytest
from pydantic import ValidationError
from scripts.seed_portfolio_demo import (
    validate_portfolio_artifacts,
    validate_portfolio_response_contracts,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

from droidshield.models import AppArtifact, Assessment, Retest
from tests.test_models import model_engine as _model_engine
from tests.test_models import records as _records

model_engine = _model_engine
records = _records

APK_METADATA = {
    "package_name": "com.example.portfolio",
    "version_name": "1.0",
    "version_code": 1,
    "min_sdk": 26,
    "target_sdk": 35,
    "permissions": [],
    "application": {
        "debuggable": False,
        "uses_cleartext_traffic": False,
        "allow_backup": False,
        "test_only": False,
    },
    "components": [],
    "signing_certificate": None,
}
IPA_METADATA = {
    "platform": "ios",
    "artifact_format": "ipa",
    "package_name": "com.example.portfolio",
    "version_name": "1.0",
    "version_code": None,
    "build_number": "1",
    "minimum_os": "15.0",
    "ats_allows_arbitrary_loads": False,
    "ats_exception_domain_count": 0,
    "url_scheme_count": 0,
    "usage_description_count": 0,
    "executable_present": True,
    "signature_directory_present": False,
    "embedded_provisioning_profile_present": False,
    "architectures": ["arm64"],
    "file_type": "executable",
    "load_command_count": 0,
    "code_signature_command_present": False,
    "embedded_entitlements_blob_present": False,
}


@pytest.fixture
def portfolio_artifacts(model_engine, records):
    with Session(model_engine) as session:
        artifacts = list(
            session.scalars(
                select(AppArtifact)
                .where(AppArtifact.workspace_id == records["workspace"])
                .order_by(AppArtifact.id)
            )
        )
        for artifact, metadata in zip(
            artifacts,
            [
                APK_METADATA,
                {**APK_METADATA, "platform": "android", "artifact_format": "aab"},
                IPA_METADATA,
            ],
            strict=True,
        ):
            artifact.metadata_json = deepcopy(metadata)
        session.commit()
        yield session, artifacts


def test_portfolio_audit_accepts_all_supported_artifact_detail_contracts(
    portfolio_artifacts, records
):
    session, _ = portfolio_artifacts
    # The unrelated workspace's deliberately incomplete fixture metadata is excluded.
    validate_portfolio_artifacts(session, records["workspace"])


@pytest.mark.parametrize(
    "extra",
    [{"platform": "android"}, {"artifact_format": "apk"}, {"untrusted_secret": "not-public"}],
)
def test_portfolio_audit_rejects_apk_metadata_that_would_break_protected_reads(
    portfolio_artifacts, records, extra
):
    session, artifacts = portfolio_artifacts
    artifacts[0].metadata_json = {**APK_METADATA, **extra}
    with pytest.raises(ValidationError):
        validate_portfolio_artifacts(session, records["workspace"])


@pytest.fixture
def portfolio_retest(portfolio_artifacts, records):
    session, _ = portfolio_artifacts
    for assessment in session.scalars(select(Assessment)):
        assessment.configuration_snapshot = {"requested_targets": ["package:test.app"]}
    artifact = session.get(AppArtifact, records["alternative_artifact"])
    retest = Retest(
        workspace_id=records["workspace"],
        project_id=records["project"],
        finding_id=records["finding"],
        original_assessment_id=records["assessment"],
        new_artifact_id=artifact.id,
        method="static",
        operator_id=records["user"],
        environment={
            "platform": "android",
            "environment": "Synthetic isolated lab",
            "tool": "Portfolio fixture",
            "tool_version": "not-run",
            "authorization_id": str(records["authorization"]),
            "authorization_revision": 1,
            "artifact_sha256": artifact.sha256,
        },
        previous_evidence=[],
        new_evidence=[],
        result="inconclusive",
    )
    session.add(retest)
    session.flush()
    return session, retest


def test_portfolio_response_audit_validates_retest_provenance_shape(portfolio_retest, records):
    session, _ = portfolio_retest
    counts = validate_portfolio_response_contracts(session, records["workspace"])
    assert counts["app_artifacts"] == 3
    assert counts["retests"] == 1


@pytest.mark.parametrize("missing", ["authorization_revision", "artifact_sha256"])
def test_portfolio_response_audit_rejects_incomplete_retest_provenance(
    portfolio_retest, records, missing
):
    session, retest = portfolio_retest
    retest.environment = {key: value for key, value in retest.environment.items() if key != missing}
    with pytest.raises(ValidationError):
        validate_portfolio_response_contracts(session, records["workspace"])


def test_portfolio_response_audit_rejects_unsupported_retest_environment_fields(
    portfolio_retest, records
):
    session, retest = portfolio_retest
    retest.environment = {**retest.environment, "portfolio_notice": "Fictional example"}
    with pytest.raises(ValidationError):
        validate_portfolio_response_contracts(session, records["workspace"])
