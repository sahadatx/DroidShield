"""Real migration guards preserve reviewed deliverable history."""

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session

from droidshield.models import Report, User
from droidshield.report_models import ReportExport, ReportSnapshot
from tests.test_analysis_migration import migrated_analysis as _migrated_analysis
from tests.test_analysis_migration import seed_result_origins

migrated_analysis = _migrated_analysis


def test_report_history_and_identity_guards(migrated_analysis):
    engine = migrated_analysis
    origin = seed_result_origins(engine)
    with Session(engine) as session:
        user = session.query(User).filter(User.workspace_id == origin["workspace_id"]).first()
        report = Report(
            workspace_id=origin["workspace_id"],
            project_id=origin["project_id"],
            assessment_id=origin["first_assessment"],
            title="Immutable client report",
            template="combined",
            version=1,
            status="awaiting_review",
            filters={},
            branding={},
            author_id=user.id,
        )
        session.add(report)
        session.flush()
        session.add(
            ReportSnapshot(
                workspace_id=report.workspace_id,
                project_id=report.project_id,
                assessment_id=report.assessment_id,
                report_id=report.id,
                version=1,
                snapshot_json={"version": 1},
                sha256="a" * 64,
            )
        )
        session.add(
            ReportExport(
                workspace_id=report.workspace_id,
                project_id=report.project_id,
                report_id=report.id,
                format="json",
                storage_ref="apk:" + "a" * 32,
                sha256="b" * 64,
                file_size=20,
                created_by=user.id,
            )
        )
        session.commit()
    statements = [
        "UPDATE report_snapshots SET version = version",
        "DELETE FROM report_snapshots",
        "UPDATE report_exports SET sha256 = sha256",
        "DELETE FROM report_exports",
        "UPDATE reports SET title = 'changed'",
    ]
    if engine.dialect.name == "postgresql":
        statements.extend(["TRUNCATE report_snapshots", "TRUNCATE report_exports"])
    for statement in statements:
        with pytest.raises(DBAPIError), engine.begin() as connection:
            connection.execute(text(statement))
