"""Replace the local demo workspace with a realistic, fictional portfolio dataset.

Run only against a newly migrated, isolated database under var/. Every record
and artifact produced here is synthetic; no external target is contacted.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import plistlib
import random
import struct
import sys
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT))

from sqlalchemy import select  # noqa: E402
from sqlalchemy.orm import Session  # noqa: E402
from tests.apk_factory import build_apk  # noqa: E402
from tests.test_mobile_intake import aab_bytes  # noqa: E402

from droidshield import (  # noqa: E402
    api_security,
    delivery_schemas,
    dynamic,
    report_schemas,
    reports,
    schemas,
    services,
)
from droidshield.config import Settings  # noqa: E402
from droidshield.cvss_scoring import score_cvss  # noqa: E402
from droidshield.db import build_engine  # noqa: E402
from droidshield.methodology import library  # noqa: E402
from droidshield.models import (  # noqa: E402
    AccessToken,
    AnalysisJob,
    AnalysisResult,
    APIExecution,
    APITarget,
    AppArtifact,
    Assessment,
    AssessmentEvidence,
    AuditEvent,
    Authorization,
    Client,
    DynamicSession,
    Evidence,
    Finding,
    Project,
    ProjectAccess,
    Report,
    Retest,
    TestExecution,
    User,
    Workspace,
)
from droidshield.report_models import ReportExport, ReportSnapshot  # noqa: E402
from droidshield.sandbox import Sandbox  # noqa: E402
from droidshield.schemas import ArtifactDetailOut  # noqa: E402
from droidshield.storage import Storage  # noqa: E402

SOURCE_DB = ROOT / "var/droidshield.db"
TARGET_DB = ROOT / "var/droidshield-portfolio.db"
STORAGE_ROOT = ROOT / "var/portfolio-artifacts"
SAMPLE_NOTICE = (
    "Synthetic portfolio example. The organization, app, authorization, evidence, "
    "and workflow state are fictional; no client system or external API was tested."
)

CLIENT_NAMES = [
    "Northstar Digital Finance",
    "Asterline Health Network",
    "Cedarwave Payments",
    "Meridian Care Partners",
    "Blueharbor Credit Union",
    "Juniper Clinical Group",
    "SummitLedger Exchange",
    "Evergreen Insurance",
    "Clearpath Diagnostics",
    "Silveroak Capital",
    "Harborlight Retail Group",
    "Redwood Benefits",
    "AtlasField Logistics",
    "Brightwell Telehealth",
    "LumenPay Services",
    "Westbridge Wealth",
    "Crescent Pharmacy Network",
    "Pinecrest Mobility",
    "Cloudline Enterprise",
    "Stonegate Microfinance",
    "Openlane Travel",
    "Fairview Home Health",
    "Ironwood Marketplace",
    "Saffron Business Bank",
    "Rivermark Utilities",
    "Daybreak Consumer Finance",
    "Oakstone Labs",
    "Tidepool Commerce",
    "Kestrel Workforce",
    "MapleBridge Insurance",
]
INDIVIDUALS = ["Nadia Rahman", "Farhan Karim", "Mira Chowdhury", "Rafi Ahmed"]
CLIENT_PREFIXES = [
    "Cobalt",
    "Granite",
    "Silverline",
    "Morrowgate",
    "Westfield",
    "Cedarstone",
    "Brightpath",
    "Oakwell",
    "Redfern",
    "Summit Ridge",
    "Lighthouse",
    "Pioneer",
    "Brookhaven",
    "Windward",
    "Ironbridge",
    "Bluecrest",
    "Meadowlark",
    "Kingswell",
]
CLIENT_SECTORS = [
    "Digital Finance",
    "Health Systems",
    "Payment Services",
    "Insurance Group",
    "Commerce Network",
    "Enterprise Solutions",
    "Microfinance",
    "Clinical Partners",
]
TEAM_FIRST_NAMES = [
    "Amina",
    "Tanvir",
    "Samira",
    "Daniel",
    "Maya",
    "Aminul",
    "Priya",
    "Omar",
    "Elena",
    "Tariq",
    "Leah",
    "Imran",
    "Nina",
    "Marcus",
    "Sadia",
    "Rohan",
    "Ayesha",
    "Noah",
    "Farzana",
    "Ishaan",
    "Sara",
    "Arif",
    "Mariam",
    "Ethan",
]
TEAM_LAST_NAMES = [
    "Haque",
    "Ahmed",
    "Khan",
    "Foster",
    "Patel",
    "Sen",
    "Siddiqui",
    "Park",
    "Hasan",
    "Morgan",
    "Chowdhury",
    "Das",
    "Reed",
    "Islam",
    "Mehta",
    "Karim",
    "Bennett",
    "Akter",
    "Roy",
    "Hossain",
    "Rahman",
    "Brooks",
    "Miller",
    "Sarker",
]
CONTACTS = [
    "Samira Khan",
    "Daniel Foster",
    "Maya Patel",
    "Aminul Haque",
    "Priya Sen",
    "Omar Siddiqui",
    "Elena Park",
    "Tariq Hasan",
    "Leah Morgan",
    "Imran Chowdhury",
    "Nina Das",
    "Marcus Reed",
    "Sadia Islam",
    "Rohan Mehta",
    "Ayesha Karim",
    "Noah Bennett",
    "Farzana Akter",
    "Ishaan Roy",
    "Sara Ahmed",
    "Arif Hossain",
]
APP_NAMES = [
    "Mobile Banking",
    "Patient Connect",
    "Merchant Hub",
    "Care Portal",
    "Digital Wallet",
    "Member Access",
    "Field Operations",
    "Claims Companion",
    "Workforce One",
    "Travel Desk",
    "Clinic Queue",
    "Business Console",
    "Market Basket",
    "Secure Inbox",
    "Family Health",
]
FRAMEWORKS = ["native", "flutter", "react_native", "other", "unknown"]
ASSESSMENT_TYPES = ["static", "dynamic", "api", "full"]
ASSESSMENT_STATUSES = [
    "draft",
    "awaiting_authorization",
    "queued",
    "running",
    "needs_review",
    "completed",
    "failed",
    "cancelled",
]
SEVERITIES = ["critical", "high", "medium", "low", "info"]
REMEDIATION_STATES = ["open", "in_progress", "fixed", "accepted_risk", "retest_required"]
CVSS = {
    "critical": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "high": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N",
    "medium": "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:H/I:N/A:N",
    "low": "CVSS:3.1/AV:L/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N",
}
FINDING_TITLES = [
    "Sensitive session value remains after sign-out",
    "Exported Android component lacks an explicit permission",
    "API response exposes another account's sample record",
    "WebView navigation accepts an untrusted destination",
    "Backup configuration includes application data",
    "Token lifetime is not bounded after credential rotation",
    "Cleartext traffic is enabled in the sample manifest",
    "Deep link accepts an unvalidated redirect parameter",
    "Debug logging includes a synthetic account identifier",
    "Dependency inventory needs version verification",
    "Biometric fallback path needs a server-side check",
    "Cache policy retains a sample profile longer than expected",
]


def utc_now() -> datetime:
    return datetime.now(UTC)


def stamp_days_ago(days: int) -> datetime:
    return utc_now() - timedelta(days=days)


def slug(value: str) -> str:
    return "".join(char.lower() for char in value if char.isalnum())


def safe_ipa(bundle: str, version: str, build: int) -> bytes:
    info = {
        "CFBundlePackageType": "APPL",
        "CFBundleIdentifier": bundle,
        "CFBundleExecutable": "SampleApp",
        "CFBundleShortVersionString": version,
        "CFBundleVersion": str(build),
        "MinimumOSVersion": "16.0",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False},
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["sampleapp"]}],
    }
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(
            "Payload/SampleApp.app/Info.plist",
            plistlib.dumps(info, fmt=plistlib.FMT_BINARY),
        )
        archive.writestr(
            "Payload/SampleApp.app/SampleApp",
            struct.pack("<IIIIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0),
        )
    return output.getvalue()


def copy_identity(source: Session, target: Session) -> tuple[Workspace, User, User, User]:
    old_workspace = source.scalar(select(Workspace))
    admins = source.scalars(select(User).where(User.role == "ADMIN", User.status == "active")).all()
    if old_workspace is None or not admins:
        raise RuntimeError("The existing local workspace and active administrator are required")
    admin_source = admins[0]
    workspace = Workspace(
        id=old_workspace.id,
        name="DroidShield Portfolio · Synthetic Dataset",
        created_at=old_workspace.created_at,
    )
    target.add(workspace)
    target.flush()
    admin = User(
        id=admin_source.id,
        workspace_id=old_workspace.id,
        email=admin_source.email,
        full_name=admin_source.full_name,
        password_hash=admin_source.password_hash,
        role=admin_source.role,
        status=admin_source.status,
        created_at=admin_source.created_at,
        updated_at=admin_source.updated_at,
    )
    analyst = User(
        workspace_id=old_workspace.id,
        email="amina.haque@portfolio.example.com",
        full_name="Amina Haque",
        password_hash=None,
        role="SECURITY_ANALYST",
        status="active",
        created_at=stamp_days_ago(180),
        updated_at=stamp_days_ago(2),
    )
    reviewer = User(
        workspace_id=old_workspace.id,
        email="tanvir.ahmed@portfolio.example.com",
        full_name="Tanvir Ahmed",
        password_hash=None,
        role="ADMIN",
        status="active",
        created_at=stamp_days_ago(160),
        updated_at=stamp_days_ago(3),
    )
    target.add_all([admin, analyst, reviewer])
    target.flush()
    for credential in source.scalars(
        select(AccessToken).where(
            AccessToken.user_id == admin.id,
            AccessToken.revoked_at.is_(None),
            AccessToken.expires_at > utc_now(),
        )
    ):
        target.add(
            AccessToken(
                id=credential.id,
                user_id=admin.id,
                token_hash=credential.token_hash,
                expires_at=credential.expires_at,
                revoked_at=None,
                created_at=credential.created_at,
            )
        )
    target.flush()
    return workspace, admin, analyst, reviewer


def validate_portfolio_artifacts(session: Session, workspace_id) -> None:
    """Reject synthetic artifacts that the protected detail API cannot serialize."""
    for artifact in session.scalars(
        select(AppArtifact).where(AppArtifact.workspace_id == workspace_id)
    ):
        ArtifactDetailOut.model_validate(artifact)


def validate_portfolio_response_contracts(session: Session, workspace_id) -> dict[str, int]:
    """Validate every persisted public record before publishing a preview database."""
    pairs = [
        (User, schemas.MeOut),
        (Client, schemas.ClientOut),
        (Project, schemas.ProjectOut),
        (AppArtifact, schemas.ArtifactDetailOut),
        (Authorization, schemas.AuthorizationOut),
        (Assessment, schemas.AssessmentOut),
        (AnalysisJob, schemas.AnalysisJobOut),
        (AnalysisResult, schemas.AnalysisOut),
        (APITarget, api_security.TargetOut),
        (APIExecution, api_security.ExecutionOut),
        (DynamicSession, dynamic.DynamicOut),
        (Finding, schemas.FindingDetailOut),
        (TestExecution, delivery_schemas.ExecutionOut),
        (AssessmentEvidence, delivery_schemas.EvidenceOut),
        (Retest, delivery_schemas.RetestOut),
        (Report, report_schemas.ReportOut),
        (ReportExport, report_schemas.ReportExportOut),
    ]
    counts = {}
    for model, output in pairs:
        rows = list(session.scalars(select(model).where(model.workspace_id == workspace_id)))
        for row in rows:
            output.model_validate(row)
        counts[model.__tablename__] = len(rows)

    for report in session.scalars(select(Report).where(Report.workspace_id == workspace_id)):
        snapshot = session.scalar(
            select(ReportSnapshot).where(
                ReportSnapshot.report_id == report.id,
                ReportSnapshot.workspace_id == workspace_id,
            )
        )
        if snapshot is None:
            raise RuntimeError("Portfolio report has no frozen detail snapshot")
        report_schemas.ReportDetailOut.model_validate(
            {
                **report_schemas.ReportOut.model_validate(report).model_dump(),
                "snapshot": snapshot.snapshot_json,
                "snapshot_sha256": snapshot.sha256,
            }
        )

    events = list(
        session.scalars(select(AuditEvent).where(AuditEvent.workspace_id == workspace_id))
    )
    for event in events:
        schemas.AuditEventOut.model_validate(
            {
                "id": event.id,
                "timestamp": event.created_at,
                "actor_id": event.actor_id,
                "action": event.action,
                "resource_type": event.resource_type,
                "resource_id": event.resource_id,
                "result": event.result,
                "request_id": event.request_id,
                "source": event.source_metadata,
            }
        )
    counts[AuditEvent.__tablename__] = len(events)
    return counts


def validate_portfolio_consistency(session: Session, workspace_id) -> None:
    """Refuse to publish portfolio records that look like work never performed."""
    validate_portfolio_response_contracts(session, workspace_id)
    active_assessment = session.scalar(
        select(Assessment.id)
        .where(
            Assessment.workspace_id == workspace_id,
            Assessment.status.in_(["queued", "running"]),
        )
        .limit(1)
    )
    if active_assessment:
        raise RuntimeError("Portfolio examples cannot leave active work with expired scope")

    pretest_assessments = set(
        session.scalars(
            select(Assessment.id).where(
                Assessment.workspace_id == workspace_id,
                Assessment.status.in_(["draft", "awaiting_authorization", "failed", "cancelled"]),
            )
        )
    )
    for finding in session.scalars(select(Finding).where(Finding.workspace_id == workspace_id)):
        assessment = session.get(Assessment, finding.assessment_id)
        if assessment is None:
            raise RuntimeError("Portfolio finding has no source assessment")
        if assessment.id in pretest_assessments:
            raise RuntimeError("Pre-test and failed/cancelled assessments cannot have findings")
        if assessment.status == "needs_review" and finding.verification_status != "unreviewed":
            raise RuntimeError("Needs-review findings must remain unreviewed")
        if finding.verification_status == "confirmed" and assessment.status != "completed":
            raise RuntimeError(
                "Only completed, independently reviewed assessments can confirm findings"
            )

    for execution in session.scalars(
        select(TestExecution).where(TestExecution.workspace_id == workspace_id)
    ):
        if execution.assessment_id in pretest_assessments and (
            execution.status != "not_run" or execution.evidence_ids or execution.finding_ids
        ):
            raise RuntimeError(
                "Pre-test coverage must remain Not Run and have no evidence or findings"
            )

    approved_passes = set(
        session.scalars(
            select(Retest.finding_id).where(
                Retest.workspace_id == workspace_id,
                Retest.review_decision == "approve",
                Retest.result == "pass",
            )
        )
    )
    for finding in session.scalars(
        select(Finding).where(
            Finding.workspace_id == workspace_id,
            Finding.remediation_status == "fixed",
        )
    ):
        if finding.verification_status != "confirmed" or finding.id not in approved_passes:
            raise RuntimeError(
                "A Fixed finding must have confirmed, approved passing retest evidence"
            )

    for execution in session.scalars(
        select(APIExecution).where(APIExecution.workspace_id == workspace_id)
    ):
        job = session.get(AnalysisJob, execution.job_id)
        assessment = session.get(Assessment, execution.assessment_id)
        if (
            execution.status != "cancelled"
            or execution.result_json is not None
            or job is None
            or job.status != execution.status
            or assessment is None
            or assessment.status != "cancelled"
        ):
            raise RuntimeError("API sample executions must be aligned, cancelled, and result-free")

    for item in session.scalars(
        select(DynamicSession).where(DynamicSession.workspace_id == workspace_id)
    ):
        job = session.get(AnalysisJob, item.job_id)
        assessment = session.get(Assessment, item.assessment_id)
        if (
            item.status != "cancelled"
            or item.result_json is not None
            or item.device_id != "not-launched"
            or job is None
            or job.status != item.status
            or assessment is None
            or assessment.status != "cancelled"
        ):
            raise RuntimeError(
                "Dynamic sample sessions must be aligned cancellations with no device run"
            )

    snapshots = list(
        session.scalars(select(ReportSnapshot).where(ReportSnapshot.workspace_id == workspace_id))
    )
    report_count = session.query(Report).filter(Report.workspace_id == workspace_id).count()
    if len(snapshots) != report_count:
        raise RuntimeError("Every portfolio report needs one immutable version snapshot")
    for snapshot in snapshots:
        digest = hashlib.sha256(reports.canonical(snapshot.snapshot_json)).hexdigest()
        if digest != snapshot.sha256:
            raise RuntimeError("Portfolio report snapshot checksum does not match its contents")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-db", type=Path, default=TARGET_DB)
    parser.add_argument("--storage-root", type=Path, default=STORAGE_ROOT)
    args = parser.parse_args()
    target_db = args.target_db.expanduser().resolve()
    storage_root = args.storage_root.expanduser().resolve()
    allowed_root = (ROOT / "var").resolve()
    if (
        target_db == SOURCE_DB.resolve()
        or not target_db.is_relative_to(allowed_root)
        or target_db.suffix != ".db"
        or not storage_root.is_relative_to(allowed_root)
        or storage_root == (ROOT / "var/artifacts").resolve()
    ):
        raise RuntimeError("Portfolio output must use isolated paths under var/")
    settings = Settings(
        environment="development",
        database_url=f"sqlite:///{target_db}",
        storage_root=storage_root,
    )
    if not target_db.exists() or not SOURCE_DB.exists():
        raise RuntimeError("Migrate the portfolio database and preserve the source database first")
    if storage_root.exists() and any(path.is_file() for path in storage_root.rglob("*")):
        raise RuntimeError("Portfolio storage already contains data; refusing to overwrite it")

    rng = random.Random(20261031)
    target_engine = build_engine(settings.database_url)
    source_engine = build_engine(f"sqlite:///{SOURCE_DB}")
    storage = Storage(storage_root)
    evidence_storage = Storage(storage_root / "evidence")
    sandbox = Sandbox(settings)
    counts: dict[str, int] = {}

    with Session(source_engine) as source, Session(target_engine) as session:
        if session.scalar(select(Workspace.id).limit(1)) is not None:
            raise RuntimeError("The portfolio database is already populated; refusing to overwrite")
        workspace, admin, analyst, reviewer = copy_identity(source, session)
        workspace_id = workspace.id

        team_users = [admin, analyst, reviewer]
        roles = ["ADMIN", "SECURITY_ANALYST", "VIEWER"]
        for index in range(97):
            first = TEAM_FIRST_NAMES[index % len(TEAM_FIRST_NAMES)]
            last = TEAM_LAST_NAMES[(index * 7) % len(TEAM_LAST_NAMES)]
            record = User(
                workspace_id=workspace_id,
                email=f"{first.lower()}.{last.lower()}.{index + 1:03d}@portfolio.example.com",
                full_name=f"{first} {last}",
                password_hash=None,
                role=roles[index % len(roles)],
                status="disabled" if index % 17 == 0 else "active",
                created_at=stamp_days_ago(rng.randint(20, 400)),
                updated_at=stamp_days_ago(rng.randint(0, 18)),
            )
            team_users.append(record)
            session.add(record)
        session.flush()

        clients: list[Client] = []
        for index in range(100):
            company = index < 96
            if index < len(CLIENT_NAMES):
                name = CLIENT_NAMES[index]
            elif company:
                generated = index - len(CLIENT_NAMES)
                sequence = generated // (len(CLIENT_PREFIXES) * len(CLIENT_SECTORS)) + 1
                prefix = CLIENT_PREFIXES[generated % len(CLIENT_PREFIXES)]
                sector = CLIENT_SECTORS[(generated // len(CLIENT_PREFIXES)) % len(CLIENT_SECTORS)]
                name = f"{prefix} {sector} {sequence:02d}"
            else:
                name = INDIVIDUALS[index - 96]
            item_status = "archived" if index in {6, 14, 22, 30, 46, 62, 78, 94} else "active"
            contact = CONTACTS[index % len(CONTACTS)]
            domain = f"{slug(name)}.example.com"
            created = stamp_days_ago(rng.randint(90, 360))
            record = Client(
                workspace_id=workspace_id,
                client_type="company" if company else "individual",
                name=name,
                organization_name=name if company else None,
                website=f"https://{domain}" if company else None,
                contact_person=contact,
                contact_email=f"security@{domain}" if company else f"{slug(name)}@example.com",
                notes=SAMPLE_NOTICE,
                status=item_status,
                archive_reason="Synthetic historical account state."
                if item_status == "archived"
                else None,
                created_by=analyst.id,
                created_at=created,
                updated_at=created + timedelta(days=rng.randint(1, 30)),
            )
            clients.append(record)
            session.add(record)
        session.flush()
        active_clients = [client for client in clients if client.status == "active"]

        projects: list[Project] = []
        project_specs: list[tuple[str, str, str]] = []
        for index in range(120):
            client = active_clients[index % len(active_clients)]
            brand = slug(client.name)
            platform = "ios" if index % 5 in {1, 4} else "android"
            app = APP_NAMES[(index * 7 + rng.randrange(len(APP_NAMES))) % len(APP_NAMES)]
            framework = FRAMEWORKS[(index + rng.randrange(len(FRAMEWORKS))) % len(FRAMEWORKS)]
            package = f"com.{brand}.mobile{index + 1:02d}"
            item_status = ["active", "active", "on_hold", "active", "archived"][index % 5]
            created = stamp_days_ago(rng.randint(65, 330))
            record = Project(
                workspace_id=workspace_id,
                client_id=client.id,
                name=f"{app} · {'iOS' if platform == 'ios' else 'Android'} {index + 1:02d}",
                application_name=app,
                package_id=package,
                platform=platform,
                framework=framework,
                repository_url=f"https://code.example.com/{brand}/mobile-{index + 1:02d}",
                description=f"Synthetic portfolio application record. {SAMPLE_NOTICE}",
                scope_notes="Scope shown for interface demonstration only; no permission to test any real service is implied.",
                status=item_status,
                archive_reason="Synthetic portfolio lifecycle example."
                if item_status == "archived"
                else None,
                created_by=analyst.id,
                created_at=created,
                updated_at=created + timedelta(days=rng.randint(1, 20)),
            )
            projects.append(record)
            project_specs.append((platform, package, brand))
            session.add(record)
        session.flush()
        active_projects = [project for project in projects if project.status == "active"]
        for project in active_projects:
            session.add(
                ProjectAccess(
                    workspace_id=workspace_id,
                    project_id=project.id,
                    user_id=analyst.id,
                    created_by=admin.id,
                    created_at=project.created_at,
                )
            )
        eligible_team = [user for user in team_users if user.status == "active"]
        for index, project in enumerate(projects):
            for offset in range(2):
                user = eligible_team[(index * 3 + offset * 11) % len(eligible_team)]
                if user.id == analyst.id:
                    continue
                session.add(
                    ProjectAccess(
                        workspace_id=workspace_id,
                        project_id=project.id,
                        user_id=user.id,
                        created_by=admin.id,
                        created_at=project.created_at,
                    )
                )
        session.flush()
        counts["clients"] = len(clients)
        counts["projects"] = len(projects)

        artifacts_by_project: dict[object, list[AppArtifact]] = {}
        formats = {"apk": 0, "aab": 0, "ipa": 0}
        builds = ["debug", "release", "unknown"]
        for index, project in enumerate(projects):
            platform, package, brand = project_specs[projects.index(project)]
            build_count = 3 if platform == "android" and index % 4 == 0 else 2
            artifacts_by_project[project.id] = []
            for version_index in range(build_count):
                version_code = 100 + version_index * 13 + index
                version_name = f"{1 + (index % 3)}.{version_index}.{(index * 7) % 10}"
                if platform == "ios":
                    artifact_format = "ipa"
                    payload = safe_ipa(package, version_name, version_code)
                    engine_name = "ipa"
                    filename = f"{brand}-ios-{version_name}.ipa"
                elif version_index == 1 and index % 4 == 0:
                    artifact_format = "aab"
                    payload = aab_bytes(package=package)
                    engine_name = "aab"
                    filename = f"{brand}-android-{version_name}.aab"
                else:
                    artifact_format = "apk"
                    payload = build_apk(
                        package_name=package,
                        version_name=version_name,
                        version_code=version_code,
                        debuggable=(index + version_index) % 9 == 0,
                        cleartext=(index + version_index) % 7 == 0,
                        allow_backup=(index + version_index) % 4 == 0,
                        components=(
                            [{"kind": "activity", "name": ".DeepLinkActivity", "exported": True}]
                            if (index + version_index) % 3 == 0
                            else []
                        ),
                    )
                    engine_name = "manifest"
                    filename = f"{brand}-android-{version_name}.apk"
                staged = storage.stage(io.BytesIO(payload), settings.max_apk_bytes)
                try:
                    inspected = sandbox.run(staged.path, "inspect", engine=engine_name)
                    if (
                        inspected["sha256"] != staged.sha256
                        or inspected["file_size"] != staged.file_size
                    ):
                        raise RuntimeError("Sandbox intake returned a mismatched fixture digest")
                    metadata = dict(inspected["metadata"])
                    ref = storage.publish(staged)
                finally:
                    staged.close()
                artifact_created = stamp_days_ago(260 if version_index == 0 else 8)
                artifact = AppArtifact(
                    workspace_id=workspace_id,
                    project_id=project.id,
                    version_name=metadata.get("version_name") or version_name,
                    version_code=metadata.get("version_code"),
                    sha256=staged.sha256,
                    storage_ref=ref,
                    original_filename=filename,
                    file_size=staged.file_size,
                    build_type=builds[(index + version_index) % len(builds)],
                    metadata_json=metadata,
                    created_by=analyst.id,
                    created_at=artifact_created,
                )
                artifacts_by_project[project.id].append(artifact)
                session.add(artifact)
                formats[artifact_format] += 1
        session.flush()
        for records in artifacts_by_project.values():
            records.sort(key=lambda item: item.created_at)
        counts["artifacts"] = sum(formats.values())

        authorizations: dict[object, Authorization] = {}
        now = utc_now()
        for index, project in enumerate(projects):
            platform, package, brand = project_specs[projects.index(project)]
            target = f"{'bundle' if platform == 'ios' else 'package'}:{package}"
            api_target = f"https://api.{brand}.example.com/v1/mobile"
            status = ["verified", "pending", "verified", "revoked"][index % 4]
            valid_from = now - timedelta(days=365)
            valid_until = now - timedelta(hours=2)
            record = Authorization(
                workspace_id=workspace_id,
                project_id=project.id,
                status=status,
                approved_targets=[target, api_target],
                exclusions=[],
                valid_from=valid_from,
                valid_until=valid_until,
                evidence_ref=f"portfolio-authorization-{index + 1:04d}",
                notes=SAMPLE_NOTICE,
                verified_by=reviewer.id if status in {"verified", "revoked"} else None,
                verified_at=valid_from + timedelta(hours=2)
                if status in {"verified", "revoked"}
                else None,
                revoked_at=valid_until - timedelta(days=3) if status == "revoked" else None,
                revocation_reason="Synthetic historical revocation example."
                if status == "revoked"
                else None,
                created_by=analyst.id,
                created_at=project.created_at + timedelta(days=1),
                updated_at=project.created_at + timedelta(days=5),
            )
            authorizations[project.id] = record
            session.add(record)
        session.flush()

        # Keep a balanced mix of completed and historical workflow states across
        # all four assessment types without fabricating active worker jobs.
        assessments: list[Assessment] = []
        assessment_meta: dict[object, tuple[Project, str, str]] = {}
        completed_pool: list[Assessment] = []
        eligible = [p for p in active_projects if authorizations[p.id].status == "verified"]
        if len(eligible) < 8:
            raise RuntimeError(
                "The synthetic dataset needs active projects with verified sample scope"
            )
        # The local portfolio is historical and authorization windows are
        # intentionally expired. Do not seed stale queue/running work that a
        # worker cannot safely claim. Keep the state-machine options in the UI;
        # real queued/running records are created by the authorized workflow.
        portfolio_statuses = [
            "draft",
            "awaiting_authorization",
            "needs_review",
            "failed",
            "cancelled",
        ]
        for index in range(480):
            status = "completed" if index < 200 else portfolio_statuses[(index - 200) // 56]
            requested_type = ASSESSMENT_TYPES[index % len(ASSESSMENT_TYPES)]
            pool = eligible if status in {"needs_review", "completed"} else active_projects
            if requested_type in {"static", "dynamic"}:
                pool = [
                    candidate
                    for candidate in pool
                    if project_specs[projects.index(candidate)][0] == "android"
                ]
            project = pool[index % len(pool)]
            platform, package, brand = project_specs[projects.index(project)]
            assessment_type = requested_type
            if assessment_type in {"static", "dynamic"} and platform != "android":
                assessment_type = "full"
            artifact = None
            if assessment_type != "api":
                candidates = artifacts_by_project[project.id]
                if assessment_type == "static":
                    candidates = [
                        a
                        for a in candidates
                        if a.metadata_json.get("artifact_format", "apk") == "apk"
                    ]
                if assessment_type == "dynamic":
                    candidates = [
                        a
                        for a in candidates
                        if a.metadata_json.get("artifact_format", "apk") == "apk"
                    ]
                artifact = candidates[0] if candidates else artifacts_by_project[project.id][0]
            if assessment_type == "api":
                targets = [f"https://api.{brand}.example.com/v1/mobile/accounts/{index + 10}"]
            else:
                prefix = "bundle" if platform == "ios" else "package"
                targets = [f"{prefix}:{package}"]
            permit = authorizations[project.id]
            created = stamp_days_ago(rng.randint(24, 245))
            finished = created + timedelta(days=rng.randint(2, 8))
            manual = status in {"needs_review", "completed"}
            snapshot = {
                "requested_targets": targets,
                "engine": "manifest",
                "portfolio_sample": True,
                "portfolio_notice": SAMPLE_NOTICE,
            }
            if manual:
                snapshot["manual"] = {
                    "mode": "analyst_record",
                    "started_by": str(analyst.id),
                    "submitted_by": str(analyst.id),
                    "contributors": [str(analyst.id)],
                    "platform": platform,
                    "environment": "Synthetic portfolio fixture; no real device or customer data.",
                    "tools": [],
                    "limitations": SAMPLE_NOTICE,
                    "authorization_id": str(permit.id),
                    "authorization_revision": permit.revision,
                    "approved_targets": list(permit.approved_targets),
                    "exclusions": [],
                    "valid_from": permit.valid_from.isoformat(),
                    "valid_until": permit.valid_until.isoformat(),
                    "artifact_sha256": artifact.sha256 if artifact else None,
                }
                snapshot["manual"]["summary"] = SAMPLE_NOTICE
            record = Assessment(
                workspace_id=workspace_id,
                project_id=project.id,
                artifact_id=artifact.id if artifact else None,
                authorization_id=permit.id,
                name=f"{project.application_name} · {assessment_type.title()} Review {index + 1:03d}",
                assessment_type=assessment_type,
                status=status,
                configuration_snapshot=snapshot,
                tool_versions={},
                created_by=analyst.id,
                reviewer_id=reviewer.id if status == "completed" else None,
                started_at=created + timedelta(days=1)
                if status in {"needs_review", "completed", "failed", "cancelled"}
                else None,
                completed_at=finished if status == "completed" else None,
                cancelled_at=finished if status == "cancelled" else None,
                failure_reason="Synthetic scenario: source access was unavailable; no target was tested."
                if status == "failed"
                else None,
                cancellation_reason="Synthetic scenario: engagement was paused before testing."
                if status == "cancelled"
                else None,
                created_at=created,
                updated_at=finished
                if status in {"needs_review", "completed", "failed", "cancelled"}
                else created,
            )
            assessments.append(record)
            session.add(record)
            session.flush([record])
            assessment_meta[record.id] = (project, platform, brand)
            if status == "completed":
                completed_pool.append(record)
        session.flush()
        counts["assessments"] = len(assessments)

        framework = library()
        masvs = [
            ref["id"]
            for case in framework["cases"]
            for ref in case["references"]
            if ref["framework"] == "MASVS"
        ]
        cwe_values = ["CWE-200", "CWE-284", "CWE-312", "CWE-319", "CWE-522", "CWE-926"]
        finding_records: list[Finding] = []
        evidence_records: dict[object, list[AssessmentEvidence]] = {}
        # Every completed scenario gets a reviewed example finding so reports can
        # demonstrate the delivery flow. Needs-review examples have unreviewed
        # candidates; pre-test and failed/cancelled examples have no findings.
        for index, assessment in enumerate(assessments):
            number = (
                2
                if assessment.status == "completed"
                else 1
                if assessment.status == "needs_review"
                else 0
            )
            for slot in range(number):
                project, platform, brand = assessment_meta[assessment.id]
                severity = SEVERITIES[(index + slot) % len(SEVERITIES)]
                verification = (
                    "confirmed"
                    if assessment.status == "completed" and slot == 0
                    else "false_positive"
                    if assessment.status == "completed"
                    else "unreviewed"
                )
                vector = CVSS.get(severity)
                scored = score_cvss(vector) if vector else None
                created = assessment.created_at + timedelta(days=1, hours=slot)
                record = Finding(
                    workspace_id=workspace_id,
                    project_id=project.id,
                    assessment_id=assessment.id,
                    artifact_id=assessment.artifact_id,
                    title=FINDING_TITLES[(index + slot * 3) % len(FINDING_TITLES)],
                    description=SAMPLE_NOTICE
                    + " This row is illustrative and is not a real vulnerability report.",
                    affected_component=(
                        f"https://api.{brand}.example.com/v1/accounts/{{accountId}}"
                        if assessment.assessment_type == "api"
                        else f"{assessment.configuration_snapshot['requested_targets'][0]} · sample component"
                    ),
                    category=[
                        "data_storage",
                        "api_authorization",
                        "network_communication",
                        "authentication",
                        "platform",
                        "cryptography",
                        "privacy",
                    ][index % 7],
                    severity=severity,
                    verification_status=verification,
                    remediation_status=REMEDIATION_STATES[(index + slot) % len(REMEDIATION_STATES)],
                    cvss_vector=vector,
                    cvss_score=scored["score"] if scored else None,
                    masvs_mapping=[masvs[(index + slot) % len(masvs)]] if masvs else [],
                    cwe_mapping=[cwe_values[(index + slot) % len(cwe_values)]],
                    reproduction_steps="Use the synthetic account and fixture only. This sample describes a demonstration flow; no real target was contacted.",
                    impact="Illustrative impact statement for a fictional mobile application. No customer data or service was involved.",
                    remediation="Apply the documented control in a test build, then record evidence from an authorized environment.",
                    evidence_provenance={
                        "source": "synthetic_portfolio",
                        "contributors": [str(analyst.id)],
                        "masvs_version": "2.1.0",
                        "portfolio_notice": SAMPLE_NOTICE,
                    },
                    assigned_reviewer=reviewer.id if verification != "unreviewed" else None,
                    created_by=analyst.id,
                    created_at=created,
                    updated_at=created,
                )
                finding_records.append(record)
                session.add(record)
                session.flush([record])
                evidence_records[record.id] = []
        session.flush()

        for index, finding in enumerate(finding_records):
            assessment = next(item for item in assessments if item.id == finding.assessment_id)
            project, platform, brand = assessment_meta[assessment.id]
            content = (
                f"{SAMPLE_NOTICE}\n"
                f"Fixture: {project.application_name}; finding example {index + 1:03d}.\n"
                "Observation: a redacted, generated value is shown to illustrate evidence handling.\n"
                "No credential, personal record, production URL, or raw customer traffic is included."
            ).encode()
            staged = evidence_storage.stage(io.BytesIO(content), 262_144)
            try:
                ref = evidence_storage.publish(staged)
            finally:
                staged.close()
            release_ref = (
                f"portfolio-release-{index + 1:04d}"
                if assessment.assessment_type == "api"
                else None
            )
            evidence = AssessmentEvidence(
                workspace_id=workspace_id,
                project_id=project.id,
                assessment_id=assessment.id,
                finding_id=finding.id,
                artifact_id=assessment.artifact_id,
                release_ref=release_ref,
                title=f"Synthetic sanitized observation {index + 1:03d}",
                artifact_ref=ref,
                sha256=staged.sha256,
                file_size=staged.file_size,
                platform=platform,
                tool="Portfolio fixture",
                tool_version="not-run",
                environment="Synthetic portfolio data; no real system or device.",
                redaction_count=0,
                created_by=analyst.id,
                created_at=assessment.created_at + timedelta(days=1),
            )
            session.add(evidence)
            evidence_records[finding.id].append(evidence)
            session.add(
                Evidence(
                    workspace_id=workspace_id,
                    finding_id=finding.id,
                    artifact_ref=ref,
                    kind="synthetic_sanitized_text",
                    provenance={"source": "synthetic_portfolio", "sha256": staged.sha256},
                    created_by=analyst.id,
                    created_at=evidence.created_at,
                )
            )
        session.flush()
        for finding in finding_records:
            ids = [str(item.id) for item in evidence_records[finding.id]]
            finding.evidence_provenance = {**finding.evidence_provenance, "evidence_ids": ids}

        # Versioned coverage data gives every methodology filter a matching row.
        cases = framework["cases"]
        coverage_statuses = ["not_run", "pass", "fail", "na", "blocked"]
        executions_count = 0
        for index, assessment in enumerate(assessments):
            project, platform, _brand = assessment_meta[assessment.id]
            related_findings = [
                item for item in finding_records if item.assessment_id == assessment.id
            ]
            related_evidence = [
                item
                for values in evidence_records.values()
                for item in values
                if item.assessment_id == assessment.id
            ]
            for slot in range(3):
                case = cases[(index * 3 + slot) % len(cases)]
                status = (
                    coverage_statuses[(index + slot) % len(coverage_statuses)]
                    if assessment.status in {"completed", "needs_review"}
                    else "not_run"
                )
                evidence_ids = (
                    [str(related_evidence[0].id)]
                    if status in {"pass", "fail"} and related_evidence
                    else []
                )
                failed_finding = related_findings[0] if related_findings else None
                finding_ids = (
                    [str(failed_finding.id)] if status == "fail" and failed_finding else []
                )
                if status == "fail" and not finding_ids:
                    status = "blocked"
                session.add(
                    TestExecution(
                        workspace_id=workspace_id,
                        project_id=project.id,
                        assessment_id=assessment.id,
                        case_id=case["id"],
                        case_snapshot=case,
                        status=status,
                        platform=platform,
                        environment="Synthetic portfolio fixture; no real device or customer data.",
                        tool="Portfolio procedure example",
                        tool_version="not-run",
                        notes=SAMPLE_NOTICE,
                        evidence_ids=evidence_ids,
                        finding_ids=finding_ids,
                        operator_id=analyst.id,
                        contributors=[str(analyst.id)],
                        created_at=assessment.created_at + timedelta(days=2),
                        updated_at=assessment.created_at + timedelta(days=2),
                    )
                )
                executions_count += 1
        session.flush()
        counts["findings"] = len(finding_records)
        counts["protected_evidence"] = sum(len(v) for v in evidence_records.values())
        counts["coverage_entries"] = executions_count

        # Each confirmed completed sample has a distinct newer app artifact or,
        # for API examples, an explicitly synthetic release reference.
        retests_count = 0
        complete_findings = [
            finding
            for finding in finding_records
            if finding.verification_status == "confirmed"
            and next(a for a in assessments if a.id == finding.assessment_id).status == "completed"
        ]
        for index, finding in enumerate(complete_findings):
            assessment = next(item for item in assessments if item.id == finding.assessment_id)
            project, platform, _brand = assessment_meta[assessment.id]
            result = ["pass", "fail", "inconclusive", "not_reproducible"][index % 4]
            reviewed = [None, "approve", "reject"][index % 3]
            previous = evidence_records[finding.id][0]
            new_evidence_ids = []
            new_artifact = None
            environment = {
                "platform": platform,
                "environment": "Synthetic portfolio retest fixture; no customer system was tested.",
                "tool": "Portfolio retest example",
                "tool_version": "not-run",
                "authorization_id": str(assessment.authorization_id),
                "authorization_revision": authorizations[project.id].revision,
                "artifact_sha256": None,
            }
            if assessment.assessment_type == "api":
                original_release = previous.release_ref or f"portfolio-release-{index + 1:04d}"
                new_release = f"portfolio-release-r{index + 1:04d}"
                environment.update(
                    {"original_release_ref": original_release, "new_release_ref": new_release}
                )
                content = f"{SAMPLE_NOTICE}\nAPI retest reference: {new_release}. No request was sent.".encode()
                staged = evidence_storage.stage(io.BytesIO(content), 262_144)
                try:
                    ref = evidence_storage.publish(staged)
                finally:
                    staged.close()
                new_proof = AssessmentEvidence(
                    workspace_id=workspace_id,
                    project_id=project.id,
                    assessment_id=assessment.id,
                    finding_id=finding.id,
                    artifact_id=None,
                    release_ref=new_release,
                    title=f"Synthetic API retest observation {index + 1:03d}",
                    artifact_ref=ref,
                    sha256=staged.sha256,
                    file_size=staged.file_size,
                    platform=platform,
                    tool="Portfolio retest example",
                    tool_version="not-run",
                    environment=environment["environment"],
                    redaction_count=0,
                    created_by=analyst.id,
                    created_at=assessment.completed_at + timedelta(days=1),
                )
                session.add(new_proof)
                session.flush()
                new_evidence_ids.append(str(new_proof.id))
            else:
                versions = artifacts_by_project[project.id]
                original_format = next(
                    item.metadata_json.get("artifact_format", "apk")
                    for item in versions
                    if item.id == finding.artifact_id
                )
                new_artifact = next(
                    (
                        item
                        for item in reversed(versions)
                        if item.id != finding.artifact_id
                        and item.metadata_json.get("artifact_format", "apk") == original_format
                    ),
                    None,
                )
                if new_artifact is None:
                    continue
                content = f"{SAMPLE_NOTICE}\nNew build {new_artifact.version_name}; no external device was used.".encode()
                staged = evidence_storage.stage(io.BytesIO(content), 262_144)
                try:
                    ref = evidence_storage.publish(staged)
                finally:
                    staged.close()
                new_proof = AssessmentEvidence(
                    workspace_id=workspace_id,
                    project_id=project.id,
                    assessment_id=assessment.id,
                    finding_id=finding.id,
                    artifact_id=new_artifact.id,
                    release_ref=None,
                    title=f"Synthetic build retest observation {index + 1:03d}",
                    artifact_ref=ref,
                    sha256=staged.sha256,
                    file_size=staged.file_size,
                    platform=platform,
                    tool="Portfolio retest example",
                    tool_version="not-run",
                    environment=environment["environment"],
                    redaction_count=0,
                    created_by=analyst.id,
                    created_at=assessment.completed_at + timedelta(days=1),
                )
                session.add(new_proof)
                session.flush()
                new_evidence_ids.append(str(new_proof.id))
            environment["artifact_sha256"] = new_artifact.sha256 if new_artifact else None
            method = {
                "static": "static",
                "dynamic": "dynamic",
                "api": "api",
                "full": "manual",
            }[assessment.assessment_type]
            session.add(
                Retest(
                    workspace_id=workspace_id,
                    project_id=project.id,
                    finding_id=finding.id,
                    original_assessment_id=assessment.id,
                    review_decision=reviewed,
                    new_artifact_id=new_artifact.id if new_artifact else None,
                    method=method,
                    operator_id=analyst.id,
                    environment=environment,
                    previous_evidence=[str(previous.id)],
                    new_evidence=new_evidence_ids,
                    result=result,
                    notes=SAMPLE_NOTICE,
                    reviewer_id=reviewer.id if reviewed else None,
                    reviewed_at=assessment.completed_at + timedelta(days=2) if reviewed else None,
                    created_at=assessment.completed_at + timedelta(days=1),
                )
            )
            if reviewed == "approve" and result == "pass":
                finding.remediation_status = "fixed"
            retests_count += 1
        approved_passes = set(
            session.scalars(
                select(Retest.finding_id).where(
                    Retest.review_decision == "approve",
                    Retest.result == "pass",
                )
            )
        )
        for finding in finding_records:
            if finding.remediation_status == "fixed" and (
                finding.verification_status != "confirmed" or finding.id not in approved_passes
            ):
                finding.remediation_status = "retest_required"
        session.flush()
        counts["retests"] = retests_count

        # Populate API target and execution tables with expired, reserved-domain
        # configurations. Only cancelled parent assessments receive an
        # execution record, and that record explicitly says no request ran.
        api_assessments = [a for a in assessments if a.assessment_type == "api"]
        auth_methods = ["none", "bearer", "api_key", "cookie"]
        api_count = 0
        for index, assessment in enumerate(api_assessments):
            project, _platform, _brand = assessment_meta[assessment.id]
            url = assessment.configuration_snapshot["requested_targets"][0]
            method = auth_methods[index % len(auth_methods)]
            target = APITarget(
                workspace_id=workspace_id,
                project_id=project.id,
                assessment_id=assessment.id,
                name=f"{project.application_name} API baseline · sample {index + 1:02d}",
                endpoints=[
                    {"url": url, "method": "GET", "expect_authentication": method != "none"}
                ],
                excluded_endpoints=[f"https://api.{brand}.example.com/v1/admin"],
                auth_method=method,
                primary_secret_ref=None
                if method == "none"
                else f"portfolio.sample.primary{index + 1}",
                secondary_secret_ref=None,
                requests_per_minute=10 + index % 30,
                test_window_start=now - timedelta(days=30),
                test_window_end=now - timedelta(days=29),
                created_by=analyst.id,
                created_at=assessment.created_at + timedelta(hours=1),
            )
            session.add(target)
            session.flush()
            if assessment.status != "cancelled":
                continue
            state = "cancelled"
            cancelled_at = assessment.created_at + timedelta(hours=3)
            job = AnalysisJob(
                workspace_id=workspace_id,
                assessment_id=assessment.id,
                artifact_id=None,
                status=state,
                configuration_snapshot={
                    "portfolio_simulation": True,
                    "portfolio_notice": SAMPLE_NOTICE,
                },
                tool_versions={},
                cancellation_reason="portfolio_sample_not_run",
                started_at=None,
                completed_at=cancelled_at,
                attempt_count=0,
                created_at=assessment.created_at + timedelta(hours=1),
                updated_at=cancelled_at,
            )
            session.add(job)
            session.flush()
            session.add(
                APIExecution(
                    workspace_id=workspace_id,
                    project_id=project.id,
                    assessment_id=assessment.id,
                    target_id=target.id,
                    job_id=job.id,
                    status=state,
                    created_by=analyst.id,
                    configuration_snapshot={
                        "portfolio_simulation": True,
                        "portfolio_notice": SAMPLE_NOTICE,
                    },
                    result_json=None,
                    started_at=job.started_at,
                    completed_at=job.completed_at,
                    failure_reason=job.failure_reason,
                    cancellation_reason=job.cancellation_reason,
                    created_at=job.created_at,
                    updated_at=job.updated_at,
                )
            )
            api_count += 1
        session.flush()
        counts["api_targets"] = len(api_assessments)
        counts["api_execution_scenarios"] = api_count

        # Keep only cancellation examples. No lab device is configured, no
        # worker is started, and no application is launched.
        dynamic_assessments = [a for a in assessments if a.assessment_type == "dynamic"]
        scenarios = ["package_inspection", "launch_observe", "frida_observe", "proxy_observe"]
        dynamic_count = 0
        for index, assessment in enumerate(dynamic_assessments):
            project, _platform, brand = assessment_meta[assessment.id]
            if assessment.artifact_id is None or assessment.status != "cancelled":
                continue
            state = "cancelled"
            scenario = scenarios[index % len(scenarios)]
            cancelled_at = assessment.created_at + timedelta(hours=2)
            job = AnalysisJob(
                workspace_id=workspace_id,
                assessment_id=assessment.id,
                artifact_id=assessment.artifact_id,
                status=state,
                configuration_snapshot={
                    "portfolio_simulation": True,
                    "portfolio_notice": SAMPLE_NOTICE,
                },
                tool_versions={},
                cancellation_reason="portfolio_sample_not_run",
                started_at=None,
                completed_at=cancelled_at,
                attempt_count=0,
                created_at=assessment.created_at,
                updated_at=cancelled_at,
            )
            session.add(job)
            session.flush()
            session.add(
                DynamicSession(
                    workspace_id=workspace_id,
                    project_id=project.id,
                    assessment_id=assessment.id,
                    artifact_id=assessment.artifact_id,
                    job_id=job.id,
                    device_id="not-launched",
                    scenario=scenario,
                    timeout_seconds=30,
                    status=state,
                    notes=SAMPLE_NOTICE,
                    created_by=analyst.id,
                    configuration_snapshot={
                        "portfolio_simulation": True,
                        "portfolio_notice": SAMPLE_NOTICE,
                        "proxy_targets": [],
                    },
                    result_json=None,
                    started_at=None,
                    completed_at=cancelled_at,
                    failure_reason=None,
                    cancellation_reason="portfolio_sample_not_run",
                    created_at=assessment.created_at,
                    updated_at=cancelled_at,
                )
            )
            dynamic_count += 1
        session.flush()
        counts["dynamic_session_scenarios"] = dynamic_count
        counts["analysis_jobs"] = session.query(AnalysisJob).count()

        # Audit examples contain only safe action/resource metadata.
        resources = (
            [("client", item.id) for item in clients]
            + [("project", item.id) for item in projects]
            + [("assessment", item.id) for item in assessments]
            + [("finding", item.id) for item in finding_records]
        )
        actions = [
            "client.created",
            "project.created",
            "authorization.verified",
            "assessment.created",
            "assessment.manual_submitted",
            "finding.reviewed",
            "report.snapshot_created",
            "retest.reviewed",
            "artifact.uploaded",
            "evidence.created",
        ]
        for index in range(400):
            resource_type, resource_id = resources[index % len(resources)]
            action = actions[index % len(actions)]
            created = stamp_days_ago(rng.randint(0, 320))
            session.add(
                AuditEvent(
                    workspace_id=workspace_id,
                    actor_id=[admin.id, analyst.id, reviewer.id][index % 3],
                    action=action,
                    resource_type=resource_type,
                    resource_id=resource_id,
                    result="failure" if index % 19 == 0 else "success",
                    request_id=f"portfolio-{created:%Y%m%d}-{index + 1:04d}",
                    source_metadata={"source": "synthetic_portfolio", "channel": "sample_seed"},
                    created_at=created,
                )
            )
        session.flush()

        # Use the production report service for real immutable snapshots and
        # bounded protected exports built entirely from the synthetic fixture.
        report_assessments = completed_pool[:100]
        report_rows = []
        for index, assessment in enumerate(report_assessments):
            author_context = services.Context(session, admin, f"portfolio-report-{index + 1:03d}")
            payload = report_schemas.ReportCreate(
                title=f"{assessment.name} · {['Executive', 'Technical', 'Combined'][index % 3]} Portfolio Report",
                template=["executive", "technical", "combined"][index % 3],
                severity_filter=SEVERITIES,
                include_evidence=True,
                include_remediation=True,
                executive_summary=SAMPLE_NOTICE
                + " This preview is for interface demonstration only.",
                limitations=SAMPLE_NOTICE + " No external system was assessed.",
                branding_name="DroidShield Synthetic Portfolio",
            )
            report = reports.create(author_context, assessment.id, payload, settings)
            session.flush()
            if index % 3 != 0:
                reviewer_context = services.Context(
                    session, reviewer, f"portfolio-report-review-{index + 1:03d}"
                )
                reports.release(reviewer_context, report.id)
                session.flush()
                if index % 3 == 2:
                    reports.export(
                        author_context, report.id, "json" if index % 2 else "pdf", settings
                    )
                    session.flush()
            report_rows.append(report)
        # One valid but unreleased draft represents the draft-report filter state.
        if completed_pool:
            assessment = completed_pool[-1]
            project, platform, _brand = assessment_meta[assessment.id]
            draft_report = Report(
                workspace_id=workspace_id,
                project_id=project.id,
                assessment_id=assessment.id,
                title="Portfolio report · Draft review scenario",
                template="combined",
                version=2,
                status="draft",
                filters={
                    "severities": SEVERITIES,
                    "include_evidence": True,
                    "include_remediation": True,
                },
                branding={"name": "DroidShield Synthetic Portfolio"},
                reviewer_id=None,
                approved_at=None,
                author_id=admin.id,
                created_at=assessment.completed_at + timedelta(days=3),
            )
            session.add(draft_report)
            session.flush()
            snapshot = {
                "schema_version": 1,
                "generated_at": utc_now().isoformat(),
                "title": draft_report.title,
                "template": "combined",
                "version": 2,
                "branding_name": "DroidShield Synthetic Portfolio",
                "client": {
                    "id": str(next(c.id for c in clients if c.id == project.client_id)),
                    "name": next(c.name for c in clients if c.id == project.client_id),
                },
                "project": {
                    "id": str(project.id),
                    "name": project.name,
                    "application_name": project.application_name,
                    "package_id": project.package_id,
                    "framework": project.framework,
                    "platform": platform,
                },
                "assessment": {
                    "id": str(assessment.id),
                    "name": assessment.name,
                    "type": assessment.assessment_type,
                    "reviewer_id": str(reviewer.id),
                },
                "executive_summary": SAMPLE_NOTICE,
                "limitations": SAMPLE_NOTICE,
                "findings": [],
                "coverage": {"summary": {}, "cases": []},
                "risk_summary": {value: 0 for value in SEVERITIES},
                "remediation_roadmap": [],
                "retests": [],
            }
            encoded = reports.canonical(snapshot)
            session.add(
                ReportSnapshot(
                    workspace_id=workspace_id,
                    report_id=draft_report.id,
                    project_id=project.id,
                    assessment_id=assessment.id,
                    version=2,
                    snapshot_json=snapshot,
                    sha256=hashlib.sha256(encoded).hexdigest(),
                    created_at=draft_report.created_at,
                )
            )
        session.flush()
        validate_portfolio_consistency(session, workspace_id)
        session.commit()
        counts["reports"] = session.query(Report).count()
        counts["report_exports"] = session.query(reports.ReportExport).count()
        counts["audit_events"] = session.query(AuditEvent).count()
        counts["users"] = session.query(User).count()

    target_engine.dispose()
    source_engine.dispose()
    print("Synthetic portfolio dataset created in the isolated development workspace:")
    for name, amount in counts.items():
        print(f"  {name}: {amount}")
    print("  artifact formats: APK/AAB/IPA; all files are generated fixtures")
    print("  network requests and dynamic device sessions executed: 0")


if __name__ == "__main__":
    main()
