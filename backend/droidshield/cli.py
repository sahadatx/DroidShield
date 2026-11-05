import argparse
import getpass
import signal
import sys
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

from alembic import command
from alembic.config import Config
from pydantic import EmailStr, TypeAdapter, ValidationError
from sqlalchemy import select

from droidshield.auth import hash_password, issue_token
from droidshield.config import Settings
from droidshield.db import build_engine, session_factory
from droidshield.models import (
    AccessToken,
    AppArtifact,
    AuditEvent,
    AuthorizationAttachment,
    User,
    Workspace,
)


def migrate(settings: Settings) -> None:
    config = Config()
    config.set_main_option("script_location", str(Path(__file__).resolve().parent / "migrations"))
    config.attributes["database_url"] = settings.database_url
    command.upgrade(config, "head")


def seed_demo(settings: Settings, workspace_id: UUID, confirmed: bool) -> None:
    """Add visibly synthetic engagement setup records to an empty dev workspace."""
    if settings.environment != "development":
        raise SystemExit("Synthetic portfolio data is available only in development.")
    if not confirmed:
        raise SystemExit("Pass --confirm-synthetic-data to add clearly labeled demo records.")

    from droidshield import services as svc
    from droidshield.schemas import AssessmentCreate, ClientCreate, ProjectCreate

    engine = build_engine(settings.database_url)
    created = {"clients": 0, "projects": 0, "assessments": 0}
    try:
        with session_factory(engine).begin() as session:
            workspace = session.get(Workspace, workspace_id)
            if workspace is None:
                raise SystemExit("Workspace not found.")
            if any(
                session.scalar(select(model.id).where(model.workspace_id == workspace_id).limit(1))
                is not None
                for model in (svc.Client, svc.Project, svc.Assessment)
            ):
                raise SystemExit(
                    "The workspace already has engagement records; demo data was not added."
                )
            admin = session.scalar(
                select(User)
                .where(
                    User.workspace_id == workspace_id,
                    User.role == "ADMIN",
                    User.status == "active",
                )
                .order_by(User.created_at, User.id)
                .limit(1)
            )
            if admin is None:
                raise SystemExit("An active workspace administrator is required.")

            ctx = svc.Context(session=session, user=admin, request_id=f"demo-seed-{uuid4()}")
            client_specs = [
                ("Northstar Fintech", "Northstar Mobile Group"),
                ("Aster Health", "Aster Care Systems"),
                ("Orbit Digital Assets", "Orbit Wallet Labs"),
                ("Meridian Enterprise", "Meridian Field Operations"),
            ]
            clients = {}
            for key, organization in client_specs:
                record = svc.create_client(
                    ctx,
                    ClientCreate(
                        client_type="company",
                        name=f"DEMO · {key}",
                        organization_name=organization,
                        website=f"https://{key.lower().replace(' ', '-')}.example.test",
                        notes=(
                            "SYNTHETIC PORTFOLIO DATA — fictional organization for UI review. "
                            "No client engagement, approval, or testing authorization exists."
                        ),
                    ),
                )
                clients[key] = record
                created["clients"] += 1

            project_specs = [
                (
                    "Northstar Fintech",
                    "Northstar Android Banking",
                    "Northstar Mobile",
                    "com.droidshield.demo.northstar.android",
                    "android",
                    "native",
                ),
                (
                    "Northstar Fintech",
                    "Northstar iOS Banking",
                    "Northstar Mobile",
                    "com.droidshield.demo.northstar.ios",
                    "ios",
                    "native",
                ),
                (
                    "Aster Health",
                    "Aster Patient App",
                    "Aster Care",
                    "com.droidshield.demo.aster.patient",
                    "android",
                    "flutter",
                ),
                (
                    "Aster Health",
                    "Aster Clinician App",
                    "Aster Clinician",
                    "com.droidshield.demo.aster.clinician",
                    "ios",
                    "flutter",
                ),
                (
                    "Orbit Digital Assets",
                    "Orbit Wallet",
                    "Orbit Wallet",
                    "com.droidshield.demo.orbit.wallet",
                    "android",
                    "react_native",
                ),
                (
                    "Meridian Enterprise",
                    "Meridian Field Service",
                    "Meridian Field",
                    "com.droidshield.demo.meridian.field",
                    "android",
                    "other",
                ),
                (
                    "Meridian Enterprise",
                    "Meridian Workforce",
                    "Meridian Workforce",
                    "com.droidshield.demo.meridian.workforce",
                    "ios",
                    "other",
                ),
                (
                    "Northstar Fintech",
                    "Northstar Merchant",
                    "Northstar Merchant",
                    "com.droidshield.demo.northstar.merchant",
                    "android",
                    "flutter",
                ),
            ]
            projects = []
            for client_key, name, app_name, identity, platform, framework in project_specs:
                if framework == "native":
                    technology = "Kotlin" if platform == "android" else "Swift"
                elif framework == "flutter":
                    technology = "Flutter"
                elif framework == "react_native":
                    technology = "React Native"
                else:
                    technology = "Kony" if "Field Service" in name else "Volt MX"
                record = svc.create_project(
                    ctx,
                    ProjectCreate(
                        client_id=clients[client_key].id,
                        name=f"DEMO · {name}",
                        application_name=app_name,
                        package_id=identity,
                        platform=platform,
                        framework=framework,
                        description=(
                            f"Synthetic portfolio project. Declared technology: {technology}. "
                            "Technology is illustrative and does not imply analysis coverage."
                        ),
                        scope_notes=(
                            "DEMO ONLY. No real target, client approval, or testing scope. "
                            "Do not authorize or execute testing against this sample project."
                        ),
                    ),
                )
                projects.append(record)
                created["projects"] += 1

            for project in projects:
                app_target = (
                    f"{'bundle' if project.platform == 'ios' else 'package'}:{project.package_id}"
                )
                plan = (
                    [
                        ("Static analysis preparation", "static", "dex"),
                        ("Android runtime lab preparation", "dynamic", "manifest"),
                        ("API security preparation", "api", "manifest"),
                        ("Full mobile engagement preparation", "full", "manifest"),
                    ]
                    if project.platform == "android"
                    else [
                        ("iOS manual review preparation", "full", "manifest"),
                        ("API security preparation", "api", "manifest"),
                    ]
                )
                for index, (label, kind, engine_name) in enumerate(plan):
                    target = (
                        ["https://api.example.test/v1/profile"] if kind == "api" else [app_target]
                    )
                    assessment = svc.create_assessment(
                        ctx,
                        AssessmentCreate(
                            project_id=project.id,
                            name=f"DEMO · {label}",
                            assessment_type=kind,
                            requested_targets=target,
                            engine=engine_name,
                        ),
                    )
                    # Submitted means only that authorization is still awaited.
                    # No artifacts, permits, jobs, or scan results are fabricated.
                    if index % 2 == 1:
                        svc.submit_assessment(ctx, assessment.id, assessment.revision)
                    created["assessments"] += 1

        print(
            "Added synthetic records: "
            f"{created['clients']} clients, {created['projects']} projects, "
            f"{created['assessments']} draft/authorization-waiting assessments. "
            "No APKs, authorizations, findings, executions, or reports were created."
        )
    finally:
        engine.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description="DroidShield administrative setup")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("migrate", help="Apply versioned database migrations")
    worker = sub.add_parser("worker", help="Run the isolated static analysis worker")
    worker.add_argument(
        "--once", action="store_true", help="Handle at most one eligible static job and exit"
    )
    dynamic_worker = sub.add_parser("dynamic-worker", help="Run the controlled Android lab worker")
    dynamic_worker.add_argument("--once", action="store_true", help="Handle one lab job and exit")
    api_worker = sub.add_parser("api-worker", help="Run scoped HTTPS API assessments")
    api_worker.add_argument("--once", action="store_true", help="Handle one API job and exit")
    ca = sub.add_parser("init-proxy-ca", help="Create a dedicated lab CA; never installs trust")
    ca.add_argument("--directory", required=True, type=Path)
    cleanup = sub.add_parser(
        "cleanup-storage", help="Remove old unreferenced objects and temporary files"
    )
    cleanup.add_argument("--older-than-hours", type=int, default=24)
    bootstrap = sub.add_parser("bootstrap", help="Create a workspace and its first admin")
    bootstrap.add_argument("--workspace", required=True)
    bootstrap.add_argument("--email", required=True)
    bootstrap.add_argument("--name", required=True)
    demo = sub.add_parser(
        "seed-demo", help="Add visibly synthetic portfolio records to an empty dev workspace"
    )
    demo.add_argument("--workspace-id", required=True, type=UUID)
    demo.add_argument("--confirm-synthetic-data", action="store_true")
    user = sub.add_parser("create-user", help="Provision a user via trusted local administration")
    user.add_argument("--workspace-id", required=True, type=UUID)
    user.add_argument("--email", required=True)
    user.add_argument("--name", required=True)
    user.add_argument("--role", choices=["ADMIN", "SECURITY_ANALYST", "VIEWER"], required=True)
    token = sub.add_parser(
        "issue-token", help="Issue an expiring token for an existing active user"
    )
    token.add_argument("--user-id", required=True, type=UUID)
    revoke = sub.add_parser("revoke-tokens", help="Revoke all tokens for a user")
    revoke.add_argument("--user-id", required=True, type=UUID)
    password_cmd = sub.add_parser(
        "set-password", help="Set a user's browser sign-in password using a hidden prompt"
    )
    password_cmd.add_argument("--user-id", required=True, type=UUID)
    args = parser.parse_args()
    settings = Settings()
    if args.command == "seed-demo":
        seed_demo(settings, args.workspace_id, args.confirm_synthetic_data)
        return
    if args.command == "migrate":
        migrate(settings)
        print("Database migration complete.")
        return
    if args.command == "init-proxy-ca":
        from droidshield.proxy import initialize_ca

        try:
            initialize_ca(args.directory)
        except (OSError, ValueError):
            print("CA creation failed. Choose a new protected directory.", file=sys.stderr)
            raise SystemExit(1) from None
        print(
            "Dedicated lab CA created. Configure protected cert/key paths and app debug trust separately."
        )
        return
    if args.command in {"worker", "dynamic-worker", "api-worker"}:
        if args.command == "api-worker":
            from droidshield.api_security import run_once
        elif args.command == "dynamic-worker":
            from droidshield.dynamic import run_once
        else:
            from droidshield.worker import run_once

        label = {
            "dynamic-worker": "Dynamic lab",
            "api-worker": "API assessment",
            "worker": "Static analysis",
        }[args.command]

        engine = build_engine(settings.database_url)
        stopping = threading.Event()
        previous_handlers = {}
        for signum in (signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.signal(
                signum, lambda _signum, _frame: stopping.set()
            )
        try:
            if args.once:
                handled = run_once(settings, engine, should_stop=stopping.is_set)
                print(f"{label} job handled." if handled else f"No eligible {label.lower()} job.")
            else:
                print(f"{label} worker started.", flush=True)
                while not stopping.is_set():
                    if not run_once(settings, engine, should_stop=stopping.is_set):
                        stopping.wait(settings.worker_poll_seconds)
                print(f"{label} worker stopped.")
        except Exception:
            print(
                "Worker failed. Check database migrations and protected storage.", file=sys.stderr
            )
            raise SystemExit(1) from None
        finally:
            for signum, handler in previous_handlers.items():
                signal.signal(signum, handler)
            engine.dispose()
        return
    if args.command == "cleanup-storage":
        from droidshield.storage import Storage

        if args.older_than_hours < 1:
            parser.error("Cleanup requires a grace period of at least one hour")
        engine = build_engine(settings.database_url)
        try:
            with session_factory(engine)() as session:
                referenced = set(session.scalars(select(AppArtifact.storage_ref)).all())
                authorization_documents = set(
                    session.scalars(select(AuthorizationAttachment.storage_ref)).all()
                )
            threshold = time.time() - args.older_than_hours * 3600
            count = Storage(settings.storage_root).clean_orphans(referenced, threshold)
            count += Storage(
                settings.storage_root / "authorization-attachments",
                reference_prefix="authdoc",
                object_suffix=".bin",
            ).clean_orphans(authorization_documents, threshold)
            print(f"Removed {count} old unreferenced storage entries.")
        except Exception:
            print("Storage cleanup failed; check database and storage access.", file=sys.stderr)
            raise SystemExit(1) from None
        finally:
            engine.dispose()
        return
    if args.command in {"bootstrap", "create-user"}:
        try:
            email = str(TypeAdapter(EmailStr).validate_python(args.email)).lower()
        except ValidationError:
            parser.error("A valid email address is required")
        if not args.name.strip() or len(args.name.strip()) > 200:
            parser.error("Name must contain between 1 and 200 characters")
    password_hash = None
    if args.command == "set-password":
        try:
            password = getpass.getpass("New password (minimum 12 characters): ")
            confirmation = getpass.getpass("Confirm new password: ")
        except (EOFError, KeyboardInterrupt):
            parser.error("Password setup requires an interactive terminal")
        if password != confirmation:
            parser.error("Passwords do not match")
        try:
            password_hash = hash_password(password)
        except ValueError as exc:
            parser.error(str(exc))
        del password, confirmation
    engine = build_engine(settings.database_url)
    try:
        with session_factory(engine).begin() as session:
            if args.command == "bootstrap":
                if session.scalar(select(Workspace.id).limit(1)) is not None:
                    parser.error("Workspace already exists; use create-user or issue-token")
                if not args.workspace.strip() or len(args.workspace.strip()) > 200:
                    parser.error("Workspace name must contain between 1 and 200 characters")
                workspace = Workspace(name=args.workspace.strip())
                session.add(workspace)
                session.flush()
                account = User(
                    workspace_id=workspace.id,
                    email=email,
                    full_name=args.name.strip(),
                    role="ADMIN",
                )
                session.add(account)
                session.flush()
                action = "workspace.bootstrapped"
            elif args.command == "create-user":
                workspace = session.get(Workspace, args.workspace_id)
                if workspace is None:
                    parser.error("Workspace not found")
                if session.scalar(
                    select(User.id).where(User.workspace_id == workspace.id, User.email == email)
                ):
                    parser.error("Email already exists in this workspace")
                account = User(
                    workspace_id=workspace.id,
                    email=email,
                    full_name=args.name.strip(),
                    role=args.role,
                )
                session.add(account)
                session.flush()
                action = "user.provisioned"
            elif args.command == "set-password":
                account = session.get(User, args.user_id)
                if account is None:
                    parser.error("User not found")
                account.password_hash = password_hash
                workspace = session.get(Workspace, account.workspace_id)
                action = "user.password_changed"
            else:
                account = session.get(User, args.user_id)
                if account is None or account.status != "active":
                    parser.error("Active user not found")
                workspace = session.get(Workspace, account.workspace_id)
                action = "token.revoked" if args.command == "revoke-tokens" else "token.issued"
            if args.command in {"revoke-tokens", "set-password"}:
                for item in session.scalars(
                    select(AccessToken).where(
                        AccessToken.user_id == account.id, AccessToken.revoked_at.is_(None)
                    )
                ):
                    item.revoked_at = datetime.now(UTC)
                credential = None
            elif args.command in {"bootstrap", "create-user"}:
                credential = None
            else:
                credential = issue_token(session, account.id, settings.token_ttl_hours)
            session.add(
                AuditEvent(
                    workspace_id=workspace.id,
                    actor_id=None,
                    action=action,
                    resource_type="user",
                    resource_id=account.id,
                    result="success",
                    request_id=str(uuid4()),
                    source_metadata={"channel": "trusted_local_cli"},
                )
            )
            # Do not print a credential until its transaction has committed.
            output = (workspace.id, account.id, credential)
        print(f"Workspace ID: {output[0]}\nUser ID: {output[1]}")
        if args.command == "set-password":
            print("Password saved. Existing browser sessions and API tokens were revoked.")
        elif args.command in {"bootstrap", "create-user"}:
            print(
                "No browser token was issued. Set a sign-in password with: "
                f"droidshield set-password --user-id {output[1]}"
            )
        elif output[2] is None:
            print("All user tokens revoked.")
        else:
            print(
                "API bearer token (shown once; browser sign-in uses email and password, "
                f"expires in {settings.token_ttl_hours} hours): {output[2]}"
            )
    except Exception:
        print("Setup failed. Check database connectivity and migrations.", file=sys.stderr)
        raise SystemExit(1) from None
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
