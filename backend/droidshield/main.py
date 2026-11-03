import logging
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID, uuid4

import anyio
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.orm.exc import StaleDataError
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from droidshield import __version__
from droidshield.api import router
from droidshield.api_security import router as api_security_router
from droidshield.auth import LoginRateLimiter
from droidshield.config import Settings
from droidshield.db import build_engine, session_factory
from droidshield.delivery_api import router as delivery_router
from droidshield.dynamic import router as dynamic_router
from droidshield.errors import DomainError
from droidshield.models import AuditEvent
from droidshield.report_api import router as report_router

SCHEMA_REVISION = "0011_workspace_settings"
logger = logging.getLogger("droidshield")


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    config = settings or Settings()
    database = engine or build_engine(config.database_url)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        yield
        if engine is None:
            database.dispose()

    app = FastAPI(
        title="DroidShield",
        version=__version__,
        lifespan=lifespan,
        description="Android and iOS assessment workspace with protected APK/AAB/IPA intake, isolated Android engines, analyst coverage, independent review, reports and retests.",
        docs_url="/docs" if config.environment != "production" else None,
        redoc_url=None,
        openapi_url="/openapi.json" if config.environment != "production" else None,
    )
    app.state.settings = config
    app.state.engine = database
    app.state.session_factory = session_factory(database)
    app.state.upload_limiter = anyio.Semaphore(config.max_concurrent_uploads)
    app.state.login_limiter = LoginRateLimiter(app.state.session_factory)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=config.allowed_hosts)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=config.cors_origins,
        allow_credentials=False,
        allow_methods=["GET", "POST", "PATCH", "PUT"],
        allow_headers=[
            "Authorization",
            "Content-Type",
            "Idempotency-Key",
            "X-CSRF-Token",
            "X-Request-ID",
        ],
        expose_headers=["X-Request-ID", "X-Content-SHA256", "Content-Disposition"],
    )

    @app.middleware("http")
    async def request_context(request: Request, call_next):
        incoming = request.headers.get("X-Request-ID", "")
        try:
            request.state.request_id = str(UUID(incoming))
        except ValueError:
            request.state.request_id = str(uuid4())
        response = await call_next(request)
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path != "/docs":
            response.headers["Content-Security-Policy"] = (
                "default-src 'none'; script-src 'self'; style-src 'self'; "
                "connect-src 'self'; img-src 'self' data:; font-src 'self'; "
                "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
            )
        return response

    def error(request: Request, status: int, code: str, message: str, details=None):
        headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
        return JSONResponse(
            status_code=status,
            headers=headers,
            content={
                "error": {"code": code, "message": message, "details": details or []},
                "request_id": request.state.request_id,
            },
        )

    def audit_failure(request: Request):
        actor = getattr(request.state, "actor_id", None)
        if actor is None:
            return
        route = request.scope.get("route")
        try:
            with app.state.session_factory.begin() as session:
                session.add(
                    AuditEvent(
                        workspace_id=request.state.workspace_id,
                        actor_id=actor,
                        action="request.denied",
                        resource_type="api",
                        resource_id=None,
                        result="failure",
                        request_id=request.state.request_id,
                        source_metadata={
                            "method": request.method,
                            "route": getattr(route, "path", "unknown"),
                        },
                    )
                )
        except SQLAlchemyError:
            # No exception details: database URLs or values may contain secrets.
            logger.error("Failed to persist audit event; request_id=%s", request.state.request_id)

    @app.exception_handler(DomainError)
    async def domain_error(request: Request, exc: DomainError):
        await run_in_threadpool(audit_failure, request)
        return error(request, exc.status, exc.code, exc.message, exc.details)

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request: Request, exc: RequestValidationError):
        details = [{"location": list(item["loc"]), "type": item["type"]} for item in exc.errors()]
        await run_in_threadpool(audit_failure, request)
        # Omit Pydantic's rejected input and exception context from responses.
        return error(request, 422, "validation_error", "Check the indicated fields", details)

    @app.exception_handler(IntegrityError)
    async def integrity_error(request: Request, _exc: IntegrityError):
        await run_in_threadpool(audit_failure, request)
        return error(
            request,
            409,
            "conflict",
            "A conflicting record exists; reload or retry with the same idempotency key",
        )

    @app.exception_handler(StaleDataError)
    async def stale_data(request: Request, _exc: StaleDataError):
        await run_in_threadpool(audit_failure, request)
        return error(request, 409, "conflict", "The record changed. Reload it before saving")

    @app.exception_handler(Exception)
    async def unexpected_error(request: Request, _exc: Exception):
        logger.error("Unhandled request failure; request_id=%s", request.state.request_id)
        return error(request, 500, "internal_error", "The request could not be completed")

    @app.get("/health/live", tags=["Health"])
    def live():
        return {"status": "ok", "service": "DroidShield", "version": __version__}

    @app.get("/health/ready", tags=["Health"])
    def ready():
        try:
            with database.connect() as connection:
                revision = connection.execute(
                    text("SELECT version_num FROM alembic_version")
                ).scalar()
                if revision != SCHEMA_REVISION:
                    raise DomainError(503, "not_ready", "Database migration is required")
                connection.execute(text("SELECT 1 FROM users LIMIT 1"))
        except SQLAlchemyError as exc:
            raise DomainError(
                503, "not_ready", "Database is unavailable or requires migration"
            ) from exc
        return {
            "status": "ready",
            "schema_revision": SCHEMA_REVISION,
            "checked_at": datetime.now(UTC).isoformat(),
            "analysis_workers": "static_dynamic_api_worker_cli",
        }

    app.include_router(router)
    app.include_router(dynamic_router)
    app.include_router(api_security_router)
    app.include_router(delivery_router)
    app.include_router(report_router)
    web = Path(__file__).resolve().parent / "web"

    @app.get("/assets/app.js", include_in_schema=False)
    def javascript():
        return FileResponse(web / "app.js", media_type="text/javascript")

    @app.get("/assets/styles.css", include_in_schema=False)
    def stylesheet():
        return FileResponse(web / "styles.css", media_type="text/css")

    @app.get("/", include_in_schema=False)
    def frontend():
        return FileResponse(web / "index.html", media_type="text/html")

    return app
