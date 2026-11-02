"""Shared authenticated API dependencies and response helpers."""

import secrets
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, Header, Query, Request
from fastapi.responses import Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from sqlalchemy.orm import Session

from droidshield import schemas as s
from droidshield import services as svc
from droidshield.auth import CSRF_COOKIE, SESSION_COOKIE, authenticate
from droidshield.db import get_session
from droidshield.errors import DomainError
from droidshield.models import Workspace

bearer = HTTPBearer(auto_error=False)


def db_session(request: Request):
    yield from get_session(request)


DB = Annotated[Session, Depends(db_session, scope="function")]


def user_view(session: Session, user) -> dict:
    """Return the authenticated identity with its workspace display label."""
    workspace = session.get(Workspace, user.workspace_id)
    return {
        **s.MeOut.model_validate(user).model_dump(),
        "workspace_name": workspace.name if workspace else None,
    }


def context(
    request: Request,
    session: DB,
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer)],
) -> svc.Context:
    if credentials is not None and credentials.scheme.lower() == "bearer":
        user = authenticate(session, credentials.credentials)
    else:
        session_cookie = request.cookies.get(SESSION_COOKIE)
        if not session_cookie:
            raise DomainError(401, "unauthenticated", "Valid authentication is required")
        user = authenticate(session, session_cookie)
        request.state.auth_method = "cookie"
        request.state.session_cookie = session_cookie
    request.state.actor_id = user.id
    request.state.workspace_id = user.workspace_id
    if getattr(request.state, "auth_method", None) == "cookie" and request.method not in {
        "GET",
        "HEAD",
        "OPTIONS",
    }:
        csrf_cookie = request.cookies.get(CSRF_COOKIE, "")
        csrf_header = request.headers.get("X-CSRF-Token", "")
        origin = request.headers.get("Origin")
        fetch_site = request.headers.get("Sec-Fetch-Site", "")
        if (
            not csrf_cookie
            or not csrf_header
            or not secrets.compare_digest(csrf_cookie, csrf_header)
            or fetch_site == "cross-site"
            or (origin and not same_host_origin(origin, request.url.netloc))
        ):
            raise DomainError(403, "csrf_failed", "Request origin could not be verified")
    return svc.Context(session, user, request.state.request_id)


def same_host_origin(origin: str, request_netloc: str) -> bool:
    try:
        parsed = urlsplit(origin)
        return (
            parsed.scheme in {"http", "https"}
            and parsed.netloc.lower() == request_netloc.lower()
            and parsed.path in {"", "/"}
            and not parsed.query
            and not parsed.fragment
        )
    except ValueError:
        return False


def set_auth_cookies(request: Request, response: Response, session_id: str, csrf: str) -> None:
    settings = request.app.state.settings
    max_age = settings.token_ttl_hours * 60 * 60
    secure = settings.environment == "production"
    response.set_cookie(
        SESSION_COOKIE,
        session_id,
        max_age=max_age,
        httponly=True,
        secure=secure,
        samesite="strict",
        path="/",
    )
    response.set_cookie(
        CSRF_COOKIE,
        csrf,
        max_age=max_age,
        httponly=False,
        secure=secure,
        samesite="strict",
        path="/",
    )


Ctx = Annotated[svc.Context, Depends(context)]
Limit = Annotated[int, Query(ge=1, le=100)]
Offset = Annotated[int, Query(ge=0, le=10_000)]
Idem = Annotated[
    str,
    Header(alias="Idempotency-Key", min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$"),
]


def page(ctx: svc.Context, query, output: type[BaseModel], limit: int, offset: int) -> dict:
    items, total = svc.paginate(ctx, query, limit, offset)
    return {
        "items": [
            client_view(ctx, item) if output is s.ClientOut else output.model_validate(item)
            for item in items
        ],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def client_view(ctx: svc.Context, record: svc.Client) -> s.ClientOut:
    response = s.ClientOut.model_validate(record)
    if ctx.user.role != "ADMIN" and record.created_by != ctx.user.id:
        # A project grant permits necessary contact lookup, not private notes
        # about the parent's other engagements.
        response = response.model_copy(update={"notes": None, "archive_reason": None})
    return response
