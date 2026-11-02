"""Authentication and identity HTTP routes."""

import secrets
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import select

from droidshield import schemas as s
from droidshield import services as svc
from droidshield.api_common import (
    DB,
    Ctx,
    context,
    user_view,
)
from droidshield.api_common import (
    same_host_origin as _same_host_origin,
)
from droidshield.api_common import (
    set_auth_cookies as _set_auth_cookies,
)
from droidshield.auth import (
    CSRF_COOKIE,
    SESSION_COOKIE,
    authenticate,
    authenticate_password,
    issue_token,
    token_hash,
)
from droidshield.errors import DomainError
from droidshield.models import AccessToken, AuditEvent

router = APIRouter()


@router.post("/auth/login", response_model=s.AuthSessionOut, tags=["Identity"])
def login(data: s.PasswordLogin, request: Request, response: Response, session: DB):
    origin = request.headers.get("Origin")
    if request.headers.get("Sec-Fetch-Site") == "cross-site" or (
        origin and not _same_host_origin(origin, request.url.netloc)
    ):
        raise DomainError(403, "csrf_failed", "Request origin could not be verified")
    client_host = request.client.host if request.client else "unknown"
    if not request.app.state.login_limiter.allow(client_host):
        raise DomainError(429, "login_rate_limited", "Too many sign-in attempts. Try again shortly")
    user = authenticate_password(session, str(data.email), data.password.get_secret_value())
    session_id = issue_token(session, user.id, request.app.state.settings.token_ttl_hours)
    csrf = secrets.token_urlsafe(32)
    _set_auth_cookies(request, response, session_id, csrf)
    request.state.actor_id = user.id
    request.state.workspace_id = user.workspace_id
    session.add(
        AuditEvent(
            workspace_id=user.workspace_id,
            actor_id=user.id,
            action="auth.login",
            resource_type="user",
            resource_id=user.id,
            result="success",
            request_id=request.state.request_id,
            source_metadata={"method": "password"},
        )
    )
    return {"user": user_view(session, user), "csrf_token": csrf}


@router.get("/auth/session", response_model=s.AuthSessionOut, tags=["Identity"])
def auth_session(request: Request, response: Response, session: DB):
    session_id = request.cookies.get(SESSION_COOKIE, "")
    user = authenticate(session, session_id)
    csrf = secrets.token_urlsafe(32)
    _set_auth_cookies(request, response, session_id, csrf)
    request.state.actor_id = user.id
    request.state.workspace_id = user.workspace_id
    return {"user": user_view(session, user), "csrf_token": csrf}


@router.post("/auth/logout", tags=["Identity"])
def logout(request: Request, response: Response, ctx: svc.Context = Depends(context)):
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        credential = ctx.session.scalar(
            select(AccessToken).where(
                AccessToken.user_id == ctx.user.id,
                AccessToken.token_hash == token_hash(session_id),
                AccessToken.revoked_at.is_(None),
            )
        )
        if credential is not None:
            credential.revoked_at = datetime.now(UTC)
    ctx.session.add(
        AuditEvent(
            workspace_id=ctx.user.workspace_id,
            actor_id=ctx.user.id,
            action="auth.logout",
            resource_type="user",
            resource_id=ctx.user.id,
            result="success",
            request_id=ctx.request_id,
            source_metadata={"method": "password_session"},
        )
    )
    secure = request.app.state.settings.environment == "production"
    response.delete_cookie(SESSION_COOKIE, path="/", secure=secure, samesite="strict")
    response.delete_cookie(CSRF_COOKIE, path="/", secure=secure, samesite="strict")
    return {"status": "signed_out"}


@router.get("/me", response_model=s.MeOut, tags=["Identity"])
def me(ctx: Ctx):
    return user_view(ctx.session, ctx.user)
