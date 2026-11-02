"""Aggregate router for the stable versioned API surface.

Route implementations live in workflow-specific modules. Shared authentication,
validation, and pagination helpers are in :mod:`droidshield.api_common`.
"""

from fastapi import APIRouter

# Keep these imports available for compatibility with existing integrations.
__all__ = [
    "Ctx",
    "DB",
    "Idem",
    "Limit",
    "Offset",
    "bearer",
    "client_view",
    "context",
    "db_session",
    "page",
    "user_view",
    "router",
]

from droidshield.api_common import (
    DB,
    Ctx,
    Idem,
    Limit,
    Offset,
    bearer,
    client_view,
    context,
    db_session,
    page,
    user_view,
)
from droidshield.assessment_api import router as assessment_router
from droidshield.directory_api import router as directory_router
from droidshield.evidence_api import router as evidence_router
from droidshield.identity_api import router as identity_router

router = APIRouter(prefix="/api/v1")
router.include_router(identity_router)
router.include_router(directory_router)
router.include_router(assessment_router)
router.include_router(evidence_router)
