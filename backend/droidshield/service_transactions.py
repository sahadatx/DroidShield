"""Session-scoped transaction helpers for idempotent service operations."""

import hashlib
import json
from collections.abc import Callable
from typing import TypeVar
from uuid import UUID

from pydantic import BaseModel
from sqlalchemy import select

from droidshield.errors import conflict
from droidshield.models import IdempotencyRecord
from droidshield.service_context import Context

T = TypeVar("T")


def once(
    ctx: Context,
    key: str,
    operation: str,
    payload: BaseModel,
    lookup: Callable[[UUID], T],
    create: Callable[[], T],
) -> T:
    request_hash = hashlib.sha256(
        json.dumps(payload.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    previous = ctx.session.scalar(
        select(IdempotencyRecord).where(
            IdempotencyRecord.workspace_id == ctx.workspace_id,
            IdempotencyRecord.user_id == ctx.user.id,
            IdempotencyRecord.key == key,
        )
    )
    if previous:
        if previous.operation != operation or previous.request_hash != request_hash:
            raise conflict("Idempotency key was already used for a different request")
        return lookup(previous.response_resource_id)
    result = create()
    ctx.session.flush()
    ctx.session.add(
        IdempotencyRecord(
            workspace_id=ctx.workspace_id,
            user_id=ctx.user.id,
            key=key,
            operation=operation,
            request_hash=request_hash,
            response_resource_id=result.id,
        )
    )
    ctx.session.flush()
    return result
