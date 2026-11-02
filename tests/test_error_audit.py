"""A contended audit write must not block unrelated ASGI request processing."""

import asyncio
import time
from contextlib import contextmanager
from threading import Event
from uuid import uuid4

import httpx

from tests.test_api import api as _api

api = _api


def test_denied_request_audit_wait_keeps_event_loop_responsive(api):
    original = api.client.app.state.session_factory
    entered, release = Event(), Event()

    class ContendedAudit:
        def __call__(self):
            return original()

        @contextmanager
        def begin(self):
            entered.set()
            assert release.wait(2), "The event loop could not release the audit wait"
            with original.begin() as session:
                yield session

    api.client.app.state.session_factory = ContendedAudit()

    async def exercise():
        transport = httpx.ASGITransport(app=api.client.app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            denied = asyncio.create_task(
                client.get(f"/api/v1/findings/{uuid4()}", headers=api.headers())
            )
            started = time.monotonic()
            while not entered.is_set() and time.monotonic() - started < 1:
                await asyncio.sleep(0.01)
            assert entered.is_set()
            # This timer can run only if the audit wait yields the event loop.
            release.set()
            response = await denied
            assert response.status_code == 404
            assert time.monotonic() - started < 1

    try:
        asyncio.run(exercise())
    finally:
        release.set()
        api.client.app.state.session_factory = original
