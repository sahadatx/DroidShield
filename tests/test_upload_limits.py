import asyncio
from types import SimpleNamespace

import anyio
import pytest
from starlette.requests import Request

from droidshield.config import Settings
from droidshield.errors import DomainError
from droidshield.storage import Storage
from droidshield.uploads import _parse
from tests.test_uploads import static_draft, upload
from tests.test_uploads import upload_api as upload_api


def test_upload_capacity_returns_retryable_error_before_processing_bytes(upload_api):
    api = upload_api
    _, draft = static_draft(api)
    api.client.app.state.upload_limiter = anyio.Semaphore(0)
    response = upload(api, draft)
    assert response.status_code == 429
    assert response.json()["error"]["code"] == "upload_capacity"
    assert not list(api.client.app.state.settings.storage_root.rglob("*.apk"))


def test_stalled_multipart_transfer_is_bounded_and_cleans_up(tmp_path):
    settings = Settings(_env_file=None, environment="test", upload_timeout_seconds=1)
    app = SimpleNamespace(state=SimpleNamespace(settings=settings))

    async def receive():
        await asyncio.sleep(2)
        return {"type": "http.request", "body": b"", "more_body": False}

    request = Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/upload",
            "query_string": b"",
            "headers": [(b"content-type", b"multipart/form-data; boundary=test")],
            "app": app,
        },
        receive=receive,
    )
    store = Storage(tmp_path)
    with pytest.raises(DomainError) as error:
        asyncio.run(_parse(request, store))
    assert error.value.status == 408
    assert error.value.code == "upload_timeout"
    assert not list(store.staging.iterdir())
