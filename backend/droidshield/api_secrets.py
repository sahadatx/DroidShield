"""Project-bound HTTP credentials from an administrator-owned private local file.

Only references and authentication kinds leave this module. Never persist or log
credential values, resolved headers, or the store path in assessment records.
"""

from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path
from uuid import UUID

_REF = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
_HEADER = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}\Z")
_FORBIDDEN = {
    "host",
    "content-length",
    "transfer-encoding",
    "connection",
    "proxy-authorization",
    "proxy-connection",
    "upgrade",
    "accept-encoding",
    "authorization",
    "cookie",
}


class SecretError(Exception):
    """A fixed, safe failure; never include parsed data in its message."""


def _entries(settings) -> dict:
    path = getattr(settings, "api_secret_store", None)
    if path is None:
        return {}
    fd = None
    try:
        path = Path(path)
        if not path.is_absolute():
            raise SecretError()
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size > 65536
        ):
            raise SecretError()
        with os.fdopen(fd, "rb") as stream:
            fd = None
            body = stream.read(65537)
        if len(body) > 65536:
            raise SecretError()
        entries = json.loads(body)
        if not isinstance(entries, dict) or len(entries) > 100:
            raise SecretError()
        for key, value in entries.items():
            if not isinstance(key, str) or not _REF.fullmatch(key) or not isinstance(value, dict):
                raise SecretError()
            if set(value) != {"workspace_id", "project_id", "kind", "value", "header"}:
                raise SecretError()
            if not all(
                isinstance(value[field], str) for field in ("workspace_id", "project_id", "kind")
            ):
                raise SecretError()
            UUID(value["workspace_id"])
            UUID(value["project_id"])
            kind, secret, header = value["kind"], value["value"], value["header"]
            if (
                kind not in {"bearer", "api_key", "cookie"}
                or not isinstance(secret, str)
                or not 1 <= len(secret) <= 4096
                or any(ord(char) < 32 or ord(char) > 126 for char in secret)
            ):
                raise SecretError()
            if kind == "api_key":
                if (
                    not isinstance(header, str)
                    or not _HEADER.fullmatch(header)
                    or header.lower() in _FORBIDDEN
                ):
                    raise SecretError()
            elif header is not None:
                raise SecretError()
        return entries
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as exc:
        raise SecretError() from exc
    finally:
        if fd is not None:
            os.close(fd)


def list_references(settings, workspace_id: UUID, project_id: UUID) -> list[dict[str, str]]:
    return [
        {"ref": ref, "kind": entry["kind"]}
        for ref, entry in _entries(settings).items()
        if entry["workspace_id"] == str(workspace_id) and entry["project_id"] == str(project_id)
    ]


def resolve(
    settings, reference: str | None, workspace_id: UUID, project_id: UUID, kind: str
) -> dict[str, str]:
    if kind == "none" and reference is None:
        return {}
    entry = _entries(settings).get(reference)
    if (
        entry is None
        or entry["workspace_id"] != str(workspace_id)
        or entry["project_id"] != str(project_id)
        or entry["kind"] != kind
    ):
        raise SecretError()
    if kind == "bearer":
        return {"Authorization": "Bearer " + entry["value"]}
    if kind == "cookie":
        return {"Cookie": entry["value"]}
    return {entry["header"]: entry["value"]}
