from typing import Any


class DomainError(Exception):
    def __init__(
        self, status: int, code: str, message: str, details: list[dict[str, Any]] | None = None
    ):
        self.status = status
        self.code = code
        self.message = message
        self.details = details or []


def conflict(message: str) -> DomainError:
    return DomainError(409, "conflict", message)


def not_found() -> DomainError:
    return DomainError(404, "not_found", "Resource not found")
