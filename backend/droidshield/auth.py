import base64
import hashlib
import secrets
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from time import time_ns
from uuid import UUID

from sqlalchemy import delete, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from droidshield.errors import DomainError
from droidshield.models import AccessToken, LoginRateLimitEntry, User

SESSION_COOKIE = "ds_session"
CSRF_COOKIE = "ds_csrf"
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_PASSWORD_BYTES_MAX = 1024
_SQLITE_LOGIN_RATE_LIMIT_LOCK = threading.Lock()


def utc(value: datetime) -> datetime:
    """SQLite returns naive timestamps; all persisted timestamps represent UTC."""
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    """Hash a password with a per-account salt using the stdlib scrypt KDF."""
    encoded = password.encode("utf-8")
    if len(password) < 12 or len(encoded) > _PASSWORD_BYTES_MAX:
        raise ValueError("Password must be at least 12 characters and at most 1024 UTF-8 bytes")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        encoded,
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=32,
        maxmem=64 * 1024 * 1024,
    )
    return "$".join(
        (
            "scrypt-v1",
            str(_SCRYPT_N),
            str(_SCRYPT_R),
            str(_SCRYPT_P),
            base64.urlsafe_b64encode(salt).decode("ascii"),
            base64.urlsafe_b64encode(digest).decode("ascii"),
        )
    )


def verify_password(password: str, encoded_hash: str | None) -> bool:
    """Verify only bounded hashes produced by hash_password."""
    encoded = password.encode("utf-8")
    if len(encoded) > _PASSWORD_BYTES_MAX:
        return False
    try:
        algorithm, n, r, p, salt_text, digest_text = (encoded_hash or "").split("$")
        if algorithm != "scrypt-v1":
            return False
        n_value, r_value, p_value = int(n), int(r), int(p)
        if (n_value, r_value, p_value) != (_SCRYPT_N, _SCRYPT_R, _SCRYPT_P):
            return False
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
        if len(salt) != 16 or len(expected) != 32:
            return False
        actual = hashlib.scrypt(
            encoded,
            salt=salt,
            n=n_value,
            r=r_value,
            p=p_value,
            dklen=len(expected),
            maxmem=64 * 1024 * 1024,
        )
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError, UnicodeError):
        return False


class LoginRateLimiter:
    """Database-backed sliding window shared by every API worker."""

    def __init__(
        self,
        session_factory: Callable[[], Session],
        limit: int = 10,
        window_seconds: int = 60,
    ):
        if limit < 1 or window_seconds < 1:
            raise ValueError("Login rate limit and window must be positive")
        self.session_factory = session_factory
        self.limit = limit
        self.window_seconds = window_seconds

    def allow(self, key: str) -> bool:
        normalized = key.strip()[:128] or "unknown"
        key_hash = hashlib.sha256(
            b"droidshield-login-rate-limit-v1\0" + normalized.encode("utf-8", "replace")
        ).hexdigest()
        window_us = self.window_seconds * 1_000_000
        cutoff = datetime.now(UTC) - timedelta(seconds=self.window_seconds)

        try:
            with self.session_factory() as session:
                dialect = session.get_bind().dialect.name
                if dialect == "sqlite":
                    # SQLite has no row-level FOR UPDATE; serialize its dev-only
                    # login transactions within this process before reading state.
                    with _SQLITE_LOGIN_RATE_LIMIT_LOCK:
                        return self._allow_in_session(session, dialect, key_hash, cutoff, window_us)
                return self._allow_in_session(session, dialect, key_hash, cutoff, window_us)
        except SQLAlchemyError as exc:
            # Login must fail closed if the shared limiter cannot be consulted.
            raise DomainError(
                503,
                "login_rate_limiter_unavailable",
                "Sign-in is temporarily unavailable",
            ) from exc

    def _allow_in_session(self, session, dialect, key_hash, cutoff, window_us):
        if dialect not in {"postgresql", "sqlite"}:
            raise DomainError(
                503,
                "login_rate_limiter_unavailable",
                "Sign-in is temporarily unavailable",
            )
        with session.begin():
            # Expired keys are removed continuously, keeping only recent login sources.
            session.execute(
                delete(LoginRateLimitEntry).where(LoginRateLimitEntry.updated_at < cutoff)
            )
            values = {
                "key_hash": key_hash,
                "attempt_times_us": [],
                "updated_at": datetime.now(UTC),
            }
            statement = (
                pg_insert(LoginRateLimitEntry).values(**values)
                if dialect == "postgresql"
                else sqlite_insert(LoginRateLimitEntry).values(**values)
            )
            session.execute(
                statement.on_conflict_do_nothing(index_elements=[LoginRateLimitEntry.key_hash])
            )
            entry = session.scalar(
                select(LoginRateLimitEntry)
                .where(LoginRateLimitEntry.key_hash == key_hash)
                .with_for_update()
            )
            if entry is None:
                raise DomainError(
                    503,
                    "login_rate_limiter_unavailable",
                    "Sign-in is temporarily unavailable",
                )
            # Sample the clock only after taking the shared row lock. If a
            # request records its timestamp while waiting for that lock, it
            # can later appear older than an attempt that was committed first;
            # the sliding-window filter would then discard that newer attempt.
            now_us = time_ns() // 1_000
            now = datetime.fromtimestamp(now_us / 1_000_000, UTC)
            attempts = [
                int(attempt)
                for attempt in entry.attempt_times_us
                if 0 <= now_us - int(attempt) < window_us
            ]
            allowed = len(attempts) < self.limit
            if allowed:
                attempts.append(now_us)
            entry.attempt_times_us = attempts
            entry.updated_at = now
            return allowed


def issue_token(session: Session, user_id: UUID, ttl_hours: int) -> str:
    token = "ds_" + secrets.token_urlsafe(48)
    session.add(
        AccessToken(
            user_id=user_id,
            token_hash=token_hash(token),
            expires_at=datetime.now(UTC) + timedelta(hours=ttl_hours),
        )
    )
    return token


def authenticate(session: Session, token: str) -> User:
    if not token.startswith("ds_") or len(token) > 256:
        raise DomainError(401, "unauthenticated", "Valid authentication is required")
    result = session.execute(
        select(AccessToken, User)
        .join(User, AccessToken.user_id == User.id)
        .where(AccessToken.token_hash == token_hash(token))
    ).first()
    if result is None:
        raise DomainError(401, "unauthenticated", "Valid authentication is required")
    credential, user = result
    if (
        credential.revoked_at
        or utc(credential.expires_at) <= datetime.now(UTC)
        or user.status != "active"
    ):
        raise DomainError(401, "unauthenticated", "Valid authentication is required")
    return user


def authenticate_password(session: Session, email: str, password: str) -> User:
    """Resolve an active account without revealing whether an email exists."""
    candidates = session.scalars(select(User).where(User.email == email.lower())).all()
    matches = []
    checked_password = False
    for user in candidates:
        if user.password_hash is not None:
            checked_password = True
            if verify_password(password, user.password_hash):
                matches.append(user)
    if not checked_password:
        # Keep unknown-email requests close to the cost of a real password check.
        verify_password(password, _dummy_password_hash())
    if len(matches) != 1 or matches[0].status != "active":
        raise DomainError(401, "unauthenticated", "Email or password is incorrect")
    return matches[0]


_DUMMY_HASH: str | None = None


def _dummy_password_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        salt = b"ds-dummy-salt-01"
        digest = hashlib.scrypt(
            b"not-a-real-account-password",
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=32,
            maxmem=64 * 1024 * 1024,
        )
        _DUMMY_HASH = "$".join(
            (
                "scrypt-v1",
                str(_SCRYPT_N),
                str(_SCRYPT_R),
                str(_SCRYPT_P),
                base64.urlsafe_b64encode(salt).decode("ascii"),
                base64.urlsafe_b64encode(digest).decode("ascii"),
            )
        )
    return _DUMMY_HASH
