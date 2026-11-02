import base64
import hashlib
import secrets
import threading
from collections import OrderedDict, deque
from datetime import UTC, datetime, timedelta
from time import monotonic
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from droidshield.errors import DomainError
from droidshield.models import AccessToken, User

SESSION_COOKIE = "ds_session"
CSRF_COOKIE = "ds_csrf"
_SCRYPT_N = 1 << 14
_SCRYPT_R = 8
_SCRYPT_P = 1
_PASSWORD_BYTES_MAX = 1024


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
    """Small bounded per-process guard for repeated password guesses."""

    def __init__(self, limit: int = 10, window_seconds: int = 60, max_keys: int = 2048):
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._attempts: OrderedDict[str, deque[float]] = OrderedDict()
        self._lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = monotonic()
        with self._lock:
            attempts = self._attempts.setdefault(key[:128] or "unknown", deque())
            self._attempts.move_to_end(key[:128] or "unknown")
            while attempts and now - attempts[0] >= self.window_seconds:
                attempts.popleft()
            if len(attempts) >= self.limit:
                return False
            attempts.append(now)
            while len(self._attempts) > self.max_keys:
                self._attempts.popitem(last=False)
            return True


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
