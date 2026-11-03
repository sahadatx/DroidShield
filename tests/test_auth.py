"""Shared authentication controls across independently configured API workers."""

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

from sqlalchemy import select
from sqlalchemy.orm import Session

from droidshield.auth import LoginRateLimiter
from droidshield.db import build_engine, session_factory
from droidshield.models import Base, LoginRateLimitEntry


def test_login_rate_limit_serializes_concurrent_workers(tmp_path):
    database_url = f"sqlite:///{tmp_path / 'shared-login-limits.db'}"
    first_engine = build_engine(database_url)
    second_engine = build_engine(database_url)
    try:
        Base.metadata.create_all(first_engine)
        limiters = (
            LoginRateLimiter(session_factory(first_engine)),
            LoginRateLimiter(session_factory(second_engine)),
        )
        barrier = Barrier(12)

        def attempt(index):
            barrier.wait(timeout=5)
            return limiters[index % 2].allow("198.51.100.24")

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(attempt, range(12)))

        assert sum(results) == 10
        with Session(first_engine) as session:
            entry = session.scalar(select(LoginRateLimitEntry))
            assert entry is not None and len(entry.attempt_times_us) == 10
    finally:
        first_engine.dispose()
        second_engine.dispose()
