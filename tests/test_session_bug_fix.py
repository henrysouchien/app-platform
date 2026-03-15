from __future__ import annotations

import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime, timedelta
from itertools import count
from pathlib import Path

import psycopg2.extensions
import psycopg2.pool as psycopg2_pool
import pytest


APP_PLATFORM_ROOT = Path(__file__).resolve().parents[1]
if str(APP_PLATFORM_ROOT) not in sys.path:
    sys.path.insert(0, str(APP_PLATFORM_ROOT))

from app_platform.auth import AuthServiceBase, InMemoryUserStore, PostgresSessionStore
from app_platform.db.pool import PoolManager
from app_platform.db.session import SessionManager


class SlowPoolList(list):
    """Amplify pool races when locking is missing."""

    def __bool__(self) -> bool:
        time.sleep(0.001)
        return len(self) > 0

    def pop(self, *args):
        time.sleep(0.001)
        return super().pop(*args)


class FakeConnectionInfo:
    transaction_status = psycopg2.extensions.TRANSACTION_STATUS_IDLE


class FakeCursor:
    def __init__(self, state: dict[str, dict]) -> None:
        self._state = state
        self._result = None

    def __enter__(self) -> "FakeCursor":
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def execute(self, query: str, params=None) -> None:
        normalized = " ".join(query.split())
        if normalized == "SELECT 1":
            self._result = (1,)
            return

        if normalized.startswith("SELECT s.session_id, s.user_id, s.expires_at,"):
            session_id, now = params
            session = self._state["sessions"].get(session_id)
            if not session or session["expires_at"] <= now:
                self._result = None
                return

            user = self._state["users"][session["user_id"]]
            self._result = {
                "session_id": session_id,
                "user_id": session["user_id"],
                "expires_at": session["expires_at"],
                "email": user["email"],
                "name": user["name"],
                "tier": user["tier"],
                "google_user_id": user["google_user_id"],
            }
            return

        if normalized.startswith("UPDATE user_sessions SET last_accessed = %s WHERE session_id = %s"):
            last_accessed, session_id = params
            session = self._state["sessions"].get(session_id)
            if session is not None:
                session["last_accessed"] = last_accessed
            self._result = None
            return

        raise AssertionError(f"Unexpected query: {normalized}")

    def fetchone(self):
        return self._result


class FakeConnection:
    def __init__(self, state: dict[str, dict], identifier: int) -> None:
        self._state = state
        self.identifier = identifier
        self.closed = False
        self.info = FakeConnectionInfo()

    def cursor(self) -> FakeCursor:
        return FakeCursor(self._state)

    def commit(self) -> None:
        return None

    def rollback(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True


@pytest.fixture()
def fake_db_state() -> dict[str, dict]:
    return {
        "users": {
            1: {
                "email": "session@example.com",
                "name": "Session User",
                "tier": "registered",
                "google_user_id": "google-user-1",
            }
        },
        "sessions": {},
    }


@pytest.fixture()
def fake_connect(monkeypatch, fake_db_state):
    ids = count()

    def _connect(*args, **kwargs):
        return FakeConnection(fake_db_state, next(ids))

    monkeypatch.setattr(psycopg2_pool.psycopg2, "connect", _connect)
    return _connect


@pytest.fixture()
def pool_manager(fake_connect) -> PoolManager:
    manager = PoolManager(
        database_url="postgresql://postgres:postgres@localhost:5432/postgres",
        min_connections=1,
        max_connections=10,
    )
    yield manager
    manager.close()


def test_pool_manager_concurrent_access(pool_manager: PoolManager) -> None:
    """ThreadedConnectionPool must survive concurrent getconn/putconn from multiple threads."""

    pool = pool_manager.get_pool()
    pool._pool = SlowPoolList(pool._pool)
    errors: list[Exception] = []
    successes: list[bool] = []

    def checkout_and_return() -> None:
        try:
            conn = pool.getconn()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
                    assert cur.fetchone() == (1,)
                successes.append(True)
            finally:
                pool.putconn(conn)
        except Exception as exc:  # pragma: no cover - asserted via errors list
            errors.append(exc)

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(checkout_and_return) for _ in range(50)]
        for future in as_completed(futures):
            future.result()

    assert len(errors) == 0, f"Pool errors under concurrency: {errors}"
    assert len(successes) == 50


def test_concurrent_session_lookups(
    pool_manager: PoolManager,
    fake_db_state: dict[str, dict],
) -> None:
    """Session lookups must return valid user under concurrent access."""

    test_session_id = "session-123"
    now = datetime.now(UTC)
    fake_db_state["sessions"][test_session_id] = {
        "user_id": 1,
        "created_at": now,
        "expires_at": now + timedelta(hours=1),
        "last_accessed": now,
    }

    pool = pool_manager.get_pool()
    pool._pool = SlowPoolList(pool._pool)
    session_manager = SessionManager(pool_manager=pool_manager)
    auth_service = AuthServiceBase(
        session_store=PostgresSessionStore(session_manager.get_db_session),
        user_store=InMemoryUserStore(),
        strict_mode=True,
    )

    results: list[dict[str, object] | None] = []

    def lookup() -> None:
        results.append(auth_service.get_user_by_session(test_session_id))

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(lookup) for _ in range(30)]
        for future in as_completed(futures):
            future.result()

    assert len(results) == 30
    assert all(result is not None for result in results), (
        f"Session lookup returned None {results.count(None)}/30 times"
    )
