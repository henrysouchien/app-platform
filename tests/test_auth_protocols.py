from __future__ import annotations

from contextlib import nullcontext
from datetime import UTC, datetime, timedelta

from app_platform.auth import (
    InMemorySessionStore,
    InMemoryUserStore,
    PostgresSessionStore,
    PostgresUserStore,
    SessionStore,
    UserStore,
)


class FakeCursor:
    def __init__(self, fetchone_results=None, rowcount: int = 0):
        self.fetchone_results = list(fetchone_results or [])
        self.rowcount = rowcount
        self.executed = []

    def execute(self, query, params=None):
        normalized_query = " ".join(query.split())
        self.executed.append((normalized_query, params))

    def fetchone(self):
        if not self.fetchone_results:
            return None
        return self.fetchone_results.pop(0)


class FakeConnection:
    def __init__(self, cursor: FakeCursor):
        self._cursor = cursor
        self.commit_count = 0

    def cursor(self):
        return self._cursor

    def commit(self):
        self.commit_count += 1


def test_session_store_implementations_satisfy_protocol():
    memory_store = InMemorySessionStore()
    postgres_store = PostgresSessionStore(lambda: nullcontext(FakeConnection(FakeCursor())))

    assert isinstance(memory_store, SessionStore)
    assert isinstance(postgres_store, SessionStore)


def test_user_store_implementations_satisfy_protocol():
    memory_store = InMemoryUserStore()
    postgres_store = PostgresUserStore(lambda: nullcontext(FakeConnection(FakeCursor())))

    assert isinstance(memory_store, UserStore)
    assert isinstance(postgres_store, UserStore)


def test_postgres_session_store_returns_required_session_shape():
    cursor = FakeCursor(
        fetchone_results=[
            {
                "user_id": 17,
                "google_user_id": "google-17",
                "email": "user@example.com",
                "name": "Example User",
                "tier": "registered",
                "last_accessed": None,
            }
        ]
    )
    conn = FakeConnection(cursor)
    store = PostgresSessionStore(lambda: nullcontext(conn))

    session = store.get_session("session-1")

    assert session == {
        "user_id": 17,
        "google_user_id": "google-17",
        "email": "user@example.com",
        "name": "Example User",
        "tier": "registered",
    }
    assert conn.commit_count == 0
    assert len(cursor.executed) == 1


def test_postgres_session_store_get_session_is_read_only():
    cursor = FakeCursor(
        fetchone_results=[
            {
                "user_id": 17,
                "google_user_id": "google-17",
                "email": "user@example.com",
                "name": "Example User",
                "tier": "registered",
                "last_accessed": datetime.now(UTC) - timedelta(seconds=30),
            }
        ]
    )
    conn = FakeConnection(cursor)
    store = PostgresSessionStore(lambda: nullcontext(conn))

    session = store.get_session("session-1")

    assert session == {
        "user_id": 17,
        "google_user_id": "google-17",
        "email": "user@example.com",
        "name": "Example User",
        "tier": "registered",
    }
    assert conn.commit_count == 0
    assert len(cursor.executed) == 1


def test_postgres_user_store_returns_user_id_and_user_dict():
    cursor = FakeCursor(
        fetchone_results=[
            None,
            None,
            {
                "id": 23,
                "email": "new@example.com",
                "name": "New User",
                "tier": "registered",
                "google_user_id": "google-23",
            },
        ]
    )
    conn = FakeConnection(cursor)
    store = PostgresUserStore(lambda: nullcontext(conn))

    user_id, user_dict = store.get_or_create_user(
        "google-23",
        "new@example.com",
        "New User",
    )

    assert user_id == 23
    assert user_dict == {
        "email": "new@example.com",
        "name": "New User",
        "tier": "registered",
        "google_user_id": "google-23",
    }
    assert conn.commit_count == 1
