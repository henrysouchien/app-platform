from __future__ import annotations

from contextlib import contextmanager

import pytest

from app_platform.db.user_scope import (
    MAX_POSTGRES_INTEGER,
    USER_ID_SETTING,
    bind_user_scope,
    normalize_db_user_id,
    user_scoped_db_session,
)


class _Cursor:
    def __init__(self, conn: "_Connection") -> None:
        self.conn = conn
        self.closed = False

    def execute(self, sql: str, params: tuple[str, str]) -> None:
        self.conn.executions.append((sql, params))

    def close(self) -> None:
        self.closed = True
        self.conn.cursor_closed += 1


class _Connection:
    def __init__(self, *, autocommit: bool = False) -> None:
        self.autocommit = autocommit
        self.executions: list[tuple[str, tuple[str, str]]] = []
        self.cursor_closed = 0
        self.rollbacks = 0

    def cursor(self) -> _Cursor:
        return _Cursor(self)

    def rollback(self) -> None:
        self.rollbacks += 1


class _ConnectionWithoutRollback:
    autocommit = False

    def __init__(self) -> None:
        self.cursor_calls = 0

    def cursor(self):
        self.cursor_calls += 1
        return _Cursor(self)


class _Factory:
    def __init__(self, conn: _Connection) -> None:
        self.conn = conn
        self.calls = 0
        self.exits = 0

    @contextmanager
    def __call__(self):
        self.calls += 1
        try:
            yield self.conn
        finally:
            self.exits += 1


@pytest.mark.parametrize(
    "raw",
    [
        0,
        -1,
        "",
        "  ",
        "1.0",
        "+1",
        "user-1",
        True,
        False,
        MAX_POSTGRES_INTEGER + 1,
        "9" * 5_000,
    ],
)
def test_normalize_db_user_id_rejects_non_positive_or_non_decimal_values(raw) -> None:
    with pytest.raises(ValueError, match="positive"):
        normalize_db_user_id(raw)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(1, 1), ("1", 1), (" 42 ", 42), ("0007", 7), (MAX_POSTGRES_INTEGER, MAX_POSTGRES_INTEGER)],
)
def test_normalize_db_user_id_accepts_positive_decimal_values(raw, expected: int) -> None:
    assert normalize_db_user_id(raw) == expected


def test_bind_user_scope_uses_transaction_local_parameter_and_closes_cursor() -> None:
    conn = _Connection()

    resolved = bind_user_scope(conn, user_id="42")

    assert resolved == 42
    assert conn.executions == [
        (
            "SELECT set_config(%s, %s, true)",
            (USER_ID_SETTING, "42"),
        )
    ]
    assert conn.cursor_closed == 1


def test_user_scoped_session_rolls_back_successful_read_before_pool_return() -> None:
    conn = _Connection()
    factory = _Factory(conn)

    with user_scoped_db_session(user_id=101, session_factory=factory) as scoped:
        assert scoped is conn
        assert conn.rollbacks == 0

    assert conn.rollbacks == 1
    assert factory.calls == 1
    assert factory.exits == 1


def test_user_scoped_session_rolls_back_and_preserves_body_error() -> None:
    conn = _Connection()
    factory = _Factory(conn)

    with pytest.raises(RuntimeError, match="body failed"):
        with user_scoped_db_session(user_id=202, session_factory=factory):
            raise RuntimeError("body failed")

    assert conn.rollbacks == 1
    assert factory.exits == 1


def test_user_scoped_session_rejects_identity_before_acquiring_connection() -> None:
    conn = _Connection()
    factory = _Factory(conn)

    with pytest.raises(ValueError, match="positive integer"):
        with user_scoped_db_session(user_id="not-a-user", session_factory=factory):
            pass

    assert factory.calls == 0


def test_user_scoped_session_rejects_autocommit_before_binding_identity() -> None:
    conn = _Connection(autocommit=True)
    factory = _Factory(conn)

    with pytest.raises(RuntimeError, match="autocommit disabled"):
        with user_scoped_db_session(user_id=101, session_factory=factory):
            pass

    assert conn.executions == []
    assert conn.rollbacks == 0
    assert factory.calls == 1
    assert factory.exits == 1


def test_user_scoped_session_rejects_missing_rollback_before_binding_identity() -> None:
    conn = _ConnectionWithoutRollback()
    factory = _Factory(conn)

    with pytest.raises(RuntimeError, match="must support rollback"):
        with user_scoped_db_session(user_id=101, session_factory=factory):
            pass

    assert conn.cursor_calls == 0
    assert factory.calls == 1
    assert factory.exits == 1


def test_user_scoped_session_rolls_back_when_bind_fails() -> None:
    conn = _Connection()
    factory = _Factory(conn)

    def fail_cursor():
        raise RuntimeError("bind failed")

    conn.cursor = fail_cursor  # type: ignore[method-assign]

    with pytest.raises(RuntimeError, match="bind failed"):
        with user_scoped_db_session(user_id=101, session_factory=factory):
            pass

    assert conn.rollbacks == 1
    assert factory.exits == 1
