from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app_platform.auth.service import AuthServiceBase
from app_platform.auth.stores import InMemorySessionStore, InMemoryUserStore
from app_platform.db.exceptions import AuthenticationError, SessionLookupError


def _user_info() -> dict[str, str]:
    return {
        "user_id": "provider-user-1",
        "google_user_id": "provider-user-1",
        "email": "user@example.com",
        "name": "Example User",
    }


class RecordingTokenVerifier:
    def __init__(self):
        self.tokens = []

    def verify(self, token: str):
        self.tokens.append(token)
        return {"google_user_id": "provider-user-1"}, None


class RecordingAuthService(AuthServiceBase):
    def __init__(self, *args, **kwargs):
        self.hook_calls = []
        super().__init__(*args, **kwargs)

    def on_user_created(self, user_id, user_info):
        self.hook_calls.append((user_id, user_info))


class SimpleUserStore:
    def __init__(self, *, user_id="db-user-1", user_dict=None, error: Exception | None = None):
        self.user_id = user_id
        self.user_dict = user_dict or {
            "email": "user@example.com",
            "name": "Example User",
            "tier": "registered",
            "google_user_id": user_id,
        }
        self.error = error
        self.calls = []

    def get_or_create_user(self, provider_user_id: str, email: str, name: str):
        self.calls.append((provider_user_id, email, name))
        if self.error is not None:
            raise self.error
        return self.user_id, dict(self.user_dict)


class SimpleSessionStore:
    def __init__(
        self,
        *,
        session_result=None,
        delete_result: bool = True,
        cleanup_result: int = 0,
        create_error: Exception | None = None,
        get_error: Exception | None = None,
        delete_error: Exception | None = None,
        cleanup_error: Exception | None = None,
        touch_error: Exception | None = None,
    ):
        self.session_result = session_result
        self.delete_result = delete_result
        self.cleanup_result = cleanup_result
        self.create_error = create_error
        self.get_error = get_error
        self.delete_error = delete_error
        self.cleanup_error = cleanup_error
        self.touch_error = touch_error
        self.created = []
        self.get_calls = []
        self.delete_calls = []
        self.cleanup_calls = 0
        self.touch_calls = []

    def create_session(self, session_id: str, user_id, expires_at):
        if self.create_error is not None:
            raise self.create_error
        self.created.append((session_id, user_id, expires_at))

    def get_session(self, session_id: str):
        self.get_calls.append(session_id)
        if self.get_error is not None:
            raise self.get_error
        return self.session_result

    def delete_session(self, session_id: str):
        self.delete_calls.append(session_id)
        if self.delete_error is not None:
            raise self.delete_error
        return self.delete_result

    def cleanup_expired(self):
        self.cleanup_calls += 1
        if self.cleanup_error is not None:
            raise self.cleanup_error
        return self.cleanup_result

    def touch_session(self, session_id: str) -> None:
        self.touch_calls.append(session_id)
        if self.touch_error is not None:
            raise self.touch_error


def _memory_service() -> AuthServiceBase:
    user_store = InMemoryUserStore()
    session_store = InMemorySessionStore(users_dict=user_store.users_dict)
    return AuthServiceBase(
        session_store=session_store,
        user_store=user_store,
        session_duration=timedelta(minutes=5),
        cleanup_interval=timedelta(seconds=0),
    )


def test_verify_token_delegates_to_configured_verifier():
    verifier = RecordingTokenVerifier()
    service = _memory_service()
    service.token_verifier = verifier

    user_info, error = service.verify_token("token-123")

    assert verifier.tokens == ["token-123"]
    assert user_info == {"google_user_id": "provider-user-1"}
    assert error is None


def test_create_get_delete_session_round_trip_with_memory_stores():
    service = _memory_service()

    session_id = service.create_user_session(_user_info())

    resolved_user = service.get_user_by_session(session_id)
    deleted = service.delete_session(session_id)

    assert isinstance(session_id, str)
    assert resolved_user == {
        "user_id": "provider-user-1",
        "google_user_id": "provider-user-1",
        "email": "user@example.com",
        "name": "Example User",
        "tier": "registered",
    }
    assert deleted is True
    assert service.get_user_by_session(session_id) is None


def test_on_user_created_runs_for_primary_non_memory_store():
    user_store = SimpleUserStore(user_id=42)
    session_store = SimpleSessionStore()
    service = RecordingAuthService(
        session_store=session_store,
        user_store=user_store,
        session_duration=timedelta(minutes=5),
        cleanup_interval=timedelta(seconds=0),
    )

    service.create_user_session(_user_info())

    assert service.hook_calls == [(42, _user_info())]
    assert len(session_store.created) == 1


def test_create_user_session_falls_back_when_primary_raises_and_not_strict():
    fallback_user_store = InMemoryUserStore()
    fallback_session_store = InMemorySessionStore(users_dict=fallback_user_store.users_dict)
    service = RecordingAuthService(
        session_store=SimpleSessionStore(),
        user_store=SimpleUserStore(error=RuntimeError("db down")),
        strict_mode=False,
        fallback_session_store=fallback_session_store,
        fallback_user_store=fallback_user_store,
        session_duration=timedelta(minutes=5),
        cleanup_interval=timedelta(seconds=0),
    )

    session_id = service.create_user_session(_user_info())

    assert session_id in fallback_session_store.user_sessions_dict
    assert service.hook_calls == []


def test_create_user_session_raises_authentication_error_when_strict_mode():
    fallback_user_store = InMemoryUserStore()
    fallback_session_store = InMemorySessionStore(users_dict=fallback_user_store.users_dict)
    service = RecordingAuthService(
        session_store=SimpleSessionStore(),
        user_store=SimpleUserStore(error=RuntimeError("db down")),
        strict_mode=True,
        fallback_session_store=fallback_session_store,
        fallback_user_store=fallback_user_store,
        session_duration=timedelta(minutes=5),
        cleanup_interval=timedelta(seconds=0),
    )

    with pytest.raises(AuthenticationError, match="Session creation failed"):
        service.create_user_session(_user_info())


def test_get_user_by_session_uses_fallback_only_on_primary_exception():
    fallback_result = {
        "user_id": "fallback-user",
        "google_user_id": "fallback-user",
        "email": "fallback@example.com",
        "name": "Fallback User",
        "tier": "registered",
    }
    primary_session_store = SimpleSessionStore(get_error=RuntimeError("db down"))
    fallback_session_store = SimpleSessionStore(session_result=fallback_result)
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
        fallback_session_store=fallback_session_store,
        fallback_user_store=SimpleUserStore(),
    )

    user = service.get_user_by_session("session-1")

    assert user == fallback_result
    assert primary_session_store.get_calls == ["session-1"]
    assert fallback_session_store.get_calls == ["session-1"]
    assert primary_session_store.touch_calls == []
    assert fallback_session_store.touch_calls == ["session-1"]


def test_get_user_by_session_does_not_fallback_on_primary_miss():
    primary_session_store = SimpleSessionStore(session_result=None)
    fallback_session_store = SimpleSessionStore(
        session_result={
            "user_id": "fallback-user",
            "google_user_id": "fallback-user",
            "email": "fallback@example.com",
            "name": "Fallback User",
            "tier": "registered",
        }
    )
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
        fallback_session_store=fallback_session_store,
        fallback_user_store=SimpleUserStore(),
    )

    user = service.get_user_by_session("session-2")

    assert user is None
    assert fallback_session_store.get_calls == []
    assert primary_session_store.touch_calls == []


def test_get_user_by_session_raises_lookup_error_when_primary_fails_and_fallback_misses():
    primary_session_store = SimpleSessionStore(get_error=RuntimeError("db down"))
    fallback_session_store = SimpleSessionStore(session_result=None)
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
        fallback_session_store=fallback_session_store,
        fallback_user_store=SimpleUserStore(),
    )

    with pytest.raises(SessionLookupError, match="cannot verify session"):
        service.get_user_by_session("session-3")

    assert primary_session_store.get_calls == ["session-3"]
    assert fallback_session_store.get_calls == ["session-3"]
    assert fallback_session_store.touch_calls == []


def test_get_user_by_session_raises_lookup_error_in_strict_mode_when_primary_raises():
    primary_session_store = SimpleSessionStore(get_error=RuntimeError("db down"))
    fallback_session_store = SimpleSessionStore(
        session_result={
            "user_id": "fallback-user",
            "google_user_id": "fallback-user",
            "email": "fallback@example.com",
            "name": "Fallback User",
            "tier": "registered",
        }
    )
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
        strict_mode=True,
        fallback_session_store=fallback_session_store,
        fallback_user_store=SimpleUserStore(),
    )

    with pytest.raises(SessionLookupError, match="Primary session store unavailable"):
        service.get_user_by_session("session-4")

    assert fallback_session_store.get_calls == []


def test_get_user_by_session_debounces_touch_calls_per_session():
    session_result = {
        "user_id": "primary-user",
        "google_user_id": "primary-user",
        "email": "primary@example.com",
        "name": "Primary User",
        "tier": "registered",
    }
    primary_session_store = SimpleSessionStore(session_result=session_result)
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
    )

    for _ in range(30):
        assert service.get_user_by_session("session-debounce") == session_result

    assert primary_session_store.get_calls == ["session-debounce"] * 30
    assert primary_session_store.touch_calls == ["session-debounce"]


def test_get_user_by_session_swallow_touch_failures_after_successful_lookup():
    session_result = {
        "user_id": "primary-user",
        "google_user_id": "primary-user",
        "email": "primary@example.com",
        "name": "Primary User",
        "tier": "registered",
    }
    primary_session_store = SimpleSessionStore(
        session_result=session_result,
        touch_error=RuntimeError("touch failed"),
    )
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
    )

    user = service.get_user_by_session("session-touch-failure")

    assert user == session_result
    assert primary_session_store.touch_calls == ["session-touch-failure"]


def test_get_user_by_session_touches_primary_store_on_primary_hit():
    session_result = {
        "user_id": "primary-user",
        "google_user_id": "primary-user",
        "email": "primary@example.com",
        "name": "Primary User",
        "tier": "registered",
    }
    primary_session_store = SimpleSessionStore(session_result=session_result)
    fallback_session_store = SimpleSessionStore(session_result={"user_id": "fallback"})
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
        fallback_session_store=fallback_session_store,
        fallback_user_store=SimpleUserStore(),
    )

    user = service.get_user_by_session("session-primary-touch")

    assert user == session_result
    assert primary_session_store.touch_calls == ["session-primary-touch"]
    assert fallback_session_store.touch_calls == []


def test_get_user_by_session_prunes_touch_cache_entries_older_than_thirty_minutes():
    session_result = {
        "user_id": "primary-user",
        "google_user_id": "primary-user",
        "email": "primary@example.com",
        "name": "Primary User",
        "tier": "registered",
    }
    primary_session_store = SimpleSessionStore(session_result=session_result)
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
    )
    service._touch_cache["stale-session"] = datetime.now(UTC) - timedelta(minutes=31)

    user = service.get_user_by_session("session-cache-prune")

    assert user == session_result
    assert "stale-session" not in service._touch_cache
    assert "session-cache-prune" in service._touch_cache


def test_delete_session_uses_fallback_only_on_primary_exception():
    primary_session_store = SimpleSessionStore(delete_error=RuntimeError("db down"))
    fallback_session_store = SimpleSessionStore(delete_result=True)
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
        fallback_session_store=fallback_session_store,
        fallback_user_store=SimpleUserStore(),
    )

    deleted = service.delete_session("session-4")

    assert deleted is True
    assert primary_session_store.delete_calls == ["session-4"]
    assert fallback_session_store.delete_calls == ["session-4"]


def test_delete_session_returns_false_in_strict_mode_when_primary_raises():
    primary_session_store = SimpleSessionStore(delete_error=RuntimeError("db down"))
    fallback_session_store = SimpleSessionStore(delete_result=True)
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
        strict_mode=True,
        fallback_session_store=fallback_session_store,
        fallback_user_store=SimpleUserStore(),
    )

    deleted = service.delete_session("session-5")

    assert deleted is False
    assert fallback_session_store.delete_calls == []


def test_delete_session_clears_touch_cache_entry():
    primary_session_store = SimpleSessionStore(delete_result=True)
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
    )
    service._touch_cache["session-6"] = datetime.now(UTC)

    deleted = service.delete_session("session-6")

    assert deleted is True
    assert "session-6" not in service._touch_cache


def test_cleanup_expired_sessions_runs_primary_and_fallback_even_in_strict_mode():
    primary_session_store = SimpleSessionStore(cleanup_error=RuntimeError("db down"))
    fallback_session_store = SimpleSessionStore(cleanup_result=2)
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
        strict_mode=True,
        fallback_session_store=fallback_session_store,
        fallback_user_store=SimpleUserStore(),
        cleanup_interval=timedelta(hours=1),
    )
    service.last_cleanup = datetime.now(UTC) - timedelta(hours=2)

    cleaned = service.cleanup_expired_sessions()

    assert cleaned == 2
    assert primary_session_store.cleanup_calls == 1
    assert fallback_session_store.cleanup_calls == 1


def test_cleanup_expired_sessions_returns_zero_when_fallback_raises():
    primary_session_store = SimpleSessionStore(cleanup_result=1)
    fallback_session_store = SimpleSessionStore(cleanup_error=RuntimeError("memory down"))
    service = AuthServiceBase(
        session_store=primary_session_store,
        user_store=SimpleUserStore(),
        fallback_session_store=fallback_session_store,
        fallback_user_store=SimpleUserStore(),
        cleanup_interval=timedelta(hours=1),
    )
    old_last_cleanup = datetime.now(UTC) - timedelta(hours=2)
    service.last_cleanup = old_last_cleanup

    cleaned = service.cleanup_expired_sessions()

    assert cleaned == 0
    assert service.last_cleanup == old_last_cleanup
