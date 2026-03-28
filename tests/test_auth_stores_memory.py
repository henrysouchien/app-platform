from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app_platform.auth.stores import InMemorySessionStore, InMemoryUserStore


def test_in_memory_user_store_creates_and_updates_users():
    store = InMemoryUserStore()

    user_id, created_user = store.get_or_create_user(
        "google-user-1",
        "first@example.com",
        "First User",
    )
    _, updated_user = store.get_or_create_user(
        "google-user-1",
        "updated@example.com",
        "Updated User",
    )

    assert user_id == "google-user-1"
    assert created_user["tier"] == "registered"
    assert "created_at" in created_user
    assert updated_user["email"] == "updated@example.com"
    assert updated_user["name"] == "Updated User"


def test_in_memory_session_store_round_trip_returns_auth_payload():
    user_store = InMemoryUserStore()
    session_store = InMemorySessionStore(users_dict=user_store.users_dict)
    user_id, _ = user_store.get_or_create_user(
        "google-user-2",
        "user2@example.com",
        "User Two",
    )

    session_store.create_session(
        "session-2",
        user_id,
        datetime.now(UTC) + timedelta(minutes=10),
    )

    session = session_store.get_session("session-2")

    assert session == {
        "user_id": "google-user-2",
        "google_user_id": "google-user-2",
        "email": "user2@example.com",
        "name": "User Two",
        "tier": "registered",
    }
    assert session_store.delete_session("session-2") is True
    assert session_store.get_session("session-2") is None


def test_in_memory_session_store_get_session_does_not_mutate_last_accessed():
    user_store = InMemoryUserStore()
    session_store = InMemorySessionStore(users_dict=user_store.users_dict)
    user_id, _ = user_store.get_or_create_user(
        "google-user-read-only",
        "readonly@example.com",
        "Read Only",
    )
    session_store.create_session(
        "session-read-only",
        user_id,
        datetime.now(UTC) + timedelta(minutes=10),
    )
    original_last_accessed = session_store.user_sessions_dict["session-read-only"][
        "last_accessed"
    ]

    session = session_store.get_session("session-read-only")

    assert session is not None
    assert (
        session_store.user_sessions_dict["session-read-only"]["last_accessed"]
        == original_last_accessed
    )


def test_in_memory_session_store_expires_and_cleans_up_sessions():
    user_store = InMemoryUserStore()
    session_store = InMemorySessionStore(users_dict=user_store.users_dict)
    user_id, _ = user_store.get_or_create_user(
        "google-user-3",
        "user3@example.com",
        "User Three",
    )

    session_store.create_session(
        "expired-now",
        user_id,
        datetime.now(UTC) - timedelta(seconds=1),
    )
    assert session_store.get_session("expired-now") is None
    assert "expired-now" not in session_store.user_sessions_dict

    session_store.create_session(
        "expired-later",
        user_id,
        datetime.now(UTC) - timedelta(seconds=1),
    )
    session_store.create_session(
        "active",
        user_id,
        datetime.now(UTC) + timedelta(minutes=5),
    )

    cleaned_count = session_store.cleanup_expired()

    assert cleaned_count == 1
    assert "expired-later" not in session_store.user_sessions_dict
    assert "active" in session_store.user_sessions_dict


def test_in_memory_session_store_touch_updates_last_accessed():
    user_store = InMemoryUserStore()
    session_store = InMemorySessionStore(users_dict=user_store.users_dict)
    user_id, _ = user_store.get_or_create_user(
        "google-user-4",
        "user4@example.com",
        "User Four",
    )
    session_store.create_session(
        "session-4",
        user_id,
        datetime.now(UTC) + timedelta(minutes=5),
    )
    original_last_accessed = session_store.user_sessions_dict["session-4"]["last_accessed"]

    session_store.touch_session("session-4")

    assert (
        session_store.user_sessions_dict["session-4"]["last_accessed"]
        >= original_last_accessed
    )
