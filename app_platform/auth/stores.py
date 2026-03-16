"""Storage backends for app_platform.auth."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any, Callable, ContextManager, Dict, Optional


def _utcnow() -> datetime:
    return datetime.now(UTC)


_TOUCH_INTERVAL = timedelta(minutes=5)


class PostgresSessionStore:
    """SessionStore backed by the ``user_sessions`` table."""

    def __init__(self, get_session_fn: Callable[[], ContextManager[Any]]):
        self._get_session_fn = get_session_fn

    def create_session(self, session_id: str, user_id: Any, expires_at: datetime) -> None:
        with self._get_session_fn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO user_sessions (session_id, user_id, expires_at)
                VALUES (%s, %s, %s)
                """,
                (session_id, user_id, expires_at),
            )
            conn.commit()

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        with self._get_session_fn() as conn:
            cursor = conn.cursor()
            now = _utcnow()
            cursor.execute(
                """
                SELECT s.session_id, s.user_id, s.expires_at, s.last_accessed,
                       u.email, u.name, u.tier, u.google_user_id
                FROM user_sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.session_id = %s AND s.expires_at > %s
                """,
                (session_id, now),
            )
            result = cursor.fetchone()
            if not result:
                return None

            last_accessed = result["last_accessed"]
            # Normalize both to naive UTC for safe comparison (DB may return
            # naive or aware depending on driver/test setup).
            now_cmp = now.replace(tzinfo=None)
            if last_accessed is not None and last_accessed.tzinfo is not None:
                last_accessed = last_accessed.replace(tzinfo=None)
            if last_accessed is None or (now_cmp - last_accessed) > _TOUCH_INTERVAL:
                cursor.execute(
                    """
                    UPDATE user_sessions
                    SET last_accessed = %s
                    WHERE session_id = %s
                    """,
                    (now, session_id),
                )
                conn.commit()

            return {
                "user_id": result["user_id"],
                "google_user_id": result["google_user_id"],
                "email": result["email"],
                "name": result["name"],
                "tier": result["tier"],
            }

    def delete_session(self, session_id: str) -> bool:
        with self._get_session_fn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM user_sessions WHERE session_id = %s",
                (session_id,),
            )
            conn.commit()
        return True

    def cleanup_expired(self) -> int:
        with self._get_session_fn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM user_sessions WHERE expires_at < %s",
                (_utcnow(),),
            )
            cleaned_count = cursor.rowcount
            conn.commit()
        return cleaned_count

    def touch_session(self, session_id: str) -> None:
        with self._get_session_fn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE user_sessions
                SET last_accessed = %s
                WHERE session_id = %s
                """,
                (_utcnow(), session_id),
            )
            conn.commit()


class InMemorySessionStore:
    """Dict-backed session storage for dev/test flows."""

    def __init__(
        self,
        users_dict: Optional[Dict[Any, Dict[str, Any]]] = None,
        sessions_dict: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.users_dict = users_dict if users_dict is not None else {}
        self.user_sessions_dict = sessions_dict if sessions_dict is not None else {}

    def create_session(self, session_id: str, user_id: Any, expires_at: datetime) -> None:
        now = _utcnow()
        self.user_sessions_dict[session_id] = {
            "user_id": user_id,
            "created_at": now,
            "expires_at": expires_at,
            "last_accessed": now,
        }

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        session_info = self.user_sessions_dict.get(session_id)
        if not session_info:
            return None

        now = _utcnow()
        if now > session_info["expires_at"]:
            del self.user_sessions_dict[session_id]
            return None

        session_info["last_accessed"] = now
        user_id = session_info["user_id"]
        user_info = self.users_dict.get(user_id)
        if not user_info:
            return None

        return {
            "user_id": user_id,
            "google_user_id": user_id,
            "email": user_info["email"],
            "name": user_info["name"],
            "tier": user_info["tier"],
        }

    def delete_session(self, session_id: str) -> bool:
        if session_id not in self.user_sessions_dict:
            return False
        del self.user_sessions_dict[session_id]
        return True

    def cleanup_expired(self) -> int:
        now = _utcnow()
        expired_session_ids = [
            session_id
            for session_id, session_info in self.user_sessions_dict.items()
            if now > session_info["expires_at"]
        ]
        for session_id in expired_session_ids:
            del self.user_sessions_dict[session_id]
        return len(expired_session_ids)

    def touch_session(self, session_id: str) -> None:
        session_info = self.user_sessions_dict.get(session_id)
        if session_info:
            session_info["last_accessed"] = _utcnow()


class PostgresUserStore:
    """UserStore backed by the ``users`` table."""

    def __init__(self, get_session_fn: Callable[[], ContextManager[Any]]):
        self._get_session_fn = get_session_fn

    def get_or_create_user(
        self,
        provider_user_id: str,
        email: str,
        name: str,
    ) -> tuple[Any, Dict[str, Any]]:
        with self._get_session_fn() as conn:
            cursor = conn.cursor()

            existing_user = self._find_user_by_google_id(cursor, provider_user_id)
            if existing_user is None and email:
                existing_user = self._find_user_by_email(cursor, email)

            if existing_user is not None:
                self._update_existing_user(
                    conn,
                    cursor,
                    existing_user["id"],
                    provider_user_id,
                    email,
                    name,
                )
                return existing_user["id"], {
                    "email": email if email is not None else existing_user["email"],
                    "name": name if name is not None else existing_user["name"],
                    "tier": existing_user["tier"],
                    "google_user_id": (
                        provider_user_id
                        if provider_user_id is not None
                        else existing_user["google_user_id"]
                    ),
                }

            cursor.execute(
                """
                INSERT INTO users (
                    google_user_id,
                    email,
                    name,
                    tier,
                    auth_provider,
                    created_at,
                    updated_at
                )
                VALUES (%s, %s, %s, %s, %s, NOW(), NOW())
                RETURNING id, email, name, tier, google_user_id
                """,
                (provider_user_id, email, name, "registered", "google"),
            )
            result = cursor.fetchone()
            conn.commit()
            return result["id"], {
                "email": result["email"],
                "name": result["name"],
                "tier": result["tier"],
                "google_user_id": result["google_user_id"],
            }

    def _find_user_by_google_id(
        self,
        cursor: Any,
        provider_user_id: str,
    ) -> Optional[Dict[str, Any]]:
        cursor.execute(
            """
            SELECT id, email, name, tier, google_user_id
            FROM users
            WHERE google_user_id = %s
            """,
            (provider_user_id,),
        )
        return cursor.fetchone()

    def _find_user_by_email(
        self,
        cursor: Any,
        email: str,
    ) -> Optional[Dict[str, Any]]:
        cursor.execute(
            """
            SELECT id, email, name, tier, google_user_id
            FROM users
            WHERE email = %s
            """,
            (email,),
        )
        return cursor.fetchone()

    def _update_existing_user(
        self,
        conn: Any,
        cursor: Any,
        user_id: Any,
        provider_user_id: Optional[str],
        email: Optional[str],
        name: Optional[str],
    ) -> None:
        update_fields = []
        values = []

        if email is not None:
            update_fields.append("email = %s")
            values.append(email)
        if name is not None:
            update_fields.append("name = %s")
            values.append(name)
        if provider_user_id is not None:
            update_fields.append("google_user_id = %s")
            values.append(provider_user_id)

        if not update_fields:
            return

        values.append(user_id)
        cursor.execute(
            f"""
            UPDATE users
            SET {", ".join(update_fields)}, updated_at = NOW()
            WHERE id = %s
            """,
            tuple(values),
        )
        conn.commit()


class InMemoryUserStore:
    """Dict-backed user storage for dev/test flows."""

    def __init__(self, users_dict: Optional[Dict[str, Dict[str, Any]]] = None):
        self.users_dict = users_dict if users_dict is not None else {}

    def get_or_create_user(
        self,
        provider_user_id: str,
        email: str,
        name: str,
    ) -> tuple[Any, Dict[str, Any]]:
        if provider_user_id not in self.users_dict:
            self.users_dict[provider_user_id] = {
                "email": email,
                "name": name,
                "tier": "registered",
                "google_user_id": provider_user_id,
                "created_at": _utcnow().isoformat(),
            }
        else:
            self.users_dict[provider_user_id].update(
                {
                    "email": email,
                    "name": name,
                    "google_user_id": provider_user_id,
                }
            )

        return provider_user_id, dict(self.users_dict[provider_user_id])


__all__ = [
    "InMemorySessionStore",
    "InMemoryUserStore",
    "PostgresSessionStore",
    "PostgresUserStore",
]
