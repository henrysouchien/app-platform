"""Generic auth service for app_platform."""

from __future__ import annotations

import logging
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any, Dict, Optional

from app_platform.db.exceptions import AuthenticationError

from .protocols import SessionStore, TokenVerifier, UserStore
from .stores import InMemoryUserStore

logger = logging.getLogger(__name__)


class AuthServiceBase:
    """Generic auth service with pluggable stores and fallback semantics."""

    def __init__(
        self,
        session_store: SessionStore,
        user_store: UserStore,
        token_verifier: Optional[TokenVerifier] = None,
        session_duration: timedelta = timedelta(days=7),
        cleanup_interval: timedelta = timedelta(hours=1),
        strict_mode: bool = False,
        fallback_session_store: Optional[SessionStore] = None,
        fallback_user_store: Optional[UserStore] = None,
    ):
        self.session_store = session_store
        self.user_store = user_store
        self.token_verifier = token_verifier
        self.session_duration = session_duration
        self.cleanup_interval = cleanup_interval
        self.strict_mode = strict_mode
        self.fallback_session_store = fallback_session_store
        self.fallback_user_store = fallback_user_store
        self.last_cleanup = datetime.now(UTC)

    def _generate_session_id(self) -> str:
        return secrets.token_urlsafe(32)

    def _provider_user_id(self, user_info: Dict[str, Any]) -> str:
        provider_user_id = user_info.get("google_user_id") or user_info.get("user_id")
        if provider_user_id is None:
            raise KeyError("google_user_id")
        return provider_user_id

    def _should_run_user_created_hook(self) -> bool:
        return not isinstance(self.user_store, InMemoryUserStore)

    def verify_token(
        self,
        token: str,
    ) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        if self.token_verifier is None:
            return None, "Token verifier not configured"

        try:
            return self.token_verifier.verify(token)
        except Exception as exc:
            return None, f"Token verification failed: {exc}"

    def create_user_session(self, user_info: Dict[str, Any]) -> str:
        try:
            try:
                user_id, _ = self.user_store.get_or_create_user(
                    self._provider_user_id(user_info),
                    user_info["email"],
                    user_info["name"],
                )
                if self._should_run_user_created_hook():
                    self.on_user_created(user_id, user_info)

                session_id = self._generate_session_id()
                expires_at = datetime.now(UTC) + self.session_duration
                self.session_store.create_session(session_id, user_id, expires_at)
                return session_id

            except Exception as exc:
                if self.strict_mode:
                    raise AuthenticationError(
                        f"Primary session creation failed: {exc}",
                        original_error=exc,
                    ) from exc
                if (
                    self.fallback_session_store is None
                    or self.fallback_user_store is None
                ):
                    raise

            user_id, _ = self.fallback_user_store.get_or_create_user(
                self._provider_user_id(user_info),
                user_info["email"],
                user_info["name"],
            )
            session_id = self._generate_session_id()
            expires_at = datetime.now(UTC) + self.session_duration
            self.fallback_session_store.create_session(session_id, user_id, expires_at)
            return session_id

        except Exception as exc:
            raise AuthenticationError(
                f"Session creation failed: {exc}",
                original_error=exc,
            ) from exc

    def get_user_by_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        if not session_id:
            return None

        try:
            try:
                session = self.session_store.get_session(session_id)
                if session is not None:
                    return session
                return None

            except Exception as exc:
                logger.warning(
                    "Primary session lookup failed for session_id=%s...: %s",
                    session_id[:8], exc,
                )
                if self.strict_mode:
                    raise AuthenticationError(
                        f"Primary session lookup failed: {exc}",
                        original_error=exc,
                    ) from exc
                if self.fallback_session_store is None:
                    return None

            return self.fallback_session_store.get_session(session_id)

        except Exception as exc:
            logger.warning(
                "Session lookup failed (outer) for session_id=%s...: %s",
                session_id[:8], exc,
            )
            return None

    def delete_session(self, session_id: str) -> bool:
        if not session_id:
            return False

        try:
            try:
                return self.session_store.delete_session(session_id)

            except Exception as exc:
                if self.strict_mode:
                    raise AuthenticationError(
                        f"Primary session deletion failed: {exc}",
                        original_error=exc,
                    ) from exc
                if self.fallback_session_store is None:
                    return False

            return self.fallback_session_store.delete_session(session_id)

        except Exception:
            return False

    def cleanup_expired_sessions(self) -> int:
        now = datetime.now(UTC)
        if now - self.last_cleanup < self.cleanup_interval:
            return 0

        cleaned_count = 0

        try:
            try:
                cleaned_count += self.session_store.cleanup_expired()
            except Exception:
                pass

            if self.fallback_session_store is not None:
                cleaned_count += self.fallback_session_store.cleanup_expired()

            self.last_cleanup = now
            return cleaned_count

        except Exception:
            return 0

    def on_user_created(self, user_id: Any, user_info: Dict[str, Any]) -> None:
        """Hook for subclasses to attach domain-specific behavior."""


__all__ = ["AuthServiceBase"]
