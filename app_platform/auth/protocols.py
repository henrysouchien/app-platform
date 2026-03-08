"""Protocol contracts for app_platform.auth."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, Protocol, runtime_checkable


@runtime_checkable
class SessionStore(Protocol):
    """Backend contract for session persistence."""

    def create_session(self, session_id: str, user_id: Any, expires_at: datetime) -> None:
        """Persist a new session."""

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Resolve a session id to the normalized auth payload."""

    def delete_session(self, session_id: str) -> bool:
        """Delete a session if present."""

    def cleanup_expired(self) -> int:
        """Delete expired sessions and return the cleanup count."""

    def touch_session(self, session_id: str) -> None:
        """Update last-accessed metadata for a session."""


@runtime_checkable
class UserStore(Protocol):
    """Backend contract for user persistence."""

    def get_or_create_user(
        self,
        provider_user_id: str,
        email: str,
        name: str,
    ) -> tuple[Any, Dict[str, Any]]:
        """Return the resolved user id and normalized user payload."""


@runtime_checkable
class TokenVerifier(Protocol):
    """Contract for OAuth/OIDC token verification."""

    def verify(self, token: str) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        """Validate a provider token and return either user info or an error."""


__all__ = ["SessionStore", "TokenVerifier", "UserStore"]
