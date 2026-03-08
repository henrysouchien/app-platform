"""Google OAuth token verification for app_platform.auth."""

from __future__ import annotations

from typing import Any, Dict, Optional

from google.auth.transport import requests as google_requests
from google.oauth2 import id_token


class GoogleTokenVerifier:
    """TokenVerifier implementation backed by google-auth."""

    def __init__(
        self,
        client_id: Optional[str],
        dev_mode: bool = False,
        dev_user: Optional[Dict[str, Any]] = None,
    ):
        self.client_id = client_id
        self.dev_mode = dev_mode
        self.dev_user = dev_user or {
            "user_id": "dev_user_123",
            "email": "dev@example.com",
            "name": "Development User",
            "google_user_id": "dev_google_123",
        }

    def verify(self, token: str) -> tuple[Optional[Dict[str, Any]], Optional[str]]:
        try:
            if self.dev_mode or not self.client_id:
                return dict(self.dev_user), None

            id_info = id_token.verify_oauth2_token(
                token,
                google_requests.Request(),
                self.client_id,
            )
            return {
                "user_id": id_info["sub"],
                "email": id_info["email"],
                "name": id_info.get("name", ""),
                "google_user_id": id_info["sub"],
            }, None

        except Exception as exc:
            return None, f"Google token verification failed: {exc}"


__all__ = ["GoogleTokenVerifier"]
