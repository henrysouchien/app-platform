"""CSRF protection middleware for cookie-authenticated browser requests."""

from __future__ import annotations

import hmac
import secrets
import time
from hashlib import sha256
from http.cookies import CookieError, SimpleCookie
from typing import Iterable

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
DEFAULT_CSRF_MAX_AGE_SECONDS = 12 * 60 * 60
DEFAULT_CSRF_EXEMPT_PATHS = frozenset(
    {
        "/api/csrf-token",
        "/auth/google",
        "/auth/dev-login",
        "/plaid/webhook",
        "/api/snaptrade/webhook",
        "/api/billing/webhooks/stripe",
        "/api/log-frontend",
    }
)
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


def _session_fingerprint(session_id: str) -> str:
    return sha256(session_id.encode("utf-8")).hexdigest()


def _signature(secret_key: str, token: str, session_id: str, timestamp: int) -> str:
    payload = f"{token}|{_session_fingerprint(session_id)}|{timestamp}".encode("utf-8")
    return hmac.new(secret_key.encode("utf-8"), payload, sha256).hexdigest()


def sign_csrf_token(secret_key: str, token: str, session_id: str, timestamp: int | None = None) -> str:
    """Return the signed cookie payload for a CSRF token."""
    timestamp = int(time.time()) if timestamp is None else timestamp
    signature = _signature(secret_key, token, session_id, timestamp)
    return f"{token}.{_session_fingerprint(session_id)}.{timestamp}.{signature}"


def _parse_signed_token(signed_token: str) -> tuple[str, str, int, str] | None:
    parts = signed_token.split(".")
    if len(parts) != 4:
        return None

    cookie_header_token, cookie_session_fingerprint, timestamp_text, supplied_signature = parts
    try:
        timestamp = int(timestamp_text)
    except ValueError:
        return None

    return cookie_header_token, cookie_session_fingerprint, timestamp, supplied_signature


def _validate_signed_token(
    *,
    secret_key: str,
    signed_token: str,
    expected_header_token: str,
    session_id: str,
    max_age_seconds: int,
    now: int | None,
) -> bool:
    parsed = _parse_signed_token(signed_token)
    if not parsed:
        return False

    cookie_header_token, cookie_session_fingerprint, timestamp, supplied_signature = parsed
    if not hmac.compare_digest(expected_header_token, cookie_header_token):
        return False

    if not hmac.compare_digest(cookie_session_fingerprint, _session_fingerprint(session_id)):
        return False

    now = int(time.time()) if now is None else now
    if timestamp > now + 60 or now - timestamp > max_age_seconds:
        return False

    expected_signature = _signature(secret_key, cookie_header_token, session_id, timestamp)
    return hmac.compare_digest(supplied_signature, expected_signature)


def validate_csrf_token(
    *,
    secret_key: str,
    header_token: str | None,
    cookie_token: str | None,
    session_id: str,
    max_age_seconds: int = DEFAULT_CSRF_MAX_AGE_SECONDS,
    now: int | None = None,
) -> bool:
    """Validate a CSRF header token against the current browser session."""
    if not header_token:
        return False

    signed_header = _parse_signed_token(header_token)
    if signed_header:
        return _validate_signed_token(
            secret_key=secret_key,
            signed_token=header_token,
            expected_header_token=signed_header[0],
            session_id=session_id,
            max_age_seconds=max_age_seconds,
            now=now,
        )

    if not cookie_token:
        return False

    return _validate_signed_token(
        secret_key=secret_key,
        signed_token=cookie_token,
        expected_header_token=header_token,
        session_id=session_id,
        max_age_seconds=max_age_seconds,
        now=now,
    )


def _token_from_valid_cookie(
    *,
    secret_key: str,
    cookie_token: str | None,
    session_id: str,
    max_age_seconds: int,
) -> str | None:
    if not cookie_token:
        return None

    parsed = _parse_signed_token(cookie_token)
    if not parsed:
        return None

    header_token = parsed[0]
    if validate_csrf_token(
        secret_key=secret_key,
        header_token=header_token,
        cookie_token=cookie_token,
        session_id=session_id,
        max_age_seconds=max_age_seconds,
    ):
        return header_token

    return None


def create_csrf_token_response(
    request: Request,
    *,
    secret_key: str,
    secure_cookie: bool = False,
    cookie_name: str = CSRF_COOKIE_NAME,
    max_age_seconds: int = DEFAULT_CSRF_MAX_AGE_SECONDS,
) -> JSONResponse:
    """Issue a CSRF token bound to the current session cookie."""
    session_id = request.cookies.get("session_id", "")
    cookie_token = request.cookies.get(cookie_name)
    token = _token_from_valid_cookie(
        secret_key=secret_key,
        cookie_token=cookie_token,
        session_id=session_id,
        max_age_seconds=max_age_seconds,
    )
    signed_token = cookie_token if token and cookie_token else None

    if not token or not signed_token:
        token = secrets.token_urlsafe(32)
        signed_token = sign_csrf_token(secret_key, token, session_id)

    response = JSONResponse({"csrf_token": signed_token})
    response.set_cookie(
        cookie_name,
        signed_token,
        max_age=max_age_seconds,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        path="/",
    )
    return response


class CsrfProtectionMiddleware:
    """Require CSRF tokens on unsafe requests that carry the session cookie."""

    def __init__(
        self,
        app: ASGIApp,
        *,
        secret_key: str,
        cookie_name: str = CSRF_COOKIE_NAME,
        header_name: str = CSRF_HEADER_NAME,
        session_cookie_name: str = "session_id",
        exempt_paths: Iterable[str] = DEFAULT_CSRF_EXEMPT_PATHS,
        max_age_seconds: int = DEFAULT_CSRF_MAX_AGE_SECONDS,
    ) -> None:
        self.app = app
        self.secret_key = secret_key
        self.cookie_name = cookie_name
        self.header_name = header_name
        self.session_cookie_name = session_cookie_name
        self.exempt_paths = set(exempt_paths)
        self.max_age_seconds = max_age_seconds

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        method = scope.get("method", "GET").upper()
        path = scope.get("path", "")
        if method not in UNSAFE_METHODS or path in self.exempt_paths:
            await self.app(scope, receive, send)
            return

        headers = Headers(scope=scope)
        cookies = self._parse_cookies(headers.get("cookie", ""))
        session_id = cookies.get(self.session_cookie_name)
        if not session_id:
            await self.app(scope, receive, send)
            return

        if validate_csrf_token(
            secret_key=self.secret_key,
            header_token=headers.get(self.header_name),
            cookie_token=cookies.get(self.cookie_name),
            session_id=session_id,
            max_age_seconds=self.max_age_seconds,
        ):
            await self.app(scope, receive, send)
            return

        response = JSONResponse(
            {"detail": "CSRF token missing or invalid", "error": "csrf_failed"},
            status_code=403,
        )
        await response(scope, receive, send)

    @staticmethod
    def _parse_cookies(cookie_header: str) -> dict[str, str]:
        parsed = SimpleCookie()
        try:
            parsed.load(cookie_header)
        except CookieError:
            return {}
        return {key: morsel.value for key, morsel in parsed.items()}


__all__ = [
    "CSRF_COOKIE_NAME",
    "CSRF_HEADER_NAME",
    "DEFAULT_CSRF_EXEMPT_PATHS",
    "DEFAULT_CSRF_MAX_AGE_SECONDS",
    "CsrfProtectionMiddleware",
    "create_csrf_token_response",
    "sign_csrf_token",
    "validate_csrf_token",
]
