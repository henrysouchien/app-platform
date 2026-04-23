"""Per-user session state for the gateway proxy."""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any, Callable, Optional, Protocol

import httpx
from fastapi import HTTPException

_INIT_PASSTHROUGH_ERRORS = frozenset(
    {
        "credentials_unavailable",
        "credentials_timeout",
        "strict_mode_default_user",
    }
)


def _consumer_key_hash(api_key: str) -> str:
    """Return a short stable hash for gateway consumer-key rotation checks."""

    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]


class TokenStore(Protocol):
    """Protocol for pluggable gateway session token storage."""

    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str) -> None: ...
    def delete(self, key: str) -> None: ...
    def clear(self) -> None: ...


class InMemoryTokenStore:
    """Default in-memory token store backed by a plain dict."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def clear(self) -> None:
        self._data.clear()


class GatewaySessionManager:
    """Manage per-user gateway tokens and chat stream locks."""

    def __init__(self, token_store: TokenStore | None = None) -> None:
        self._token_store: TokenStore = (
            token_store if token_store is not None else InMemoryTokenStore()
        )
        self._consumer_hashes: dict[str, str] = {}
        self._stream_locks: dict[str, asyncio.Lock] = {}
        self._state_lock = asyncio.Lock()

    @staticmethod
    def _token_key(user_key: str, conversation_id: str | None = None) -> str:
        """Build a composite key for per-conversation state."""

        if conversation_id:
            return f"{user_key}:t:{conversation_id}"
        return user_key

    async def get_token(
        self,
        user_key: str,
        client: httpx.AsyncClient,
        api_key_fn: Callable[[], str],
        gateway_url_fn: Callable[[], str],
        force_refresh: bool = False,
        conversation_id: str | None = None,
        channel: str | None = None,
        user_email: str | None = None,
    ) -> str:
        """Resolve or refresh a gateway session token."""

        token_key = self._token_key(user_key, conversation_id)
        api_key = api_key_fn()
        consumer_hash = _consumer_key_hash(api_key)
        if self._consumer_hashes.get(token_key) != consumer_hash:
            force_refresh = True

        token = None if force_refresh else self._token_store.get(token_key)
        if token:
            return token

        token = await self._initialize_session(
            client=client,
            api_key=api_key,
            gateway_url=gateway_url_fn(),
            user_id=user_key,
            channel=channel,
            user_email=user_email,
        )
        self._token_store.set(token_key, token)
        self._consumer_hashes[token_key] = consumer_hash
        return token

    async def get_stream_lock(
        self, user_key: str, conversation_id: str | None = None
    ) -> asyncio.Lock:
        """Return the per-user or per-conversation chat stream lock."""

        async with self._state_lock:
            lock_key = self._token_key(user_key, conversation_id)
            lock = self._stream_locks.get(lock_key)
            if lock is None:
                lock = asyncio.Lock()
                self._stream_locks[lock_key] = lock
            return lock

    def invalidate_token(self, user_key: str, conversation_id: str | None = None) -> None:
        """Drop any cached gateway session token for the user or conversation."""

        token_key = self._token_key(user_key, conversation_id)
        self._token_store.delete(token_key)
        self._consumer_hashes.pop(token_key, None)

    def lookup_token(self, user_key: str, conversation_id: str | None = None) -> str | None:
        """Look up a cached token without auto-initializing."""

        return self._token_store.get(self._token_key(user_key, conversation_id))

    def reset(self) -> None:
        """Reset cached state without replacing existing containers when possible."""

        self._token_store.clear()
        self._consumer_hashes.clear()
        self._stream_locks.clear()

    async def _initialize_session(
        self,
        client: httpx.AsyncClient,
        api_key: str,
        gateway_url: str,
        user_id: str | None = None,
        channel: str | None = None,
        user_email: str | None = None,
    ) -> str:
        """Create a new gateway session token via API key auth."""

        init_payload = {"api_key": api_key}
        if user_id is not None:
            init_payload["user_id"] = user_id
        if user_email is not None:
            init_payload["user_email"] = user_email
        if channel:
            init_payload["context"] = {"channel": str(channel)}

        response = await client.post(
            f"{gateway_url}/api/chat/init",
            json=init_payload,
        )
        if response.status_code != 200:
            try:
                error_body = response.json()
            except ValueError:
                error_body = None
            if (
                isinstance(error_body, dict)
                and error_body.get("error") in _INIT_PASSTHROUGH_ERRORS
            ):
                raise HTTPException(status_code=response.status_code, detail=error_body)
            raise HTTPException(
                status_code=502,
                detail=f"Gateway session init failed ({response.status_code})",
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise HTTPException(
                status_code=502,
                detail="Gateway session init returned non-JSON response",
            ) from exc

        token = self._extract_session_token(payload if isinstance(payload, dict) else {})
        if not token:
            raise HTTPException(
                status_code=502,
                detail="Gateway session init response missing session token",
            )
        return token

    def _extract_session_token(self, payload: dict[str, Any]) -> Optional[str]:
        """Extract a session token from the init payload."""

        token = payload.get("session_token") or payload.get("token")
        if token:
            return str(token)

        session = payload.get("session")
        if isinstance(session, dict):
            nested = session.get("session_token") or session.get("token")
            if nested:
                return str(nested)

        return None


__all__ = ["GatewaySessionManager", "InMemoryTokenStore", "TokenStore"]
