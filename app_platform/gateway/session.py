"""Per-user session state for the gateway proxy."""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Optional

import httpx
from fastapi import HTTPException


class GatewaySessionManager:
    """Manage per-user gateway tokens and chat stream locks."""

    def __init__(self) -> None:
        self._tokens: dict[str, str] = {}
        self._stream_locks: dict[str, asyncio.Lock] = {}
        self._state_lock = asyncio.Lock()

    async def get_token(
        self,
        user_key: str,
        client: httpx.AsyncClient,
        api_key_fn: Callable[[], str],
        gateway_url_fn: Callable[[], str],
        force_refresh: bool = False,
    ) -> str:
        """Resolve or refresh a per-user gateway session token."""

        token = None if force_refresh else self._tokens.get(user_key)
        if token:
            return token

        token = await self._initialize_session(
            client=client,
            api_key=api_key_fn(),
            gateway_url=gateway_url_fn(),
        )
        self._tokens[user_key] = token
        return token

    async def get_stream_lock(self, user_key: str) -> asyncio.Lock:
        """Return the per-user chat stream lock."""

        async with self._state_lock:
            lock = self._stream_locks.get(user_key)
            if lock is None:
                lock = asyncio.Lock()
                self._stream_locks[user_key] = lock
            return lock

    def invalidate_token(self, user_key: str) -> None:
        """Drop any cached gateway session token for the user."""

        self._tokens.pop(user_key, None)

    def reset(self) -> None:
        """Reset in-memory state without replacing dict objects."""

        self._tokens.clear()
        self._stream_locks.clear()

    async def _initialize_session(
        self,
        client: httpx.AsyncClient,
        api_key: str,
        gateway_url: str,
    ) -> str:
        """Create a new gateway session token via API key auth."""

        response = await client.post(
            f"{gateway_url}/api/chat/init",
            json={"api_key": api_key},
        )
        if response.status_code != 200:
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


__all__ = ["GatewaySessionManager"]
