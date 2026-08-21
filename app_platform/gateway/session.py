"""Per-user session state for the gateway proxy."""

from __future__ import annotations

import asyncio
import hashlib
from collections import OrderedDict
from typing import Any, Callable, Optional, Protocol
from uuid import uuid4

import httpx
from fastapi import HTTPException

from .subject_assertion import (
    GatewaySubjectAssertionIssuer,
    load_subject_assertion_issuer,
)

_INIT_PASSTHROUGH_ERRORS = frozenset(
    {
        "auth_failed",
        "channel_mismatch",
        "credential_resolver_invalid",
        "credentials_unavailable",
        "credentials_timeout",
        "missing_user_id",
        "strict_mode_default_user",
    }
)
_CHAT_INIT_PATH = "/api/chat/init"
_CONTROL_INIT_PATH = "/api/control/session"
_MAX_SESSION_STATE_ENTRIES = 256


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

    def __init__(
        self,
        token_store: TokenStore | None = None,
        *,
        max_session_state_entries: int = _MAX_SESSION_STATE_ENTRIES,
        subject_assertion_issuer: GatewaySubjectAssertionIssuer | None = None,
    ) -> None:
        self._token_store: TokenStore = (
            token_store if token_store is not None else InMemoryTokenStore()
        )
        self._max_session_state_entries = max(1, int(max_session_state_entries))
        self._subject_assertion_issuer = (
            subject_assertion_issuer
            if subject_assertion_issuer is not None
            else load_subject_assertion_issuer(required=False)
        )
        self._consumer_hashes: dict[str, str] = {}
        self._session_ids: dict[str, str] = {}
        self._token_locks: dict[str, asyncio.Lock] = {}
        self._stream_locks: dict[str, asyncio.Lock] = {}
        self._token_recency: OrderedDict[str, None] = OrderedDict()
        self._stream_lock_recency: OrderedDict[str, None] = OrderedDict()
        self._state_lock = asyncio.Lock()
        # Eligibility is principal/session scoped; never share choices across users.
        self._capability_choices: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _token_key(user_key: str, conversation_id: str | None = None) -> str:
        """Build a composite key for per-conversation state."""

        if conversation_id:
            return f"{user_key}:t:{conversation_id}"
        return user_key

    @staticmethod
    def _control_token_key(user_key: str) -> str:
        """Build a separate token key for the control-plane session."""

        return f"{user_key}:control"

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
        self._touch_token_key(token_key)
        self._evict_idle_token_state(protected_key=token_key)
        api_key = api_key_fn()
        consumer_hash = _consumer_key_hash(api_key)
        cached_token_before_lock = self._token_store.get(token_key)
        if self._consumer_hashes.get(token_key) != consumer_hash:
            force_refresh = True

        token = None if force_refresh else cached_token_before_lock
        if token:
            return token

        token_lock = await self._get_token_lock(token_key)
        async with token_lock:
            current_token = self._token_store.get(token_key)
            current_hash = self._consumer_hashes.get(token_key)
            needs_refresh = force_refresh or current_hash != consumer_hash

            if current_token and current_hash == consumer_hash:
                if not needs_refresh or current_token != cached_token_before_lock:
                    return current_token

            token, session_id, capability_choices = await self._initialize_session_state(
                client=client,
                api_key=api_key,
                gateway_url=gateway_url_fn(),
                user_id=user_key,
                channel=channel,
                user_email=user_email,
                init_path=_CHAT_INIT_PATH,
            )
            self._token_store.set(token_key, token)
            if session_id:
                self._session_ids[token_key] = session_id
            else:
                self._session_ids.pop(token_key, None)
            if capability_choices is not None:
                self._capability_choices[token_key] = capability_choices
            else:
                self._capability_choices.pop(token_key, None)
            self._consumer_hashes[token_key] = consumer_hash
            self._touch_token_key(token_key)
            self._evict_idle_token_state(protected_key=token_key)
            return token

    def get_cached_capability_choices(
        self,
        user_key: str,
        conversation_id: str | None = None,
    ) -> dict[str, Any] | None:
        """Return choices only for the exact authenticated session key."""

        return self._capability_choices.get(self._token_key(user_key, conversation_id))

    async def ensure_capability_choices(
        self,
        user_key: str,
        client: httpx.AsyncClient,
        api_key_fn: Callable[[], str],
        gateway_url_fn: Callable[[], str],
        *,
        channel: str | None = None,
        user_email: str | None = None,
        force_refresh: bool = False,
    ) -> dict[str, Any] | None:
        """Ensure chat init has returned choices for this authenticated user."""

        token_key = self._token_key(user_key)
        if force_refresh:
            self._capability_choices.pop(token_key, None)
        cached = self._capability_choices.get(token_key)
        if cached is not None:
            return cached
        await self.get_token(
            user_key=user_key,
            client=client,
            api_key_fn=api_key_fn,
            gateway_url_fn=gateway_url_fn,
            force_refresh=True,
            channel=channel,
            user_email=user_email,
        )
        return self._capability_choices.get(token_key)

    async def get_control_token(
        self,
        user_key: str,
        client: httpx.AsyncClient,
        api_key_fn: Callable[[], str],
        gateway_url_fn: Callable[[], str],
        force_refresh: bool = False,
        channel: str | None = None,
        user_email: str | None = None,
    ) -> str:
        """Resolve or refresh a per-user gateway control-plane token."""

        token_key = self._control_token_key(user_key)
        self._touch_token_key(token_key)
        self._evict_idle_token_state(protected_key=token_key)
        api_key = api_key_fn()
        consumer_hash = _consumer_key_hash(api_key)
        cached_token_before_lock = self._token_store.get(token_key)
        if self._consumer_hashes.get(token_key) != consumer_hash:
            force_refresh = True

        token = None if force_refresh else cached_token_before_lock
        if token:
            return token

        token_lock = await self._get_token_lock(token_key)
        async with token_lock:
            current_token = self._token_store.get(token_key)
            current_hash = self._consumer_hashes.get(token_key)
            needs_refresh = force_refresh or current_hash != consumer_hash

            if current_token and current_hash == consumer_hash:
                if not needs_refresh or current_token != cached_token_before_lock:
                    return current_token

            token, session_id, _capability_choices = await self._initialize_session_state(
                client=client,
                api_key=api_key,
                gateway_url=gateway_url_fn(),
                user_id=user_key,
                channel=channel,
                user_email=user_email,
                init_path=_CONTROL_INIT_PATH,
            )
            self._token_store.set(token_key, token)
            if session_id:
                self._session_ids[token_key] = session_id
            else:
                self._session_ids.pop(token_key, None)
            self._consumer_hashes[token_key] = consumer_hash
            self._touch_token_key(token_key)
            self._evict_idle_token_state(protected_key=token_key)
            return token

    async def _get_token_lock(self, token_key: str) -> asyncio.Lock:
        """Return the lock used to single-flight token initialization."""

        async with self._state_lock:
            self._touch_token_key(token_key)
            lock = self._token_locks.get(token_key)
            if lock is None:
                lock = asyncio.Lock()
                self._token_locks[token_key] = lock
            self._evict_idle_token_state(protected_key=token_key)
            return lock

    async def get_stream_lock(
        self, user_key: str, conversation_id: str | None = None
    ) -> asyncio.Lock:
        """Return the per-user or per-conversation chat stream lock."""

        async with self._state_lock:
            lock_key = self._token_key(user_key, conversation_id)
            self._touch_stream_lock_key(lock_key)
            lock = self._stream_locks.get(lock_key)
            if lock is None:
                lock = asyncio.Lock()
                self._stream_locks[lock_key] = lock
            self._evict_idle_stream_locks(protected_key=lock_key)
            return lock

    def invalidate_token(self, user_key: str, conversation_id: str | None = None) -> None:
        """Drop any cached gateway session token for the user or conversation."""

        token_key = self._token_key(user_key, conversation_id)
        self._token_store.delete(token_key)
        self._consumer_hashes.pop(token_key, None)
        self._session_ids.pop(token_key, None)
        self._capability_choices.pop(token_key, None)
        self._token_recency.pop(token_key, None)
        token_lock = self._token_locks.get(token_key)
        if token_lock is None or not token_lock.locked():
            self._token_locks.pop(token_key, None)

    def invalidate_control_token(self, user_key: str) -> None:
        """Drop any cached gateway control-plane token for the user."""

        token_key = self._control_token_key(user_key)
        self._token_store.delete(token_key)
        self._consumer_hashes.pop(token_key, None)
        self._session_ids.pop(token_key, None)
        self._token_recency.pop(token_key, None)
        token_lock = self._token_locks.get(token_key)
        if token_lock is None or not token_lock.locked():
            self._token_locks.pop(token_key, None)

    def lookup_token(self, user_key: str, conversation_id: str | None = None) -> str | None:
        """Look up a cached token without auto-initializing."""

        token_key = self._token_key(user_key, conversation_id)
        token = self._token_store.get(token_key)
        if token is not None:
            self._touch_token_key(token_key)
            self._evict_idle_token_state(protected_key=token_key)
        return token

    def lookup_session_id(self, user_key: str, conversation_id: str | None = None) -> str | None:
        """Look up the cached upstream chat session id without auto-initializing."""

        token_key = self._token_key(user_key, conversation_id)
        session_id = self._session_ids.get(token_key)
        if session_id is not None:
            self._touch_token_key(token_key)
            self._evict_idle_token_state(protected_key=token_key)
        return session_id

    def reset(self) -> None:
        """Reset cached state without replacing existing containers when possible."""

        self._token_store.clear()
        self._consumer_hashes.clear()
        self._session_ids.clear()
        self._capability_choices.clear()
        self._token_locks.clear()
        self._stream_locks.clear()
        self._token_recency.clear()
        self._stream_lock_recency.clear()

    def _touch_token_key(self, token_key: str) -> None:
        """Mark token state as recently used for bounded idle eviction."""

        self._token_recency[token_key] = None
        self._token_recency.move_to_end(token_key)

    def _touch_stream_lock_key(self, lock_key: str) -> None:
        """Mark stream-lock state as recently used for bounded idle eviction."""

        self._stream_lock_recency[lock_key] = None
        self._stream_lock_recency.move_to_end(lock_key)

    def _evict_idle_token_state(self, *, protected_key: str | None = None) -> None:
        """Reclaim least-recently-used idle token state over the configured cap."""

        while len(self._token_recency) > self._max_session_state_entries:
            evicted = False
            for token_key in list(self._token_recency):
                if token_key == protected_key:
                    continue
                token_lock = self._token_locks.get(token_key)
                if token_lock is not None and token_lock.locked():
                    continue
                stream_lock = self._stream_locks.get(token_key)
                if stream_lock is not None and stream_lock.locked():
                    continue

                self._token_recency.pop(token_key, None)
                self._token_store.delete(token_key)
                self._consumer_hashes.pop(token_key, None)
                self._session_ids.pop(token_key, None)
                self._capability_choices.pop(token_key, None)
                self._token_locks.pop(token_key, None)
                evicted = True
                break
            if not evicted:
                return

    def _evict_idle_stream_locks(self, *, protected_key: str | None = None) -> None:
        """Reclaim least-recently-used stream locks without dropping held locks."""

        while len(self._stream_lock_recency) > self._max_session_state_entries:
            evicted = False
            for lock_key in list(self._stream_lock_recency):
                if lock_key == protected_key:
                    continue
                lock = self._stream_locks.get(lock_key)
                if lock is not None and lock.locked():
                    continue

                self._stream_lock_recency.pop(lock_key, None)
                self._stream_locks.pop(lock_key, None)
                evicted = True
                break
            if not evicted:
                return

    async def _initialize_session(
        self,
        client: httpx.AsyncClient,
        api_key: str,
        gateway_url: str,
        user_id: str | None = None,
        channel: str | None = None,
        user_email: str | None = None,
        init_path: str = _CHAT_INIT_PATH,
    ) -> str:
        """Create a new gateway session token via API key auth."""

        token, _session_id, _capability_choices = await self._initialize_session_state(
            client=client,
            api_key=api_key,
            gateway_url=gateway_url,
            user_id=user_id,
            channel=channel,
            user_email=user_email,
            init_path=init_path,
        )
        return token

    async def _initialize_session_state(
        self,
        client: httpx.AsyncClient,
        api_key: str,
        gateway_url: str,
        user_id: str | None = None,
        channel: str | None = None,
        user_email: str | None = None,
        init_path: str = _CHAT_INIT_PATH,
    ) -> tuple[str, str | None, dict[str, Any] | None]:
        """Create a new gateway session and retain its scoped eligible choices."""

        init_payload = {"api_key": api_key}
        if user_id is not None:
            init_payload["user_id"] = user_id
        if user_email is not None:
            init_payload["user_email"] = user_email
        if channel:
            init_payload["context"] = {"channel": str(channel)}
        if str(channel or "").strip().lower() == "web" and self._subject_assertion_issuer:
            request_id = str(uuid4())
            init_payload["request_id"] = request_id
            init_payload["subject_assertion"] = self._subject_assertion_issuer.issue(
                user_id=str(user_id or ""),
                email=user_email,
                request_id=request_id,
                channel="web",
            )

        try:
            # Bounded explicitly: the shared client disables the read timeout for
            # SSE streaming. This init POST runs while holding the per-user token
            # lock — an unbounded wait here silently parks every subsequent chat
            # send for the user (Lane H LH-13).
            response = await client.post(
                f"{gateway_url}{init_path}",
                json=init_payload,
                timeout=httpx.Timeout(10.0, read=20.0),
            )
        except httpx.TimeoutException as exc:
            raise HTTPException(
                status_code=504,
                detail={
                    "error": "gateway_session_init_timeout",
                    "message": "Gateway session init did not respond in time.",
                },
            ) from exc
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
        session_id = self._extract_session_id(payload if isinstance(payload, dict) else {})
        capability_choices = None
        if init_path == _CHAT_INIT_PATH and isinstance(payload, dict):
            capability_choices = self._extract_capability_choices(payload)
        return token, session_id, capability_choices

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

    def _extract_session_id(self, payload: dict[str, Any]) -> Optional[str]:
        """Extract the gateway session id from the init payload when present."""

        session_id = payload.get("session_id")
        if session_id:
            return str(session_id)

        session = payload.get("session")
        if isinstance(session, dict):
            nested = session.get("session_id")
            if nested:
                return str(nested)

        return None

    @staticmethod
    def _extract_capability_choices(payload: dict[str, Any]) -> dict[str, Any] | None:
        """Extract the closed capability-choice map from authenticated init."""

        raw = payload.get("capability_choices")
        if not isinstance(raw, dict):
            return None
        return dict(raw)


__all__ = ["GatewaySessionManager", "InMemoryTokenStore", "TokenStore"]
