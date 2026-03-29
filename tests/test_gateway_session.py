from __future__ import annotations

import asyncio

import httpx

from app_platform.gateway.session import GatewaySessionManager


class FalsyTokenStore:
    """A valid store that is falsy (empty container). Guards against `or` regression."""

    def __init__(self) -> None:
        self._data: dict[str, str] = {}

    def __bool__(self) -> bool:
        return False

    def get(self, key: str) -> str | None:
        return self._data.get(key)

    def set(self, key: str, value: str) -> None:
        self._data[key] = value

    def delete(self, key: str) -> None:
        self._data.pop(key, None)

    def clear(self) -> None:
        self._data.clear()


def test_gateway_session_manager_caches_tokens_per_user_key() -> None:
    manager = GatewaySessionManager()
    calls = {"init": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["init"] += 1
        return httpx.Response(200, json={"session_token": f"token-{calls['init']}"})

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            first = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
            )
            second = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
            )
            third = await manager.get_token(
                user_key="user-2",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
            )

            assert first == "token-1"
            assert second == "token-1"
            assert third == "token-2"
            assert calls["init"] == 2
        finally:
            await client.aclose()

    asyncio.run(run())


def test_gateway_session_manager_accepts_custom_token_store() -> None:
    store = FalsyTokenStore()
    manager = GatewaySessionManager(token_store=store)

    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"session_token": "token-1"})

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            token = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
            )

            assert token == "token-1"
            assert store.get("user-1") == "token-1"
            assert manager._token_store is store
        finally:
            await client.aclose()

    asyncio.run(run())


def test_gateway_session_manager_returns_per_user_stream_locks() -> None:
    manager = GatewaySessionManager()

    async def run() -> None:
        first = await manager.get_stream_lock("user-1")
        second = await manager.get_stream_lock("user-1")
        third = await manager.get_stream_lock("user-2")

        assert first is second
        assert first is not third

    asyncio.run(run())


def test_gateway_session_manager_lookup_token() -> None:
    manager = GatewaySessionManager()

    assert manager.lookup_token("user-1") is None
    manager._token_store.set("user-1", "tok-1")
    assert manager.lookup_token("user-1") == "tok-1"


def test_gateway_session_manager_reset_clears_state_in_place() -> None:
    manager = GatewaySessionManager()
    store = manager._token_store
    locks = manager._stream_locks

    async def run() -> None:
        manager._token_store.set("user-1", "token-1")
        manager._stream_locks["user-1"] = await manager.get_stream_lock("user-1")

    asyncio.run(run())

    manager.reset()

    assert manager._token_store is store
    assert manager._stream_locks is locks
    assert manager.lookup_token("user-1") is None
    assert manager._stream_locks == {}


def test_gateway_session_manager_force_refresh_updates_cached_token() -> None:
    manager = GatewaySessionManager()
    calls = {"init": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["init"] += 1
        if calls["init"] == 1:
            return httpx.Response(200, json={"session": {"token": "token-1"}})
        return httpx.Response(200, json={"session": {"session_token": "token-2"}})

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            first = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
            )
            second = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
                force_refresh=True,
            )

            assert first == "token-1"
            assert second == "token-2"
            assert manager.lookup_token("user-1") == "token-2"
            assert calls["init"] == 2
        finally:
            await client.aclose()

    asyncio.run(run())
