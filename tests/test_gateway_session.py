from __future__ import annotations

import asyncio

import httpx

from app_platform.gateway.session import GatewaySessionManager


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


def test_gateway_session_manager_returns_per_user_stream_locks() -> None:
    manager = GatewaySessionManager()

    async def run() -> None:
        first = await manager.get_stream_lock("user-1")
        second = await manager.get_stream_lock("user-1")
        third = await manager.get_stream_lock("user-2")

        assert first is second
        assert first is not third

    asyncio.run(run())


def test_gateway_session_manager_reset_clears_state_in_place() -> None:
    manager = GatewaySessionManager()
    tokens = manager._tokens
    locks = manager._stream_locks

    async def run() -> None:
        manager._tokens["user-1"] = "token-1"
        manager._stream_locks["user-1"] = await manager.get_stream_lock("user-1")

    asyncio.run(run())

    manager.reset()

    assert manager._tokens is tokens
    assert manager._stream_locks is locks
    assert manager._tokens == {}
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
            assert manager._tokens["user-1"] == "token-2"
            assert calls["init"] == 2
        finally:
            await client.aclose()

    asyncio.run(run())
