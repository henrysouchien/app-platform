from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from fastapi import HTTPException

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


def test_gateway_session_manager_conversation_locks_are_independent() -> None:
    manager = GatewaySessionManager()

    async def run() -> None:
        per_user = await manager.get_stream_lock("user-1")
        per_user_again = await manager.get_stream_lock("user-1", None)
        thread_one = await manager.get_stream_lock("user-1", "thread-1")
        thread_one_again = await manager.get_stream_lock("user-1", "thread-1")
        thread_two = await manager.get_stream_lock("user-1", "thread-2")

        assert per_user is per_user_again
        assert thread_one is thread_one_again
        assert thread_one is not thread_two
        assert per_user is not thread_one

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


def test_gateway_session_manager_conversation_tokens_are_independent() -> None:
    manager = GatewaySessionManager()
    calls = {"init": 0, "payloads": []}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["init"] += 1
        calls["payloads"].append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"session_token": f"token-{calls['init']}"})

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            per_user = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
            )
            thread_one = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
                conversation_id="thread-1",
            )
            thread_one_again = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
                conversation_id="thread-1",
            )
            thread_two = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
                conversation_id="thread-2",
            )

            assert per_user == "token-1"
            assert thread_one == "token-2"
            assert thread_one_again == "token-2"
            assert thread_two == "token-3"
            assert manager.lookup_token("user-1") == "token-1"
            assert manager.lookup_token("user-1", "thread-1") == "token-2"
            assert manager.lookup_token("user-1", "thread-2") == "token-3"
            assert calls["init"] == 3
        finally:
            await client.aclose()

    asyncio.run(run())

    assert calls["payloads"] == [
        {"api_key": "api-key", "user_id": "user-1"},
        {"api_key": "api-key", "user_id": "user-1"},
        {"api_key": "api-key", "user_id": "user-1"},
    ]


def test_gateway_session_manager_invalidate_scoped_to_conversation() -> None:
    manager = GatewaySessionManager()
    calls = {"init": 0}

    async def handler(_request: httpx.Request) -> httpx.Response:
        calls["init"] += 1
        return httpx.Response(200, json={"session_token": f"token-{calls['init']}"})

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            per_user = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
            )
            thread_one = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
                conversation_id="thread-1",
            )
            thread_two = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "api-key",
                gateway_url_fn=lambda: "http://gateway.local",
                conversation_id="thread-2",
            )

            manager.invalidate_token("user-1", "thread-1")

            assert per_user == "token-1"
            assert thread_one == "token-2"
            assert thread_two == "token-3"
            assert manager.lookup_token("user-1") == "token-1"
            assert manager.lookup_token("user-1", "thread-1") is None
            assert manager.lookup_token("user-1", "thread-2") == "token-3"
        finally:
            await client.aclose()

    asyncio.run(run())


def test_consumer_hash_mismatch_forces_refresh() -> None:
    manager = GatewaySessionManager()
    calls = {"init": 0}
    key_state = {"api_key": "key-A"}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["init"] += 1
        return httpx.Response(200, json={"session_token": f"token-{calls['init']}"})

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            first = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: key_state["api_key"],
                gateway_url_fn=lambda: "http://gateway.local",
            )
            key_state["api_key"] = "key-B"
            second = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: key_state["api_key"],
                gateway_url_fn=lambda: "http://gateway.local",
            )

            assert first == "token-1"
            assert second == "token-2"
            assert manager.lookup_token("user-1") == "token-2"
            assert calls["init"] == 2
        finally:
            await client.aclose()

    asyncio.run(run())


def test_consumer_hash_match_reuses_token() -> None:
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
                api_key_fn=lambda: "key-A",
                gateway_url_fn=lambda: "http://gateway.local",
            )
            second = await manager.get_token(
                user_key="user-1",
                client=client,
                api_key_fn=lambda: "key-A",
                gateway_url_fn=lambda: "http://gateway.local",
            )

            assert first == "token-1"
            assert second == "token-1"
            assert calls["init"] == 1
        finally:
            await client.aclose()

    asyncio.run(run())


def test_initialize_session_sends_user_id_top_level() -> None:
    manager = GatewaySessionManager()
    captured: list[dict[str, str]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.append(json.loads(request.content.decode("utf-8")))
        return httpx.Response(200, json={"session_token": f"token-{len(captured)}"})

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            without_user = await manager._initialize_session(
                client=client,
                api_key="api-key",
                gateway_url="http://gateway.local",
            )
            with_user = await manager._initialize_session(
                client=client,
                api_key="api-key",
                gateway_url="http://gateway.local",
                user_id="user-1",
            )

            assert without_user == "token-1"
            assert with_user == "token-2"
        finally:
            await client.aclose()

    asyncio.run(run())

    assert captured == [
        {"api_key": "api-key"},
        {"api_key": "api-key", "user_id": "user-1"},
    ]


def test_init_structured_error_credentials_unavailable() -> None:
    manager = GatewaySessionManager()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            401,
            json={"error": "credentials_unavailable", "user_id": "u1"},
        )

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            with pytest.raises(HTTPException) as exc_info:
                await manager._initialize_session(
                    client=client,
                    api_key="api-key",
                    gateway_url="http://gateway.local",
                    user_id="u1",
                )
        finally:
            await client.aclose()

        assert exc_info.value.status_code == 401
        assert exc_info.value.detail == {"error": "credentials_unavailable", "user_id": "u1"}

    asyncio.run(run())


def test_init_structured_error_credentials_timeout() -> None:
    manager = GatewaySessionManager()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            504,
            json={"error": "credentials_timeout", "timeout_seconds": 5.0},
        )

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            with pytest.raises(HTTPException) as exc_info:
                await manager._initialize_session(
                    client=client,
                    api_key="api-key",
                    gateway_url="http://gateway.local",
                    user_id="u1",
                )
        finally:
            await client.aclose()

        assert exc_info.value.status_code == 504
        assert exc_info.value.detail == {"error": "credentials_timeout", "timeout_seconds": 5.0}

    asyncio.run(run())


def test_init_structured_error_strict_mode() -> None:
    manager = GatewaySessionManager()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "strict_mode_default_user"})

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            with pytest.raises(HTTPException) as exc_info:
                await manager._initialize_session(
                    client=client,
                    api_key="api-key",
                    gateway_url="http://gateway.local",
                )
        finally:
            await client.aclose()

        assert exc_info.value.status_code == 400
        assert exc_info.value.detail == {"error": "strict_mode_default_user"}

    asyncio.run(run())


def test_init_unstructured_error_falls_back_502() -> None:
    manager = GatewaySessionManager()

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, content="gateway exploded")

    async def run() -> None:
        client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        try:
            with pytest.raises(HTTPException) as exc_info:
                await manager._initialize_session(
                    client=client,
                    api_key="api-key",
                    gateway_url="http://gateway.local",
                    user_id="u1",
                )
        finally:
            await client.aclose()

        assert exc_info.value.status_code == 502
        assert exc_info.value.detail == "Gateway session init failed (500)"

    asyncio.run(run())
