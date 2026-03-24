from __future__ import annotations

import asyncio
import socket
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
import uvicorn

from app_platform.gateway import GatewayConfig, create_gateway_router


def _build_app(
    handler,
    user_by_session=None,
    config: GatewayConfig | None = None,
    http_client_factory=None,
):
    transport = httpx.MockTransport(handler)

    def get_current_user(request: Request) -> dict:
        session_id = request.cookies.get("session_id")
        user = (
            user_by_session(session_id)
            if user_by_session is not None
            else {"user_id": 101, "email": "test@example.com", "tier": "paid"}
        )
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")
        return user

    router = create_gateway_router(
        config=config
        or GatewayConfig(
            gateway_url="http://gateway.local",
            api_key="gateway-api-key",
            ssl_verify=True,
        ),
        get_current_user=get_current_user,
        http_client_factory=http_client_factory
        or (lambda: httpx.AsyncClient(transport=transport)),
    )

    app = FastAPI()
    app.include_router(router, prefix="/api/gateway")
    return app, router


def _chat_payload() -> dict:
    return {
        "messages": [{"role": "user", "content": "hello"}],
        "context": {"portfolio_name": "Main Portfolio"},
    }


def _sse_response(payload: bytes) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        stream=httpx.ByteStream(payload),
    )


def test_registered_user_chat_requires_paid_tier() -> None:
    calls = {"init": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(
        handler,
        user_by_session=lambda _session_id: {
            "user_id": 101,
            "email": "registered@example.com",
            "tier": "registered",
        },
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "context": {"portfolio_name": "Main Portfolio", "purpose": "chat"},
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 403
    assert response.json() == {
        "detail": {
            "error": "upgrade_required",
            "message": "AI chat requires a paid subscription.",
            "tier_required": "paid",
            "tier_current": "registered",
        }
    }
    assert calls["init"] == 0


def test_registered_user_normalizer_purpose_is_allowed() -> None:
    calls = {"init": 0, "chat": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            calls["chat"] += 1
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(
        handler,
        user_by_session=lambda _session_id: {
            "user_id": 101,
            "email": "registered@example.com",
            "tier": "registered",
        },
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "context": {"portfolio_name": "Main Portfolio", "purpose": "normalizer"},
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert calls == {"init": 1, "chat": 1}


def _unused_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@asynccontextmanager
async def _serve_app(app: FastAPI):
    port = _unused_tcp_port()
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host="127.0.0.1",
            port=port,
            log_level="warning",
            lifespan="off",
        )
    )
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        if not server.started:
            raise AssertionError("Uvicorn test server did not start")
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        await asyncio.wait_for(task, timeout=5)


class _StalledStream(httpx.AsyncByteStream):
    def __init__(self) -> None:
        self.started = asyncio.Event()
        self.closed = asyncio.Event()
        self._release = asyncio.Event()

    async def __aiter__(self):
        self.started.set()
        await self._release.wait()
        if False:
            yield b""

    async def aclose(self) -> None:
        self.closed.set()
        self._release.set()


def test_disconnect_during_stalled_stream_releases_lock_and_refreshes_session_token(
    monkeypatch,
) -> None:
    disconnect_state: dict[str, asyncio.Event | None] = {"event": None}
    real_is_disconnected = Request.is_disconnected

    async def fake_is_disconnected(self: Request) -> bool:
        event = disconnect_state["event"]
        if event is not None and self.url.path.endswith("/api/gateway/chat"):
            return event.is_set()
        return await real_is_disconnected(self)

    monkeypatch.setattr(Request, "is_disconnected", fake_is_disconnected)

    async def run() -> None:
        disconnect_requested = asyncio.Event()
        disconnect_state["event"] = disconnect_requested
        stalled_stream = _StalledStream()
        calls = {"init": 0, "chat_auth": []}

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/chat/init":
                calls["init"] += 1
                return httpx.Response(200, json={"session_token": f"token-{calls['init']}"})

            if request.url.path == "/api/chat":
                authorization = request.headers.get("authorization")
                calls["chat_auth"].append(authorization)
                if authorization == "Bearer token-1" and len(calls["chat_auth"]) == 1:
                    return httpx.Response(
                        200,
                        headers={"content-type": "text/event-stream"},
                        stream=stalled_stream,
                    )
                if authorization == "Bearer token-1":
                    return httpx.Response(409, content="stream active")
                if authorization == "Bearer token-2":
                    return _sse_response(b'data: {"type":"stream_complete"}\n\n')
                raise AssertionError(f"Unexpected authorization header: {authorization}")

            raise AssertionError(f"Unexpected path: {request.url.path}")

        app, router = _build_app(handler)
        async with _serve_app(app) as base_url:
            async with httpx.AsyncClient(
                base_url=base_url,
                timeout=httpx.Timeout(10.0, read=None),
            ) as client:
                headers = {"cookie": "session_id=s-1"}
                async with client.stream(
                    "POST",
                    "/api/gateway/chat",
                    headers=headers,
                    json=_chat_payload(),
                ) as response:
                    assert response.status_code == 200
                    await asyncio.wait_for(stalled_stream.started.wait(), timeout=2)
                    disconnect_requested.set()
                    await asyncio.wait_for(stalled_stream.closed.wait(), timeout=5)

                    user_lock = await router._session_manager.get_stream_lock("101")
                    for _ in range(100):
                        if not user_lock.locked() and "101" not in router._session_manager._tokens:
                            break
                        await asyncio.sleep(0.05)

                    assert not user_lock.locked()
                    assert "101" not in router._session_manager._tokens

                disconnect_requested.clear()
                second = await client.post(
                    "/api/gateway/chat",
                    headers=headers,
                    json=_chat_payload(),
                )

        disconnect_state["event"] = None

        assert second.status_code == 200
        assert calls["init"] == 2
        assert calls["chat_auth"] == ["Bearer token-1", "Bearer token-2"]

    asyncio.run(run())
