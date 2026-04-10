from __future__ import annotations

import json

import httpx
import pytest
from fastapi import APIRouter, FastAPI
from fastapi.testclient import TestClient

import routes.gateway_proxy as gateway_proxy


@pytest.fixture(autouse=True)
def _reset_proxy_state() -> None:
    gateway_proxy._reset_proxy_state_for_tests()
    yield
    gateway_proxy._reset_proxy_state_for_tests()


def _chat_payload() -> dict:
    return {
        "messages": [{"role": "user", "content": "hello"}],
        "context": {"portfolio_name": "Main Portfolio"},
    }


def test_gateway_proxy_shim_exports_legacy_surface() -> None:
    paths = {route.path for route in gateway_proxy.gateway_proxy_router.routes}

    assert isinstance(gateway_proxy.gateway_proxy_router, APIRouter)
    assert "/chat" in paths
    assert "/tool-approval" in paths
    assert callable(gateway_proxy._reset_proxy_state_for_tests)
    assert callable(gateway_proxy._create_http_client)
    assert isinstance(gateway_proxy._gateway_session_tokens, dict)
    assert isinstance(gateway_proxy._user_stream_locks, dict)
    assert gateway_proxy.auth_service is not None


def test_gateway_proxy_shim_reads_env_at_request_time(monkeypatch: pytest.MonkeyPatch) -> None:
    captured = {"verify": None, "init_payload": None, "chat_url": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            captured["init_payload"] = json.loads(request.content.decode("utf-8"))
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["chat_url"] = str(request.url)
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=httpx.ByteStream(b'data: {"type":"stream_complete"}\n\n'),
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    def fake_default_http_client_factory(ssl_verify):
        captured["verify"] = ssl_verify
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(gateway_proxy, "default_http_client_factory", fake_default_http_client_factory)
    monkeypatch.setattr(
        gateway_proxy.auth_service,
        "get_user_by_session",
        lambda session_id: {"user_id": 101, "email": "test@example.com", "tier": "paid"},
    )
    monkeypatch.setenv("GATEWAY_URL", "http://gateway.from.env")
    monkeypatch.setenv("GATEWAY_API_KEY", "env-api-key")
    monkeypatch.setenv("GATEWAY_SSL_VERIFY", "false")

    app = FastAPI()
    app.include_router(gateway_proxy.gateway_proxy_router, prefix="/api/gateway")

    with TestClient(app) as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert captured["verify"] is False
    assert captured["init_payload"] == {"api_key": "env-api-key", "user_id": "101"}
    assert captured["chat_url"] == "http://gateway.from.env/api/chat"


def test_gateway_proxy_shim_create_http_client_is_monkeypatchable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = {"factory_called": False}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                stream=httpx.ByteStream(b'data: {"type":"stream_complete"}\n\n'),
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    def fake_create_http_client():
        captured["factory_called"] = True
        return httpx.AsyncClient(transport=httpx.MockTransport(handler))

    monkeypatch.setattr(gateway_proxy, "_create_http_client", fake_create_http_client)
    monkeypatch.setattr(
        gateway_proxy.auth_service,
        "get_user_by_session",
        lambda session_id: {"user_id": 101, "email": "test@example.com", "tier": "paid"},
    )
    monkeypatch.setenv("GATEWAY_URL", "http://gateway.local")
    monkeypatch.setenv("GATEWAY_API_KEY", "gateway-api-key")

    app = FastAPI()
    app.include_router(gateway_proxy.gateway_proxy_router, prefix="/api/gateway")

    with TestClient(app) as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert captured["factory_called"] is True
