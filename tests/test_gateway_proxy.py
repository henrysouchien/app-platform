from __future__ import annotations

import hashlib
import json

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from app_platform.gateway import GatewayConfig, GatewaySessionManager, create_gateway_router
from app_platform.gateway.proxy import default_http_client_factory


def _build_client(
    handler,
    user_by_session=None,
    config: GatewayConfig | None = None,
    http_client_factory=None,
    session_manager: GatewaySessionManager | None = None,
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
        config=config or GatewayConfig(
            gateway_url="http://gateway.local",
            api_key="gateway-api-key",
            ssl_verify=True,
        ),
        get_current_user=get_current_user,
        http_client_factory=http_client_factory
        or (lambda: httpx.AsyncClient(transport=transport)),
        session_manager=session_manager,
    )

    app = FastAPI()
    app.include_router(router, prefix="/api/gateway")
    return TestClient(app), router


def _chat_payload() -> dict:
    return {
        "messages": [{"role": "user", "content": "hello"}],
        "context": {"portfolio_name": "Main Portfolio", "channel": "spoofed"},
        "model": "claude-opus-4-6",
    }


def _sse_response(payload: bytes) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        stream=httpx.ByteStream(payload),
    )


class _LockedOnly:
    def locked(self) -> bool:
        return True


def _research_chat_payload(thread_id: object = "100") -> dict:
    payload = _chat_payload()
    payload["context"] = {
        **payload["context"],
        "purpose": "research_workspace",
        "thread_id": thread_id,
    }
    return payload


def _consumer_hash(api_key: str) -> str:
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]


def test_proxy_caches_gateway_session_token() -> None:
    calls = {"init": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        first = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})
        second = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert first.status_code == 200
    assert second.status_code == 200
    assert calls["init"] == 1


def test_proxy_forwards_metadata_to_upstream_chat() -> None:
    captured = {"payload": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["payload"] = json.loads(request.content.decode("utf-8"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "metadata": {"document_context": {"source_id": "DOC_1", "source_type": "filing"}},
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert captured["payload"]["metadata"] == {
        "document_context": {"source_id": "DOC_1", "source_type": "filing"}
    }


def test_proxy_approval_uses_same_session_token() -> None:
    captured = {"auth_headers": []}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "session-a"})
        if request.url.path == "/api/chat":
            captured["auth_headers"].append(request.headers.get("authorization"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/tool-approval":
            captured["auth_headers"].append(request.headers.get("authorization"))
            return httpx.Response(200, json={"ok": True})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})
        approval = client.post(
            "/api/gateway/tool-approval",
            json={"tool_call_id": "t1", "nonce": "n1", "approved": True},
            cookies={"session_id": "s-1"},
        )

    assert approval.status_code == 200
    assert captured["auth_headers"] == ["Bearer session-a", "Bearer session-a"]


def test_proxy_uses_injected_session_manager() -> None:
    captured = {"auth_header": None}
    manager = GatewaySessionManager()
    manager._token_store.set("101", "pre-seeded-token")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/tool-approval":
            captured["auth_header"] = request.headers.get("authorization")
            return httpx.Response(200, json={"ok": True})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler, session_manager=manager)[0] as client:
        response = client.post(
            "/api/gateway/tool-approval",
            json={"tool_call_id": "t1", "nonce": "n1", "approved": True},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert captured["auth_header"] == "Bearer pre-seeded-token"


def test_proxy_chat_refreshes_token_on_401() -> None:
    calls = {"init": 0, "chat_auth": []}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": f"token-{calls['init']}"})
        if request.url.path == "/api/chat":
            auth = request.headers.get("authorization")
            calls["chat_auth"].append(auth)
            if auth == "Bearer token-1":
                return httpx.Response(401, content="expired")
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert calls["init"] == 2
    assert calls["chat_auth"] == ["Bearer token-1", "Bearer token-2"]


def test_proxy_approval_401_returns_error_without_refresh() -> None:
    calls = {"init": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/tool-approval":
            return httpx.Response(401, content="nonce/session mismatch")
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})
        approval = client.post(
            "/api/gateway/tool-approval",
            json={"tool_call_id": "t1", "nonce": "n1", "approved": True},
            cookies={"session_id": "s-1"},
        )

    assert approval.status_code == 401
    body = approval.json()
    assert body["error_code"] == "approval_failed"
    assert body["detail"] == "nonce/session mismatch"
    assert calls["init"] == 1


def test_proxy_approval_404_returns_expired_error_code() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/tool-approval":
            return httpx.Response(404, json={"error": "Unknown tool_call_id"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})
        approval = client.post(
            "/api/gateway/tool-approval",
            json={"tool_call_id": "t1", "nonce": "n1", "approved": True},
            cookies={"session_id": "s-1"},
        )

    assert approval.status_code == 404
    body = approval.json()
    assert body["error_code"] == "approval_expired"
    assert body["error"] == "Unknown tool_call_id"


def test_proxy_approval_500_returns_generic_error_code() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/tool-approval":
            return httpx.Response(500, content="gateway approval blew up")
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})
        approval = client.post(
            "/api/gateway/tool-approval",
            json={"tool_call_id": "t1", "nonce": "n1", "approved": True},
            cookies={"session_id": "s-1"},
        )

    assert approval.status_code == 500
    body = approval.json()
    assert body["error_code"] == "approval_failed"
    assert "gateway approval blew up" in body["detail"]


def test_proxy_approval_non_dict_json_body() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/tool-approval":
            return httpx.Response(422, json=["validation error"])
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})
        approval = client.post(
            "/api/gateway/tool-approval",
            json={"tool_call_id": "t1", "nonce": "n1", "approved": True},
            cookies={"session_id": "s-1"},
        )

    assert approval.status_code == 422
    body = approval.json()
    assert body["error_code"] == "approval_failed"
    assert "validation error" in body["detail"]


def test_proxy_approval_upstream_cannot_overwrite_error_code() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/tool-approval":
            return httpx.Response(404, json={"error_code": "spoofed", "upstream_status": 999})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})
        approval = client.post(
            "/api/gateway/tool-approval",
            json={"tool_call_id": "t1", "nonce": "n1", "approved": True},
            cookies={"session_id": "s-1"},
        )

    assert approval.status_code == 404
    body = approval.json()
    assert body["error_code"] == "approval_expired"
    assert body["upstream_status"] == 404


def test_proxy_rejects_unauthenticated_request() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Upstream should not be called without auth")

    with _build_client(handler, user_by_session=lambda session_id: None)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload())

    assert response.status_code == 401


def test_proxy_forwards_allow_tool_type() -> None:
    captured = {"approval_payload": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/tool-approval":
            captured["approval_payload"] = json.loads(request.content.decode("utf-8"))
            return httpx.Response(200, json={"ok": True})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})
        response = client.post(
            "/api/gateway/tool-approval",
            json={"tool_call_id": "t1", "nonce": "n1", "approved": True, "allow_tool_type": True},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert captured["approval_payload"]["allow_tool_type"] is True


def test_proxy_sse_passthrough_ordering() -> None:
    sse_bytes = (
        b'data: {"type":"text_delta","text":"a"}\n\n'
        b'data: {"type":"tool_approval_request","tool_call_id":"t1","nonce":"n1","tool_name":"run_bash","tool_input":{"cmd":"ls"}}\n\n'
        b'data: {"type":"stream_complete"}\n\n'
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return _sse_response(sse_bytes)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    first = response.text.find('"type":"text_delta"')
    second = response.text.find('"type":"tool_approval_request"')
    third = response.text.find('"type":"stream_complete"')
    assert first != -1 and second != -1 and third != -1
    assert first < second < third


def test_proxy_enforces_channel_web_and_strips_model() -> None:
    captured = {"chat_payload": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["chat_payload"] = json.loads(request.content.decode("utf-8"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert captured["chat_payload"]["context"]["channel"] == "web"
    assert captured["chat_payload"]["context"]["user_id"] == "101"
    assert captured["chat_payload"]["context"]["portfolio_name"] == "Main Portfolio"
    assert "model" not in captured["chat_payload"]


def test_proxy_overwrites_client_supplied_user_id() -> None:
    captured = {"chat_payload": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["chat_payload"] = json.loads(request.content.decode("utf-8"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    spoofed_payload = {
        "messages": [{"role": "user", "content": "hello"}],
        "context": {"user_id": "attacker-999"},
    }

    with _build_client(handler)[0] as client:
        response = client.post("/api/gateway/chat", json=spoofed_payload, cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert captured["chat_payload"]["context"]["user_id"] == "101"


def test_proxy_context_enricher_modifies_context() -> None:
    captured = {"chat_payload": None, "args": None}

    def context_enricher(request: Request, user: dict[str, object], context: dict[str, object]) -> dict[str, str]:
        captured["args"] = (request, user, context)
        return {"anthropic_api_key": "user-api-key"}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["chat_payload"] = json.loads(request.content.decode("utf-8"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    config = GatewayConfig(
        gateway_url="http://gateway.local",
        api_key="gateway-api-key",
        ssl_verify=True,
        context_enricher=context_enricher,
    )

    with _build_client(handler, config=config)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert captured["chat_payload"]["messages"] == _chat_payload()["messages"]
    assert captured["chat_payload"]["context"] == {
        "portfolio_name": "Main Portfolio",
        "channel": "web",
        "user_id": "101",
        "anthropic_api_key": "user-api-key",
    }
    assert isinstance(captured["args"][0], Request)
    assert captured["args"][1] == {"user_id": 101, "email": "test@example.com", "tier": "paid"}
    assert captured["args"][2] == {
        "portfolio_name": "Main Portfolio",
        "channel": "web",
        "user_id": "101",
    }


def test_proxy_context_enricher_exception_uses_original_context() -> None:
    captured = {"chat_payload": None}

    def context_enricher(_request: Request, _user: dict[str, object], _context: dict[str, object]) -> dict[str, str]:
        raise RuntimeError("boom")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["chat_payload"] = json.loads(request.content.decode("utf-8"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    config = GatewayConfig(
        gateway_url="http://gateway.local",
        api_key="gateway-api-key",
        ssl_verify=True,
        context_enricher=context_enricher,
    )

    with _build_client(handler, config=config)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert captured["chat_payload"]["context"] == {
        "portfolio_name": "Main Portfolio",
        "channel": "web",
        "user_id": "101",
    }
    assert "anthropic_api_key" not in captured["chat_payload"]["context"]


def test_proxy_context_enricher_cannot_clobber_reserved_fields() -> None:
    captured = {"chat_payload": None}

    def context_enricher(_request: Request, _user: dict[str, object], _context: dict[str, object]) -> dict[str, str]:
        return {
            "channel": "desktop",
            "user_id": "attacker-999",
            "anthropic_api_key": "user-api-key",
        }

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["chat_payload"] = json.loads(request.content.decode("utf-8"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    config = GatewayConfig(
        gateway_url="http://gateway.local",
        api_key="gateway-api-key",
        ssl_verify=True,
        context_enricher=context_enricher,
    )

    with _build_client(handler, config=config)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert captured["chat_payload"]["context"]["channel"] == "web"
    assert captured["chat_payload"]["context"]["user_id"] == "101"
    assert captured["chat_payload"]["context"]["anthropic_api_key"] == "user-api-key"


def test_proxy_context_enricher_mutation_then_raise_does_not_leak() -> None:
    captured = {"chat_payload": None}

    def context_enricher(_request: Request, _user: dict[str, object], context: dict[str, object]) -> dict[str, str]:
        context["channel"] = "desktop"
        context["user_id"] = "attacker-999"
        context["mutated"] = "yes"
        raise RuntimeError("boom")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["chat_payload"] = json.loads(request.content.decode("utf-8"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    config = GatewayConfig(
        gateway_url="http://gateway.local",
        api_key="gateway-api-key",
        ssl_verify=True,
        context_enricher=context_enricher,
    )

    with _build_client(handler, config=config)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert captured["chat_payload"]["context"] == {
        "portfolio_name": "Main Portfolio",
        "channel": "web",
        "user_id": "101",
    }


def test_proxy_min_chat_tier_registered_allows_free_user() -> None:
    calls = {"init": 0, "chat": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            calls["chat"] += 1
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    config = GatewayConfig(
        gateway_url="http://gateway.local",
        api_key="gateway-api-key",
        ssl_verify=True,
        min_chat_tier="registered",
    )

    with _build_client(
        handler,
        user_by_session=lambda _session_id: {
            "user_id": 101,
            "email": "registered@example.com",
            "tier": "registered",
        },
        config=config,
    )[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert calls == {"init": 1, "chat": 1}


def test_proxy_min_chat_tier_default_blocks_registered_user() -> None:
    calls = {"init": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "token-1"})
        raise AssertionError("Upstream should not be called for blocked users")

    with _build_client(
        handler,
        user_by_session=lambda _session_id: {
            "user_id": 101,
            "email": "registered@example.com",
            "tier": "registered",
        },
    )[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "upgrade_required"
    assert response.json()["detail"]["tier_required"] == "paid"
    assert "paid" in response.json()["detail"]["message"]
    assert calls["init"] == 0


def test_proxy_min_chat_tier_invalid_raises_at_config_time() -> None:
    with pytest.raises(ValueError, match="Invalid min_chat_tier='vip'"):
        GatewayConfig(min_chat_tier="vip")


def test_proxy_min_chat_tier_normalizes_input() -> None:
    assert GatewayConfig(min_chat_tier=" Registered ").min_chat_tier == "registered"
    assert GatewayConfig(min_chat_tier=None).min_chat_tier == "paid"  # type: ignore[arg-type]
    assert GatewayConfig(min_chat_tier="").min_chat_tier == "paid"


def test_proxy_forwards_request_headers_from_factory_and_filters_reserved_headers() -> None:
    captured = {"headers": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["headers"] = dict(request.headers)
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    def request_headers_factory(request: Request) -> dict[str, str]:
        assert request.headers["x-client-header"] == "client"
        return {
            "X-Conversation-ID": "conv-789",
            "X-Request-ID": "req-123",
            "authorization": "Bearer should-not-pass",
        }

    config = GatewayConfig(
        gateway_url="http://gateway.local",
        api_key="gateway-api-key",
        ssl_verify=True,
        request_headers_factory=request_headers_factory,
    )

    with _build_client(handler, config=config)[0] as client:
        response = client.post(
            "/api/gateway/chat",
            headers={"X-Client-Header": "client"},
            json=_chat_payload(),
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert captured["headers"]["x-conversation-id"] == "conv-789"
    assert captured["headers"]["x-request-id"] == "req-123"
    assert captured["headers"]["authorization"] == "Bearer token-1"


def test_proxy_allows_concurrent_research_streams_for_different_threads() -> None:
    calls = {"init": 0, "chat": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": f"token-{calls['init']}"})
        if request.url.path == "/api/chat":
            calls["chat"] += 1
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    client, router = _build_client(handler)
    router._session_manager._stream_locks["101:t:100"] = _LockedOnly()  # type: ignore[assignment]

    with client:
        response = client.post(
            "/api/gateway/chat",
            json=_research_chat_payload("200"),
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert calls == {"init": 1, "chat": 1}
    assert router._session_manager.lookup_token("101", "200") == "token-1"
    assert router._session_manager.lookup_token("101") is None


def test_proxy_rejects_concurrent_research_streams_for_same_thread() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Upstream should not be called when research thread lock is held")

    client, router = _build_client(handler)
    router._session_manager._stream_locks["101:t:100"] = _LockedOnly()  # type: ignore[assignment]

    with client:
        response = client.post(
            "/api/gateway/chat",
            json=_research_chat_payload("100"),
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 409


def test_proxy_portfolio_chat_still_rejects_concurrent_stream() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Upstream should not be called when user lock is held")

    client, router = _build_client(handler)
    router._session_manager._stream_locks["101"] = _LockedOnly()  # type: ignore[assignment]

    with client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 409


def test_proxy_research_without_thread_id_falls_back_to_user_lock() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Upstream should not be called when user lock is held")

    payload = _research_chat_payload()
    payload["context"].pop("thread_id")

    client, router = _build_client(handler)
    router._session_manager._stream_locks["101"] = _LockedOnly()  # type: ignore[assignment]

    with client:
        response = client.post("/api/gateway/chat", json=payload, cookies={"session_id": "s-1"})

    assert response.status_code == 409


def test_proxy_research_does_not_block_portfolio_chat() -> None:
    calls = {"init": 0, "chat": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": f"token-{calls['init']}"})
        if request.url.path == "/api/chat":
            calls["chat"] += 1
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    client, router = _build_client(handler)
    router._session_manager._stream_locks["101:t:100"] = _LockedOnly()  # type: ignore[assignment]

    with client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert calls == {"init": 1, "chat": 1}
    assert router._session_manager.lookup_token("101") == "token-1"


def test_proxy_research_whitespace_thread_id_falls_back_to_user_lock() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Upstream should not be called when user lock is held")

    client, router = _build_client(handler)
    router._session_manager._stream_locks["101"] = _LockedOnly()  # type: ignore[assignment]

    with client:
        response = client.post(
            "/api/gateway/chat",
            json=_research_chat_payload(" "),
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 409


def test_proxy_research_session_expired_retries_with_conversation_token() -> None:
    calls = {"init": 0, "chat_auth": []}
    manager = GatewaySessionManager()
    manager._token_store.set("101", "portfolio-token")
    manager._consumer_hashes["101"] = _consumer_hash("gateway-api-key")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": f"token-{calls['init']}"})
        if request.url.path == "/api/chat":
            auth = request.headers.get("authorization")
            calls["chat_auth"].append(auth)
            if auth == "Bearer token-1":
                return httpx.Response(401, content="expired")
            if auth == "Bearer token-2":
                return _sse_response(b'data: {"type":"stream_complete"}\n\n')
            raise AssertionError(f"Unexpected authorization header: {auth}")
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler, session_manager=manager)[0] as client:
        response = client.post(
            "/api/gateway/chat",
            json=_research_chat_payload("100"),
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert calls["init"] == 2
    assert calls["chat_auth"] == ["Bearer token-1", "Bearer token-2"]
    assert manager.lookup_token("101") == "portfolio-token"
    assert manager.lookup_token("101", "100") == "token-2"


def test_proxy_research_auth_expired_invalidates_conversation_token_only() -> None:
    calls = {"init": 0, "chat_auth": []}
    manager = GatewaySessionManager()
    manager._token_store.set("101", "portfolio-token")
    manager._consumer_hashes["101"] = _consumer_hash("gateway-api-key")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": f"token-{calls['init']}"})
        if request.url.path == "/api/chat":
            auth = request.headers.get("authorization")
            calls["chat_auth"].append(auth)
            if auth == "Bearer token-1":
                return httpx.Response(401, json={"error": "auth_expired"})
            if auth == "Bearer token-2":
                return _sse_response(b'data: {"type":"stream_complete"}\n\n')
            raise AssertionError(f"Unexpected authorization header: {auth}")
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler, session_manager=manager)[0] as client:
        response = client.post(
            "/api/gateway/chat",
            json=_research_chat_payload("100"),
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert calls["init"] == 2
    assert calls["chat_auth"] == ["Bearer token-1", "Bearer token-2"]
    assert manager.lookup_token("101") == "portfolio-token"
    assert manager.lookup_token("101", "100") == "token-2"


def test_proxy_rejects_concurrent_stream() -> None:
    class _LockedOnly:
        def locked(self) -> bool:
            return True

    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("Upstream should not be called when lock is held")

    client, router = _build_client(handler)
    router._session_manager._stream_locks["101"] = _LockedOnly()  # type: ignore[assignment]

    with client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 409


def test_proxy_approval_bypasses_stream_lock() -> None:
    class _LockedOnly:
        def locked(self) -> bool:
            return True

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/tool-approval":
            return httpx.Response(200, json={"ok": True})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    client, router = _build_client(handler)
    router._session_manager._token_store.set("101", "token-1")
    router._session_manager._stream_locks["101"] = _LockedOnly()  # type: ignore[assignment]

    with client:
        response = client.post(
            "/api/gateway/tool-approval",
            json={"tool_call_id": "t1", "nonce": "n1", "approved": False},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200


def test_proxy_sse_response_headers_and_no_token_cookie() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache"
    assert response.headers["x-accel-buffering"] == "no"
    assert "set-cookie" not in response.headers


def test_proxy_accepts_nested_session_token_payload() -> None:
    captured = {"auth": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session": {"token": "nested-token"}})
        if request.url.path == "/api/chat":
            captured["auth"] = request.headers.get("authorization")
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert captured["auth"] == "Bearer nested-token"


@pytest.mark.parametrize(
    ("ssl_verify", "expected"),
    [
        (True, True),
        (False, False),
        ("/tmp/custom-ca.pem", "/tmp/custom-ca.pem"),
    ],
)
def test_default_http_client_factory_respects_ssl_verify(
    monkeypatch: pytest.MonkeyPatch,
    ssl_verify,
    expected,
) -> None:
    captured = {}

    class _DummyClient:
        async def aclose(self) -> None:
            return None

    def fake_async_client(*, timeout, verify):
        captured["timeout"] = timeout
        captured["verify"] = verify
        return _DummyClient()

    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)

    client = default_http_client_factory(ssl_verify)

    assert isinstance(client, _DummyClient)
    assert captured["verify"] == expected
    assert captured["timeout"].connect == 10.0
    assert captured["timeout"].read is None
    assert captured["timeout"].write == 30.0
    assert captured["timeout"].pool == 30.0
