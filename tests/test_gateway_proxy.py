from __future__ import annotations

import asyncio
import hashlib
import json
from typing import Any

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
        headers={"content-type": "text/event-stream", "X-Control-Plane-Version": "1"},
        stream=httpx.ByteStream(payload),
    )


class _ControlStreamResponseSpy:
    def __init__(
        self,
        chunks: list[bytes],
        *,
        block_after_chunks: bool = False,
        close_exception: BaseException | None = None,
        raise_after_close: bool = False,
    ) -> None:
        self.status_code = 200
        self.headers = {
            "content-type": "text/event-stream",
            "X-Control-Plane-Version": "1",
        }
        self.chunks = chunks
        self.block_after_chunks = block_after_chunks
        self.close_exception = close_exception
        self.raise_after_close = raise_after_close
        self.close_calls = 0
        self.waiting = asyncio.Event()
        self.closed = asyncio.Event()

    async def aiter_raw(self):
        for chunk in self.chunks:
            yield chunk
        if not self.block_after_chunks:
            return

        self.waiting.set()
        await self.closed.wait()
        if self.raise_after_close:
            raise RuntimeError("upstream stream closed while blocked")

    async def aclose(self) -> None:
        self.close_calls += 1
        self.closed.set()
        if self.close_exception is not None:
            raise self.close_exception


class _ControlStreamClientSpy:
    def __init__(
        self,
        upstream_response: _ControlStreamResponseSpy,
        *,
        close_exception: BaseException | None = None,
    ) -> None:
        self.upstream_response = upstream_response
        self.close_exception = close_exception
        self.close_calls = 0
        self.sent_requests: list[tuple[httpx.Request, bool]] = []
        self.post_timeouts: list[httpx.Timeout | float | None] = []

    async def post(
        self,
        _url: str,
        *,
        json=None,
        timeout: httpx.Timeout | float | None = None,
    ) -> httpx.Response:
        self.post_timeouts.append(timeout)
        return httpx.Response(200, json={"session_token": "control-token"})

    def build_request(self, method: str, url: str, *, headers=None, params=None) -> httpx.Request:
        request_url = str(httpx.URL(url, params=params)) if params else url
        return httpx.Request(method, request_url, headers=headers)

    async def send(self, request: httpx.Request, *, stream: bool = False) -> _ControlStreamResponseSpy:
        self.sent_requests.append((request, stream))
        return self.upstream_response

    async def aclose(self) -> None:
        self.close_calls += 1
        if self.close_exception is not None:
            raise self.close_exception


def _control_events_request(*, disconnected: bool = False) -> Request:
    async def receive():
        if disconnected:
            return {"type": "http.disconnect"}
        await asyncio.sleep(3600)
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(
        {
            "type": "http",
            "asgi": {"version": "3.0", "spec_version": "2.3"},
            "http_version": "1.1",
            "method": "GET",
            "scheme": "http",
            "path": "/api/gateway/control/events",
            "raw_path": b"/api/gateway/control/events",
            "query_string": b"",
            "headers": [],
            "client": ("testclient", 50000),
            "server": ("testserver", 80),
        },
        receive,
    )


async def _open_control_events_stream(
    upstream_response: _ControlStreamResponseSpy,
    *,
    request: Request | None = None,
    client_close_exception: BaseException | None = None,
):
    client_spy = _ControlStreamClientSpy(
        upstream_response,
        close_exception=client_close_exception,
    )

    router = create_gateway_router(
        config=GatewayConfig(
            gateway_url="http://gateway.local",
            api_key="gateway-api-key",
            ssl_verify=True,
        ),
        get_current_user=lambda _request: {
            "user_id": 101,
            "email": "test@example.com",
            "tier": "paid",
        },
        http_client_factory=lambda: client_spy,
        session_manager=GatewaySessionManager(),
    )
    endpoint = next(
        route.endpoint
        for route in router.routes
        if getattr(route, "path", None) == "/control/{path:path}"
    )
    response = await endpoint(
        path="events",
        request=request or _control_events_request(),
        user={"user_id": 101, "email": "test@example.com", "tier": "paid"},
    )
    assert len(client_spy.post_timeouts) == 1
    session_init_timeout = client_spy.post_timeouts[0]
    assert isinstance(session_init_timeout, httpx.Timeout)
    assert session_init_timeout.connect == 10.0
    assert session_init_timeout.read == 20.0
    return response, client_spy


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


def test_proxy_forwards_document_context_in_surviving_request_context() -> None:
    captured = {"payload": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["payload"] = json.loads(request.content.decode("utf-8"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    document_context = {
        "context_schema_version": "v2",
        "provenance_status": "verified",
        "source_id": "edgar:0000950170-25-010491",
        "source_type": "filing",
        "section": "Item 7",
        "anchor": {
            "anchor_kind": "filing_quote",
            "selected_text": "Cloud revenue increased.",
            "confidence": "quote",
            "source_html_hash": "source-html-hash",
        },
    }

    with _build_client(handler)[0] as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "context": {
                    **_chat_payload()["context"],
                    "document_context": document_context,
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert captured["payload"]["context"]["document_context"] == document_context
    assert captured["payload"]["context"]["channel"] == "web"


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
    assert body["detail"] == "Gateway approval failed"
    assert "nonce/session mismatch" not in approval.text
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
    assert body["detail"] == "Gateway approval expired"


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
    assert body["detail"] == "Gateway approval failed"
    assert "gateway approval blew up" not in approval.text


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
    assert body["detail"] == "Gateway approval failed"
    assert "validation error" not in approval.text


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


def test_proxy_enforces_channel_web_and_forwards_model_and_effort() -> None:
    captured = {"chat_payload": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            captured["chat_payload"] = json.loads(request.content.decode("utf-8"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post(
            "/api/gateway/chat",
            json={**_chat_payload(), "effort": "medium"},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert captured["chat_payload"]["context"]["channel"] == "web"
    assert captured["chat_payload"]["context"]["user_id"] == "101"
    assert captured["chat_payload"]["context"]["portfolio_name"] == "Main Portfolio"
    assert captured["chat_payload"]["model"] == "claude-opus-4-6"
    assert captured["chat_payload"]["effort"] == "medium"


def test_proxy_rejects_invalid_effort() -> None:
    with _build_client(lambda *_args, **_kwargs: None)[0] as client:
        response = client.post(
            "/api/gateway/chat",
            json={**_chat_payload(), "effort": "ludicrous"},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 422


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


def test_proxy_context_enricher_exception_can_fail_request() -> None:
    calls = {"upstream": 0}

    def context_enricher(_request: Request, _user: dict[str, object], _context: dict[str, object]) -> dict[str, str]:
        raise RuntimeError("boom")

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["upstream"] += 1
        raise AssertionError(f"Unexpected upstream request: {request.url.path}")

    config = GatewayConfig(
        gateway_url="http://gateway.local",
        api_key="gateway-api-key",
        ssl_verify=True,
        context_enricher=context_enricher,
        fail_on_context_enricher_error=True,
    )

    with _build_client(handler, config=config)[0] as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 502
    assert response.json()["detail"] == "Gateway proxy error"
    assert "boom" not in response.text
    assert calls["upstream"] == 0


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


def test_proxy_explicit_conversation_id_scopes_token_and_lock() -> None:
    calls = {"init": 0, "chat_auth": [], "chat_payloads": []}
    manager = GatewaySessionManager()
    manager._token_store.set("101", "default-token")
    manager._consumer_hashes["101"] = _consumer_hash("gateway-api-key")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": f"conv-token-{calls['init']}"})
        if request.url.path == "/api/chat":
            calls["chat_auth"].append(request.headers.get("authorization"))
            calls["chat_payloads"].append(json.loads(request.content.decode("utf-8")))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    client, router = _build_client(handler, session_manager=manager)
    router._session_manager._stream_locks["101"] = _LockedOnly()  # type: ignore[assignment]

    with client:
        first = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "context": {
                    "portfolio_name": "Main Portfolio",
                    "purpose": "chat",
                    "conversation_id": "compact:one",
                },
            },
            cookies={"session_id": "s-1"},
        )
        second = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "context": {
                    "portfolio_name": "Main Portfolio",
                    "purpose": "chat",
                    "conversation_id": "compact:two",
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert first.status_code == 200
    assert second.status_code == 200
    assert calls["init"] == 2
    assert calls["chat_auth"] == ["Bearer conv-token-1", "Bearer conv-token-2"]
    assert calls["chat_payloads"][0]["context"]["purpose"] == "chat"
    assert calls["chat_payloads"][1]["context"]["purpose"] == "chat"
    assert manager.lookup_token("101") == "default-token"
    assert manager.lookup_token("101", "compact:one") == "conv-token-1"
    assert manager.lookup_token("101", "compact:two") == "conv-token-2"
    assert "101:t:compact:one" in router._session_manager._stream_locks
    assert "101:t:compact:two" in router._session_manager._stream_locks


@pytest.mark.parametrize("invalid_conversation_id", ["bad/slash", "x" * 129])
def test_proxy_invalid_explicit_conversation_id_falls_back_to_default(
    invalid_conversation_id: str,
) -> None:
    calls = {"init": 0, "chat_auth": []}
    manager = GatewaySessionManager()
    manager._token_store.set("101", "default-token")
    manager._consumer_hashes["101"] = _consumer_hash("gateway-api-key")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "unexpected-token"})
        if request.url.path == "/api/chat":
            calls["chat_auth"].append(request.headers.get("authorization"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler, session_manager=manager)[0] as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "context": {
                    "portfolio_name": "Main Portfolio",
                    "purpose": "chat",
                    "conversation_id": invalid_conversation_id,
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert calls == {"init": 0, "chat_auth": ["Bearer default-token"]}
    assert manager.lookup_token("101") == "default-token"
    assert manager.lookup_token("101", invalid_conversation_id) is None


def test_proxy_research_thread_id_wins_over_explicit_conversation_id() -> None:
    calls = {"init": 0, "chat_auth": []}
    manager = GatewaySessionManager()
    manager._token_store.set("101:t:compact-1", "explicit-token")
    manager._consumer_hashes["101:t:compact-1"] = _consumer_hash("gateway-api-key")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "thread-token"})
        if request.url.path == "/api/chat":
            calls["chat_auth"].append(request.headers.get("authorization"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    client, router = _build_client(handler, session_manager=manager)
    router._session_manager._stream_locks["101:t:compact-1"] = _LockedOnly()  # type: ignore[assignment]
    payload = _research_chat_payload("100")
    payload["context"]["conversation_id"] = "compact-1"

    with client:
        response = client.post(
            "/api/gateway/chat",
            json=payload,
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert calls == {"init": 1, "chat_auth": ["Bearer thread-token"]}
    assert manager.lookup_token("101", "compact-1") == "explicit-token"
    assert manager.lookup_token("101", "100") == "thread-token"


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


def test_control_proxy_bootstraps_separate_session_and_sanitizes_dispatch_payload() -> None:
    captured = {"session_payload": None, "run_payload": None, "run_auth": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            captured["session_payload"] = json.loads(request.content.decode("utf-8"))
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/profiles":
            return httpx.Response(200, json={"profiles": [{"name": "analyst"}]})
        if request.url.path == "/api/control/skills":
            return httpx.Response(200, json={"skills": [{"name": "critical-factors"}]})
        if request.url.path == "/api/control/runs":
            captured["run_auth"] = request.headers.get("authorization")
            captured["run_payload"] = json.loads(request.content.decode("utf-8"))
            return httpx.Response(
                200,
                json={
                    "run": {
                        "kind": "autonomous",
                        "run_id": "bg_1",
                        "task_id": "bg_1",
                        "state": "running",
                    }
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "critical-factors",
                "task": None,
                "channel": "spoofed",
                "user_id": "spoofed-user",
                "context": "Review the selected portfolio.",
                "dispatch_scope": {
                    "kind": "portfolio",
                    "source": "user_selected",
                    "portfolio_name": "core",
                    "display_name": "Core",
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.headers["x-control-plane-version"] == "1"
    assert captured["session_payload"] == {
        "api_key": "gateway-api-key",
        "user_id": "101",
        "user_email": "test@example.com",
        "context": {"channel": "web"},
    }
    assert captured["run_auth"] == "Bearer control-token"
    assert captured["run_payload"] == {
        "kind": "autonomous",
        "profile": "analyst",
        "mode": "skill",
        "skill": "critical-factors",
        "task": None,
        "channel": "web",
        "context": "Review the selected portfolio.",
        "dispatch_scope": {
            "kind": "portfolio",
            "source": "user_selected",
            "portfolio_name": "core",
            "display_name": "Core",
        },
    }


@pytest.mark.parametrize(
    "payload",
    [
        {
            "kind": "autonomous",
            "profile": "_fixture",
            "mode": "skill",
            "skill": "critical-factors",
            "task": "Exercise fixture guard.",
        },
        {
            "kind": "autonomous",
            "profile": "analyst",
            "mode": "skill",
            "skill": "fixture-sleep",
            "task": "Exercise fixture guard.",
        },
        {
            "kind": "autonomous",
            "profile": "analyst",
            "mode": "skill",
            "skill": "critical-factors",
            "task": "Exercise fixture guard.",
            "dev_mode": True,
        },
        {
            "kind": "autonomous",
            "profile": "analyst",
            "mode": "skill",
            "skill": "critical-factors",
            "task": "Exercise fixture guard.",
            "dev_mode": False,
        },
        {
            "kind": "chat",
            "message": "Exercise chat fixture guard.",
            "dev_mode": True,
        },
        {
            "kind": "chat",
            "message": "Exercise chat fixture guard.",
            "dev_mode": False,
        },
    ],
)
def test_control_proxy_rejects_web_fixture_and_dev_mode_dispatches(payload: dict[str, Any]) -> None:
    upstream_calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request.url.path)
        return httpx.Response(500, json={"unexpected": request.url.path})

    with _build_client(handler)[0] as client:
        response = client.post(
            "/api/gateway/control/runs",
            json=payload,
            headers={"X-Agent-Control-QA-Bridge": "fixture-approval-artifact"},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 403
    assert response.json() == {
        "detail": {
            "error": "web_control_dev_dispatch_forbidden",
            "message": "Web Agent Control cannot launch fixture or dev-mode runs.",
        }
    }
    assert upstream_calls == []


def test_control_proxy_rejects_web_dev_dispatch_before_gateway_contract_preflight() -> None:
    upstream_calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request.url.path)
        return httpx.Response(
            200,
            json={"package": {"contracts": ["control-plane-v1", "control-chat-continuation-v1"]}},
        )

    config = GatewayConfig(
        gateway_url="http://gateway.local",
        api_key="gateway-api-key",
        ssl_verify=True,
        required_contracts=frozenset({"control-plane-v1"}),
        control_chat_continuation_contract="control-chat-continuation-v1",
    )

    with _build_client(handler, config=config)[0] as client:
        response = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "critical-factors",
                "task": "Exercise fixture guard.",
                "dev_mode": False,
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["error"] == "web_control_dev_dispatch_forbidden"
    assert upstream_calls == []


def test_control_events_stream_uses_control_token_and_bypasses_chat_stream_lock() -> None:
    class _LockedOnly:
        def locked(self) -> bool:
            return True

    captured = {"event_auth": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/events":
            captured["event_auth"] = request.headers.get("authorization")
            return _sse_response(b'data: {"type":"run_state_changed","run_id":"bg_1","state":"running"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    client, router = _build_client(handler)
    router._session_manager._stream_locks["101"] = _LockedOnly()  # type: ignore[assignment]

    with client:
        response = client.get("/api/gateway/control/events", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-cache"
    assert response.headers["x-accel-buffering"] == "no"
    assert captured["event_auth"] == "Bearer control-token"
    assert '"type":"run_state_changed"' in response.text
    assert "set-cookie" not in response.headers


def test_control_events_stream_eof_closes_upstream_and_client_once() -> None:
    chunk = b'data: {"type":"run_state_changed","run_id":"bg_1","state":"running"}\n\n'

    async def run() -> None:
        upstream = _ControlStreamResponseSpy([chunk])
        response, client_spy = await _open_control_events_stream(upstream)

        chunks = []
        async for body_chunk in response.body_iterator:
            chunks.append(body_chunk)

        assert response.status_code == 200
        assert chunks == [chunk]
        assert upstream.close_calls == 1
        assert client_spy.close_calls == 1

    asyncio.run(run())


def test_control_events_stream_cancellation_reraises_and_closes_once() -> None:
    chunk = b'data: {"type":"run_state_changed","run_id":"bg_1","state":"running"}\n\n'

    async def run() -> None:
        upstream = _ControlStreamResponseSpy(
            [chunk],
            block_after_chunks=True,
            close_exception=RuntimeError("upstream close failed"),
        )
        response, client_spy = await _open_control_events_stream(
            upstream,
            client_close_exception=RuntimeError("client close failed"),
        )
        iterator = response.body_iterator.__aiter__()

        assert response.status_code == 200
        assert await iterator.__anext__() == chunk

        next_chunk = asyncio.create_task(iterator.__anext__())
        await upstream.waiting.wait()
        next_chunk.cancel()

        with pytest.raises(asyncio.CancelledError):
            await next_chunk

        assert upstream.close_calls == 1
        assert client_spy.close_calls == 1

    asyncio.run(run())


def test_control_events_stream_disconnect_close_is_memoized_with_finally_cleanup() -> None:
    chunk = b'data: {"type":"run_state_changed","run_id":"bg_1","state":"running"}\n\n'

    async def run() -> None:
        upstream = _ControlStreamResponseSpy(
            [chunk],
            block_after_chunks=True,
            close_exception=RuntimeError("upstream close failed"),
            raise_after_close=True,
        )
        response, client_spy = await _open_control_events_stream(
            upstream,
            request=_control_events_request(disconnected=True),
        )
        iterator = response.body_iterator.__aiter__()

        assert await iterator.__anext__() == chunk
        next_chunk = asyncio.create_task(iterator.__anext__())
        await upstream.waiting.wait()

        with pytest.raises(StopAsyncIteration):
            await asyncio.wait_for(next_chunk, timeout=3)

        assert upstream.close_calls == 1
        assert client_spy.close_calls == 1

    asyncio.run(run())


def test_control_proxy_sanitizes_autonomous_run_messages() -> None:
    captured = {"message_auth": None, "message_payload": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1/messages":
            captured["message_auth"] = request.headers.get("authorization")
            captured["message_payload"] = json.loads(request.content.decode("utf-8"))
            return httpx.Response(
                200,
                json={
                    "run": {
                        "kind": "autonomous",
                        "run_id": "bg_1",
                        "task_id": "bg_1",
                        "state": "running",
                    },
                    "delivery_status": "delivered",
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/messages",
            json={
                "message": "Check source quality.",
                "message_id": "web-1",
                "channel": "cli",
                "user_id": "spoofed-user",
                "context": {"channel": "cli", "risk_user_id": "spoofed-risk-user", "trace": "keep"},
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert captured["message_auth"] == "Bearer control-token"
    assert captured["message_payload"] == {
        "message": "Check source quality.",
        "message_id": "web-1",
    }


def test_control_proxy_sanitizes_resume_payload_and_uses_control_token() -> None:
    captured = {"resume_auth": None, "resume_payload": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1/resume":
            captured["resume_auth"] = request.headers.get("authorization")
            captured["resume_payload"] = json.loads(request.content.decode("utf-8"))
            return httpx.Response(
                200,
                json={
                    "run": {
                        "kind": "autonomous",
                        "run_id": "bg_2",
                        "task_id": "bg_2",
                        "state": "running",
                        "resumed_from": "bg_1",
                    }
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/resume",
            json={
                "message": "Continue with read-only summary.",
                "request_id": "web-resume-1",
                "channel": "cli",
                "user_id": "spoofed-user",
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert captured["resume_auth"] == "Bearer control-token"
    assert captured["resume_payload"] == {
        "message": "Continue with read-only summary.",
        "request_id": "web-resume-1",
    }


def test_control_proxy_rejects_resume_context_objects_before_forwarding() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/resume",
            json={
                "message": "Continue with read-only summary.",
                "request_id": "web-resume-1",
                "channel": "cli",
                "user_id": "spoofed-user",
                "context": {"channel": "cli", "risk_user_id": "spoofed-risk-user", "trace": "reject"},
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "control_request_contract_invalid"
    assert response.json()["detail"]["issues"] == [
        {"path": "context", "message": "Input should be a valid string", "type": "string_type"}
    ]
    assert calls == []


def test_control_proxy_cancel_uses_control_token_without_request_body() -> None:
    captured = {"cancel_auth": None, "cancel_content": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1":
            captured["cancel_auth"] = request.headers.get("authorization")
            captured["cancel_content"] = request.content
            return httpx.Response(
                200,
                json={
                    "kind": "autonomous",
                    "run_id": "bg_1",
                    "task_id": "bg_1",
                    "state": "cancelled",
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.delete("/api/gateway/control/runs/bg_1", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert captured["cancel_auth"] == "Bearer control-token"
    assert captured["cancel_content"] == b""


def test_control_proxy_sanitizes_approval_decision_payload_and_uses_route_scope() -> None:
    captured = {"approval_auth": None, "approval_payload": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_task_1/approvals/ap_1":
            captured["approval_auth"] = request.headers.get("authorization")
            captured["approval_payload"] = json.loads(request.content.decode("utf-8"))
            return httpx.Response(200, json={"ok": True})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        response = client.post(
            "/api/gateway/control/runs/bg_task_1/approvals/ap_1",
            json={
                "approved": False,
                "allow_tool_type": False,
                "reason": "Denied from analyst control deck",
                "channel": "cli",
                "user_id": "spoofed-user",
                "context": {"channel": "cli", "risk_user_id": "spoofed-risk-user", "trace": "keep"},
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert captured["approval_auth"] == "Bearer control-token"
    assert captured["approval_payload"] == {
        "approved": False,
        "allow_tool_type": False,
        "reason": "Denied from analyst control deck",
    }


def test_control_proxy_stores_chat_run_token_and_uses_it_for_continuation() -> None:
    captured = {"dispatch_auth": None, "message_auth": None, "message_payload": None}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            captured["dispatch_auth"] = request.headers.get("authorization")
            return httpx.Response(
                200,
                json={
                    "run": {
                        "kind": "chat",
                        "run_id": "sess_1",
                        "state": "completed",
                    },
                    "chat_session_token": "chat-run-token",
                    "chat_session_expires_at": 4_102_444_800,
                },
            )
        if request.url.path == "/api/control/runs/sess_1/messages":
            captured["message_auth"] = request.headers.get("authorization")
            captured["message_payload"] = json.loads(request.content.decode("utf-8"))
            return httpx.Response(
                200,
                json={
                    "run": {
                        "kind": "chat",
                        "run_id": "sess_1",
                        "state": "completed",
                    }
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler)[0] as client:
        dispatch = client.post(
            "/api/gateway/control/runs",
            json={"kind": "chat", "message": "Start chat run", "channel": "spoofed"},
            cookies={"session_id": "s-1"},
        )
        continuation = client.post(
            "/api/gateway/control/runs/sess_1/messages",
            json={
                "messages": [{"role": "user", "content": "Continue"}],
                "request_id": "web-chat-1",
                "context": {"channel": "cli", "email": "spoofed@example.com", "topic": "risk"},
            },
            cookies={"session_id": "s-1"},
        )

    assert dispatch.status_code == 200
    assert "chat_session_token" not in dispatch.json()
    assert dispatch.json()["run"]["messageable"] is True
    assert captured["dispatch_auth"] == "Bearer control-token"
    assert continuation.status_code == 200
    assert continuation.json()["run"]["messageable"] is True
    assert captured["message_auth"] == "Bearer chat-run-token"
    assert captured["message_payload"] == {
        "messages": [{"role": "user", "content": "Continue"}],
        "request_id": "web-chat-1",
        "context": {"channel": "web", "topic": "risk"},
    }


def test_control_proxy_continues_chat_run_with_control_contract_without_cached_chat_token() -> None:
    captured = {"health_calls": 0, "message_auth": None}

    config = GatewayConfig(
        gateway_url="http://gateway.local",
        api_key="gateway-api-key",
        ssl_verify=True,
        control_chat_continuation_contract="control-chat-continuation-v1",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            captured["health_calls"] += 1
            return httpx.Response(
                200,
                json={"package": {"contracts": ["control-chat-continuation-v1"]}},
            )
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/sess_1/messages":
            captured["message_auth"] = request.headers.get("authorization")
            return httpx.Response(
                200,
                json={
                    "run": {
                        "kind": "chat",
                        "run_id": "sess_1",
                        "state": "completed",
                    }
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with _build_client(handler, config=config)[0] as client:
        response = client.post(
            "/api/gateway/control/runs/sess_1/messages",
            json={"messages": [{"role": "user", "content": "Continue"}]},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert captured["health_calls"] == 1
    assert captured["message_auth"] == "Bearer control-token"
    assert response.json()["run"]["messageable"] is True


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

    def fake_async_client(*, timeout, verify, trust_env):
        captured["timeout"] = timeout
        captured["verify"] = verify
        captured["trust_env"] = trust_env
        return _DummyClient()

    monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)

    client = default_http_client_factory(ssl_verify)

    assert isinstance(client, _DummyClient)
    assert captured["verify"] == expected
    assert captured["trust_env"] is False
    assert captured["timeout"].connect == 10.0
    assert captured["timeout"].read is None
    assert captured["timeout"].write == 30.0
    assert captured["timeout"].pool == 30.0
