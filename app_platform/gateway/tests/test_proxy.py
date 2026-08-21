from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import socket
import subprocess
import sys
import textwrap
from contextlib import asynccontextmanager
from typing import Any

import httpx
import pytest
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from pydantic import ValidationError
import uvicorn

from app_platform.gateway import GatewayConfig, create_gateway_router
from app_platform.gateway.models import GatewayChatRequest
from app_platform.gateway import proxy as proxy_module
from app_platform.gateway.proxy import _build_gateway_chat_payload, _get_user_key

_CONTROL_CHAT_CONTINUATION_CONTRACT = "control-chat-continuation-v1"
_CONTROL_REQUEST_CONTRACT = "control-request-v1"
_CONTROL_RESPONSE_CONTRACT = "control-response-v1"


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


def _control_chat_continuation_config() -> GatewayConfig:
    return GatewayConfig(
        gateway_url="http://gateway.local",
        api_key="gateway-api-key",
        ssl_verify=True,
        control_chat_continuation_contract=_CONTROL_CHAT_CONTINUATION_CONTRACT,
    )


def _control_chat_continuation_health_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={"package": {"contracts": [_CONTROL_CHAT_CONTINUATION_CONTRACT]}},
    )


def _chat_payload() -> dict:
    return {
        "messages": [{"role": "user", "content": "hello"}],
        "context": {"portfolio_name": "Main Portfolio"},
    }


def _assert_web_session_init_payload(payload: object) -> None:
    assert isinstance(payload, dict)
    body = dict(payload)
    request_id = body.pop("request_id", None)
    subject_assertion = body.pop("subject_assertion", None)
    assert body == {
        "api_key": "gateway-api-key",
        "user_id": "101",
        "user_email": "test@example.com",
        "context": {"channel": "web"},
    }
    assert (request_id is None) == (subject_assertion is None)
    if request_id is not None:
        assert isinstance(request_id, str) and request_id
        assert isinstance(subject_assertion, str) and len(subject_assertion.split(".")) == 3


def _chat_attachment(
    content: bytes = b"hello attachment",
    *,
    index: int = 1,
    display_name: str = "notes.md",
    media_type: str = "text/markdown",
) -> dict[str, Any]:
    return {
        "schema_version": "chat-attachment/1",
        "input_name": "source_document" if index == 1 else f"source_document_{index}",
        "display_name": display_name,
        "media_type": media_type,
        "encoding": "utf-8",
        "content_bytes": len(content),
        "content_sha256": hashlib.sha256(content).hexdigest(),
        "content_b64": base64.b64encode(content).decode("ascii"),
    }


def _agent_run_schedule_create_payload() -> dict:
    return {
        "kind": "agent_run_schedule",
        "name": "weekday-nvda-earnings-watch",
        "enabled": True,
        "timezone": "America/New_York",
        "cadence": {
            "type": "weekly",
            "days_of_week": [1, 2, 3, 4, 5],
            "time_of_day": "08:30",
        },
        "dispatch": {
            "kind": "autonomous",
            "profile": "analyst",
            "mode": "skill",
            "skill": "earnings-review",
            "ticker": "NVDA",
            "task": None,
            "context": "Review new earnings/news and report material changes.",
        },
        "request_id": "schedule-create-1",
    }


def _readable_resource_payload(**overrides) -> dict:
    payload = {
        "resource_id": "note:bg_visible:daily:2026-06-12",
        "control_run_id": "bg_visible",
        "skill_run_id": "skill_visible",
        "contract_name": "MarkdownNote",
        "content_type": "text/markdown",
        "content_class": "human_readable",
        "content_snapshot_id": "sha256:" + "a" * 64,
        "content_sha256": "a" * 64,
        "content_bytes": 42,
        "truncated": False,
        "title": "Daily note",
        "source_path": "daily/2026-06-12.md",
        "created_at": "2026-06-12T15:46:49Z",
    }
    content = overrides.get("content")
    if isinstance(content, str):
        content_bytes = content.encode("utf-8")
        overrides.setdefault("content_bytes", len(content_bytes))
        overrides.setdefault("content_sha256", hashlib.sha256(content_bytes).hexdigest())
    payload.update(overrides)
    return payload


def _sse_response(payload: bytes) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"content-type": "text/event-stream"},
        stream=httpx.ByteStream(payload),
    )


def _assert_control_response_contract_error(response: httpx.Response, issues: list[dict[str, str]]) -> None:
    assert response.status_code == 502
    assert response.json()["detail"] == {
        "error": "control_response_contract_invalid",
        "message": "Agent Control received an unexpected control-plane response.",
        "action": "Run Agent Control dev status and verify the upstream control-plane response schema before retrying.",
        "contract": _CONTROL_RESPONSE_CONTRACT,
        "issues": issues,
    }


def _assert_control_request_contract_error(response: httpx.Response, issues: list[dict[str, str]]) -> None:
    assert response.status_code == 400
    assert response.json()["detail"] == {
        "error": "control_request_contract_invalid",
        "message": "Agent Control received an invalid browser control-plane request.",
        "action": "Reload the page and retry the Agent Control action before continuing the run.",
        "contract": _CONTROL_REQUEST_CONTRACT,
        "issues": issues,
    }


def test_build_gateway_chat_payload_enforces_web_channel_and_user_id() -> None:
    payload = _build_gateway_chat_payload(
        GatewayChatRequest.model_validate(_chat_payload()),
        "web",
        user_key="101",
        request_id="req-1",
    )

    assert payload == {
        "messages": [{"role": "user", "content": "hello"}],
        "context": {
            "portfolio_name": "Main Portfolio",
            "channel": "web",
            "user_id": "101",
        },
        "metadata": {},
        "user_id": "101",
        "request_id": "req-1",
    }


def test_build_gateway_chat_payload_forwards_stable_intent_and_effort() -> None:
    request = GatewayChatRequest.model_validate(
        {
            **_chat_payload(),
            "model_key": "anthropic.claude-sonnet-5",
            "effort": "High",
            "catalog_revision": "2026-08-13.1",
        }
    )
    payload = _build_gateway_chat_payload(request, "web", user_key="101")

    assert payload["model_key"] == "anthropic.claude-sonnet-5"
    assert payload["effort"] == "high"
    assert payload["catalog_revision"] == "2026-08-13.1"
    assert payload["context"]["channel"] == "web"


def test_build_gateway_chat_payload_forwards_ui_blocks_contract_when_present() -> None:
    request = GatewayChatRequest.model_validate(
        {
            **_chat_payload(),
            "ui_blocks_contract": {
                "contract_version": 1,
            },
        }
    )

    payload = _build_gateway_chat_payload(request, "web", user_key="101")

    assert payload["ui_blocks_contract"] == {
        "contract_version": 1,
    }


def test_build_gateway_chat_payload_omits_ui_blocks_contract_when_absent() -> None:
    payload = _build_gateway_chat_payload(
        GatewayChatRequest.model_validate(_chat_payload()),
        "web",
        user_key="101",
    )

    assert "ui_blocks_contract" not in payload


def test_build_gateway_chat_payload_forwards_closed_attachment_envelope() -> None:
    request = GatewayChatRequest.model_validate(
        {**_chat_payload(), "attachments": [_chat_attachment()]}
    )

    payload = _build_gateway_chat_payload(
        request, "web", user_key="101", request_id="req-attach"
    )

    assert payload["attachments"] == [_chat_attachment()]
    assert "attachments" not in payload["context"]


def test_build_gateway_chat_payload_forwards_exact_investment_selection() -> None:
    request = GatewayChatRequest.model_validate(
        {
            **_chat_payload(),
            "investment_artifact_selection": {
                "artifact_id": "artifact:quant-1",
                "view": "excerpt",
            },
        }
    )

    payload = _build_gateway_chat_payload(request, "web", user_key="101")

    assert payload["investment_artifact_selection"] == {
        "artifact_id": "artifact:quant-1",
        "view": "excerpt",
    }
    assert "investment_artifact_selection" not in payload["context"]


@pytest.mark.parametrize(
    "selection",
    [
        {"artifact_id": "", "view": "summary"},
        {"artifact_id": " artifact:quant-1", "view": "summary"},
        {"artifact_id": "artifact:quant-1", "view": "schema"},
        {"artifact_id": "artifact:quant-1", "view": "SUMMARY"},
        {"artifact_id": "artifact:quant-1", "view": "summary", "run_id": "run-1"},
    ],
)
def test_gateway_chat_request_rejects_invalid_investment_selection(
    selection: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        GatewayChatRequest.model_validate(
            {
                **_chat_payload(),
                "investment_artifact_selection": selection,
            }
        )


@pytest.mark.parametrize(
    ("override", "expected_fragment"),
    [
        ({"content_b64": "data:text/plain;base64,aGVsbG8="}, "content_b64"),
        ({"content_b64": "aGVsbG8"}, "content_b64"),
        ({"content_sha256": "A" * 64}, "content_sha256"),
        ({"display_name": "../notes.md"}, "display_name"),
        ({"display_name": "notes\u0085.md"}, "display_name"),
        ({"media_type": "application/pdf"}, "media_type"),
        ({"unexpected": True}, "unexpected"),
    ],
)
def test_gateway_chat_request_rejects_invalid_attachment_contract(
    override: dict[str, Any],
    expected_fragment: str,
) -> None:
    attachment = {**_chat_attachment(), **override}
    with pytest.raises(ValidationError) as exc_info:
        GatewayChatRequest.model_validate(
            {**_chat_payload(), "attachments": [attachment]}
        )

    assert expected_fragment in str(exc_info.value)


def test_gateway_chat_request_rejects_non_deterministic_attachment_input_names() -> (
    None
):
    with pytest.raises(ValidationError, match="source_document_2"):
        GatewayChatRequest.model_validate(
            {
                **_chat_payload(),
                "attachments": [
                    _chat_attachment(),
                    {**_chat_attachment(index=2), "input_name": "other_name"},
                ],
            }
        )


def test_gateway_chat_request_rejects_empty_and_non_utf8_attachments() -> None:
    with pytest.raises(ValidationError):
        GatewayChatRequest.model_validate(
            {**_chat_payload(), "attachments": [_chat_attachment(b"")]}
        )
    with pytest.raises(ValidationError, match="valid UTF-8"):
        GatewayChatRequest.model_validate(
            {**_chat_payload(), "attachments": [_chat_attachment(b"\xff")]}
        )


def test_gateway_chat_request_bounds_encoded_attachment_before_decode() -> None:
    attachment = {
        **_chat_attachment(),
        "content_b64": "A" * 1_398_108,
    }

    with pytest.raises(ValidationError, match="at most 1398104 characters"):
        GatewayChatRequest.model_validate(
            {**_chat_payload(), "attachments": [attachment]}
        )


def test_gateway_chat_request_enforces_count_and_aggregate_byte_limits() -> None:
    with pytest.raises(ValidationError, match="more than 8 files"):
        GatewayChatRequest.model_validate(
            {
                **_chat_payload(),
                "attachments": [
                    _chat_attachment(
                        b"x",
                        index=index,
                        display_name=f"doc-{index}.txt",
                        media_type="text/plain",
                    )
                    for index in range(1, 10)
                ],
            }
        )

    one_mib = b"x" * (1024 * 1024)
    with pytest.raises(ValidationError, match="aggregate decoded byte limit"):
        GatewayChatRequest.model_validate(
            {
                **_chat_payload(),
                "attachments": [
                    _chat_attachment(
                        one_mib,
                        index=index,
                        display_name=f"doc-{index}.txt",
                        media_type="text/plain",
                    )
                    for index in range(1, 6)
                ],
            }
        )


def test_gateway_chat_request_rejects_invalid_effort() -> None:
    with pytest.raises(ValidationError):
        GatewayChatRequest.model_validate({**_chat_payload(), "effort": "ludicrous"})


def test_gateway_chat_request_rejects_non_string_model_key() -> None:
    with pytest.raises(ValidationError):
        GatewayChatRequest.model_validate(
            {**_chat_payload(), "model_key": ["anthropic.claude-sonnet-5"]}
        )


def test_gateway_chat_openapi_projects_canonical_request_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"OpenAPI generation must not call upstream: {request.url.path}")

    app, _router = _build_app(handler)
    schema = app.openapi()

    request_schema = schema["paths"]["/api/gateway/chat"]["post"]["requestBody"]
    assert request_schema["content"]["application/json"]["schema"] == {
        "$ref": "#/components/schemas/GatewayChatRequest"
    }
    gateway_chat_schema = schema["components"]["schemas"]["GatewayChatRequest"]
    assert gateway_chat_schema["additionalProperties"] is False
    assert gateway_chat_schema["required"] == ["messages"]
    assert gateway_chat_schema["properties"]["attachments"]["items"] == {
        "$ref": "#/components/schemas/ChatAttachmentV1"
    }
    assert (
        gateway_chat_schema["properties"]["ui_blocks_contract"]["anyOf"][0]
        == {"$ref": "#/components/schemas/GatewayUiBlocksContract"}
    )


def test_gateway_capability_choices_returns_session_driver_projection() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return httpx.Response(200, json={"status": "ok", "package": {"contracts": []}})
        if request.url.path == "/api/chat/init":
            return httpx.Response(
                200,
                json={
                    "session_token": "token-1",
                    "session_id": "sess-1",
                    "capability_choices": {
                        "session.driver": {
                            "capability": "session.driver",
                            "catalog_revision": "2026-08-13.1",
                            "policy_revision": "2026-08-13.1",
                            "selected": {
                                "model_key": "anthropic.claude-opus-5",
                                "label": "Opus 5",
                                "effort": "high",
                                "reason": "capability_default",
                            },
                            "notices": [],
                            "choices": [{
                                "model_key": "anthropic.claude-opus-5",
                                "label": "Opus 5",
                                "supported_efforts": ["high"],
                                "default_effort": "high",
                                "lifecycle": "active",
                            }],
                        }
                    },
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/capability-choices/session.driver",
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "capability": "session.driver",
        "catalog_revision": "2026-08-13.1",
        "policy_revision": "2026-08-13.1",
        "selected": {
            "model_key": "anthropic.claude-opus-5",
            "label": "Opus 5",
            "effort": "high",
            "reason": "capability_default",
        },
        "notices": [],
        "choices": [{
            "model_key": "anthropic.claude-opus-5",
            "label": "Opus 5",
            "supported_efforts": ["high"],
            "default_effort": "high",
            "lifecycle": "active",
        }],
    }


def test_get_user_key_requires_primary_user_id() -> None:
    with pytest.raises(HTTPException) as exc_info:
        _get_user_key({"google_user_id": "fallback", "email": "fallback@example.com"})

    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "Invalid user identity (user_id missing — auth middleware bug)"


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


def test_chat_subscribe_proxies_cached_research_conversation_session() -> None:
    subscribe_requests: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1", "session_id": "sess-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/subscribe":
            subscribe_requests.append({
                "authorization": request.headers.get("authorization"),
                "params": dict(request.url.params),
            })
            return _sse_response(
                b'data: {"seq":2,"session_id":"sess-1","schema_version":1,'
                b'"event":{"type":"stream_complete","usage":{}}}\n\n'
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        chat_response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "context": {
                    "purpose": "research_workspace",
                    "thread_id": 7,
                },
            },
            cookies={"session_id": "s-1"},
        )
        subscribe_response = client.get(
            "/api/gateway/chat/subscribe?conversation_id=7&after_seq=1"
            "&ui_blocks_contract_version=1",
            cookies={"session_id": "s-1"},
        )

    assert chat_response.status_code == 200
    assert subscribe_response.status_code == 200
    assert "stream_complete" in subscribe_response.text
    assert subscribe_requests == [
        {
            "authorization": "Bearer token-1",
            "params": {
                "session_id": "sess-1",
                "after_seq": "1",
                "client_label": "risk_module_web",
                "ui_blocks_contract_version": "1",
            },
        }
    ]


def test_chat_subscribe_requires_cached_conversation_session() -> None:
    calls = {"upstream": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["upstream"] += 1
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/chat/subscribe?conversation_id=7&after_seq=1",
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 404
    assert response.json() == {
        "detail": {
            "error": "gateway_chat_session_not_found",
            "message": "No cached gateway chat session exists for this conversation.",
        }
    }
    assert calls["upstream"] == 0


def test_chat_cancel_proxies_cached_conversation_session() -> None:
    cancel_requests: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1", "session_id": "sess-1"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/cancel":
            cancel_requests.append({
                "authorization": request.headers.get("authorization"),
                "body": json.loads(request.content.decode("utf-8")),
            })
            return httpx.Response(200, json={"status": "cancelled", "session_id": "sess-1"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        chat_response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "context": {
                    "purpose": "research_workspace",
                    "thread_id": 7,
                },
            },
            cookies={"session_id": "s-1"},
        )
        cancel_response = client.post(
            "/api/gateway/chat/cancel",
            json={"conversation_id": "7"},
            cookies={"session_id": "s-1"},
        )

    assert chat_response.status_code == 200
    assert cancel_response.status_code == 200
    assert cancel_response.json() == {"status": "cancelled", "session_id": "sess-1"}
    assert cancel_requests == [
        {
            "authorization": "Bearer token-1",
            "body": {"session_id": "sess-1"},
        }
    ]


def test_chat_cancel_proxies_cached_default_chat_session() -> None:
    cancel_requests: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1", "session_id": "sess-default"})
        if request.url.path == "/api/chat":
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/cancel":
            cancel_requests.append({
                "authorization": request.headers.get("authorization"),
                "body": json.loads(request.content.decode("utf-8")),
            })
            return httpx.Response(200, json={"status": "cancelled", "session_id": "sess-default"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        chat_response = client.post(
            "/api/gateway/chat",
            json={**_chat_payload(), "context": {"purpose": "chat"}},
            cookies={"session_id": "s-1"},
        )
        cancel_response = client.post(
            "/api/gateway/chat/cancel",
            json={},
            cookies={"session_id": "s-1"},
        )

    assert chat_response.status_code == 200
    assert cancel_response.status_code == 200
    assert cancel_response.json() == {"status": "cancelled", "session_id": "sess-default"}
    assert cancel_requests == [
        {
            "authorization": "Bearer token-1",
            "body": {"session_id": "sess-default"},
        }
    ]


def test_chat_cancel_requires_cached_conversation_session() -> None:
    calls = {"upstream": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        calls["upstream"] += 1
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat/cancel",
            json={"conversation_id": "7"},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 404
    assert response.json() == {
        "detail": {
            "error": "gateway_chat_session_not_found",
            "message": "No cached gateway chat session exists for this conversation.",
        }
    }
    assert calls["upstream"] == 0


def test_registered_user_control_proxy_requires_paid_tier() -> None:
    calls = {"session": 0, "runs": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            calls["session"] += 1
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            calls["runs"] += 1
            return httpx.Response(200, json={"runs": []})
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
            "/api/gateway/control/runs",
            json={"kind": "autonomous", "profile": "analyst", "mode": "task", "task": "summarize"},
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
    assert calls == {"session": 0, "runs": 0}


def test_normalizer_purpose_is_rejected_before_gateway_init() -> None:
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

    assert response.status_code == 400
    assert response.json() == {
        "detail": {
            "error": "chat_purpose_unavailable",
            "message": "The requested chat purpose is not available.",
        }
    }
    assert calls == {"init": 0, "chat": 0}


def test_tool_approval_uses_research_conversation_session_token() -> None:
    init_calls = 0
    chat_auth: list[str | None] = []
    approval_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal init_calls
        if request.url.path == "/api/chat/init":
            init_calls += 1
            return httpx.Response(200, json={"session_token": "thread-token-7"})
        if request.url.path == "/api/chat":
            chat_auth.append(request.headers.get("authorization"))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        if request.url.path == "/api/chat/tool-approval":
            approval_requests.append(
                {
                    "authorization": request.headers.get("authorization"),
                    "payload": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(200, json={"success": True})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        chat_response = client.post(
            "/api/gateway/chat",
            json={
                "messages": [{"role": "user", "content": "hello"}],
                "context": {
                    "portfolio_name": "Main Portfolio",
                    "purpose": "research_workspace",
                    "thread_id": 7,
                },
            },
            cookies={"session_id": "s-1"},
        )
        unscoped_approval = client.post(
            "/api/gateway/tool-approval",
            json={"tool_call_id": "tool-1", "nonce": "nonce-1", "approved": False},
            cookies={"session_id": "s-1"},
        )
        scoped_approval = client.post(
            "/api/gateway/tool-approval",
            json={
                "tool_call_id": "tool-1",
                "nonce": "nonce-1",
                "approved": False,
                "allow_tool_type": False,
                "conversation_id": "7",
            },
            cookies={"session_id": "s-1"},
        )

    assert chat_response.status_code == 200
    assert unscoped_approval.status_code == 400
    assert scoped_approval.status_code == 200
    assert init_calls == 1
    assert chat_auth == ["Bearer thread-token-7"]
    assert approval_requests == [
        {
            "authorization": "Bearer thread-token-7",
            "payload": {
                "tool_call_id": "tool-1",
                "nonce": "nonce-1",
                "approved": False,
                "allow_tool_type": False,
            },
        }
    ]


def test_gateway_capabilities_projects_attachment_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/health"
        return httpx.Response(
            200,
            json={
                "package": {"contracts": ["chat-attachments-v1", "private-contract"]}
            },
        )

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/capabilities", cookies={"session_id": "s-1"}
        )

    assert response.status_code == 200
    assert response.json() == {
        "schema_version": "gateway-capabilities/1",
        "status": "available",
        "contracts": ["chat-attachments-v1"],
    }


def test_gateway_capabilities_projects_investment_selected_content_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/health"
        return httpx.Response(
            200,
            json={
                "package": {
                    "contracts": [
                        "private-contract",
                        "investment-selected-content-v1",
                    ]
                }
            },
        )

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/capabilities", cookies={"session_id": "s-1"}
        )

    assert response.status_code == 200
    assert response.json()["contracts"] == ["investment-selected-content-v1"]


def test_gateway_capabilities_maps_upstream_failure_to_typed_503() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/health"
        return httpx.Response(500, json={"error": "unavailable"})

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/capabilities", cookies={"session_id": "s-1"})

    assert response.status_code == 503
    assert response.json()["detail"] == {
        "code": "capability_unavailable",
        "message": "Gateway capabilities are temporarily unavailable.",
    }


def test_attachment_chat_requires_capability_before_chat_init() -> None:
    calls = {"health": 0, "init": 0, "chat": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            calls["health"] += 1
            return httpx.Response(200, json={"package": {"contracts": []}})
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            calls["chat"] += 1
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={**_chat_payload(), "attachments": [_chat_attachment()]},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 412
    assert response.json()["detail"] == {
        "code": "attachment_contract_unavailable",
        "message": "The active gateway does not support chat attachments.",
    }
    assert calls == {"health": 1, "init": 0, "chat": 0}


def test_attachment_validation_error_does_not_echo_content_bytes() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(
            f"Invalid attachment must not reach upstream: {request.url.path}"
        )

    app, _router = _build_app(handler)
    invalid_content = "data:text/plain;base64,c2VjcmV0LXRleHQ="

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "attachments": [
                    {**_chat_attachment(), "content_b64": invalid_content},
                ],
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 422
    assert response.json()["detail"] == {
        "code": "attachment_invalid",
        "message": "An attachment did not match the chat attachment contract.",
        "input_name": "source_document",
    }
    assert invalid_content not in response.text
    assert "secret-text" not in response.text


@pytest.mark.parametrize(
    ("attachment_override", "expected_status", "expected_code"),
    [
        ({"media_type": "application/pdf"}, 415, "attachment_media_type_unsupported"),
        ({"content_bytes": 1024 * 1024 + 1}, 413, "attachment_limit_exceeded"),
        ({"content_sha256": "0" * 64}, 422, "attachment_invalid"),
    ],
)
def test_attachment_validation_maps_to_stable_http_statuses(
    attachment_override: dict[str, Any],
    expected_status: int,
    expected_code: str,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"Invalid attachment must not reach upstream: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "attachments": [{**_chat_attachment(), **attachment_override}],
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == expected_status
    assert response.json()["detail"]["code"] == expected_code
    assert response.json()["detail"]["input_name"] == "source_document"


def test_attachment_count_limit_maps_to_413_without_echoing_content() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"Invalid attachment must not reach upstream: {request.url.path}")

    app, _router = _build_app(handler)
    attachments = [
        _chat_attachment(
            b"x",
            index=index,
            display_name=f"doc-{index}.txt",
            media_type="text/plain",
        )
        for index in range(1, 10)
    ]

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={**_chat_payload(), "attachments": attachments},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 413
    assert response.json()["detail"] == {
        "code": "attachment_limit_exceeded",
        "message": "The attachment count or size limit was exceeded.",
    }
    assert attachments[0]["content_b64"] not in response.text


def test_attachment_chat_forwards_bytes_when_capability_is_present() -> None:
    upstream_payloads: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return httpx.Response(
                200,
                json={"package": {"contracts": ["chat-attachments-v1"]}},
            )
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            upstream_payloads.append(json.loads(request.content.decode("utf-8")))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={**_chat_payload(), "attachments": [_chat_attachment()]},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert upstream_payloads[0]["attachments"] == [_chat_attachment()]
    assert upstream_payloads[0]["messages"] == _chat_payload()["messages"]


def test_investment_selection_requires_capability_before_chat_init() -> None:
    calls = {"health": 0, "init": 0, "chat": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            calls["health"] += 1
            return httpx.Response(200, json={"package": {"contracts": []}})
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            calls["chat"] += 1
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "investment_artifact_selection": {
                    "artifact_id": "artifact:quant-1",
                    "view": "summary",
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 412
    assert response.json()["detail"] == {
        "code": "investment_selection_contract_unavailable",
        "message": "The active gateway does not support Investment selections.",
    }
    assert calls == {"health": 1, "init": 0, "chat": 0}


def test_investment_selection_is_forwarded_without_extra_authority() -> None:
    upstream_payloads: list[dict[str, Any]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return httpx.Response(
                200,
                json={
                    "package": {
                        "contracts": ["investment-selected-content-v1"]
                    }
                },
            )
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            upstream_payloads.append(json.loads(request.content.decode("utf-8")))
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)
    selection = {"artifact_id": "artifact:quant-1", "view": "excerpt"}

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "investment_artifact_selection": selection,
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert upstream_payloads[0]["investment_artifact_selection"] == selection
    assert set(upstream_payloads[0]["investment_artifact_selection"]) == {
        "artifact_id",
        "view",
    }


def test_investment_selection_validation_is_nonreflecting() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"Invalid selection reached upstream: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "investment_artifact_selection": {
                    "artifact_id": "/private/secret-artifact",
                    "view": "download",
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 422
    assert response.json()["detail"] == {
        "code": "investment_selection_invalid",
        "message": "The Investment selection did not match the gateway contract.",
    }
    assert "/private/secret-artifact" not in response.text


def test_required_gateway_contract_is_checked_before_chat_init() -> None:
    calls = {"health": 0, "init": 0, "chat": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            calls["health"] += 1
            return httpx.Response(
                200,
                json={
                    "status": "ok",
                    "package": {
                        "name": "ai-agent-gateway",
                        "version": "0.14.1",
                        "contracts": ["credential-refresh-v1"],
                    },
                },
            )
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            calls["chat"] += 1
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(
        handler,
        config=GatewayConfig(
            gateway_url="http://gateway.local",
            api_key="gateway-api-key",
            ssl_verify=True,
            required_contracts=frozenset({"credential-refresh-v1"}),
        ),
    )

    with TestClient(app) as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert calls == {"health": 1, "init": 1, "chat": 1}


def test_missing_required_gateway_contract_fails_before_chat_init() -> None:
    calls = {"health": 0, "init": 0, "chat": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            calls["health"] += 1
            return httpx.Response(
                200,
                json={
                    "status": "ok",
                    "package": {
                        "name": "ai-agent-gateway",
                        "version": "0.14.0",
                        "contracts": [],
                    },
                },
            )
        if request.url.path == "/api/chat/init":
            calls["init"] += 1
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            calls["chat"] += 1
            return _sse_response(b'data: {"type":"stream_complete"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(
        handler,
        config=GatewayConfig(
            gateway_url="http://gateway.local",
            api_key="gateway-api-key",
            ssl_verify=True,
            required_contracts=frozenset({"credential-refresh-v1"}),
        ),
    )

    with TestClient(app) as client:
        response = client.post("/api/gateway/chat", json=_chat_payload(), cookies={"session_id": "s-1"})

    assert response.status_code == 502
    assert response.json()["detail"] == {
        "error": "gateway_contract_missing",
        "message": "Gateway runtime is missing required contracts.",
        "missing_contracts": ["credential-refresh-v1"],
        "available_contracts": [],
    }
    assert calls == {"health": 1, "init": 0, "chat": 0}


def test_missing_required_gateway_contract_fails_before_control_events_stream() -> None:
    calls = {"health": 0, "session": 0, "events": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            calls["health"] += 1
            return httpx.Response(
                200,
                json={
                    "status": "ok",
                    "package": {
                        "name": "ai-agent-gateway",
                        "version": "0.14.0",
                        "contracts": [],
                    },
                },
            )
        if request.url.path == "/api/control/session":
            calls["session"] += 1
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/events":
            calls["events"] += 1
            return _sse_response(b'data: {"type":"heartbeat"}\n\n')
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(
        handler,
        config=GatewayConfig(
            gateway_url="http://gateway.local",
            api_key="gateway-api-key",
            ssl_verify=True,
            required_contracts=frozenset({"credential-refresh-v1"}),
        ),
    )

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/events", cookies={"session_id": "s-1"})

    assert response.status_code == 502
    assert response.json()["detail"] == {
        "error": "gateway_contract_missing",
        "message": "Gateway runtime is missing required contracts.",
        "missing_contracts": ["credential-refresh-v1"],
        "available_contracts": [],
    }
    assert calls == {"health": 1, "session": 0, "events": 0}


def test_control_proxy_bootstraps_control_session_and_forwards_health() -> None:
    calls: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            calls.append({"path": request.url.path, "body": json.loads(request.content.decode("utf-8"))})
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/health":
            calls.append({"path": request.url.path, "authorization": request.headers.get("authorization")})
            return httpx.Response(
                200,
                json={"status": "ok", "version": "1", "endpoints": ["GET /api/control/health"]},
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/health", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json()["version"] == "1"
    assert response.json()["control_plane_version"] == "1"
    assert response.headers["x-control-plane-version"] == "1"
    assert len(calls) == 2
    assert calls[0]["path"] == "/api/control/session"
    _assert_web_session_init_payload(calls[0]["body"])
    assert calls[1] == {
        "path": "/api/control/health",
        "authorization": "Bearer control-token",
    }


def test_control_proxy_bootstrap_and_generic_dispatch_do_not_require_portfolio_context() -> None:
    calls: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            calls.append({"path": request.url.path, "body": json.loads(request.content.decode("utf-8"))})
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/health":
            calls.append({"path": request.url.path, "authorization": request.headers.get("authorization")})
            return httpx.Response(
                200,
                json={"status": "ok", "version": "1", "endpoints": ["GET /api/control/health"]},
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/profiles":
            calls.append({"path": request.url.path, "authorization": request.headers.get("authorization")})
            return httpx.Response(200, json={"profiles": [{"name": "analyst"}]})
        if request.url.path == "/api/control/runs":
            calls.append(
                {
                    "path": request.url.path,
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(
                200,
                json={"run": {"kind": "autonomous", "run_id": "bg_generic", "state": "running"}},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(
        handler,
        user_by_session=lambda _session_id: {
            "user_id": 101,
            "email": "test@example.com",
            "tier": "paid",
        },
    )

    with TestClient(app) as client:
        health = client.get("/api/gateway/control/health", cookies={"session_id": "s-1"})
        dispatch = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "task",
                "task": "Summarize control health.",
            },
            cookies={"session_id": "s-1"},
        )

    assert health.status_code == 200
    assert dispatch.status_code == 200
    assert dispatch.json() == {
        "run": {"kind": "autonomous", "run_id": "bg_generic", "state": "running"},
    }
    assert len(calls) == 4
    assert calls[0]["path"] == "/api/control/session"
    _assert_web_session_init_payload(calls[0]["body"])
    assert calls[1:] == [
        {"path": "/api/control/health", "authorization": "Bearer control-token"},
        {"path": "/api/control/profiles", "authorization": "Bearer control-token"},
        {
            "path": "/api/control/runs",
            "authorization": "Bearer control-token",
            "body": {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "task",
                "task": "Summarize control health.",
                "channel": "web",
            },
        },
    ]


def test_control_proxy_rejects_incompatible_control_plane_version() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/health":
            return httpx.Response(
                200,
                json={"status": "ok", "version": "2", "endpoints": []},
                headers={"X-Control-Plane-Version": "2"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/health", cookies={"session_id": "s-1"})

    assert response.status_code == 502
    assert response.json() == {
        "detail": {
            "error": "control_plane_version_mismatch",
            "message": "Gateway control plane version is not compatible with this client.",
            "expected_version": "1",
            "actual_version": "2",
        }
    }
    assert response.headers["x-control-plane-version"] == "2"


def test_control_proxy_rejects_missing_control_plane_version_on_health_gate() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/health":
            return httpx.Response(200, json={"status": "ok", "endpoints": []})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/health", cookies={"session_id": "s-1"})

    assert response.status_code == 502
    assert response.json() == {
        "detail": {
            "error": "control_plane_version_mismatch",
            "message": "Gateway control plane version is not compatible with this client.",
            "expected_version": "1",
            "actual_version": "missing",
        }
    }
    assert "x-control-plane-version" not in response.headers


def test_control_proxy_rejects_incompatible_control_plane_version_for_events_stream() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/events":
            return httpx.Response(
                200,
                headers={
                    "content-type": "text/event-stream",
                    "X-Control-Plane-Version": "2",
                },
                stream=httpx.ByteStream(b'data: {"type":"heartbeat"}\n\n'),
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/events", cookies={"session_id": "s-1"})

    assert response.status_code == 502
    assert response.json() == {
        "detail": {
            "error": "control_plane_version_mismatch",
            "message": "Gateway control plane version is not compatible with this client.",
            "expected_version": "1",
            "actual_version": "2",
        }
    }
    assert response.headers["x-control-plane-version"] == "2"


def test_control_proxy_allows_read_only_artifacts_and_schedules() -> None:
    requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path in {
            "/api/control/artifacts",
            "/api/artifacts/PCTY/earnings-scenarios/latest",
            "/api/control/schedules",
        }:
            requests.append(
                {
                    "path": request.url.path,
                    "authorization": request.headers.get("authorization"),
                    "params": dict(request.url.params),
                }
            )
            key = "artifact_id" if request.url.path.endswith("/latest") else request.url.path.rsplit("/", 1)[-1]
            if key == "artifact_id":
                return httpx.Response(
                    200,
                    json={"artifact_id": "latest-artifact"},
                    headers={"X-Control-Plane-Version": "1"},
                )
            if key == "schedules":
                return httpx.Response(
                    200,
                    json={
                        "schedules": [
                            {
                                "id": 123,
                                "name": "advisor-weekly",
                                "source": "launchd",
                                "enabled": True,
                                "command": ["python", "scripts/run_advisor.py"],
                                "working_directory": "/Users/example/project",
                                "log_file": "/tmp/advisor.log",
                                "environment": {"SECRET_TOKEN": "do-not-forward"},
                            }
                        ]
                    },
                    headers={"X-Control-Plane-Version": "1"},
                )
            return httpx.Response(200, json={key: []}, headers={"X-Control-Plane-Version": "1"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        artifacts = client.get(
            "/api/gateway/control/artifacts?run_id=bg_1&limit=3",
            cookies={"session_id": "s-1"},
        )
        artifact = client.get(
            "/api/gateway/artifacts/PCTY/earnings-scenarios/latest",
            cookies={"session_id": "s-1"},
        )
        schedules = client.get("/api/gateway/control/schedules", cookies={"session_id": "s-1"})

    assert artifacts.status_code == 200
    assert artifacts.json() == {"artifacts": []}
    assert artifact.status_code == 200
    assert artifact.json() == {"artifact_id": "latest-artifact"}
    assert schedules.status_code == 200
    assert schedules.json() == {
        "schedules": [
            {
                "id": 123,
                "name": "advisor-weekly",
                "source": "launchd",
                "enabled": True,
            }
        ]
    }
    assert requests == [
        {
            "path": "/api/control/artifacts",
            "authorization": "Bearer control-token",
            "params": {"run_id": "bg_1", "limit": "3"},
        },
        {
            "path": "/api/artifacts/PCTY/earnings-scenarios/latest",
            "authorization": "Bearer control-token",
            "params": {},
        },
        {
            "path": "/api/control/schedules",
            "authorization": "Bearer control-token",
            "params": {},
        },
    ]


def test_control_proxy_projects_skill_catalog_to_browser_safe_fields() -> None:
    requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/skills":
            requests.append(
                {
                    "path": request.url.path,
                    "authorization": request.headers.get("authorization"),
                    "params": dict(request.url.params),
                }
            )
            return httpx.Response(
                200,
                json={
                    "skills": [
                        {
                            "name": "earnings-review",
                            "label": "Earnings review",
                            "description": "Review recent earnings.",
                            "agent_description": "Runs the earnings review agent skill.",
                            "version": "1.0",
                            "scope": "portfolio",
                            "catalog": True,
                            "agent_callable": True,
                            "can_schedule": True,
                            "required_context": ["ticker"],
                            "credential_requirements": ["market-data"],
                            "max_turns": 8,
                            "max_budget_usd": 1.25,
                            "persist_state": False,
                            "typed_contract": "earnings-review-v1",
                            "path": "/Users/example/private/skills/earnings-review.yaml",
                            "body": "# internal skill prompt",
                            "command": ["python", "scripts/run_skill.py"],
                            "working_directory": "/Users/example/project",
                            "credentials": {"api_key": "do-not-forward"},
                            "environment": {"SECRET_TOKEN": "do-not-forward"},
                        }
                    ]
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/skills", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json() == {
        "skills": [
            {
                "name": "earnings-review",
                "label": "Earnings review",
                "description": "Review recent earnings.",
                "agent_description": "Runs the earnings review agent skill.",
                "version": "1.0",
                "scope": "portfolio",
                "catalog": True,
                "agent_callable": True,
                "can_schedule": True,
                "required_context": ["ticker"],
                "credential_requirements": ["market-data"],
                "max_turns": 8,
                "max_budget_usd": 1.25,
                "persist_state": False,
                "typed_contract": "earnings-review-v1",
            }
        ]
    }
    assert requests == [
        {
            "path": "/api/control/skills",
            "authorization": "Bearer control-token",
            "params": {},
        }
    ]


@pytest.mark.parametrize(
    ("catalog", "diagnostics"),
    [
        (
            {
                "schema_version": "skill-catalog-snapshot/1",
                "status": "healthy",
                "catalog_digest": "sha256:" + "a" * 64,
                "invalid_count": 0,
            },
            [],
        ),
        (
            {
                "schema_version": "skill-catalog-snapshot/1",
                "status": "degraded",
                "catalog_digest": "sha256:" + "b" * 64,
                "invalid_count": 1,
            },
            [
                {
                    "skill_name": "invalid-skill",
                    "code": "profile_invalid",
                    "stage": "profile",
                }
            ],
        ),
    ],
    ids=("healthy", "degraded"),
)
def test_control_proxy_preserves_canonical_skill_catalog_status(
    catalog: dict[str, object],
    diagnostics: list[dict[str, str]],
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/skills":
            return httpx.Response(
                200,
                json={
                    "skills": [{"name": "earnings-review"}],
                    "catalog": catalog,
                    "diagnostics": diagnostics,
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/skills", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json() == {
        "skills": [{"name": "earnings-review"}],
        "catalog": catalog,
        "diagnostics": diagnostics,
    }


@pytest.mark.parametrize(
    ("payload", "issue_path"),
    [
        (
            {
                "skills": [],
                "catalog": {
                    "schema_version": "skill-catalog-snapshot/1",
                    "status": "healthy",
                    "catalog_digest": "not-a-digest",
                    "invalid_count": 0,
                },
                "diagnostics": [],
            },
            "catalog.catalog_digest",
        ),
        (
            {
                "skills": [],
                "catalog": {
                    "schema_version": "skill-catalog-snapshot/1",
                    "status": "degraded",
                    "catalog_digest": "sha256:" + "c" * 64,
                    "invalid_count": 1,
                },
                "diagnostics": [
                    {
                        "skill_name": "invalid-skill",
                        "code": "profile_invalid",
                        "stage": "profile",
                        "message": "private parser details must not cross the proxy",
                    }
                ],
            },
            "diagnostics[0].message",
        ),
    ],
    ids=("invalid-digest", "diagnostic-extra-field"),
)
def test_control_proxy_rejects_malformed_skill_catalog_status(
    payload: dict[str, object],
    issue_path: str,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/skills":
            return httpx.Response(
                200,
                json=payload,
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/skills", cookies={"session_id": "s-1"})

    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["error"] == "control_response_contract_invalid"
    assert [issue["path"] for issue in detail["issues"]] == [issue_path]


def test_control_proxy_rejects_malformed_skill_catalog_response() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/skills":
            return httpx.Response(
                200,
                json={"skills": [{"description": "missing name"}]},
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/skills", cookies={"session_id": "s-1"})

    _assert_control_response_contract_error(
        response,
        [
            {
                "path": "skills[0].name",
                "message": "Field required",
                "type": "missing",
            }
        ],
    )


def test_control_proxy_rejects_object_skill_requirement_metadata() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/skills":
            return httpx.Response(
                200,
                json={
                    "skills": [
                        {
                            "name": "earnings-review",
                            "catalog": True,
                            "agent_callable": True,
                            "credential_requirements": {"token": "do-not-forward"},
                        }
                    ]
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/skills", cookies={"session_id": "s-1"})

    assert response.status_code == 502
    detail = response.json()["detail"]
    assert detail["error"] == "control_response_contract_invalid"
    assert any(
        issue["path"].startswith("skills[0].credential_requirements")
        for issue in detail["issues"]
    )


def test_control_proxy_rejects_non_finite_skill_budget_metadata() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/skills":
            return httpx.Response(
                200,
                content=(
                    b'{"skills":[{"name":"earnings-review","catalog":true,'
                    b'"agent_callable":true,"max_budget_usd":NaN}]}'
                ),
                headers={
                    "Content-Type": "application/json",
                    "X-Control-Plane-Version": "1",
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/skills", cookies={"session_id": "s-1"})

    _assert_control_response_contract_error(
        response,
        [
            {
                "path": "skills[0].max_budget_usd",
                "message": "Value error, max_budget_usd must be finite",
                "type": "value_error",
            }
        ],
    )


def test_control_proxy_filters_artifacts_to_visible_control_runs() -> None:
    requests: list[dict[str, object]] = []
    artifacts_payload = {
        "artifacts": [
            {
                "artifact_id": "artifact_visible",
                "run_id": "skill_visible",
                "skill_run_id": "skill_visible",
                "contract_name": "HtmlArtifact",
            },
            {
                "artifact_id": "artifact_hidden",
                "run_id": "bg_cli",
                "skill_run_id": "bg_cli",
                "contract_name": "HtmlArtifact",
            },
            {
                "artifact_id": "artifact_conflicting_owner",
                "control_run_id": "bg_cli",
                "run_id": "skill_visible",
                "skill_run_id": "skill_visible",
                "contract_name": "HtmlArtifact",
            },
            {
                "artifact_id": "artifact_orphaned",
                "contract_name": "DashboardArtifact",
            },
        ]
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append({"path": request.url.path, "params": dict(request.url.params)})
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/artifacts":
            return httpx.Response(200, json=artifacts_payload, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "runs": [
                        {
                            "kind": "autonomous",
                            "run_id": "bg_visible",
                            "task_id": "task_visible",
                            "state": "completed",
                            "skill_run_ids": ["skill_visible"],
                        }
                    ]
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/bg_visible":
            return httpx.Response(
                200,
                json={
                    "kind": "autonomous",
                    "run_id": "bg_visible",
                    "task_id": "task_visible",
                    "state": "completed",
                    "skill_run_ids": ["skill_visible"],
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/skill_visible":
            return httpx.Response(404, json={"detail": "Run not found"}, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs/bg_cli":
            return httpx.Response(404, json={"detail": "Run not found"}, headers={"X-Control-Plane-Version": "1"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        global_artifacts = client.get("/api/gateway/control/artifacts?limit=24", cookies={"session_id": "s-1"})
        visible_run_artifacts = client.get(
            "/api/gateway/control/artifacts?run_id=bg_visible&limit=24",
            cookies={"session_id": "s-1"},
        )
        hidden_run_artifacts = client.get(
            "/api/gateway/control/artifacts?run_id=bg_cli&limit=24",
            cookies={"session_id": "s-1"},
        )

    assert global_artifacts.status_code == 200
    assert [artifact["artifact_id"] for artifact in global_artifacts.json()["artifacts"]] == ["artifact_visible"]
    assert visible_run_artifacts.status_code == 200
    assert [artifact["artifact_id"] for artifact in visible_run_artifacts.json()["artifacts"]] == ["artifact_visible"]
    assert hidden_run_artifacts.status_code == 200
    assert hidden_run_artifacts.json() == {"artifacts": []}
    run_visibility_requests = [
        request for request in requests
        if request["path"] in {
            "/api/control/runs",
            "/api/control/runs/bg_visible",
            "/api/control/runs/skill_visible",
            "/api/control/runs/bg_cli",
        }
    ]
    assert run_visibility_requests == [
        {"path": "/api/control/runs/skill_visible", "params": {}},
        {"path": "/api/control/runs", "params": {"limit": "200"}},
        {"path": "/api/control/runs/bg_cli", "params": {}},
        {"path": "/api/control/runs/bg_visible", "params": {}},
        {"path": "/api/control/runs/bg_cli", "params": {}},
    ]


def test_control_proxy_filters_readable_resources_to_visible_human_readable_runs() -> None:
    requests: list[dict[str, object]] = []
    resources_payload = {
        "readable_resources": [
            _readable_resource_payload(),
            _readable_resource_payload(
                resource_id="note:bg_cli:daily:2026-06-12",
                control_run_id="bg_cli",
                skill_run_id="skill_cli",
            ),
            _readable_resource_payload(
                resource_id="note:bg_visible:trace",
                content_class="dev_only",
            ),
        ],
        "next_cursor": "cursor-1",
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append({"path": request.url.path, "params": dict(request.url.params)})
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/readable-resources":
            return httpx.Response(200, json=resources_payload, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "runs": [
                        {
                            "kind": "autonomous",
                            "run_id": "bg_visible",
                            "task_id": "task_visible",
                            "state": "completed",
                            "skill_run_ids": ["skill_visible"],
                        }
                    ]
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/bg_visible":
            return httpx.Response(
                200,
                json={
                    "kind": "autonomous",
                    "run_id": "bg_visible",
                    "task_id": "task_visible",
                    "state": "completed",
                    "skill_run_ids": ["skill_visible"],
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/bg_cli":
            return httpx.Response(404, json={"detail": "Run not found"}, headers={"X-Control-Plane-Version": "1"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/readable-resources?limit=24", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json() == {
        "readable_resources": [_readable_resource_payload()],
        "next_cursor": "cursor-1",
    }
    assert [
        request for request in requests
        if request["path"] in {"/api/control/runs", "/api/control/runs/bg_visible", "/api/control/runs/bg_cli"}
    ] == [
        {"path": "/api/control/runs/bg_visible", "params": {}},
        {"path": "/api/control/runs/bg_cli", "params": {}},
        {"path": "/api/control/runs", "params": {"limit": "200"}},
    ]


def test_control_proxy_rejects_readable_resource_list_content_leak_after_filtering() -> None:
    resource = _readable_resource_payload(content="## Should only appear on detail")

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/readable-resources":
            return httpx.Response(
                200,
                json={"readable_resources": [resource]},
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/bg_visible":
            return httpx.Response(
                200,
                json={"kind": "autonomous", "run_id": "bg_visible", "task_id": "task_visible", "state": "completed"},
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/readable-resources", cookies={"session_id": "s-1"})

    _assert_control_response_contract_error(
        response,
        [{"path": "readable_resources[0].content", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}],
    )


def test_control_proxy_degrades_missing_readable_resource_list_to_empty() -> None:
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/readable-resources":
            return httpx.Response(404, json={"detail": "Not Found"}, headers={"X-Control-Plane-Version": "1"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/readable-resources?limit=24", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json() == {"readable_resources": []}
    assert requests == ["/api/control/session", "/api/control/readable-resources"]


def test_control_proxy_serves_visible_readable_resource_detail() -> None:
    resource = _readable_resource_payload(content="## Daily note\n\nCaptured markdown.")
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/readable-resources/note:bg_visible:daily:2026-06-12":
            return httpx.Response(200, json=resource, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs/bg_visible":
            return httpx.Response(
                200,
                json={
                    "kind": "autonomous",
                    "run_id": "bg_visible",
                    "task_id": "task_visible",
                    "state": "completed",
                    "skill_run_ids": ["skill_visible"],
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/control/readable-resources/note:bg_visible:daily:2026-06-12",
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json() == resource
    assert requests == [
        "/api/control/session",
        "/api/control/readable-resources/note:bg_visible:daily:2026-06-12",
        "/api/control/runs/bg_visible",
    ]


def test_control_proxy_denies_hidden_or_dev_only_readable_resource_detail() -> None:
    hidden_resource = _readable_resource_payload(
        resource_id="note:bg_cli:daily:2026-06-12",
        control_run_id="bg_cli",
        skill_run_id="skill_cli",
        content="## Hidden note",
        content_bytes=999,
    )
    dev_only_resource = _readable_resource_payload(
        resource_id="note:bg_visible:trace",
        content_class="dev_only",
        content="{}",
    )

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/readable-resources/note:bg_cli:daily:2026-06-12":
            return httpx.Response(200, json=hidden_resource, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/readable-resources/note:bg_visible:trace":
            return httpx.Response(200, json=dev_only_resource, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs/bg_cli":
            return httpx.Response(404, json={"detail": "Run not found"}, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(200, json={"runs": []}, headers={"X-Control-Plane-Version": "1"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        hidden = client.get(
            "/api/gateway/control/readable-resources/note:bg_cli:daily:2026-06-12",
            cookies={"session_id": "s-1"},
        )
        dev_only = client.get(
            "/api/gateway/control/readable-resources/note:bg_visible:trace",
            cookies={"session_id": "s-1"},
        )

    assert hidden.status_code == 404
    assert hidden.json()["detail"]["error"] == "readable_resource_not_found"
    assert dev_only.status_code == 404
    assert dev_only.json()["detail"]["error"] == "readable_resource_not_found"


def test_control_proxy_keeps_global_artifacts_for_directly_visible_older_owner_runs() -> None:
    requests: list[dict[str, object]] = []
    artifacts_payload = {
        "artifacts": [
            {
                "artifact_id": "artifact_old_control_owner",
                "control_run_id": "bg_old_control_visible",
                "skill_run_id": "skill_old_control_visible",
                "contract_name": "HtmlArtifact",
            },
            {
                "artifact_id": "artifact_old_run_id_owner",
                "run_id": "bg_old_run_id_visible",
                "skill_run_id": "skill_old_run_id_visible",
                "contract_name": "HtmlArtifact",
            },
            {
                "artifact_id": "artifact_hidden_owner",
                "control_run_id": "bg_cli_hidden",
                "skill_run_id": "skill_hidden_owner",
                "contract_name": "HtmlArtifact",
            },
        ]
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append({"path": request.url.path, "params": dict(request.url.params)})
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/artifacts":
            return httpx.Response(200, json=artifacts_payload, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs/bg_old_control_visible":
            return httpx.Response(
                200,
                json={
                    "kind": "autonomous",
                    "run_id": "bg_old_control_visible",
                    "task_id": "task_old_control_visible",
                    "state": "completed",
                    "skill_run_ids": [],
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/bg_old_run_id_visible":
            return httpx.Response(
                200,
                json={
                    "kind": "autonomous",
                    "run_id": "bg_old_run_id_visible",
                    "task_id": "task_old_run_id_visible",
                    "state": "completed",
                    "skill_run_ids": ["skill_old_run_id_visible"],
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/bg_cli_hidden":
            return httpx.Response(404, json={"detail": "Run not found"}, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(200, json={"runs": []}, headers={"X-Control-Plane-Version": "1"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/artifacts?limit=24", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert [artifact["artifact_id"] for artifact in response.json()["artifacts"]] == [
        "artifact_old_control_owner",
        "artifact_old_run_id_owner",
    ]
    assert requests == [
        {"path": "/api/control/session", "params": {}},
        {"path": "/api/control/artifacts", "params": {"limit": "24"}},
        {"path": "/api/control/runs/bg_old_control_visible", "params": {}},
        {"path": "/api/control/runs/bg_old_run_id_visible", "params": {}},
        {"path": "/api/control/runs/bg_cli_hidden", "params": {}},
        {"path": "/api/control/runs", "params": {"limit": "200"}},
    ]


def test_control_proxy_rejects_conflicting_explicit_artifact_owner_fields() -> None:
    artifacts_payload = {
        "artifacts": [
            {
                "artifact_id": "artifact_conflicting_explicit_owner",
                "control_run_id": "bg_hidden",
                "task_id": "task_visible",
                "skill_run_id": "skill_conflicting_owner",
                "contract_name": "HtmlArtifact",
            },
            {
                "artifact_id": "artifact_consistent_explicit_owner",
                "control_run_id": "bg_visible",
                "task_id": "task_visible",
                "skill_run_id": "skill_consistent_owner",
                "contract_name": "HtmlArtifact",
            },
        ]
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/artifacts":
            return httpx.Response(200, json=artifacts_payload, headers={"X-Control-Plane-Version": "1"})
        if request.url.path in {"/api/control/runs/bg_visible", "/api/control/runs/task_visible"}:
            return httpx.Response(
                200,
                json={
                    "kind": "autonomous",
                    "run_id": "bg_visible",
                    "task_id": "task_visible",
                    "state": "completed",
                    "skill_run_ids": [],
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/bg_hidden":
            return httpx.Response(404, json={"detail": "Run not found"}, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "runs": [
                        {
                            "kind": "autonomous",
                            "run_id": "bg_visible",
                            "task_id": "task_visible",
                            "state": "completed",
                        }
                    ]
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/artifacts?limit=24", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert [artifact["artifact_id"] for artifact in response.json()["artifacts"]] == [
        "artifact_consistent_explicit_owner"
    ]


def test_control_proxy_rejects_conflicting_visible_explicit_owner_fields_from_recent_runs() -> None:
    artifacts_payload = {
        "artifacts": [
            {
                "artifact_id": "artifact_conflicting_visible_owners",
                "control_run_id": "bg_recent_a",
                "task_id": "task_recent_b",
                "skill_run_id": "skill_conflicting_recent",
                "contract_name": "HtmlArtifact",
            },
            {
                "artifact_id": "artifact_consistent_recent_owners",
                "control_run_id": "bg_recent_a",
                "task_id": "task_recent_a",
                "skill_run_id": "skill_consistent_recent",
                "contract_name": "HtmlArtifact",
            },
        ]
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/artifacts":
            return httpx.Response(200, json=artifacts_payload, headers={"X-Control-Plane-Version": "1"})
        if request.url.path in {
            "/api/control/runs/bg_recent_a",
            "/api/control/runs/task_recent_a",
            "/api/control/runs/task_recent_b",
        }:
            return httpx.Response(404, json={"detail": "Run not found"}, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "runs": [
                        {
                            "kind": "autonomous",
                            "run_id": "bg_recent_a",
                            "task_id": "task_recent_a",
                            "state": "completed",
                        },
                        {
                            "kind": "autonomous",
                            "run_id": "bg_recent_b",
                            "task_id": "task_recent_b",
                            "state": "completed",
                        },
                    ]
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/artifacts?limit=24", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert [artifact["artifact_id"] for artifact in response.json()["artifacts"]] == [
        "artifact_consistent_recent_owners"
    ]


def test_control_proxy_rejects_direct_owner_lookup_without_valid_run_contract() -> None:
    artifacts_payload = {
        "artifacts": [
            {
                "artifact_id": "artifact_unversioned_owner",
                "run_id": "bg_unversioned",
                "contract_name": "HtmlArtifact",
            },
            {
                "artifact_id": "artifact_invalid_owner_contract",
                "run_id": "bg_invalid_contract",
                "contract_name": "HtmlArtifact",
            },
        ]
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/artifacts":
            return httpx.Response(200, json=artifacts_payload, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs/bg_unversioned":
            return httpx.Response(
                200,
                json={"kind": "autonomous", "run_id": "bg_unversioned", "state": "completed"},
            )
        if request.url.path == "/api/control/runs/bg_invalid_contract":
            return httpx.Response(
                200,
                json={"kind": "autonomous", "run_id": "bg_invalid_contract", "state": "unknown"},
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs":
            return httpx.Response(200, json={"runs": []}, headers={"X-Control-Plane-Version": "1"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/artifacts?limit=24", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json() == {"artifacts": []}


def test_control_proxy_caps_explicit_artifact_owner_lookups() -> None:
    too_many_owner_ids = [f"bg_owner_{index}" for index in range(65)]
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/artifacts":
            return httpx.Response(
                200,
                json={"artifacts": [{"artifact_id": "artifact_too_many_owners", "control_run_id": too_many_owner_ids}]},
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/artifacts?limit=24", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json() == {"artifacts": []}
    assert calls == ["/api/control/session", "/api/control/artifacts"]


def test_artifact_detail_proxy_refreshes_stale_control_token() -> None:
    session_tokens = iter(["stale-token", "fresh-token"])
    artifact_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": next(session_tokens)})
        if request.url.path == "/api/artifacts/PCTY/earnings-scenarios/latest":
            artifact_requests.append(
                {
                    "authorization": request.headers.get("authorization"),
                    "params": dict(request.url.params),
                }
            )
            if request.headers.get("authorization") == "Bearer stale-token":
                return httpx.Response(401, json={"detail": "expired"})
            return httpx.Response(
                200,
                json={"artifact_id": "latest-artifact", "verdict": {"verdict_token": "READY"}},
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/artifacts/PCTY/earnings-scenarios/latest?view=panel",
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json()["artifact_id"] == "latest-artifact"
    assert artifact_requests == [
        {"authorization": "Bearer stale-token", "params": {"view": "panel"}},
        {"authorization": "Bearer fresh-token", "params": {"view": "panel"}},
    ]


def test_artifact_detail_proxy_requires_visible_control_artifact_owner() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/artifacts/PCTY/critical-factors/hidden-artifact":
            return httpx.Response(
                200,
                json={
                    "artifact_id": "hidden-artifact",
                    "control_run_id": "bg_hidden",
                    "contract_name": "CriticalFactors",
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/bg_hidden":
            return httpx.Response(404, json={"detail": "Run not found"}, headers={"X-Control-Plane-Version": "1"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "runs": [
                        {
                            "kind": "autonomous",
                            "run_id": "bg_visible",
                            "task_id": "task_visible",
                            "state": "completed",
                        }
                    ]
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/artifacts/PCTY/critical-factors/hidden-artifact",
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 404
    assert response.json()["detail"]["error"] == "artifact_not_found"
    assert calls == [
        "/api/control/session",
        "/api/artifacts/PCTY/critical-factors/hidden-artifact",
        "/api/control/runs/bg_hidden",
        "/api/control/runs",
    ]


def test_artifact_detail_proxy_allows_directly_visible_older_run_id_owner() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/artifacts/PCTY/critical-factors/old-artifact":
            return httpx.Response(
                200,
                json={
                    "artifact_id": "old-artifact",
                    "run_id": "bg_old_visible",
                    "skill_run_id": "skill_old_visible",
                    "contract_name": "CriticalFactors",
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/bg_old_visible":
            return httpx.Response(
                200,
                json={
                    "kind": "autonomous",
                    "run_id": "bg_old_visible",
                    "task_id": "task_old_visible",
                    "state": "completed",
                    "skill_run_ids": ["skill_old_visible"],
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/artifacts/PCTY/critical-factors/old-artifact",
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json()["artifact_id"] == "old-artifact"
    assert calls == [
        "/api/control/session",
        "/api/artifacts/PCTY/critical-factors/old-artifact",
        "/api/control/runs/bg_old_visible",
    ]


def test_artifact_detail_proxy_rejects_non_json_success_response() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/artifacts/PCTY/critical-factors/text-artifact":
            return httpx.Response(
                200,
                text="not json",
                headers={"content-type": "text/plain", "X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/artifacts/PCTY/critical-factors/text-artifact",
            cookies={"session_id": "s-1"},
        )

    _assert_control_response_contract_error(
        response,
        [{"path": "$", "message": "artifact detail response must be JSON", "type": "value_error"}],
    )
    assert calls == [
        "/api/control/session",
        "/api/artifacts/PCTY/critical-factors/text-artifact",
    ]


def test_artifact_detail_proxy_rejects_malformed_json_success_response() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/artifacts/PCTY/critical-factors/malformed-artifact":
            return httpx.Response(
                200,
                content=b"{not-json",
                headers={"content-type": "application/json", "X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/artifacts/PCTY/critical-factors/malformed-artifact",
            cookies={"session_id": "s-1"},
        )

    _assert_control_response_contract_error(
        response,
        [{"path": "$", "message": "artifact detail response must be valid JSON", "type": "value_error"}],
    )
    assert calls == [
        "/api/control/session",
        "/api/artifacts/PCTY/critical-factors/malformed-artifact",
    ]


def test_artifact_detail_proxy_rejects_encoded_path_escape_before_upstream_call() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(500, json={"unexpected": request.url.path})

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        ticker_escape = client.get(
            "/api/gateway/artifacts/%2e%2e/earnings-scenarios/latest",
            cookies={"session_id": "s-1"},
        )
        skill_escape = client.get(
            "/api/gateway/artifacts/PCTY/%2e%2e/latest",
            cookies={"session_id": "s-1"},
        )
        backslash_escape = client.get(
            "/api/gateway/artifacts/PCTY/earnings%5cscenarios/latest",
            cookies={"session_id": "s-1"},
        )
        encoded_slash_escape = client.get(
            "/api/gateway/artifacts/PCTY/earnings%2fscenarios/latest",
            cookies={"session_id": "s-1"},
        )

    assert ticker_escape.status_code == 404
    assert skill_escape.status_code == 404
    assert backslash_escape.status_code == 404
    assert encoded_slash_escape.status_code == 404
    assert calls == []


def test_control_proxy_rejects_artifact_detail_writes_and_extra_segments() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"Unexpected upstream request: {request.method} {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        write_response = client.post(
            "/api/gateway/artifacts/PCTY/earnings-scenarios/latest",
            cookies={"session_id": "s-1"},
            json={"unexpected": True},
        )
        extra_segment_response = client.get(
            "/api/gateway/artifacts/PCTY/earnings-scenarios/latest/extra",
            cookies={"session_id": "s-1"},
        )
        old_control_detail_response = client.get(
            "/api/gateway/control/artifacts/PCTY/earnings-scenarios/latest",
            cookies={"session_id": "s-1"},
        )

    assert write_response.status_code == 404
    assert write_response.json() == {"detail": "Artifact endpoint not found"}
    assert extra_segment_response.status_code == 404
    assert extra_segment_response.json() == {"detail": "Artifact endpoint not found"}
    assert old_control_detail_response.status_code == 404
    assert old_control_detail_response.json() == {"detail": "Control endpoint not found"}


def test_control_proxy_allows_backend_profile_catalog() -> None:
    requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/profiles":
            requests.append(
                {
                    "path": request.url.path,
                    "authorization": request.headers.get("authorization"),
                }
            )
            return httpx.Response(
                200,
                json={"profiles": [{"name": "analyst"}, {"name": "research_producer"}]},
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/profiles", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json() == {"profiles": [{"name": "analyst"}, {"name": "research_producer"}]}
    assert requests == [
        {
            "path": "/api/control/profiles",
            "authorization": "Bearer control-token",
        },
    ]


def test_control_proxy_validates_autonomous_dispatch_profile_catalog_before_forwarding() -> None:
    requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/profiles":
            requests.append({"path": request.url.path, "authorization": request.headers.get("authorization")})
            return httpx.Response(200, json={"profiles": [{"name": "analyst"}, {"name": "research_producer"}]})
        if request.url.path == "/api/control/runs":
            requests.append(
                {
                    "path": request.url.path,
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(
                200,
                json={"run": {"kind": "autonomous", "run_id": "bg_1", "state": "running"}},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "task",
                "task": "Summarize control evidence.",
                "channel": "excel",
                "user_id": "999",
                "dispatch_scope": {
                    "kind": "portfolio",
                    "source": "user_selected",
                    "portfolio_name": "taxable_combined",
                    "portfolio_id": None,
                    "display_name": "Taxable Combined",
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert requests == [
        {"path": "/api/control/profiles", "authorization": "Bearer control-token"},
        {
            "path": "/api/control/runs",
            "authorization": "Bearer control-token",
            "body": {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "task",
                "task": "Summarize control evidence.",
                "channel": "web",
                "dispatch_scope": {
                    "kind": "portfolio",
                    "source": "user_selected",
                    "portfolio_name": "taxable_combined",
                    "portfolio_id": None,
                    "display_name": "Taxable Combined",
                },
            },
        },
    ]


def test_control_proxy_accepts_canonical_identity_fields_on_run_payloads() -> None:
    run_payload = {
        "kind": "autonomous",
        "run_id": "bg_1",
        "task_id": "bg_1",
        "profile": "analyst",
        "mode": "task",
        "task": "Summarize control identity.",
        "state": "running",
        "user_id": "101",
        "owner_user_id": "101",
        "raw_user_id": "henry",
        "user_slug": "henry",
        "risk_user_id": 101,
        "user_email": "henry@example.com",
        "user_aliases": ["101", "henry", "henry@example.com"],
        "identity_status": "gateway_user_key_mapping",
        "identity": {
            "owner_user_id": "101",
            "user_slug": "henry",
            "aliases": ["101", "henry"],
            "identity_status": "gateway_user_key_mapping",
        },
    }
    requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            requests.append({"path": request.url.path, "body": json.loads(request.content.decode("utf-8"))})
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            requests.append({"path": request.url.path, "authorization": request.headers.get("authorization")})
            return httpx.Response(
                200,
                json={"runs": [run_payload]},
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/runs", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json() == {"runs": [run_payload]}
    assert len(requests) == 2
    assert requests[0]["path"] == "/api/control/session"
    _assert_web_session_init_payload(requests[0]["body"])
    assert requests[1] == {
        "path": "/api/control/runs",
        "authorization": "Bearer control-token",
    }


def test_control_proxy_rejects_dispatch_scope_authority_fields_before_forwarding() -> None:
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        raise AssertionError("invalid dispatch scope should not be forwarded")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "task",
                "task": "Summarize control evidence.",
                "dispatch_scope": {
                    "kind": "portfolio",
                    "source": "user_selected",
                    "portfolio_name": "taxable_combined",
                    "account_id": "acc-1",
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 400
    assert response.json()["detail"]["error"] == "control_request_contract_invalid"
    assert response.json()["detail"]["issues"] == [
        {
            "path": "dispatch_scope.account_id",
            "message": "Extra inputs are not permitted",
            "type": "extra_forbidden",
        }
    ]
    assert requests == []


def test_control_proxy_rejects_dispatch_scope_validator_error_before_forwarding() -> None:
    requests: list[str] = []

    async def validator(_request: Request, user: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
        assert user["user_id"] == 101
        assert scope["portfolio_name"] == "unknown"
        raise HTTPException(
            status_code=422,
            detail={
                "error": "dispatch_scope_portfolio_not_visible",
                "field": "dispatch_scope.portfolio_name",
            },
        )

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        raise AssertionError("invalid dispatch scope should not be forwarded")

    app, _router = _build_app(
        handler,
        config=GatewayConfig(
            gateway_url="http://gateway.local",
            api_key="gateway-api-key",
            ssl_verify=True,
            dispatch_scope_validator=validator,
        ),
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "task",
                "task": "Summarize control evidence.",
                "dispatch_scope": {
                    "kind": "portfolio",
                    "source": "user_selected",
                    "portfolio_name": "unknown",
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 422
    assert response.json()["detail"]["error"] == "dispatch_scope_portfolio_not_visible"
    assert requests == []


def test_control_proxy_forwards_validator_canonicalized_dispatch_scope() -> None:
    requests: list[dict[str, Any]] = []

    async def validator(_request: Request, _user: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
        return {
            **scope,
            "portfolio_id": "portfolio-1",
            "display_name": "Canonical Portfolio",
        }

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            requests.append(json.loads(request.content.decode("utf-8")))
            return httpx.Response(
                200,
                json={"run": {"kind": "autonomous", "run_id": "bg_1", "state": "running"}},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(
        handler,
        config=GatewayConfig(
            gateway_url="http://gateway.local",
            api_key="gateway-api-key",
            ssl_verify=True,
            dispatch_scope_validator=validator,
        ),
    )

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "chat",
                "message": "hello",
                "dispatch_scope": {
                    "kind": "portfolio",
                    "source": "user_selected",
                    "portfolio_name": "taxable_combined",
                    "display_name": "Client Portfolio",
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert requests[0]["dispatch_scope"] == {
        "kind": "portfolio",
        "source": "user_selected",
        "portfolio_name": "taxable_combined",
        "portfolio_id": "portfolio-1",
        "display_name": "Canonical Portfolio",
    }


def test_control_proxy_forwards_canonicalized_schedule_dispatch_scope() -> None:
    requests: list[dict[str, Any]] = []

    async def validator(_request: Request, user: dict[str, Any], scope: dict[str, Any]) -> dict[str, Any]:
        assert user["user_id"] == 101
        return {
            **scope,
            "portfolio_id": "portfolio-taxable",
            "display_name": "Canonical Taxable",
        }

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/profiles":
            return httpx.Response(200, json={"profiles": [{"name": "analyst"}]})
        if request.url.path == "/api/control/skills":
            return httpx.Response(200, json={"skills": [{"name": "earnings-review"}]})
        if request.url.path == "/api/control/schedules":
            body = json.loads(request.content.decode("utf-8"))
            requests.append(body)
            return httpx.Response(
                201,
                json={
                    "schedule": {
                        "schedule_id": "schedule-1",
                        "name": body["name"],
                        "kind": "agent_run_schedule",
                        "source": "agent-gateway",
                        "enabled": True,
                        "timezone": body["timezone"],
                        "cadence": body["cadence"],
                        "dispatch": body["dispatch"],
                    }
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(
        handler,
        config=GatewayConfig(
            gateway_url="http://gateway.local",
            api_key="gateway-api-key",
            ssl_verify=True,
            dispatch_scope_validator=validator,
        ),
    )
    payload = _agent_run_schedule_create_payload()
    payload["dispatch"] = {
        **payload["dispatch"],
        "dispatch_scope": {
            "kind": "portfolio",
            "source": "user_selected",
            "portfolio_name": "taxable_combined",
            "display_name": "Client Taxable",
        },
    }

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/schedules",
            json=payload,
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 201
    assert requests[0]["dispatch"]["dispatch_scope"] == {
        "kind": "portfolio",
        "source": "user_selected",
        "portfolio_name": "taxable_combined",
        "portfolio_id": "portfolio-taxable",
        "display_name": "Canonical Taxable",
    }
    assert response.json()["schedule"]["dispatch"]["dispatch_scope"] == requests[0]["dispatch"]["dispatch_scope"]


def test_control_proxy_rejects_unknown_autonomous_dispatch_profile_before_forwarding() -> None:
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/profiles":
            return httpx.Response(200, json={"profiles": [{"name": "analyst"}]})
        if request.url.path == "/api/control/runs":
            raise AssertionError("dispatch should not be forwarded")
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "autonomous",
                "profile": "not-a-profile",
                "mode": "task",
                "task": "Summarize control evidence.",
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == {
        "error": "control_dispatch_not_allowed",
        "message": "Choose a profile from the Agent Control profile catalog.",
        "field": "profile",
        "value": "not-a-profile",
        "allowed_values": ["analyst"],
    }
    assert requests == ["/api/control/session", "/api/control/profiles"]


def test_control_proxy_rejects_unknown_autonomous_dispatch_skill_before_forwarding() -> None:
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/profiles":
            return httpx.Response(200, json={"profiles": [{"name": "analyst"}]})
        if request.url.path == "/api/control/skills":
            return httpx.Response(200, json={"skills": [{"name": "research_brief"}]})
        if request.url.path == "/api/control/runs":
            raise AssertionError("dispatch should not be forwarded")
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "not-a-skill",
                "task": "Summarize control evidence.",
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == {
        "error": "control_dispatch_not_allowed",
        "message": "Choose a skill from the Agent Control skill catalog.",
        "field": "skill",
        "value": "not-a-skill",
        "allowed_values": ["research_brief"],
    }
    assert requests == ["/api/control/session", "/api/control/profiles", "/api/control/skills"]


def test_control_proxy_rejects_skill_field_on_task_dispatch_before_forwarding() -> None:
    requests: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/profiles":
            return httpx.Response(200, json={"profiles": [{"name": "analyst"}]})
        if request.url.path == "/api/control/runs":
            raise AssertionError("dispatch should not be forwarded")
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "task",
                "skill": "not-a-skill",
                "task": "Summarize control evidence.",
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 400
    assert response.json()["detail"] == {
        "error": "control_dispatch_not_allowed",
        "message": "Skill is only allowed for skill-mode Agent Control runs.",
        "field": "skill",
        "value": "not-a-skill",
        "allowed_values": [],
    }
    assert requests == ["/api/control/session", "/api/control/profiles"]


def test_control_proxy_sanitizes_dispatch_channel_and_hides_chat_token() -> None:
    requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            requests.append(
                {
                    "path": request.url.path,
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(
                200,
                json={
                    "run": {
                        "kind": "chat",
                        "run_id": "sess-chat",
                        "session_id": "sess-chat",
                        "agent": "hank",
                        "channel": "web",
                        "user_id": "101",
                        "state": "completed",
                        "started_at": "2026-05-31T00:00:00Z",
                        "ended_at": None,
                        "cost_usd": None,
                        "initial_message": "hello",
                        "skill_run_ids": [],
                        "current_verdict": None,
                        "pending_approval": None,
                    },
                    "run_id": "sess-chat",
                    "chat_session_token": "chat-secret",
                    "chat_session_id": "sess-chat",
                    "chat_session_expires_at": 9999999999,
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs",
            json={
                "kind": "chat",
                "message": "hello",
                "channel": "excel",
                "user_id": "999",
                "user_email": "attacker@example.com",
                "context": {
                    "channel": "excel",
                    "user_id": "999",
                    "portfolio_name": "spoofed",
                    "portfolioId": "portfolio-1",
                    "account_id": "acc-1",
                    "nested": {"ownerUserId": "999", "keep": "nested"},
                    "items": [{"route_id": "route-1", "keep": 1}],
                    "keep": True,
                },
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    body = response.json()
    assert "chat_session_token" not in body
    assert body["chat_session_id"] == "sess-chat"
    assert body["run"]["messageable"] is True
    assert requests == [
        {
            "path": "/api/control/runs",
            "authorization": "Bearer control-token",
            "body": {
                "kind": "chat",
                "message": "hello",
                "channel": "web",
                "context": {
                    "nested": {"keep": "nested"},
                    "items": [{"keep": 1}],
                    "keep": True,
                    "channel": "web",
                },
            },
        }
    ]


@pytest.mark.parametrize(
    ("payload", "bridge_marker"),
    [
        (
            {
                "kind": "autonomous",
                "profile": "_fixture",
                "mode": "skill",
                "skill": "critical-factors",
                "task": "Exercise fixture guard.",
            },
            "fixture-approval-artifact",
        ),
        (
            {
                "kind": "autonomous",
                "profile": "_Fixture",
                "mode": "skill",
                "skill": "critical-factors",
                "task": "Exercise fixture guard.",
            },
            "fixture-approval-artifact",
        ),
        (
            {
                "kind": "autonomous",
                "profile": "_fixture",
                "mode": "skill",
                "skill": "fixture-terminal-failure",
                "task": "Exercise fixture guard.",
                "dev_mode": True,
            },
            "fixture-terminal-failure",
        ),
        (
            {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "fixture-sleep",
                "task": "Exercise fixture guard.",
            },
            "fixture-approval-artifact",
        ),
        (
            {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "Fixture-Sleep",
                "task": "Exercise fixture guard.",
            },
            "fixture-approval-artifact",
        ),
        (
            {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "fixture_sleep",
                "task": "Exercise fixture guard.",
            },
            "fixture-approval-artifact",
        ),
        (
            {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "FIXTURE-SLEEP",
                "task": "Exercise fixture guard.",
            },
            "fixture-approval-artifact",
        ),
        (
            {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "critical-factors",
                "task": "Exercise fixture guard.",
                "dev_mode": True,
            },
            "fixture-approval-artifact",
        ),
        (
            {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "critical-factors",
                "task": "Exercise fixture guard.",
                "dev_mode": False,
            },
            "fixture-approval-artifact",
        ),
        (
            {
                "kind": "chat",
                "message": "Exercise chat fixture guard.",
                "dev_mode": True,
            },
            "fixture-approval-artifact",
        ),
        (
            {
                "kind": "chat",
                "message": "Exercise chat fixture guard.",
                "dev_mode": False,
            },
            "fixture-approval-artifact",
        ),
    ],
)
def test_control_proxy_rejects_web_fixture_and_dev_mode_dispatches(
    payload: dict[str, Any],
    bridge_marker: str,
) -> None:
    upstream_calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        upstream_calls.append(request.url.path)
        return httpx.Response(500, json={"unexpected": request.url.path})

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs",
            json=payload,
            headers={"X-Agent-Control-QA-Bridge": bridge_marker},
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


def test_control_proxy_rejects_encoded_path_escape_before_upstream_call() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        return httpx.Response(500, json={"unexpected": request.url.path})

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        chat_escape = client.get("/api/gateway/control/%2e%2e/chat/init", cookies={"session_id": "s-1"})
        session_escape = client.get("/api/gateway/control/runs/%2e%2e/session", cookies={"session_id": "s-1"})

    assert chat_escape.status_code == 404
    assert session_escape.status_code == 404
    assert calls == []


def test_control_proxy_uses_stored_chat_token_for_chat_run_messages() -> None:
    message_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return _control_chat_continuation_health_response()
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "run": {"kind": "chat", "run_id": "sess-chat", "state": "running"},
                    "run_id": "sess-chat",
                    "chat_session_token": "chat-secret",
                    "chat_session_id": "sess-chat",
                    "chat_session_expires_at": 9999999999,
                },
            )
        if request.url.path == "/api/control/runs/sess-chat/messages":
            message_requests.append(
                {
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(
                200,
                json={"run": {"kind": "chat", "run_id": "sess-chat", "state": "completed"}},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler, config=_control_chat_continuation_config())

    with TestClient(app) as client:
        start = client.post(
            "/api/gateway/control/runs",
            json={"kind": "chat", "message": "hello", "channel": "excel"},
            cookies={"session_id": "s-1"},
        )
        response = client.post(
            "/api/gateway/control/runs/sess-chat/messages",
            json={
                "messages": [{"role": "user", "content": "hello"}],
                "context": {"channel": "excel", "purpose": "agent-control", "user_id": "999"},
                "user_id": "999",
            },
            cookies={"session_id": "s-1"},
        )

    assert start.status_code == 200
    assert response.status_code == 200
    assert message_requests == [
        {
            "authorization": "Bearer chat-secret",
            "body": {
                "messages": [{"role": "user", "content": "hello"}],
                "context": {"channel": "web", "purpose": "agent-control"},
            },
        }
    ]


def test_control_proxy_blocks_cached_chat_token_when_continuation_contract_is_missing() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/health":
            return httpx.Response(200, json={"package": {"contracts": []}})
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "run": {"kind": "chat", "run_id": "sess-chat", "state": "running"},
                    "run_id": "sess-chat",
                    "chat_session_token": "chat-secret",
                    "chat_session_id": "sess-chat",
                    "chat_session_expires_at": 9999999999,
                },
            )
        if request.url.path == "/api/control/runs/sess-chat/messages":
            raise AssertionError("chat continuation should be blocked before upstream")
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler, config=_control_chat_continuation_config())

    with TestClient(app) as client:
        start = client.post(
            "/api/gateway/control/runs",
            json={"kind": "chat", "message": "hello", "channel": "excel"},
            cookies={"session_id": "s-1"},
        )
        response = client.post(
            "/api/gateway/control/runs/sess-chat/messages",
            json={"messages": [{"role": "user", "content": "hello"}]},
            cookies={"session_id": "s-1"},
        )

    assert start.status_code == 200
    assert start.json()["run"]["messageable"] is False
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "error": "chat_run_not_messageable",
        "message": "This chat run is not continuable from Agent Control.",
    }
    assert calls == [
        "/api/health",
        "/api/control/session",
        "/api/control/runs",
    ]


def test_control_proxy_drops_expired_chat_token_for_chat_run_messages() -> None:
    message_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return _control_chat_continuation_health_response()
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "run": {"kind": "chat", "run_id": "sess-chat", "state": "running"},
                    "run_id": "sess-chat",
                    "chat_session_token": "chat-secret",
                    "chat_session_id": "sess-chat",
                    "chat_session_expires_at": 1,
                },
            )
        if request.url.path == "/api/control/runs/sess-chat/messages":
            message_requests.append(
                {
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(401, json={"detail": "expired"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler, config=_control_chat_continuation_config())

    with TestClient(app) as client:
        start = client.post(
            "/api/gateway/control/runs",
            json={"kind": "chat", "message": "hello", "channel": "excel"},
            cookies={"session_id": "s-1"},
        )
        response = client.post(
            "/api/gateway/control/runs/sess-chat/messages",
            json={"messages": [{"role": "user", "content": "hello"}]},
            cookies={"session_id": "s-1"},
        )

    assert start.status_code == 200
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "chat_run_not_messageable"
    assert message_requests == [
        {
            "authorization": "Bearer control-token",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
        },
        {
            "authorization": "Bearer control-token",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
        }
    ]


def test_control_proxy_maps_upstream_chat_token_401_to_control_conflict() -> None:
    message_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return _control_chat_continuation_health_response()
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "run": {"kind": "chat", "run_id": "sess-chat", "state": "running"},
                    "run_id": "sess-chat",
                    "chat_session_token": "chat-secret",
                    "chat_session_id": "sess-chat",
                    "chat_session_expires_at": 9999999999,
                },
            )
        if request.url.path == "/api/control/runs/sess-chat/messages":
            message_requests.append(
                {
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(401, json={"detail": "expired"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler, config=_control_chat_continuation_config())

    with TestClient(app) as client:
        start = client.post(
            "/api/gateway/control/runs",
            json={"kind": "chat", "message": "hello", "channel": "excel"},
            cookies={"session_id": "s-1"},
        )
        response = client.post(
            "/api/gateway/control/runs/sess-chat/messages",
            json={"messages": [{"role": "user", "content": "hello"}]},
            cookies={"session_id": "s-1"},
        )

    assert start.status_code == 200
    assert response.status_code == 409
    assert response.json()["detail"]["error"] == "chat_run_not_messageable"
    assert message_requests == [
        {
            "authorization": "Bearer chat-secret",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
        },
        {
            "authorization": "Bearer control-token",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
        },
        {
            "authorization": "Bearer control-token",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
        },
    ]


def test_control_proxy_retries_stale_chat_token_with_control_token() -> None:
    message_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "run": {"kind": "chat", "run_id": "sess-chat", "state": "running"},
                    "run_id": "sess-chat",
                    "chat_session_token": "chat-secret",
                    "chat_session_id": "sess-chat",
                    "chat_session_expires_at": 9999999999,
                },
            )
        if request.url.path == "/api/control/runs/sess-chat/messages":
            request_payload = {
                "authorization": request.headers.get("authorization"),
                "body": json.loads(request.content.decode("utf-8")),
            }
            message_requests.append(request_payload)
            if request.headers.get("authorization") == "Bearer chat-secret":
                return httpx.Response(401, json={"detail": "expired"})
            return httpx.Response(
                200,
                json={"run": {"kind": "chat", "run_id": "sess-chat", "state": "completed"}},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        start = client.post(
            "/api/gateway/control/runs",
            json={"kind": "chat", "message": "hello", "channel": "excel"},
            cookies={"session_id": "s-1"},
        )
        response = client.post(
            "/api/gateway/control/runs/sess-chat/messages",
            json={"messages": [{"role": "user", "content": "hello"}]},
            cookies={"session_id": "s-1"},
        )

    assert start.status_code == 200
    assert response.status_code == 200
    assert message_requests == [
        {
            "authorization": "Bearer chat-secret",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
        },
        {
            "authorization": "Bearer control-token",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
        },
    ]


def test_control_proxy_preserves_chat_token_when_list_runs_reports_completed_chat_run() -> None:
    message_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs" and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "run": {"kind": "chat", "run_id": "sess-chat", "state": "running"},
                    "run_id": "sess-chat",
                    "chat_session_token": "chat-secret",
                    "chat_session_id": "sess-chat",
                    "chat_session_expires_at": 9999999999,
                },
            )
        if request.url.path == "/api/control/runs" and request.method == "GET":
            return httpx.Response(
                200,
                json={"runs": [{"kind": "chat", "run_id": "sess-chat", "state": "completed"}]},
            )
        if request.url.path == "/api/control/runs/sess-chat/messages":
            message_requests.append(
                {
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(200, json={"run": {"kind": "chat", "run_id": "sess-chat", "state": "completed"}})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        start = client.post(
            "/api/gateway/control/runs",
            json={"kind": "chat", "message": "hello", "channel": "excel"},
            cookies={"session_id": "s-1"},
        )
        runs = client.get("/api/gateway/control/runs", cookies={"session_id": "s-1"})
        response = client.post(
            "/api/gateway/control/runs/sess-chat/messages",
            json={"messages": [{"role": "user", "content": "hello"}]},
            cookies={"session_id": "s-1"},
        )

    assert start.status_code == 200
    assert runs.status_code == 200
    assert runs.json()["runs"][0]["messageable"] is True
    assert response.status_code == 200
    assert message_requests == [
        {
            "authorization": "Bearer chat-secret",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
        }
    ]


@pytest.mark.parametrize("state", ["failed", "interrupted", "cancelled"])
def test_control_proxy_blocks_observed_non_messageable_chat_run_states(state: str) -> None:
    message_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return _control_chat_continuation_health_response()
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs" and request.method == "POST":
            return httpx.Response(
                200,
                json={
                    "run": {"kind": "chat", "run_id": "sess-chat", "state": "running"},
                    "run_id": "sess-chat",
                    "chat_session_token": "chat-secret",
                    "chat_session_id": "sess-chat",
                    "chat_session_expires_at": 9999999999,
                },
            )
        if request.url.path == "/api/control/runs" and request.method == "GET":
            return httpx.Response(
                200,
                json={"runs": [{"kind": "chat", "run_id": "sess-chat", "state": state}]},
            )
        if request.url.path == "/api/control/runs/sess-chat/messages":
            message_requests.append(
                {
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(409, json={"error": "not_messageable"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler, config=_control_chat_continuation_config())

    with TestClient(app) as client:
        start = client.post(
            "/api/gateway/control/runs",
            json={"kind": "chat", "message": "hello", "channel": "excel"},
            cookies={"session_id": "s-1"},
        )
        runs = client.get("/api/gateway/control/runs", cookies={"session_id": "s-1"})
        response = client.post(
            "/api/gateway/control/runs/sess-chat/messages",
            json={"messages": [{"role": "user", "content": "hello"}]},
            cookies={"session_id": "s-1"},
        )

    assert start.status_code == 200
    assert runs.status_code == 200
    assert runs.json()["runs"][0]["messageable"] is False
    assert response.status_code == 409
    assert response.json()["detail"] == {
        "error": "chat_run_not_messageable",
        "message": "This chat run is not continuable from Agent Control.",
    }
    assert message_requests == []


def test_control_proxy_marks_server_scoped_chat_runs_messageable_with_control_fallback() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return _control_chat_continuation_health_response()
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={"runs": [{"kind": "chat", "run_id": "sess-normal", "state": "completed"}]},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler, config=_control_chat_continuation_config())

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/runs", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json()["runs"] == [
        {"kind": "chat", "run_id": "sess-normal", "state": "completed", "messageable": True}
    ]


def test_control_proxy_marks_server_scoped_chat_runs_not_messageable_without_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return httpx.Response(200, json={"package": {"contracts": []}})
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={"runs": [{"kind": "chat", "run_id": "sess-normal", "state": "completed"}]},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler, config=_control_chat_continuation_config())

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/runs", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json()["runs"] == [
        {"kind": "chat", "run_id": "sess-normal", "state": "completed", "messageable": False}
    ]


def test_control_proxy_rejects_invalid_control_run_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={"runs": [{"kind": "chat", "run_id": "sess-normal", "state": "unknown"}]},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/runs", cookies={"session_id": "s-1"})

    assert response.status_code == 502
    assert response.json()["detail"] == {
        "error": "control_run_contract_invalid",
        "message": "Gateway control run payload did not match the typed control-plane contract.",
        "action": "Run Agent Control dev status and verify the upstream control-plane run-state schema before retrying.",
        "contract": "control-run-v1",
        "issues": [
            {
                "path": "runs[0].state",
                "message": "Value error, unknown control run state: unknown",
                "type": "value_error",
            }
        ],
    }


def test_control_proxy_requires_direct_run_detail_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1":
            return httpx.Response(200, json={"run_id": "bg_1", "state": "running"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/runs/bg_1", cookies={"session_id": "s-1"})

    assert response.status_code == 502
    assert response.json()["detail"] == {
        "error": "control_run_contract_invalid",
        "message": "Gateway control run payload did not match the typed control-plane contract.",
        "action": "Run Agent Control dev status and verify the upstream control-plane run-state schema before retrying.",
        "contract": "control-run-v1",
        "issues": [
            {"path": "kind", "message": "Field required", "type": "missing"},
        ],
    }


def test_control_proxy_requires_cancel_response_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1":
            return httpx.Response(200, json={"run_id": "bg_1", "state": "cancelled"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.delete("/api/gateway/control/runs/bg_1", cookies={"session_id": "s-1"})

    assert response.status_code == 502
    assert response.json()["detail"] == {
        "error": "control_run_contract_invalid",
        "message": "Gateway control run payload did not match the typed control-plane contract.",
        "action": "Run Agent Control dev status and verify the upstream control-plane run-state schema before retrying.",
        "contract": "control-run-v1",
        "issues": [
            {"path": "kind", "message": "Field required", "type": "missing"},
        ],
    }


def test_control_proxy_does_not_cache_chat_token_from_invalid_run_contract() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "run": {"kind": "chat", "run_id": "sess-invalid", "state": "unknown"},
                    "run_id": "sess-invalid",
                    "chat_session_token": "chat-secret",
                    "chat_session_id": "sess-invalid",
                    "chat_session_expires_at": 9999999999,
                },
            )
        if request.url.path == "/api/control/runs/sess-invalid/messages":
            raise AssertionError("invalid run contract should not cache a chat continuation token")
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        start = client.post(
            "/api/gateway/control/runs",
            json={"kind": "chat", "message": "hello"},
            cookies={"session_id": "s-1"},
        )
        follow_up = client.post(
            "/api/gateway/control/runs/sess-invalid/messages",
            json={"messages": [{"role": "user", "content": "continue"}]},
            cookies={"session_id": "s-1"},
        )

    assert start.status_code == 502
    assert follow_up.status_code == 409
    assert follow_up.json()["detail"]["error"] == "chat_run_not_messageable"
    assert calls == [
        "/api/control/session",
        "/api/control/runs",
    ]


def test_control_proxy_rejects_invalid_approval_list_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/approvals":
            return httpx.Response(200, json={"approvals": [{"state": "pending_user"}]})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/approvals", cookies={"session_id": "s-1"})

    _assert_control_response_contract_error(
        response,
        [
            {
                "path": "approvals[0]",
                "message": "Value error, approval_id, pending_id, tool_call_id, or id must be a non-empty string",
                "type": "value_error",
            }
        ],
    )


def test_control_proxy_preserves_redacted_approval_notification_metadata() -> None:
    payload = {
        "approvals": [
            {
                "approval_id": "approval_1",
                "state": "pending_user",
                "session_id": "bg_1",
                "tool_name": "execute_trade",
                "notification": {
                    "state": "sent",
                    "channels": ["telegram"],
                    "last_sent_at": "2026-07-03T15:00:50Z",
                },
            }
        ]
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/approvals":
            return httpx.Response(200, json=payload, headers={"X-Control-Plane-Version": "1"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/approvals", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json() == payload


def test_control_proxy_forwards_valid_approval_decision_request_contract() -> None:
    calls: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            calls.append({"path": request.url.path})
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1/approvals/approval_1":
            calls.append(
                {
                    "path": request.url.path,
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(200, json={"success": True})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/approvals/approval_1",
            json={
                "approved": True,
                "allow_tool_type": False,
                "reason": "Reviewed from analyst control deck",
                "user_id": "attacker",
                "channel": "desktop",
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json() == {"success": True}
    assert calls == [
        {"path": "/api/control/session"},
        {
            "path": "/api/control/runs/bg_1/approvals/approval_1",
            "authorization": "Bearer control-token",
            "body": {
                "approved": True,
                "allow_tool_type": False,
                "reason": "Reviewed from analyst control deck",
            },
        },
    ]


def test_control_proxy_forwards_valid_approval_notification_retry_request_contract() -> None:
    calls: list[dict[str, object]] = []
    retry_response = {
        "status": "queued",
        "approval_id": "approval_1",
        "requeued": 1,
        "delivery_scheduled": False,
        "notification": {
            "state": "pending",
            "channels": ["telegram"],
        },
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            calls.append({"path": request.url.path})
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1/approvals/approval_1/notifications/retry":
            calls.append(
                {
                    "path": request.url.path,
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(200, json=retry_response, headers={"X-Control-Plane-Version": "1"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/approvals/approval_1/notifications/retry",
            json={},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json() == retry_response
    assert calls == [
        {"path": "/api/control/session"},
        {
            "path": "/api/control/runs/bg_1/approvals/approval_1/notifications/retry",
            "authorization": "Bearer control-token",
            "body": {},
        },
    ]


def test_control_proxy_rejects_invalid_approval_notification_retry_request_before_forwarding() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/approvals/approval_1/notifications/retry",
            json={"notification_destination": "@private_user"},
            cookies={"session_id": "s-1"},
        )

    _assert_control_request_contract_error(
        response,
        [
            {
                "path": "notification_destination",
                "message": "Extra inputs are not permitted",
                "type": "extra_forbidden",
            }
        ],
    )
    assert calls == []


def test_control_proxy_rejects_unsafe_approval_notification_retry_response_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1/approvals/approval_1/notifications/retry":
            return httpx.Response(
                200,
                json={
                    "status": "queued",
                    "approval_id": "approval_1",
                    "requeued": 1,
                    "delivery_scheduled": False,
                    "notification": {
                        "state": "pending",
                        "channels": ["telegram"],
                        "message": "Raw notification copy must not cross this contract.",
                    },
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/approvals/approval_1/notifications/retry",
            json={},
            cookies={"session_id": "s-1"},
        )

    _assert_control_response_contract_error(
        response,
        [
            {
                "path": "notification.message",
                "message": "Extra inputs are not permitted",
                "type": "extra_forbidden",
            }
        ],
    )


def test_control_proxy_sanitizes_approval_notification_retry_error_bodies() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1/approvals/approval_1/notifications/retry":
            return httpx.Response(
                500,
                json={
                    "detail": "Raw delivery failed.",
                    "notification_destination": "@private_user",
                    "message": "Raw notification copy must not cross this contract.",
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/approvals/approval_1/notifications/retry",
            json={},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 500
    assert response.json() == {
        "detail": {
            "error": "approval_notification_retry_failed",
            "message": "Approval notification retry could not be completed.",
        }
    }
    assert "notification_destination" not in json.dumps(response.json())
    assert "@private_user" not in json.dumps(response.json())


def test_control_proxy_rejects_invalid_approval_decision_request_contract_before_forwarding() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/approvals/approval_1",
            json={"approved": "false", "allow_tool_type": False},
            cookies={"session_id": "s-1"},
        )

    _assert_control_request_contract_error(
        response,
        [{"path": "approved", "message": "Input should be a valid boolean", "type": "bool_type"}],
    )
    assert calls == []


def test_control_proxy_rejects_extra_approval_decision_request_fields_before_forwarding() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/approvals/approval_1",
            json={"approved": True, "allow_tool_type": False, "run_id": "bg_1"},
            cookies={"session_id": "s-1"},
        )

    _assert_control_request_contract_error(
        response,
        [{"path": "run_id", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}],
    )
    assert calls == []


def test_control_proxy_rejects_malformed_approval_decision_json_before_forwarding() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/approvals/approval_1",
            content="{",
            headers={"content-type": "application/json"},
            cookies={"session_id": "s-1"},
        )

    _assert_control_request_contract_error(
        response,
        [{"path": "$", "message": "control request must be valid JSON", "type": "value_error"}],
    )
    assert calls == []


def test_control_proxy_rejects_invalid_approval_decision_json_bytes_before_forwarding() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/approvals/approval_1",
            content=b"\xff",
            headers={"content-type": "application/json"},
            cookies={"session_id": "s-1"},
        )

    _assert_control_request_contract_error(
        response,
        [{"path": "$", "message": "control request must be valid JSON", "type": "value_error"}],
    )
    assert calls == []


@pytest.mark.parametrize(
    ("gateway_path", "payload", "issues"),
    [
        (
            "/api/gateway/control/runs/bg_1/messages",
            {"messages": [{"role": "user", "content": "Continue the run."}], "message": "Check AWS exposure."},
            [
                {
                    "path": "$",
                    "message": "run message request must include either messages or message, not both",
                    "type": "value_error",
                }
            ],
        ),
        (
            "/api/gateway/control/runs/bg_1/messages",
            {"message": "   ", "message_id": "web_1"},
            [
                {
                    "path": "message",
                    "message": "Value error, message must be a non-empty string",
                    "type": "value_error",
                }
            ],
        ),
        (
            "/api/gateway/control/runs/bg_1/messages",
            {"kind": "autonomous", "message": "Check AWS exposure.", "message_id": "web_1"},
            [{"path": "kind", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}],
        ),
        (
            "/api/gateway/control/runs/bg_1/messages",
            {"messages": [{"role": "tool", "content": "internal tool output"}]},
            [
                {
                    "path": "messages[0].role",
                    "message": "Input should be 'user' or 'assistant'",
                    "type": "literal_error",
                }
            ],
        ),
        (
            "/api/gateway/control/runs/bg_1/resume",
            {"message": "Resume from latest safe point.", "context": {"note": "ok"}},
            [{"path": "context", "message": "Input should be a valid string", "type": "string_type"}],
        ),
        (
            "/api/gateway/control/runs/bg_1/resume",
            {"message": "Resume from latest safe point.", "request_id": "web_resume_1", "run_id": "bg_1"},
            [{"path": "run_id", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}],
        ),
    ],
)
def test_control_proxy_rejects_invalid_run_write_request_contract_before_forwarding(
    gateway_path: str,
    payload: dict[str, object],
    issues: list[dict[str, str]],
) -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(gateway_path, json=payload, cookies={"session_id": "s-1"})

    _assert_control_request_contract_error(response, issues)
    assert calls == []


def test_control_proxy_rejects_non_finite_chat_run_message_deadline_before_forwarding() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/messages",
            content='{"messages":[{"role":"user","content":"Continue the run."}],"deadline_sec": NaN}',
            headers={"content-type": "application/json"},
            cookies={"session_id": "s-1"},
        )

    _assert_control_request_contract_error(
        response,
        [{"path": "deadline_sec", "message": "Value error, deadline_sec must be finite", "type": "value_error"}],
    )
    assert calls == []


@pytest.mark.parametrize(
    "gateway_path",
    [
        "/api/gateway/control/runs/bg_1/messages",
        "/api/gateway/control/runs/bg_1/resume",
    ],
)
def test_control_proxy_rejects_malformed_selected_run_write_json_before_forwarding(gateway_path: str) -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            gateway_path,
            content="{",
            headers={"content-type": "application/json"},
            cookies={"session_id": "s-1"},
        )

    _assert_control_request_contract_error(
        response,
        [{"path": "$", "message": "control request must be valid JSON", "type": "value_error"}],
    )
    assert calls == []


@pytest.mark.parametrize(
    "gateway_path",
    [
        "/api/gateway/control/runs/bg_1/messages",
        "/api/gateway/control/runs/bg_1/resume",
    ],
)
def test_control_proxy_rejects_invalid_selected_run_write_json_bytes_before_forwarding(gateway_path: str) -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            gateway_path,
            content=b"\xff",
            headers={"content-type": "application/json"},
            cookies={"session_id": "s-1"},
        )

    _assert_control_request_contract_error(
        response,
        [{"path": "$", "message": "control request must be valid JSON", "type": "value_error"}],
    )
    assert calls == []


def test_control_proxy_rejects_raw_schedule_create_before_forwarding() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/schedules",
            json={
                **_agent_run_schedule_create_payload(),
                "command": ["python", "scripts/run_agent.py"],
                "working_directory": "/tmp",
            },
            cookies={"session_id": "s-1"},
        )

    _assert_control_request_contract_error(
        response,
        [
            {"path": "command", "message": "Extra inputs are not permitted", "type": "extra_forbidden"},
            {
                "path": "working_directory",
                "message": "Extra inputs are not permitted",
                "type": "extra_forbidden",
            },
        ],
    )
    assert calls == []


def test_control_proxy_forwards_agent_run_schedule_create_after_contract_validation() -> None:
    calls: list[tuple[str, dict[str, Any] | None]] = []
    payload = _agent_run_schedule_create_payload()

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        calls.append((request.url.path, body))
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/profiles":
            return httpx.Response(200, json={"profiles": [{"name": "analyst"}]})
        if request.url.path == "/api/control/skills":
            return httpx.Response(200, json={"skills": [{"name": "earnings-review"}]})
        if request.url.path == "/api/control/schedules":
            return httpx.Response(
                200,
                json={
                    "schedule": {
                        "schedule_id": "schedule-1",
                        **payload,
                        "command": ["python", "scripts/run_agent.py"],
                        "working_directory": "/tmp",
                    }
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/schedules",
            json=payload,
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "schedule": {
            "schedule_id": "schedule-1",
            **{key: value for key, value in payload.items() if key != "request_id"},
        }
    }
    assert calls[0][0] == "/api/control/session"
    assert calls[1:] == [
        ("/api/control/profiles", None),
        ("/api/control/skills", None),
        ("/api/control/schedules", payload),
    ]


def test_control_proxy_refreshes_stale_token_before_schedule_catalog_validation() -> None:
    calls: list[tuple[str, str | None, dict[str, Any] | None]] = []
    session_tokens = iter(["stale-token", "fresh-token"])
    payload = _agent_run_schedule_create_payload()

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        calls.append((request.url.path, request.headers.get("authorization"), body))
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": next(session_tokens)})
        if request.url.path == "/api/control/profiles":
            if request.headers.get("authorization") == "Bearer stale-token":
                return httpx.Response(401, json={"detail": "expired"})
            return httpx.Response(200, json={"profiles": [{"name": "analyst"}]})
        if request.url.path == "/api/control/skills":
            return httpx.Response(200, json={"skills": [{"name": "earnings-review"}]})
        if request.url.path == "/api/control/schedules":
            return httpx.Response(
                200,
                json={
                    "schedule": {
                        "schedule_id": "schedule-1",
                        **payload,
                    }
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/schedules",
            json=payload,
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json()["schedule"]["schedule_id"] == "schedule-1"
    assert [(path, authorization) for path, authorization, _body in calls] == [
        ("/api/control/session", None),
        ("/api/control/profiles", "Bearer stale-token"),
        ("/api/control/session", None),
        ("/api/control/profiles", "Bearer fresh-token"),
        ("/api/control/skills", "Bearer fresh-token"),
        ("/api/control/schedules", "Bearer fresh-token"),
    ]
    assert calls[-1][2] == payload


def test_control_proxy_forwards_schedule_run_now_and_validates_run_response() -> None:
    calls: list[tuple[str, dict[str, Any] | None]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        calls.append((request.url.path, body))
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/schedules/schedule-1/run-now":
            return httpx.Response(
                200,
                json={
                    "run": {
                        "kind": "autonomous",
                        "run_id": "bg_1",
                        "task_id": "bg_1",
                        "state": "running",
                        "schedule_id": "schedule-1",
                    },
                    "run_id": "bg_1",
                    "task_id": "bg_1",
                    "log_path": "/tmp/bg_1.log",
                    "started_at": 1700000000,
                    "cmd": ["python", "-m", "agent.autonomous"],
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/schedules/schedule-1/run-now",
            json={},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json()["run"]["run_id"] == "bg_1"
    assert response.json()["run"]["schedule_id"] == "schedule-1"
    assert calls[0][0] == "/api/control/session"
    assert calls[1:] == [("/api/control/schedules/schedule-1/run-now", {})]


def test_control_proxy_rejects_scheduled_fixture_dispatch_before_forwarding() -> None:
    calls: list[str] = []
    payload = _agent_run_schedule_create_payload()
    payload["dispatch"] = {
        **payload["dispatch"],
        "profile": "_fixture",
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/schedules",
            json=payload,
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 403
    assert response.json() == {
        "detail": {
            "error": "web_control_dev_dispatch_forbidden",
            "message": "Web Agent Control cannot launch fixture or dev-mode runs.",
        }
    }
    assert calls == []


def test_control_proxy_rejects_unknown_scheduled_dispatch_profile_before_forwarding() -> None:
    calls: list[str] = []
    payload = _agent_run_schedule_create_payload()
    payload["dispatch"] = {
        **payload["dispatch"],
        "profile": "not-a-profile",
    }

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/profiles":
            return httpx.Response(200, json={"profiles": [{"name": "analyst"}]})
        if request.url.path == "/api/control/schedules":
            raise AssertionError("schedule create should not be forwarded")
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/schedules",
            json=payload,
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 403
    assert response.json()["detail"] == {
        "error": "control_dispatch_not_allowed",
        "message": "Choose a profile from the Agent Control profile catalog.",
        "field": "profile",
        "value": "not-a-profile",
        "allowed_values": ["analyst"],
    }
    assert calls == ["/api/control/session", "/api/control/profiles"]


def test_control_proxy_forwards_schedule_enabled_write_and_projects_response() -> None:
    calls: list[tuple[str, dict[str, Any] | None]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        calls.append((request.url.path, body))
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/schedules/schedule-1/enabled":
            return httpx.Response(
                200,
                json={
                    "schedule_id": "schedule-1",
                    "name": "weekday-nvda-earnings-watch",
                    "kind": "agent_run_schedule",
                    "enabled": False,
                    "timezone": "UTC",
                    "cadence": {"type": "daily", "time_of_day": "16:00"},
                    "dispatch": {
                        "kind": "autonomous",
                        "profile": "analyst",
                        "mode": "task",
                        "task": "Review the portfolio.",
                    },
                    "command": ["python", "scripts/run_agent.py"],
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.put(
            "/api/gateway/control/schedules/schedule-1/enabled",
            json={"enabled": False},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "schedule_id": "schedule-1",
        "name": "weekday-nvda-earnings-watch",
        "kind": "agent_run_schedule",
        "enabled": False,
        "timezone": "UTC",
        "cadence": {"type": "daily", "time_of_day": "16:00"},
        "dispatch": {
            "kind": "autonomous",
            "profile": "analyst",
            "mode": "task",
            "task": "Review the portfolio.",
        },
    }
    assert calls[0][0] == "/api/control/session"
    assert calls[1:] == [
        ("/api/control/schedules/schedule-1/enabled", {"enabled": False}),
    ]


def test_control_proxy_projects_schedule_delete_response() -> None:
    calls: list[tuple[str, dict[str, Any] | None]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content) if request.content else None
        calls.append((request.url.path, body))
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/schedules/schedule-1":
            return httpx.Response(
                200,
                json={
                    "deleted": True,
                    "schedule_id": "schedule-1",
                    "command": ["python", "scripts/run_agent.py"],
                    "working_directory": "/tmp",
                    "environment": {"SECRET_TOKEN": "do-not-forward"},
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.delete(
            "/api/gateway/control/schedules/schedule-1",
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert response.json() == {
        "deleted": True,
        "schedule_id": "schedule-1",
    }
    assert calls[0][0] == "/api/control/session"
    assert calls[1:] == [("/api/control/schedules/schedule-1", None)]


def test_control_proxy_rejects_invalid_schedule_path_id_before_forwarding() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.patch(
            "/api/gateway/control/schedules/-unsafe",
            json={"enabled": True},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 404
    assert response.json() == {"detail": "Control endpoint not found"}
    assert calls == []


def test_control_proxy_allows_empty_schedule_delete_response() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/schedules/schedule-1":
            return httpx.Response(204)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.delete(
            "/api/gateway/control/schedules/schedule-1",
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 204
    assert response.content == b""
    assert calls == ["/api/control/session", "/api/control/schedules/schedule-1"]


@pytest.mark.parametrize(
    ("gateway_path", "upstream_path"),
    [
        ("/api/gateway/control/approvals", "/api/control/approvals"),
        ("/api/gateway/control/artifacts", "/api/control/artifacts"),
        ("/api/gateway/control/schedules", "/api/control/schedules"),
        ("/api/gateway/control/runs/bg_1/logs", "/api/control/runs/bg_1/logs"),
    ],
)
def test_control_proxy_rejects_non_json_success_response_contract(
    gateway_path: str,
    upstream_path: str,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == upstream_path:
            return httpx.Response(200, content=b"ok", headers={"content-type": "text/plain"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(gateway_path, cookies={"session_id": "s-1"})

    _assert_control_response_contract_error(
        response,
        [{"path": "$", "message": "control response must be JSON", "type": "value_error"}],
    )


@pytest.mark.parametrize(
    ("gateway_path", "upstream_path"),
    [
        ("/api/gateway/control/approvals", "/api/control/approvals"),
        ("/api/gateway/control/artifacts", "/api/control/artifacts"),
        ("/api/gateway/control/schedules", "/api/control/schedules"),
        ("/api/gateway/control/runs/bg_1/logs", "/api/control/runs/bg_1/logs"),
    ],
)
def test_control_proxy_rejects_malformed_json_success_response_contract(
    gateway_path: str,
    upstream_path: str,
) -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == upstream_path:
            return httpx.Response(200, content=b"{", headers={"content-type": "application/json"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get(gateway_path, cookies={"session_id": "s-1"})

    _assert_control_response_contract_error(
        response,
        [{"path": "$", "message": "control response must be valid JSON", "type": "value_error"}],
    )


def test_control_proxy_filters_hidden_artifacts_before_contract_validation() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/artifacts":
            return httpx.Response(
                200,
                json={
                    "artifacts": [
                        {
                            "artifact_id": "artifact-visible",
                            "run_id": "skill-visible",
                            "skill_run_id": "skill-visible",
                            "contract_name": "HtmlArtifact",
                        },
                        {"contract_name": "HtmlArtifact", "run_id": "bg-hidden"},
                    ]
                },
            )
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "runs": [
                        {
                            "kind": "autonomous",
                            "run_id": "bg-visible",
                            "task_id": "task-visible",
                            "state": "completed",
                            "skill_run_ids": ["skill-visible"],
                        }
                    ]
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/skill-visible":
            return httpx.Response(404, json={"detail": "not found"})
        if request.url.path == "/api/control/runs/bg-hidden":
            return httpx.Response(404, json={"detail": "not found"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/artifacts", cookies={"session_id": "s-1"})

    assert response.status_code == 200
    assert response.json() == {
        "artifacts": [
            {
                "artifact_id": "artifact-visible",
                "run_id": "skill-visible",
                "skill_run_id": "skill-visible",
                "contract_name": "HtmlArtifact",
            }
        ]
    }
    assert calls == [
        "/api/control/session",
        "/api/control/artifacts",
        "/api/control/runs/skill-visible",
        "/api/control/runs",
        "/api/control/runs/bg-hidden",
    ]


def test_control_proxy_rejects_visible_artifact_missing_provenance_after_filtering() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/artifacts":
            return httpx.Response(
                200,
                json={
                    "artifacts": [
                        {"artifact_id": "artifact-visible", "run_id": "skill-visible"},
                    ]
                },
            )
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "runs": [
                        {
                            "kind": "autonomous",
                            "run_id": "bg-visible",
                            "task_id": "task-visible",
                            "state": "completed",
                            "skill_run_ids": ["skill-visible"],
                        }
                    ]
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/skill-visible":
            return httpx.Response(404, json={"detail": "not found"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/artifacts", cookies={"session_id": "s-1"})

    _assert_control_response_contract_error(
        response,
        [
            {
                "path": "artifacts[0]",
                "message": "Value error, skill_run_id must be a non-empty string",
                "type": "value_error",
            }
        ],
    )
    assert calls == [
        "/api/control/session",
        "/api/control/artifacts",
        "/api/control/runs/skill-visible",
        "/api/control/runs",
    ]


def test_control_proxy_rejects_invalid_visible_artifact_contract_after_filtering() -> None:
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/artifacts":
            return httpx.Response(
                200,
                json={"artifacts": [{"contract_name": "HtmlArtifact", "run_id": "skill-visible"}]},
            )
        if request.url.path == "/api/control/runs":
            return httpx.Response(
                200,
                json={
                    "runs": [
                        {
                            "kind": "autonomous",
                            "run_id": "bg-visible",
                            "task_id": "task-visible",
                            "state": "completed",
                            "skill_run_ids": ["skill-visible"],
                        }
                    ]
                },
                headers={"X-Control-Plane-Version": "1"},
            )
        if request.url.path == "/api/control/runs/skill-visible":
            return httpx.Response(404, json={"detail": "not found"})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/artifacts", cookies={"session_id": "s-1"})

    _assert_control_response_contract_error(
        response,
        [
            {
                "path": "artifacts[0]",
                "message": "Value error, artifact_id or id must be a non-empty string",
                "type": "value_error",
            }
        ],
    )
    assert calls == [
        "/api/control/session",
        "/api/control/artifacts",
        "/api/control/runs/skill-visible",
        "/api/control/runs",
    ]


def test_control_proxy_rejects_invalid_run_logs_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1/logs":
            return httpx.Response(
                200,
                json={"run_id": "bg_1", "log_lines": "line 1", "more_available": False},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/runs/bg_1/logs", cookies={"session_id": "s-1"})

    _assert_control_response_contract_error(
        response,
        [{"path": "log_lines", "message": "Input should be a valid list", "type": "list_type"}],
    )


def test_control_proxy_rejects_invalid_schedule_list_contract() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/schedules":
            return httpx.Response(200, json={"schedules": [{"enabled": True}]})
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.get("/api/gateway/control/schedules", cookies={"session_id": "s-1"})

    _assert_control_response_contract_error(
        response,
        [
            {
                "path": "schedules[0]",
                "message": "Value error, schedule_id, id, name, or label must be a non-empty string",
                "type": "value_error",
            }
        ],
    )


def test_control_proxy_uses_control_token_fallback_for_chat_run_messages() -> None:
    calls: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return _control_chat_continuation_health_response()
        if request.url.path == "/api/control/session":
            calls.append({"path": request.url.path, "authorization": request.headers.get("authorization")})
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/sess-normal/messages":
            calls.append(
                {
                    "path": request.url.path,
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(
                200,
                json={"run": {"kind": "chat", "run_id": "sess-normal", "state": "completed"}},
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler, config=_control_chat_continuation_config())

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/sess-normal/messages",
            json={"messages": [{"role": "user", "content": "hello"}]},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert calls == [
        {"path": "/api/control/session", "authorization": None},
        {
            "path": "/api/control/runs/sess-normal/messages",
            "authorization": "Bearer control-token",
            "body": {"messages": [{"role": "user", "content": "hello"}]},
        },
    ]


def test_control_proxy_uses_control_token_for_autonomous_run_messages() -> None:
    message_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1/messages":
            message_requests.append(
                {
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(
                200,
                json={
                    "run": {"kind": "autonomous", "run_id": "bg_1", "task_id": "bg_1", "state": "running"},
                    "message_id": "msg-1",
                    "delivery_status": "delivered",
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/messages",
            json={"message": "keep going", "message_id": "msg-1", "channel": "excel", "user_id": "999"},
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert message_requests == [
        {
            "authorization": "Bearer control-token",
            "body": {"message": "keep going", "message_id": "msg-1"},
        }
    ]


def test_control_proxy_uses_control_token_for_resume_and_strips_identity() -> None:
    resume_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/runs/bg_1/resume":
            resume_requests.append(
                {
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content.decode("utf-8")),
                }
            )
            return httpx.Response(
                200,
                json={
                    "run": {
                        "kind": "autonomous",
                        "run_id": "bg_2",
                        "task_id": "bg_2",
                        "state": "running",
                        "resumed_from": "bg_1",
                    },
                    "run_id": "bg_2",
                    "task_id": "bg_2",
                    "resumed_from": "bg_1",
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/control/runs/bg_1/resume",
            json={
                "message": "continue",
                "request_id": "resume-1",
                "context": "Keep prior analyst context.",
                "channel": "excel",
                "user_id": "999",
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 200
    assert resume_requests == [
        {
            "authorization": "Bearer control-token",
            "body": {
                "message": "continue",
                "request_id": "resume-1",
                "context": "Keep prior analyst context.",
            },
        }
    ]


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


class _DelayedStream(httpx.AsyncByteStream):
    def __init__(self, payload: bytes) -> None:
        self.payload = payload
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.closed = asyncio.Event()

    async def __aiter__(self):
        self.started.set()
        await self.release.wait()
        yield self.payload

    async def aclose(self) -> None:
        self.closed.set()
        self.release.set()


def test_chat_stream_sends_proxy_heartbeat_while_upstream_is_silent(monkeypatch) -> None:
    monkeypatch.setattr(proxy_module, "_STREAM_HEARTBEAT_SECONDS", 0.05)

    async def run() -> None:
        delayed_stream = _DelayedStream(b'data: {"type":"stream_complete"}\n\n')
        calls = {"init": 0, "chat": 0}

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/chat/init":
                calls["init"] += 1
                return httpx.Response(200, json={"session_token": "token-1"})
            if request.url.path == "/api/chat":
                calls["chat"] += 1
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=delayed_stream,
                )
            raise AssertionError(f"Unexpected path: {request.url.path}")

        app, _router = _build_app(handler)
        async with _serve_app(app) as base_url:
            async with httpx.AsyncClient(
                base_url=base_url,
                timeout=httpx.Timeout(10.0, read=None),
            ) as client:
                async with client.stream(
                    "POST",
                    "/api/gateway/chat",
                    headers={"cookie": "session_id=s-1"},
                    json=_chat_payload(),
                ) as response:
                    assert response.status_code == 200
                    await asyncio.wait_for(delayed_stream.started.wait(), timeout=2)

                    raw_iter = response.aiter_raw().__aiter__()
                    first_chunk = await asyncio.wait_for(raw_iter.__anext__(), timeout=2)
                    assert b'"type": "heartbeat"' in first_chunk
                    assert b"stream_complete" not in first_chunk

                    delayed_stream.release.set()
                    remaining = b""
                    for _ in range(10):
                        remaining += await asyncio.wait_for(raw_iter.__anext__(), timeout=2)
                        if b"stream_complete" in remaining:
                            break

        assert calls == {"init": 1, "chat": 1}
        assert b"stream_complete" in remaining

    asyncio.run(run())


def test_control_events_stream_remains_available_while_chat_stream_lock_is_held() -> None:
    async def run() -> None:
        delayed_chat = _DelayedStream(b'data: {"type":"stream_complete"}\n\n')
        delayed_events = _DelayedStream(
            b'data: {"type":"run_state_changed","run_id":"bg_1","state":"running"}\n\n'
        )
        calls = {"init": 0, "chat": 0, "control_session": 0, "events": 0}
        control_auth: list[str | None] = []

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/chat/init":
                calls["init"] += 1
                return httpx.Response(200, json={"session_token": "chat-token-1"})
            if request.url.path == "/api/chat":
                calls["chat"] += 1
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=delayed_chat,
                )
            if request.url.path == "/api/control/session":
                calls["control_session"] += 1
                return httpx.Response(200, json={"session_token": "control-token-1"})
            if request.url.path == "/api/control/events":
                calls["events"] += 1
                control_auth.append(request.headers.get("authorization"))
                return httpx.Response(
                    200,
                    headers={
                        "content-type": "text/event-stream",
                        "X-Control-Plane-Version": "1",
                    },
                    stream=delayed_events,
                )
            raise AssertionError(f"Unexpected path: {request.url.path}")

        app, router = _build_app(handler)
        async with _serve_app(app) as base_url:
            timeout = httpx.Timeout(10.0, read=None)
            headers = {"cookie": "session_id=s-1"}
            async with (
                httpx.AsyncClient(base_url=base_url, timeout=timeout) as chat_client,
                httpx.AsyncClient(base_url=base_url, timeout=timeout) as control_client,
            ):
                async with chat_client.stream(
                    "POST",
                    "/api/gateway/chat",
                    headers=headers,
                    json=_chat_payload(),
                ) as chat_response:
                    assert chat_response.status_code == 200
                    await asyncio.wait_for(delayed_chat.started.wait(), timeout=2)

                    user_lock = await router._session_manager.get_stream_lock("101")
                    assert user_lock.locked()

                    control_stream = control_client.stream(
                        "GET",
                        "/api/gateway/control/events",
                        headers={**headers, "accept": "text/event-stream"},
                    )
                    events_response = await asyncio.wait_for(control_stream.__aenter__(), timeout=2)
                    try:
                        assert events_response.status_code == 200
                        assert events_response.headers["content-type"].startswith("text/event-stream")
                        assert control_auth == ["Bearer control-token-1"]
                        assert user_lock.locked()

                        events_raw = events_response.aiter_raw().__aiter__()
                        delayed_events.release.set()
                        event_chunk = await asyncio.wait_for(events_raw.__anext__(), timeout=2)
                        assert b'"type":"run_state_changed"' in event_chunk
                    finally:
                        await control_stream.__aexit__(None, None, None)

                    delayed_chat.release.set()
                    raw_iter = chat_response.aiter_raw().__aiter__()
                    remaining = b""
                    for _ in range(10):
                        remaining += await asyncio.wait_for(raw_iter.__anext__(), timeout=2)
                        if b"stream_complete" in remaining:
                            break

        assert calls == {"init": 1, "chat": 1, "control_session": 1, "events": 1}
        assert b"stream_complete" in remaining

    asyncio.run(run())


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
                        if not user_lock.locked() and router._session_manager.lookup_token("101") is None:
                            break
                        await asyncio.sleep(0.05)

                    assert not user_lock.locked()
                    assert router._session_manager.lookup_token("101") is None

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


def test_proxy_auth_expired_retries_with_reinit_and_same_payload() -> None:
    script = textwrap.dedent(
        """
        import json

        import httpx
        from fastapi import FastAPI, HTTPException, Request
        from fastapi.testclient import TestClient

        from app_platform.gateway import GatewayConfig, create_gateway_router

        calls = {"init_payloads": [], "chat_payloads": [], "chat_auth": []}

        async def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/api/chat/init":
                calls["init_payloads"].append(json.loads(request.content.decode("utf-8")))
                token = f"token-{len(calls['init_payloads'])}"
                return httpx.Response(200, json={"session_token": token})
            if request.url.path == "/api/chat":
                calls["chat_payloads"].append(json.loads(request.content.decode("utf-8")))
                calls["chat_auth"].append(request.headers.get("authorization"))
                if len(calls["chat_auth"]) == 1:
                    return httpx.Response(401, json={"error": "auth_expired"})
                return httpx.Response(
                    200,
                    headers={"content-type": "text/event-stream"},
                    stream=httpx.ByteStream(b'data: {"type":"stream_complete"}\\n\\n'),
                )
            raise AssertionError(f"Unexpected path: {request.url.path}")

        transport = httpx.MockTransport(handler)

        def get_current_user(request: Request) -> dict:
            del request
            return {"user_id": 101, "email": "test@example.com", "tier": "paid"}

        router = create_gateway_router(
            GatewayConfig(
                gateway_url="http://gateway.local",
                api_key="gateway-api-key",
                ssl_verify=True,
            ),
            get_current_user=get_current_user,
            http_client_factory=lambda: httpx.AsyncClient(transport=transport),
        )

        app = FastAPI()
        app.include_router(router, prefix="/api/gateway")

        with TestClient(app) as client:
            response = client.post(
                "/api/gateway/chat",
                json={
                    "messages": [{"role": "user", "content": "hello"}],
                    "context": {"portfolio_name": "Main Portfolio"},
                },
                cookies={"session_id": "s-1"},
            )

        assert response.status_code == 200
        print(json.dumps(calls, sort_keys=True))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )
    calls = json.loads(result.stdout)

    assert len(calls["init_payloads"]) == 2
    for init_payload in calls["init_payloads"]:
        _assert_web_session_init_payload(init_payload)
    assert calls["chat_payloads"] == [
        {
            "messages": [{"role": "user", "content": "hello"}],
            "context": {"portfolio_name": "Main Portfolio", "channel": "web", "user_id": "101"},
            "metadata": {},
            "user_id": "101",
            "request_id": calls["chat_payloads"][0]["request_id"],
        },
        {
            "messages": [{"role": "user", "content": "hello"}],
            "context": {"portfolio_name": "Main Portfolio", "channel": "web", "user_id": "101"},
            "metadata": {},
            "user_id": "101",
            "request_id": calls["chat_payloads"][0]["request_id"],
        },
    ]
    assert calls["chat_auth"] == ["Bearer token-1", "Bearer token-2"]


def test_control_proxy_returns_cors_bearing_502_on_upstream_connect_error() -> None:
    """A cold/unreachable upstream must yield a handled, CORS-traversing 502 — not a bare 500 via
    ServerErrorMiddleware (which sits outside CORSMiddleware, so the browser gets net::ERR_FAILED
    with no Access-Control-Allow-Origin and the web Agent Control deck latches "unavailable")."""
    from app_platform.middleware.cors import configure_cors

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/health":
            raise httpx.ConnectError("connection refused", request=request)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)
    configure_cors(app, ["http://localhost:3000"])

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/control/health",
            cookies={"session_id": "s-1"},
            headers={"Origin": "http://localhost:3000"},
        )

    assert response.status_code == 502
    assert response.json()["detail"]["error"] == "control_upstream_unavailable"
    # The point of the fix: the error response carries CORS headers so the browser can read it.
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_control_proxy_returns_cors_bearing_504_on_upstream_timeout() -> None:
    """An upstream timeout must yield a handled, CORS-traversing 504 (same CORS-bypass hazard)."""
    from app_platform.middleware.cors import configure_cors

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/health":
            raise httpx.ReadTimeout("timed out", request=request)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)
    configure_cors(app, ["http://localhost:3000"])

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/control/health",
            cookies={"session_id": "s-1"},
            headers={"Origin": "http://localhost:3000"},
        )

    assert response.status_code == 504
    assert response.json()["detail"]["error"] == "control_upstream_timeout"
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_control_events_stream_returns_cors_bearing_502_on_upstream_connect_error() -> None:
    """The SSE control-events stream must convert a setup-time upstream connect error into a handled,
    CORS-traversing 502 rather than re-raising it as a CORS-less 500."""
    from app_platform.middleware.cors import configure_cors

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/events":
            raise httpx.ConnectError("connection refused", request=request)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)
    configure_cors(app, ["http://localhost:3000"])

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/control/events",
            cookies={"session_id": "s-1"},
            headers={"Origin": "http://localhost:3000"},
        )

    assert response.status_code == 502
    assert response.json()["detail"]["error"] == "control_upstream_unavailable"
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_control_events_stream_returns_cors_bearing_504_on_upstream_timeout() -> None:
    """The SSE control-events stream must convert a setup-time upstream timeout into a CORS-traversing 504."""
    from app_platform.middleware.cors import configure_cors

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/control/events":
            raise httpx.ConnectTimeout("timed out", request=request)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)
    configure_cors(app, ["http://localhost:3000"])

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/control/events",
            cookies={"session_id": "s-1"},
            headers={"Origin": "http://localhost:3000"},
        )

    assert response.status_code == 504
    assert response.json()["detail"]["error"] == "control_upstream_timeout"
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_artifact_detail_proxy_returns_cors_bearing_502_on_upstream_connect_error() -> None:
    """The artifact-detail proxy must convert an upstream connect error into a CORS-traversing 502."""
    from app_platform.middleware.cors import configure_cors

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/artifacts/PCTY/earnings-scenarios/latest":
            raise httpx.ConnectError("connection refused", request=request)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)
    configure_cors(app, ["http://localhost:3000"])

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/artifacts/PCTY/earnings-scenarios/latest",
            cookies={"session_id": "s-1"},
            headers={"Origin": "http://localhost:3000"},
        )

    assert response.status_code == 502
    assert response.json()["detail"]["error"] == "control_upstream_unavailable"
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_artifact_detail_proxy_returns_cors_bearing_504_on_upstream_timeout() -> None:
    """The artifact-detail proxy must convert an upstream timeout into a CORS-traversing 504."""
    from app_platform.middleware.cors import configure_cors

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/control/session":
            return httpx.Response(200, json={"session_token": "control-token"})
        if request.url.path == "/api/artifacts/PCTY/earnings-scenarios/latest":
            raise httpx.ReadTimeout("timed out", request=request)
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)
    configure_cors(app, ["http://localhost:3000"])

    with TestClient(app) as client:
        response = client.get(
            "/api/gateway/artifacts/PCTY/earnings-scenarios/latest",
            cookies={"session_id": "s-1"},
            headers={"Origin": "http://localhost:3000"},
        )

    assert response.status_code == 504
    assert response.json()["detail"]["error"] == "control_upstream_timeout"
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_open_gateway_chat_stream_times_out_when_headers_never_arrive(monkeypatch) -> None:
    monkeypatch.setattr(proxy_module, "_STREAM_OPEN_TIMEOUT_SECONDS", 0.05)

    class _HangingClient:
        def build_request(self, method, url, headers=None, json=None):
            return object()

        async def send(self, request, stream=False):
            await asyncio.sleep(3600)

    async def _run() -> None:
        with pytest.raises(HTTPException) as excinfo:
            await proxy_module._open_gateway_chat_stream(
                client=_HangingClient(),
                gateway_url="http://gateway.local",
                session_token="tok",
                payload={},
            )
        assert excinfo.value.status_code == 504
        assert excinfo.value.detail["error"] == "gateway_stream_open_timeout"

    asyncio.run(_run())


def test_read_error_body_times_out_to_empty(monkeypatch) -> None:
    monkeypatch.setattr(proxy_module, "_ERROR_BODY_READ_TIMEOUT_SECONDS", 0.05)

    class _StallingResponse:
        async def aread(self):
            await asyncio.sleep(3600)

    async def _run() -> None:
        body = await proxy_module._read_error_body(_StallingResponse())
        assert body == b""

    asyncio.run(_run())


def test_chat_stalled_error_body_returns_upstream_status_with_fallback_detail(monkeypatch) -> None:
    """LH-13 round 3: an upstream error whose BODY stalls must surface the real
    upstream status with the fallback detail — not hang, and not degrade to a
    generic 502 via a second read of the consumed stream."""

    monkeypatch.setattr(proxy_module, "_ERROR_BODY_READ_TIMEOUT_SECONDS", 0.05)

    class _StallingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            await asyncio.sleep(3600)
            yield b""

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/chat/init":
            return httpx.Response(200, json={"session_token": "token-1"})
        if request.url.path == "/api/chat":
            return httpx.Response(
                503,
                headers={"content-type": "application/json"},
                stream=_StallingStream(),
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    app, _router = _build_app(handler)

    with TestClient(app) as client:
        response = client.post(
            "/api/gateway/chat",
            json={
                **_chat_payload(),
                "context": {"portfolio_name": "Main Portfolio", "purpose": "chat"},
            },
            cookies={"session_id": "s-1"},
        )

    assert response.status_code == 503
    assert response.content == b"Gateway error (503)"
