"""Focused tests for authenticated gateway capability choices."""

from __future__ import annotations

import json

import httpx
from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient

from app_platform.gateway import GatewayConfig, create_gateway_router
from app_platform.gateway.session import GatewaySessionManager


def _choice_response(
    model_key: str,
    label: str,
    *,
    reason: str = "capability_default",
) -> dict:
    return {
        "capability": "session.driver",
        "catalog_revision": "2026-08-13.1",
        "policy_revision": "2026-08-13.1",
        "selected": {
            "model_key": model_key,
            "label": label,
            "effort": "high",
            "reason": reason,
        },
        "notices": [],
        "choices": [
            {
                "model_key": model_key,
                "label": label,
                "supported_efforts": ["high"],
                "default_effort": "high",
                "lifecycle": "active",
            }
        ],
    }


def _build_app(handler):
    transport = httpx.MockTransport(handler)

    def get_current_user(request: Request) -> dict:
        session_id = request.cookies.get("session_id")
        if not session_id:
            raise HTTPException(status_code=401, detail="Authentication required")
        user_id = 202 if session_id == "s-202" else 101
        return {
            "user_id": user_id,
            "email": f"user-{user_id}@example.com",
            "tier": "paid",
        }

    router = create_gateway_router(
        config=GatewayConfig(
            gateway_url="http://gateway.local",
            api_key="gateway-api-key",
            ssl_verify=True,
        ),
        get_current_user=get_current_user,
        http_client_factory=lambda: httpx.AsyncClient(transport=transport),
    )
    app = FastAPI()
    app.include_router(router, prefix="/api/gateway")
    return app


def test_extract_capability_choices_keeps_closed_upstream_projection() -> None:
    choices = {"session.driver": _choice_response("anthropic.claude-opus-5", "Opus 5")}
    assert GatewaySessionManager._extract_capability_choices(
        {"capability_choices": choices}
    ) == choices
    assert GatewaySessionManager._extract_capability_choices({"model_catalog": {}}) is None


def test_capability_choices_are_scoped_by_authenticated_user() -> None:
    init_users: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/health":
            return httpx.Response(200, json={"status": "ok", "package": {"contracts": []}})
        if request.url.path == "/api/chat/init":
            payload = json.loads(request.content)
            user_id = str(payload["user_id"])
            init_users.append(user_id)
            model_key = (
                "anthropic.claude-opus-5"
                if user_id == "101"
                else "openai.gpt-5-6"
            )
            label = "Opus 5" if user_id == "101" else "GPT-5.6"
            return httpx.Response(
                200,
                json={
                    "session_token": f"token-{user_id}",
                    "session_id": f"session-{user_id}",
                    "capability_choices": {
                        "session.driver": _choice_response(model_key, label)
                    },
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with TestClient(_build_app(handler)) as client:
        first = client.get(
            "/api/gateway/capability-choices/session.driver",
            cookies={"session_id": "s-101"},
        )
        second = client.get(
            "/api/gateway/capability-choices/session.driver",
            cookies={"session_id": "s-202"},
        )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["selected"]["model_key"] == "anthropic.claude-opus-5"
    assert second.json()["selected"]["model_key"] == "openai.gpt-5-6"
    assert init_users == ["101", "202"]


def test_model_preference_write_and_clear_use_chat_bearer_and_refresh_choices() -> None:
    saved = False
    init_count = 0
    preference_requests: list[dict[str, object]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        nonlocal init_count, saved
        if request.url.path == "/api/health":
            return httpx.Response(200, json={"status": "ok", "package": {"contracts": []}})
        if request.url.path == "/api/chat/init":
            init_count += 1
            return httpx.Response(
                200,
                json={
                    "session_token": f"token-{init_count}",
                    "session_id": f"session-{init_count}",
                    "capability_choices": {
                        "session.driver": _choice_response(
                            "anthropic.claude-opus-5",
                            "Opus 5",
                            reason="saved_preference" if saved else "capability_default",
                        )
                    },
                },
            )
        if request.url.path == "/api/model-preferences/session.driver":
            preference_requests.append(
                {
                    "method": request.method,
                    "authorization": request.headers.get("authorization"),
                    "body": json.loads(request.content) if request.content else None,
                }
            )
            saved = request.method == "PUT"
            return httpx.Response(
                200,
                json={
                    "capability": "session.driver",
                    "model_key": "anthropic.claude-opus-5" if saved else None,
                    "effort": "high" if saved else None,
                },
            )
        raise AssertionError(f"Unexpected path: {request.url.path}")

    with TestClient(_build_app(handler)) as client:
        initial = client.get(
            "/api/gateway/capability-choices/session.driver",
            cookies={"session_id": "s-101"},
        )
        saved_response = client.put(
            "/api/gateway/model-preferences/session.driver",
            json={
                "model_key": "anthropic.claude-opus-5",
                "effort": "high",
                "catalog_revision": "2026-08-13.1",
            },
            cookies={"session_id": "s-101"},
        )
        saved_choices = client.get(
            "/api/gateway/capability-choices/session.driver",
            cookies={"session_id": "s-101"},
        )
        cleared_response = client.delete(
            "/api/gateway/model-preferences/session.driver",
            cookies={"session_id": "s-101"},
        )
        cleared_choices = client.get(
            "/api/gateway/capability-choices/session.driver",
            cookies={"session_id": "s-101"},
        )

    assert initial.json()["selected"]["reason"] == "capability_default"
    assert saved_response.json() == {
        "capability": "session.driver",
        "model_key": "anthropic.claude-opus-5",
        "effort": "high",
    }
    assert saved_response.headers["cache-control"] == "private, no-store"
    assert saved_choices.json()["selected"]["reason"] == "saved_preference"
    assert cleared_response.json() == {
        "capability": "session.driver",
        "model_key": None,
        "effort": None,
    }
    assert cleared_choices.json()["selected"]["reason"] == "capability_default"
    assert init_count == 3
    assert preference_requests == [
        {
            "method": "PUT",
            "authorization": "Bearer token-1",
            "body": {
                "model_key": "anthropic.claude-opus-5",
                "effort": "high",
                "catalog_revision": "2026-08-13.1",
            },
        },
        {
            "method": "DELETE",
            "authorization": "Bearer token-2",
            "body": None,
        },
    ]
