from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import textwrap

import httpx
import pytest
from fastapi import HTTPException
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import jwt

from app_platform.gateway.session import GatewaySessionManager
from app_platform.gateway.subject_assertion import GatewaySubjectAssertionIssuer


def test_gateway_session_manager_invalidate_token_removes_cached_token() -> None:
    manager = GatewaySessionManager()
    manager._token_store.set("user-1", "token-1")

    manager.invalidate_token("user-1")

    assert manager.lookup_token("user-1") is None


def test_gateway_session_manager_init_payload_includes_user_id_user_email_and_channel() -> None:
    script = textwrap.dedent(
        """
        import asyncio
        import json

        from app_platform.gateway.session import GatewaySessionManager

        captured = {}

        class _FakeResponse:
            status_code = 200

            def json(self):
                return {"session_token": "token-1"}

        class _FakeClient:
            async def post(self, url, json, timeout=None):
                captured["url"] = url
                captured["json"] = json
                return _FakeResponse()

        async def _run():
            manager = GatewaySessionManager()
            token = await manager._initialize_session(
                client=_FakeClient(),
                api_key="gateway-api-key",
                gateway_url="http://gateway.local",
                user_id="101",
                channel="web",
                user_email="user@example.com",
            )
            assert token == "token-1"

        asyncio.run(_run())
        print(json.dumps(captured, sort_keys=True))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(result.stdout) == {
        "url": "http://gateway.local/api/chat/init",
        "json": {
            "api_key": "gateway-api-key",
            "user_id": "101",
            "user_email": "user@example.com",
            "context": {"channel": "web"},
        },
    }


def test_gateway_session_manager_control_token_uses_control_session_endpoint() -> None:
    script = textwrap.dedent(
        """
        import asyncio
        import json

        from app_platform.gateway.session import GatewaySessionManager

        captured = {}

        class _FakeResponse:
            status_code = 200

            def json(self):
                return {"session_token": "control-token"}

        class _FakeClient:
            async def post(self, url, json, timeout=None):
                captured["url"] = url
                captured["json"] = json
                return _FakeResponse()

        async def _run():
            manager = GatewaySessionManager()
            token = await manager.get_control_token(
                user_key="101",
                client=_FakeClient(),
                api_key_fn=lambda: "gateway-api-key",
                gateway_url_fn=lambda: "http://gateway.local",
                channel="web",
                user_email="user@example.com",
            )
            assert token == "control-token"

        asyncio.run(_run())
        print(json.dumps(captured, sort_keys=True))
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", script],
        check=True,
        capture_output=True,
        text=True,
    )

    assert json.loads(result.stdout) == {
        "url": "http://gateway.local/api/control/session",
        "json": {
            "api_key": "gateway-api-key",
            "user_id": "101",
            "user_email": "user@example.com",
            "context": {"channel": "web"},
        },
    }


def test_gateway_session_manager_attaches_assertion_to_web_init() -> None:
    captured: dict[str, object] = {}
    private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    issuer = GatewaySubjectAssertionIssuer(private_key, "risk-web-v1")

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"session_token": "token-1"}

    class _FakeClient:
        async def post(self, url, json, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return _FakeResponse()

    async def _run() -> None:
        manager = GatewaySessionManager(subject_assertion_issuer=issuer)
        await manager._initialize_session(
            client=_FakeClient(),
            api_key="gateway-api-key",
            gateway_url="http://gateway.local",
            user_id="101",
            channel="web",
            user_email="user@example.com",
        )

    asyncio.run(_run())

    payload = captured["json"]
    assert isinstance(payload, dict)
    assertion = payload.pop("subject_assertion")
    request_id = payload.pop("request_id")
    claims = jwt.decode(
        assertion,
        private_key.public_key(),
        algorithms=["EdDSA"],
        audience="agent-gateway-session-init",
        issuer="risk-module-web-auth",
    )
    assert claims["sub"] == "101"
    assert claims["email"] == "user@example.com"
    assert claims["request_id"] == request_id
    assert payload == {
        "api_key": "gateway-api-key",
        "user_id": "101",
        "user_email": "user@example.com",
        "context": {"channel": "web"},
    }


def test_gateway_session_manager_caches_chat_session_id_by_conversation() -> None:
    captured: dict[str, object] = {}

    class _FakeResponse:
        status_code = 200

        def json(self):
            return {"session_token": "token-1", "session_id": "sess-1"}

    class _FakeClient:
        async def post(self, url, json, timeout=None):
            captured["url"] = url
            captured["json"] = json
            return _FakeResponse()

    async def _run() -> GatewaySessionManager:
        manager = GatewaySessionManager()
        token = await manager.get_token(
            user_key="101",
            client=_FakeClient(),
            api_key_fn=lambda: "gateway-api-key",
            gateway_url_fn=lambda: "http://gateway.local",
            conversation_id="thread-7",
            channel="web",
            user_email="user@example.com",
        )
        assert token == "token-1"
        return manager

    manager = asyncio.run(_run())

    assert captured == {
        "url": "http://gateway.local/api/chat/init",
        "json": {
            "api_key": "gateway-api-key",
            "user_id": "101",
            "user_email": "user@example.com",
            "context": {"channel": "web"},
        },
    }
    assert manager.lookup_session_id("101", "thread-7") == "sess-1"
    manager.invalidate_token("101", "thread-7")
    assert manager.lookup_session_id("101", "thread-7") is None


def test_gateway_session_manager_init_timeout_maps_to_504() -> None:
    class _TimeoutClient:
        async def post(self, url, json, timeout=None):
            raise httpx.ReadTimeout("init timed out")

    async def _run() -> None:
        manager = GatewaySessionManager()
        with pytest.raises(HTTPException) as excinfo:
            await manager._initialize_session_state(
                client=_TimeoutClient(),
                api_key="gateway-api-key",
                gateway_url="http://gateway.local",
                user_id="101",
            )
        assert excinfo.value.status_code == 504
        assert excinfo.value.detail["error"] == "gateway_session_init_timeout"

    asyncio.run(_run())
