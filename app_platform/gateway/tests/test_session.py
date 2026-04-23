from __future__ import annotations

import json
import subprocess
import sys
import textwrap

from app_platform.gateway.session import GatewaySessionManager


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
            async def post(self, url, json):
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
