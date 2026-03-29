from __future__ import annotations

from app_platform.gateway.session import GatewaySessionManager


def test_gateway_session_manager_invalidate_token_removes_cached_token() -> None:
    manager = GatewaySessionManager()
    manager._token_store.set("user-1", "token-1")

    manager.invalidate_token("user-1")

    assert manager.lookup_token("user-1") is None
