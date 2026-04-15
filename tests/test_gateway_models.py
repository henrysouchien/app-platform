from __future__ import annotations

import pytest
from pydantic import ValidationError

from app_platform.gateway.models import GatewayChatRequest, GatewayToolApprovalRequest


def test_gateway_chat_request_defaults_context_metadata_and_model() -> None:
    payload = GatewayChatRequest(messages=[{"role": "user", "content": "hello"}])

    assert payload.context == {}
    assert payload.metadata == {}
    assert payload.model is None


def test_gateway_tool_approval_request_allows_optional_allow_tool_type() -> None:
    payload = GatewayToolApprovalRequest(
        tool_call_id="tool-1",
        nonce="nonce-1",
        approved=True,
    )

    assert payload.allow_tool_type is None


def test_gateway_chat_request_requires_message_list() -> None:
    with pytest.raises(ValidationError):
        GatewayChatRequest(messages="hello")  # type: ignore[arg-type]
