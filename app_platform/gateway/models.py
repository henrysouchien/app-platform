"""Pydantic models for the gateway proxy."""

from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class GatewayChatRequest(BaseModel):
    """Client payload for proxied gateway chat."""

    messages: list[dict[str, Any]]
    context: dict[str, Any] = Field(default_factory=dict)
    model: Optional[str] = None


class GatewayToolApprovalRequest(BaseModel):
    """Client payload for proxied gateway tool approvals."""

    tool_call_id: str
    nonce: str
    approved: bool
    allow_tool_type: Optional[bool] = None


__all__ = ["GatewayChatRequest", "GatewayToolApprovalRequest"]
