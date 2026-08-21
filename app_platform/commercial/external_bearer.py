"""Fail-closed identity contract for the future HP1 external bearer boundary."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from pydantic import Field

from .legacy_cutover import require_mcp_external_bearer
from .models import StrictCommercialModel


class ExternalBearerEvidence(StrictCommercialModel):
    """Authoritative lookup results; never raw bearer or credential material."""

    mcp_token_id: UUID | None = None
    legacy_api_key_user_id: Annotated[int, Field(gt=0)] | None = None


def resolve_mcp_external_token(evidence: ExternalBearerEvidence) -> UUID:
    """Return only an unambiguous MCP token identity; reject legacy credentials."""

    require_mcp_external_bearer(
        legacy_api_key_match=evidence.legacy_api_key_user_id is not None,
        mcp_token_match=evidence.mcp_token_id is not None,
    )
    if evidence.mcp_token_id is None:  # narrowed by the fail-closed contract above
        raise AssertionError("MCP token identity unexpectedly absent")
    return evidence.mcp_token_id


__all__ = ["ExternalBearerEvidence", "resolve_mcp_external_token"]
