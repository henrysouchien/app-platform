"""Fail-closed production composition for the customer MCP token portal."""

from __future__ import annotations

import base64
import json
import os

from database import get_db_session

from .flags import get_commercial_flags
from .mcp_token_codec import McpTokenPepperRing
from .mcp_token_portal import PostgresMcpTokenPortalService
from .mcp_token_portal_commands import PostgresMcpTokenPortalCommandService
from .mcp_tokens import McpTokenLifetimePolicy


def _lifetime_policy() -> McpTokenLifetimePolicy:
    return McpTokenLifetimePolicy(
        minimum_lifetime_seconds=60,
        maximum_self_serve_lifetime_seconds=90 * 24 * 60 * 60,
        maximum_contract_lifetime_seconds=365 * 24 * 60 * 60,
    )


def load_mcp_token_pepper_ring(
    environment: dict[str, str],
) -> McpTokenPepperRing | None:
    document = environment.get("MCP_TOKEN_PEPPERS_JSON")
    active = environment.get("MCP_TOKEN_ACTIVE_PEPPER_VERSION")
    if not document and not active:
        return None
    if not document or not active or not active.isascii() or not active.isdigit():
        raise ValueError("MCP token pepper configuration is incomplete")
    raw = json.loads(document)
    if not isinstance(raw, dict) or not raw:
        raise ValueError("MCP token pepper configuration must be a non-empty object")
    peppers: dict[int, bytes] = {}
    for version, encoded in raw.items():
        if not isinstance(version, str) or not version.isascii() or not version.isdigit():
            raise ValueError("MCP token pepper version is invalid")
        if not isinstance(encoded, str):
            raise ValueError("MCP token pepper value is invalid")
        try:
            decoded = base64.b64decode(encoded, validate=True)
        except Exception as error:
            raise ValueError("MCP token pepper must use canonical base64") from error
        if base64.b64encode(decoded).decode("ascii") != encoded:
            raise ValueError("MCP token pepper must use canonical base64")
        peppers[int(version)] = decoded
    return McpTokenPepperRing(active_version=int(active), peppers=peppers)


def build_mcp_token_portal_runtime(environment: dict[str, str] | None = None):
    """Return a runtime only when the complete rollout gate is configured."""

    from routes.mcp_token_portal import McpTokenPortalApiRuntime

    values = dict(os.environ) if environment is None else environment
    flags = get_commercial_flags()
    if not (
        flags.commercial_control_enabled
        and flags.commercial_entitlement_projection_enabled
        and flags.commercial_usage_ingest_enabled
        and flags.commercial_budget_enforcement_enabled
        and flags.mcp_external_auth_enabled
    ):
        return None
    ring = load_mcp_token_pepper_ring(values)
    if ring is None:
        return None
    lifetime = _lifetime_policy()
    return McpTokenPortalApiRuntime(
        environment=flags.environment,
        connection_context_factory=get_db_session,
        agreement_service_factory=lambda connection: PostgresMcpTokenPortalService(
            connection, flags=flags, lifetime_policy=lifetime,
        ),
        command_service_factory=lambda connection: PostgresMcpTokenPortalCommandService(
            connection, flags=flags, pepper_ring=ring, lifetime_policy=lifetime,
        ),
    )


__all__ = ["build_mcp_token_portal_runtime", "load_mcp_token_pepper_ring"]
