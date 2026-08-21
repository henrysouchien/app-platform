"""Fail-closed production composition for invite-only trial activation."""

from __future__ import annotations

import os

from database import get_db_session

from .entitlement_store import AccountEntitlementProjectionHook
from .flags import get_commercial_flags
from .invite_trials import InviteTrialService
from .invite_trial_tokens import InviteTrialTokenService
from .mcp_token_portal_runtime import load_mcp_token_pepper_ring
from .mcp_tokens import McpTokenLifetimePolicy


def build_invite_trial_runtime(environment: dict[str, str] | None = None):
    """Return the customer activation runtime only when every trial gate is enabled."""

    from routes.invite_trials import InviteTrialApiRuntime

    flags = get_commercial_flags()
    if not flags.invite_trial_enabled:
        return None
    flags.validate()
    values = dict(os.environ) if environment is None else environment
    pepper_ring = load_mcp_token_pepper_ring(values)
    if pepper_ring is None:
        raise ValueError("Invite trial token pepper configuration is incomplete")
    projection = AccountEntitlementProjectionHook(flags=flags)
    lifetime_policy = McpTokenLifetimePolicy(
        minimum_lifetime_seconds=60,
        maximum_self_serve_lifetime_seconds=90 * 24 * 60 * 60,
        maximum_contract_lifetime_seconds=365 * 24 * 60 * 60,
    )
    return InviteTrialApiRuntime(
        environment=flags.environment,
        connection_context_factory=get_db_session,
        service_factory=lambda connection: InviteTrialService(
            connection,
            flags=flags,
            projection_hook=projection,
        ),
        token_service_factory=lambda connection: InviteTrialTokenService(
            connection,
            flags=flags,
            pepper_ring=pepper_ring,
            lifetime_policy=lifetime_policy,
        ),
    )


__all__ = ["build_invite_trial_runtime"]
