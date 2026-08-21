"""Trusted MCP metadata bridge into the irreversible provider guard."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Literal
from uuid import UUID

from pydantic import Field

from app_platform.commercial.flags import get_commercial_flags
from app_platform.commercial.brokerage_binding import authorize_brokerage_account
from app_platform.commercial.irreversible_authorization import (
    IrreversibleAuthorityRequest,
    authorize_irreversible_submission,
)
from app_platform.commercial.mcp_exposure import load_mcp_exposure_manifest
from app_platform.commercial.models import StableCode, StrictCommercialModel
from database import get_db_session
from services.trading.irreversible_guard import (
    IrreversibleSubmissionFacts,
    IrreversibleSubmissionGuard,
    allow_legacy_irreversible_submission,
)
from utils.gateway_context import _COMMERCIAL_LINEAGE_CTX


class McpCommercialLineage(StrictCommercialModel):
    tool_name: str = Field(min_length=1, max_length=128)
    execution_context_id: UUID
    work_authorization_id: UUID
    workflow_run_id: UUID
    entitlement_revision: int = Field(gt=0)
    request_id: str = Field(min_length=1, max_length=255)
    session_id: str = Field(min_length=1, max_length=255)
    operation: StableCode
    capability_id: StableCode | None = None
    provider: StableCode
    billing_mode: Literal["byok", "metered"]


_TOOL_KEYS = {
    "cancel_order": "portfolio-trades-mcp:cancel_order",
    "execute_basket_trade": "portfolio-trades-mcp:execute_basket_trade",
    "execute_futures_roll": "portfolio-trades-mcp:execute_futures_roll",
    "execute_option_trade": "portfolio-trades-mcp:execute_option_trade",
    "execute_trade": "portfolio-trades-mcp:execute_trade",
}


def parse_commercial_lineage(value: object, *, tool_name: str) -> McpCommercialLineage:
    lineage = McpCommercialLineage.model_validate(value)
    if lineage.tool_name != tool_name or tool_name not in _TOOL_KEYS:
        raise ValueError("commercial lineage tool identity mismatch")
    return lineage


def current_irreversible_guard(tool_name: str) -> IrreversibleSubmissionGuard:
    lineage = _COMMERCIAL_LINEAGE_CTX.get()
    if lineage is None:
        exposure = load_mcp_exposure_manifest().tools.get(_TOOL_KEYS[tool_name])
        if exposure is not None and exposure.exposure == "hosted-public":
            raise ValueError("hosted irreversible tool requires commercial lineage")
        return allow_legacy_irreversible_submission
    if not isinstance(lineage, McpCommercialLineage) or lineage.tool_name != tool_name:
        raise ValueError("commercial lineage is not bound to this tool")
    tool_key = _TOOL_KEYS[tool_name]

    @contextmanager
    def guard(facts: IrreversibleSubmissionFacts, connection):
        def authorize(active_connection):
            result = authorize_irreversible_submission(
                active_connection,
                flags=get_commercial_flags(),
                request=IrreversibleAuthorityRequest(
                    execution_context_id=lineage.execution_context_id,
                    work_authorization_id=lineage.work_authorization_id,
                    workflow_run_id=lineage.workflow_run_id,
                    expected_entitlement_revision=lineage.entitlement_revision,
                    environment=get_commercial_flags().environment,
                    tool_key=tool_key,
                    request_id=lineage.request_id,
                    session_id=lineage.session_id,
                    operation=lineage.operation,
                    capability_id=lineage.capability_id,
                    provider=lineage.provider,
                    billing_mode=lineage.billing_mode,
                    exposure_manifest=load_mcp_exposure_manifest(),
                ),
            )
            if result.user_id != facts.user_id:
                raise ValueError("commercial authority user differs from trade owner")
            authorize_brokerage_account(
                active_connection, user_id=result.user_id,
                account_id=facts.account_id, provider=facts.provider,
            )

        if connection is not None:
            authorize(connection)
            yield
            return
        with get_db_session() as active_connection:
            active_connection.autocommit = False
            authorize(active_connection)
            yield

    return guard


__all__ = [
    "McpCommercialLineage",
    "current_irreversible_guard",
    "parse_commercial_lineage",
]
