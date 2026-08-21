"""Bounded accepted-usage reconstruction for isolated restore drills."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from .contract import (
    CommercialUsageEvent,
    CommercialUsageEventV2,
    CommercialUsageEventV3,
    validate_usage_event,
)


MAX_RESTORE_REPLAY_BATCH = 10
_ENVIRONMENTS = frozenset({"dev", "staging", "prod"})
_EVENT_COLUMNS = (
    "canonical_event_id",
    "schema_version",
    "source_product",
    "source_event_id",
    "source_payload_sha256",
    "environment",
    "occurred_at",
    "execution_context_id",
    "request_id",
    "session_id",
    "parent_turn_id",
    "workflow_run_id",
    "reservation_id",
    "funding_route_id",
    "channel",
    "provider",
    "operation",
    "model",
    "capability_id",
    "usage_state",
    "uncached_input_tokens",
    "billable_output_tokens",
    "reasoning_tokens_observed",
    "cache_write_tokens",
    "cache_read_tokens",
    "is_batch",
    "provider_units",
    "separately_billed_tool_cost_usd",
    "producer_estimated_cost_usd",
    "provider_reported_cost_usd",
    "cost_observation_kind",
    "producer_rate_version",
    "shadow_rate_version",
    "raw_billing_mode",
    "workflow_attempt_group_id",
    "workflow_attempt_number",
    "retry_of_workflow_run_id",
    "workflow_attempt_kind",
    "work_authorization_id",
    "capability_bind",
    "provider_reported_model",
)
_EVENT_SELECT = """
    SELECT usage.event_id::text AS canonical_event_id,
           usage.source_schema_version AS schema_version,
           usage.source_product, usage.source_event_id,
           usage.source_payload_sha256, usage.environment, usage.occurred_at,
           usage.execution_context_id::text, usage.request_id, usage.session_id,
           usage.parent_turn_id, usage.workflow_run_id::text,
           usage.reservation_id::text, usage.funding_route_id::text,
           usage.channel, usage.provider, usage.operation, usage.model,
           usage.capability_id, usage.usage_state,
           usage.uncached_input_tokens, usage.billable_output_tokens,
           usage.reasoning_tokens_observed, usage.cache_write_tokens,
           usage.cache_read_tokens, usage.is_batch, usage.provider_units,
           usage.separately_billed_tool_cost_usd,
           usage.producer_estimated_cost_usd, usage.provider_reported_cost_usd,
           usage.cost_observation_kind, usage.producer_rate_version,
           rate_policy.version AS shadow_rate_version,
           funding_route.billing_mode AS raw_billing_mode,
           usage.workflow_attempt_group_id::text,
           usage.workflow_attempt_number,
           usage.retry_of_workflow_run_id::text,
           usage.workflow_attempt_kind,
           usage.work_authorization_id::text,
           usage.capability_bind,
           usage.provider_reported_model
      FROM commercial_usage_events AS usage
      JOIN commercial_policy_versions AS rate_policy
        ON rate_policy.id = usage.shadow_rate_policy_id
      JOIN commercial_funding_routes AS funding_route
        ON funding_route.id = usage.funding_route_id
       AND funding_route.provider = usage.provider
"""


class CommercialUsageRestoreReplayError(ValueError):
    """Secret-safe failure while reconstructing accepted replay authority."""


@dataclass(frozen=True, slots=True)
class AcceptedUsageReplay:
    canonical_event_id: UUID
    event: CommercialUsageEvent


def _row_mapping(row: object) -> dict[str, Any]:
    if isinstance(row, Mapping):
        try:
            return {name: row[name] for name in _EVENT_COLUMNS}
        except (KeyError, TypeError):
            raise CommercialUsageRestoreReplayError(
                "accepted usage replay row shape is invalid"
            ) from None
    try:
        values = tuple(row)  # type: ignore[arg-type]
    except TypeError:
        raise CommercialUsageRestoreReplayError(
            "accepted usage replay row is invalid"
        ) from None
    if len(values) != len(_EVENT_COLUMNS):
        raise CommercialUsageRestoreReplayError(
            "accepted usage replay row shape is invalid"
        )
    return dict(zip(_EVENT_COLUMNS, values, strict=True))


def _database_identity(connection: object) -> tuple[str, str, int | None]:
    cursor = connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute(
            "SELECT current_database() AS database_name, "
            "COALESCE(inet_server_addr()::text, 'local') AS server_address, "
            "inet_server_port() AS server_port"
        )
        row = cursor.fetchone()
    finally:
        cursor.close()
    if isinstance(row, Mapping):
        try:
            database_name = row["database_name"]
            server_address = row["server_address"]
            server_port = row["server_port"]
        except (KeyError, TypeError):
            raise CommercialUsageRestoreReplayError(
                "accepted usage replay database identity is invalid"
            ) from None
    else:
        try:
            database_name, server_address, server_port = tuple(row)
        except (TypeError, ValueError):
            raise CommercialUsageRestoreReplayError(
                "accepted usage replay database identity is invalid"
            ) from None
    if not str(database_name).strip() or not str(server_address).strip():
        raise CommercialUsageRestoreReplayError(
            "accepted usage replay database identity is invalid"
        ) from None
    try:
        normalized_port = int(server_port) if server_port is not None else None
    except (TypeError, ValueError):
        raise CommercialUsageRestoreReplayError(
            "accepted usage replay database identity is invalid"
        ) from None
    return str(database_name), str(server_address), normalized_port


def _validated_replay(row: object) -> AcceptedUsageReplay:
    values = _row_mapping(row)
    canonical_raw = values.pop("canonical_event_id", None)
    if values.get("schema_version") != 3:
        values.pop("capability_bind", None)
        values.pop("provider_reported_model", None)
    try:
        canonical_event_id = UUID(str(canonical_raw))
        event = validate_usage_event(values)
    except (TypeError, ValueError, ValidationError):
        raise CommercialUsageRestoreReplayError(
            "accepted usage replay facts are invalid"
        ) from None
    if not isinstance(event, (CommercialUsageEventV2, CommercialUsageEventV3)):
        raise CommercialUsageRestoreReplayError(
            "accepted usage replay requires versioned attempt authority"
        )
    return AcceptedUsageReplay(
        canonical_event_id=canonical_event_id,
        event=event,
    )


def _load_source_batch(
    connection: object, *, environment: str, limit: int
) -> tuple[AcceptedUsageReplay, ...]:
    cursor = connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute(
            _EVENT_SELECT
            + """
             WHERE usage.environment = %s
               AND usage.source_schema_version IN (2, 3)
               AND NOT EXISTS (
                   SELECT 1
                     FROM commercial_usage_ingest_conflicts AS conflict
                    WHERE conflict.canonical_usage_event_id = usage.id
               )
             ORDER BY usage.received_at DESC, usage.id DESC
             LIMIT %s
            """,
            (environment, limit),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
    if not rows:
        raise CommercialUsageRestoreReplayError(
            "accepted versioned usage replay batch is empty"
        )
    batch = tuple(_validated_replay(row) for row in rows)
    identities = {
        (item.event.source_product, item.event.source_event_id) for item in batch
    }
    if len(identities) != len(batch):
        raise CommercialUsageRestoreReplayError(
            "accepted usage replay identities are duplicated"
        )
    return batch


def _load_restored_identity(
    connection: object,
    *,
    environment: str,
    source_product: str,
    source_event_id: str,
) -> AcceptedUsageReplay:
    cursor = connection.cursor()  # type: ignore[attr-defined]
    try:
        cursor.execute(
            _EVENT_SELECT
            + """
             WHERE usage.environment = %s
               AND usage.source_product = %s
               AND usage.source_event_id = %s
               AND usage.source_schema_version IN (2, 3)
               AND NOT EXISTS (
                   SELECT 1
                     FROM commercial_usage_ingest_conflicts AS conflict
                    WHERE conflict.canonical_usage_event_id = usage.id
               )
            """,
            (environment, source_product, source_event_id),
        )
        rows = cursor.fetchall()
    finally:
        cursor.close()
    if len(rows) != 1:
        raise CommercialUsageRestoreReplayError(
            "accepted usage replay identity is missing or ambiguous"
        )
    return _validated_replay(rows[0])


def load_accepted_usage_replay_batch(
    source_connection: object,
    restore_connection: object,
    *,
    environment: str,
    limit: int,
) -> tuple[AcceptedUsageReplay, ...]:
    """Bind exact accepted versioned usage facts across source and restore."""

    if (
        not isinstance(environment, str)
        or environment not in _ENVIRONMENTS
        or isinstance(limit, bool)
        or not isinstance(limit, int)
        or not 1 <= limit <= MAX_RESTORE_REPLAY_BATCH
    ):
        raise ValueError("accepted usage replay bounds are invalid")
    if _database_identity(source_connection) == _database_identity(restore_connection):
        raise CommercialUsageRestoreReplayError(
            "accepted usage replay requires distinct source and restore databases"
        )
    source_batch = _load_source_batch(
        source_connection,
        environment=environment,
        limit=limit,
    )
    for source in source_batch:
        restored = _load_restored_identity(
            restore_connection,
            environment=environment,
            source_product=source.event.source_product,
            source_event_id=source.event.source_event_id,
        )
        if (
            restored.canonical_event_id != source.canonical_event_id
            or restored.event != source.event
        ):
            raise CommercialUsageRestoreReplayError(
                "accepted usage replay differs between source and restore"
            )
    return source_batch


__all__ = [
    "AcceptedUsageReplay",
    "CommercialUsageRestoreReplayError",
    "MAX_RESTORE_REPLAY_BATCH",
    "load_accepted_usage_replay_batch",
]
