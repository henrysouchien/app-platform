"""Canonical commercial usage ingestion behind authenticated producer identity."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from decimal import Decimal, ROUND_HALF_UP
import json
import logging
from typing import Callable, Mapping, Protocol
from uuid import UUID, uuid4

from pydantic import ValidationError

from ..flags import CommercialFlags
from ..models import UsageAcceptanceV1
from ..rates import (
    PostgresRateSnapshotRepository,
    RateQuoteOverflowError,
    RateUsage,
    quote_usage,
)
from .auth import AuthenticatedUsageProducer
from .contract import (
    CommercialUsageEvent,
    CommercialUsageEventV2,
    CommercialUsageEventV3,
    validate_usage_event,
)


logger = logging.getLogger(__name__)
_LEDGER_COST_QUANTUM = Decimal("0.00000001")
_LEDGER_COST_MAX = Decimal("9999999999.99999999")


def _is_typed_provider_unit_event(event: CommercialUsageEvent) -> bool:
    return bool(
        event.provider_units is not None
        and event.provider_units > 0
        and event.uncached_input_tokens == 0
        and event.billable_output_tokens == 0
        and event.reasoning_tokens_observed is None
        and event.cache_write_tokens == 0
        and event.cache_read_tokens == 0
        and event.separately_billed_tool_cost_usd == 0
        and event.producer_estimated_cost_usd is None
        and event.provider_reported_cost_usd is None
        and event.cost_observation_kind == "unknown"
    )


def _normalize_ledger_cost(value: Decimal) -> Decimal:
    rounded = value.quantize(_LEDGER_COST_QUANTUM, rounding=ROUND_HALF_UP)
    if rounded > _LEDGER_COST_MAX:
        raise TerminalUsageIngestError("usage.cost_exceeds_ledger_bounds")
    return rounded


@dataclass(frozen=True)
class ReservationUsageEvidence:
    operation_started_at: datetime
    settlement_binding_id: str


class ReservationUsageVerifier(Protocol):
    def verify(self, connection, event: CommercialUsageEvent) -> ReservationUsageEvidence: ...


class RetryableUsageIngestError(RuntimeError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class TerminalUsageIngestError(ValueError):
    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True)
class _Lineage:
    payer_class: str
    billing_mode: str
    shadow_rate_policy_id: int
    workflow_started_at: datetime
    authorized_work_start_deadline: datetime
    usage_accept_until: datetime
    context_revoked_at: datetime | None
    route_effective_from: datetime
    route_effective_until: datetime | None
    route_revoked_at: datetime | None


class CommercialUsageIngestService:
    """Process each batch item in its own transaction to avoid partial ambiguity."""

    def __init__(
        self,
        *,
        connection_factory: Callable[[], object],
        flags: CommercialFlags,
        reservation_verifier: ReservationUsageVerifier | None = None,
    ) -> None:
        flags.validate()
        self._connection_factory = connection_factory
        self._flags = flags
        self._reservation_verifier = reservation_verifier

    def ingest_batch(
        self,
        raw_events: list[object],
        *,
        producer: AuthenticatedUsageProducer,
    ) -> list[UsageAcceptanceV1]:
        if not self._flags.commercial_usage_ingest_enabled:
            return [self._disabled_result(raw, producer.environment) for raw in raw_events]
        if producer.environment != self._flags.environment:
            raise TerminalUsageIngestError("usage.producer_environment_mismatch")
        results: list[UsageAcceptanceV1] = []
        for raw in raw_events:
            try:
                event = validate_usage_event(raw)
            except (ValidationError, ValueError):
                results.append(self._terminal_result(raw, producer.environment, "usage.invalid_event"))
                continue
            if event.environment != producer.environment:
                results.append(self._acceptance(event, "rejected_terminal", "usage.environment_mismatch"))
                continue
            if event.source_product not in producer.source_products:
                results.append(self._acceptance(
                    event, "rejected_terminal", "usage.source_product_not_authorized"
                ))
                continue
            results.append(self._ingest_one(event, producer=producer))
        return results

    def _ingest_one(
        self, event: CommercialUsageEvent, *, producer: AuthenticatedUsageProducer
    ) -> UsageAcceptanceV1:
        try:
            connection = self._connection_factory()
        except Exception:
            logger.exception("commercial usage ingest connection acquisition failed")
            return self._acceptance(
                event, "rejected_retryable", "usage.storage_unavailable"
            )
        try:
            self._lock_source_identity(connection, event)
            existing = self._existing(connection, event)
            if existing is not None:
                canonical_id, digest, row_id = existing
                if digest == event.source_payload_sha256:
                    connection.commit()
                    return self._acceptance(event, "duplicate", canonical_event_id=canonical_id)
                self._record_conflict(
                    connection,
                    event=event,
                    row_id=row_id,
                    canonical_digest=digest,
                    producer_key_id=producer.key_id,
                )
                connection.commit()
                return self._acceptance(event, "conflict", "usage.source_digest_conflict")

            if not isinstance(event, (CommercialUsageEventV2, CommercialUsageEventV3)):
                self._require_v2_after_retry_lineage_cutover(connection, event)

            lineage = self._load_lineage(connection, event)
            if isinstance(event, CommercialUsageEventV2) or (
                isinstance(event, CommercialUsageEventV3)
                and event.workflow_attempt_group_id is not None
            ):
                self._validate_v2_authority(connection, event)
            started_at, settlement_binding = self._prove_timing(connection, event, lineage)
            self._validate_timing(event, lineage=lineage, started_at=started_at)
            snapshot = PostgresRateSnapshotRepository(connection).load_active(
                policy_id=lineage.shadow_rate_policy_id,
                effective_at=event.occurred_at,
            )
            if snapshot is None:
                raise RetryableUsageIngestError("usage.shadow_rate_policy_unavailable")
            if event.shadow_rate_version != snapshot.version:
                raise RetryableUsageIngestError("usage.shadow_rate_version_mismatch")
            typed_unit_event = _is_typed_provider_unit_event(event)
            units = {}
            if typed_unit_event:
                units[event.operation] = event.provider_units
            elif event.provider_units is not None:
                raise TerminalUsageIngestError("usage.ambiguous_aggregate_provider_units")
            if event.usage_state == "failed_unbilled":
                pricing_state = "invalid_usage"
                normalized_cost = None
            else:
                quote = quote_usage(
                    snapshot,
                    provider=event.provider,
                    operation=event.model or event.operation,
                    usage=RateUsage(
                        uncached_input_tokens=event.uncached_input_tokens,
                        billable_output_tokens=event.billable_output_tokens,
                        reasoning_tokens_observed=event.reasoning_tokens_observed,
                        cache_write_tokens=event.cache_write_tokens,
                        cache_read_tokens=event.cache_read_tokens,
                        is_batch=event.is_batch,
                        units=units,
                    ),
                    occurred_at=event.occurred_at,
                    payer_class=lineage.payer_class,
                    work_class=event.capability_id or event.operation,
                )
                pricing_state = quote.pricing_state.value
                normalized_cost = quote.exact_cost_usd
                if normalized_cost is not None:
                    normalized_cost += event.separately_billed_tool_cost_usd
                    normalized_cost = _normalize_ledger_cost(normalized_cost)
            canonical_id = uuid4()
            self._insert(
                connection,
                event=event,
                canonical_id=canonical_id,
                lineage=lineage,
                shadow_policy_id=lineage.shadow_rate_policy_id,
                pricing_state=pricing_state,
                normalized_cost=normalized_cost,
            )
            if lineage.billing_mode == "metered":
                if settlement_binding is None:
                    raise RetryableUsageIngestError("usage.settlement_binding_unavailable")
                self._schedule_settlement(
                    connection,
                    reservation_id=UUID(str(event.reservation_id or "")),
                    usage_event_id=canonical_id,
                    settlement_binding_id=settlement_binding,
                    pricing_state=pricing_state,
                    normalized_cost=normalized_cost,
                )
            connection.commit()
            return self._acceptance(
                event, "accepted", canonical_event_id=str(canonical_id)
            )
        except RateQuoteOverflowError:
            connection.rollback()
            return self._acceptance(
                event, "rejected_terminal", "usage.cost_exceeds_ledger_bounds"
            )
        except TerminalUsageIngestError as exc:
            connection.rollback()
            return self._acceptance(event, "rejected_terminal", exc.reason_code)
        except RetryableUsageIngestError as exc:
            connection.rollback()
            return self._acceptance(event, "rejected_retryable", exc.reason_code)
        except Exception as exc:
            connection.rollback()
            if self._is_retry_lineage_v2_required(exc):
                return self._acceptance(
                    event,
                    "rejected_terminal",
                    "usage.retry_lineage_v2_required",
                )
            logger.exception(
                "commercial usage ingest storage/control failure",
                extra={
                    "source_product": event.source_product,
                    "source_event_id": event.source_event_id,
                    "environment": event.environment,
                },
            )
            return self._acceptance(event, "rejected_retryable", "usage.storage_unavailable")
        finally:
            connection.close()

    @staticmethod
    def _require_v2_after_retry_lineage_cutover(
        connection: object,
        event: CommercialUsageEvent,
    ) -> None:
        with connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                "SELECT to_regclass('commercial_retry_lineage_cutover_gates')"
            )
            table_row = cursor.fetchone()
            table_ref = (
                next(iter(table_row.values()))
                if isinstance(table_row, Mapping)
                else table_row[0]
            )
            if table_ref is None:
                return
            cursor.execute(
                """
                SELECT cutover_at,
                       statement_timestamp() >= activated_at AS is_activated
                  FROM commercial_retry_lineage_cutover_gates
                 WHERE environment = %s
                """,
                (event.environment,),
            )
            gate = cursor.fetchone()
        if isinstance(gate, Mapping):
            cutover_at = gate["cutover_at"]
            is_activated = gate["is_activated"]
        elif gate is not None:
            cutover_at, is_activated = gate
        else:
            cutover_at, is_activated = None, False
        if cutover_at is not None and (
            event.occurred_at >= cutover_at or bool(is_activated)
        ):
            raise TerminalUsageIngestError("usage.retry_lineage_v2_required")

    @staticmethod
    def _is_retry_lineage_v2_required(exc: Exception) -> bool:
        current: BaseException | None = exc
        while current is not None:
            message = str(current)
            if (
                "Usage V2 is required after retry lineage cutover" in message
                or "Usage V2 or V3 is required after retry lineage cutover"
                in message
            ):
                return True
            current = current.__cause__ or current.__context__
        return False

    @staticmethod
    def _lock_source_identity(connection, event: CommercialUsageEvent) -> None:
        with connection.cursor() as cursor:
            identity = (
                f"{len(event.environment)}:{event.environment}"
                f"{len(event.source_product)}:{event.source_product}"
                f"{len(event.source_event_id)}:{event.source_event_id}"
            )
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (identity,),
            )

    @staticmethod
    def _existing(connection, event: CommercialUsageEvent):
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT event_id::text, source_payload_sha256, id
                  FROM commercial_usage_events
                 WHERE environment = %s AND source_product = %s AND source_event_id = %s
                 FOR SHARE
                """,
                (event.environment, event.source_product, event.source_event_id),
            )
            row = cursor.fetchone()
            if isinstance(row, Mapping):
                return (
                    str(row["event_id"]), row["source_payload_sha256"], row["id"]
                )
            return row

    @staticmethod
    def _record_conflict(
        connection,
        *,
        event: CommercialUsageEvent,
        row_id: int,
        canonical_digest: str,
        producer_key_id: str,
    ) -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO commercial_usage_ingest_conflicts (
                    environment, source_product, source_event_id,
                    canonical_usage_event_id, canonical_payload_sha256,
                    conflicting_payload_sha256, producer_key_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (
                    environment, source_product, source_event_id,
                    conflicting_payload_sha256
                ) DO NOTHING
                """,
                (
                    event.environment, event.source_product, event.source_event_id,
                    row_id, canonical_digest, event.source_payload_sha256, producer_key_id,
                ),
            )

    @staticmethod
    def _load_lineage(connection, event: CommercialUsageEvent) -> _Lineage:
        try:
            context_id = UUID(str(event.execution_context_id))
            workflow_id = UUID(str(event.workflow_run_id))
            funding_id = UUID(str(event.funding_route_id))
        except (TypeError, ValueError):
            raise TerminalUsageIngestError("usage.invalid_lineage_id") from None
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT route.payer_class, route.billing_mode, context.shadow_rate_policy_id,
                       workflow.started_at, context.authorized_work_start_deadline,
                       context.usage_accept_until,
                       context.revoked_at AS context_revoked_at,
                       route.effective_from AS route_effective_from,
                       route.effective_until AS route_effective_until,
                       route.revoked_at AS route_revoked_at
                  FROM commercial_execution_contexts context
                  JOIN commercial_workflow_runs workflow
                    ON workflow.execution_context_id = context.id AND workflow.id = %s
                  JOIN commercial_funding_routes route
                    ON route.id = %s AND route.provider = %s
                   AND route.environment = context.environment
                   AND route.commercial_account_id = context.commercial_account_id
                   AND route.agreement_id = context.agreement_id
                   AND route.agreement_terms_id = context.agreement_terms_id
                 WHERE context.id = %s AND context.environment = %s
                   AND route.classification_state = 'active'
                """,
                (
                    str(workflow_id), str(funding_id), event.provider,
                    str(context_id), event.environment,
                ),
            )
            row = cursor.fetchone()
        if row is None:
            raise TerminalUsageIngestError("usage.lineage_not_found")
        if isinstance(row, Mapping):
            return _Lineage(
                payer_class=row["payer_class"],
                billing_mode=row["billing_mode"],
                shadow_rate_policy_id=row["shadow_rate_policy_id"],
                workflow_started_at=row["started_at"],
                authorized_work_start_deadline=row["authorized_work_start_deadline"],
                usage_accept_until=row["usage_accept_until"],
                context_revoked_at=row["context_revoked_at"],
                route_effective_from=row["route_effective_from"],
                route_effective_until=row["route_effective_until"],
                route_revoked_at=row["route_revoked_at"],
            )
        return _Lineage(*row)

    @staticmethod
    def _validate_v2_authority(
        connection,
        event: CommercialUsageEventV2 | CommercialUsageEventV3,
    ) -> None:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_context_id, source_product, attempt_group_id,
                       attempt_number, retry_of_workflow_run_id, attempt_kind
                  FROM commercial_workflow_attempt_lineage
                 WHERE workflow_run_id = %s
                 FOR SHARE
                """,
                (str(event.workflow_run_id),),
            )
            row = cursor.fetchone()
        if row is None:
            raise TerminalUsageIngestError("usage.attempt_lineage_not_found")
        values = (
            str(row["execution_context_id"]),
            row["source_product"],
            str(row["attempt_group_id"]),
            row["attempt_number"],
            str(row["retry_of_workflow_run_id"])
            if row["retry_of_workflow_run_id"] is not None else None,
            row["attempt_kind"],
        ) if isinstance(row, Mapping) else (
            str(row[0]), row[1], str(row[2]), row[3],
            str(row[4]) if row[4] is not None else None, row[5],
        )
        expected = (
            str(event.execution_context_id),
            event.source_product,
            str(event.workflow_attempt_group_id),
            event.workflow_attempt_number,
            str(event.retry_of_workflow_run_id)
            if event.retry_of_workflow_run_id is not None else None,
            event.workflow_attempt_kind,
        )
        if values != expected:
            raise TerminalUsageIngestError("usage.attempt_lineage_mismatch")
        if event.source_product == "risk-module-direct":
            if event.work_authorization_id is not None:
                raise TerminalUsageIngestError("usage.unexpected_work_authorization")
            return
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT execution_context_id, workflow_run_id, attempt_group_id,
                       attempt_number, retry_of_workflow_run_id, attempt_kind,
                       funding_route_id, provider, billing_mode, reservation_id,
                       operation, capability_id, request_id, session_id
                  FROM commercial_work_start_authorizations
                 WHERE authorization_id = %s
                 FOR SHARE
                """,
                (str(event.work_authorization_id),),
            )
            authority = cursor.fetchone()
        if authority is None:
            raise TerminalUsageIngestError("usage.work_authorization_not_found")
        if isinstance(authority, Mapping):
            authority_values = tuple(authority[name] for name in (
                "execution_context_id", "workflow_run_id", "attempt_group_id",
                "attempt_number", "retry_of_workflow_run_id", "attempt_kind",
                "funding_route_id", "provider", "billing_mode", "reservation_id",
                "operation", "capability_id", "request_id", "session_id",
            ))
        else:
            authority_values = tuple(authority)
        normalized = (
            str(authority_values[0]), str(authority_values[1]),
            str(authority_values[2]), authority_values[3],
            str(authority_values[4]) if authority_values[4] is not None else None,
            authority_values[5], str(authority_values[6]), authority_values[7],
            authority_values[8],
            str(authority_values[9]) if authority_values[9] is not None else None,
            authority_values[10], authority_values[11], authority_values[12],
            authority_values[13],
        )
        event_values = (
            str(event.execution_context_id), str(event.workflow_run_id),
            str(event.workflow_attempt_group_id), event.workflow_attempt_number,
            str(event.retry_of_workflow_run_id)
            if event.retry_of_workflow_run_id is not None else None,
            event.workflow_attempt_kind, str(event.funding_route_id), event.provider,
            event.raw_billing_mode,
            str(event.reservation_id) if event.reservation_id is not None else None,
            event.operation, event.capability_id, event.request_id, event.session_id,
        )
        operation_is_typed_unit = _is_typed_provider_unit_event(event)
        if (
            normalized[:10] != event_values[:10]
            or normalized[11:] != event_values[11:]
            or (not operation_is_typed_unit and normalized[10] != event_values[10])
        ):
            raise TerminalUsageIngestError("usage.work_authorization_mismatch")

    def _prove_timing(
        self, connection, event: CommercialUsageEvent, lineage: _Lineage
    ) -> tuple[datetime, str | None]:
        if event.raw_billing_mode != lineage.billing_mode:
            raise TerminalUsageIngestError("usage.billing_mode_mismatch")
        if lineage.billing_mode == "metered":
            if event.reservation_id is None:
                raise TerminalUsageIngestError("usage.reservation_required")
            try:
                UUID(str(event.reservation_id))
            except (TypeError, ValueError):
                raise TerminalUsageIngestError("usage.invalid_reservation_id") from None
            if self._reservation_verifier is None:
                raise RetryableUsageIngestError("usage.reservation_verifier_unavailable")
            evidence = self._reservation_verifier.verify(connection, event)
            return evidence.operation_started_at, evidence.settlement_binding_id
        if event.reservation_id is not None:
            raise TerminalUsageIngestError("usage.unexpected_reservation")
        return lineage.workflow_started_at, None

    @staticmethod
    def _validate_timing(
        event: CommercialUsageEvent, *, lineage: _Lineage, started_at: datetime
    ) -> None:
        if (
            started_at > event.occurred_at
            or started_at > lineage.authorized_work_start_deadline
            or event.occurred_at > lineage.usage_accept_until
            or started_at < lineage.route_effective_from
            or (lineage.route_effective_until is not None
                and started_at >= lineage.route_effective_until)
            or (lineage.context_revoked_at is not None
                and started_at >= lineage.context_revoked_at)
            or (lineage.route_revoked_at is not None
                and started_at >= lineage.route_revoked_at)
        ):
            raise TerminalUsageIngestError("usage.outside_authorized_window")

    @staticmethod
    def _schedule_settlement(
        connection,
        *,
        reservation_id: UUID,
        usage_event_id: UUID,
        settlement_binding_id: str,
        pricing_state: str,
        normalized_cost: Decimal | None,
    ) -> None:
        state = {
            "priced": "pending_priced",
            "unknown_rate": "pending_unknown_rate",
            "invalid_usage": "pending_invalid_usage",
        }[pricing_state]
        with connection.cursor() as cursor:
            cursor.execute(
                """
                INSERT INTO commercial_usage_settlement_bindings (
                    settlement_binding_id, reservation_id, usage_event_id,
                    pricing_state, normalized_cost_usd, settlement_state
                ) VALUES (%s, %s, %s, %s, %s, %s)
                """,
                (
                    settlement_binding_id, str(reservation_id), str(usage_event_id),
                    pricing_state, normalized_cost, state,
                ),
            )

    @staticmethod
    def _insert(
        connection,
        *,
        event: CommercialUsageEvent,
        canonical_id: UUID,
        lineage: _Lineage,
        shadow_policy_id: int,
        pricing_state: str,
        normalized_cost: Decimal | None,
    ) -> None:
        lineage_columns = ""
        lineage_placeholders = ""
        lineage_values: tuple[object, ...] = ()
        if isinstance(event, (CommercialUsageEventV2, CommercialUsageEventV3)):
            lineage_columns = """,
                    workflow_attempt_group_id, workflow_attempt_number,
                    retry_of_workflow_run_id, workflow_attempt_kind,
                    work_authorization_id"""
            lineage_placeholders = ", %s, %s, %s, %s, %s"
            lineage_values = (
                str(event.workflow_attempt_group_id)
                if event.workflow_attempt_group_id is not None
                else None,
                event.workflow_attempt_number,
                str(event.retry_of_workflow_run_id)
                if event.retry_of_workflow_run_id is not None else None,
                event.workflow_attempt_kind,
                str(event.work_authorization_id)
                if event.work_authorization_id is not None else None,
            )
        identity_columns = ""
        identity_placeholders = ""
        identity_values: tuple[object, ...] = ()
        if isinstance(event, CommercialUsageEventV3):
            identity_columns = ", capability_bind, provider_reported_model"
            identity_placeholders = ", %s::jsonb, %s"
            identity_values = (
                json.dumps(event.capability_bind.model_dump(mode="json")),
                event.provider_reported_model,
            )
        with connection.cursor() as cursor:
            cursor.execute(
                f"""
                INSERT INTO commercial_usage_events (
                    event_id, source_product, source_event_id, source_payload_sha256,
                    source_schema_version, environment, execution_context_id,
                    workflow_run_id, reservation_id, funding_route_id, channel,
                    request_id, session_id, parent_turn_id, provider, operation, model,
                    capability_id, payer_class, usage_state, uncached_input_tokens,
                    billable_output_tokens, reasoning_tokens_observed, cache_write_tokens,
                    cache_read_tokens, is_batch, provider_units,
                    separately_billed_tool_cost_usd, producer_rate_version,
                    shadow_rate_policy_id, pricing_state, producer_estimated_cost_usd,
                    provider_reported_cost_usd, cost_observation_kind,
                    normalized_shadow_cost_usd, occurred_at{lineage_columns}
                    {identity_columns}, metadata
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s{lineage_placeholders}{identity_placeholders},
                    '{{}}'::jsonb
                )
                """,
                (
                    str(canonical_id), event.source_product, event.source_event_id,
                    event.source_payload_sha256, event.schema_version, event.environment,
                    str(event.execution_context_id), str(event.workflow_run_id),
                    str(event.reservation_id) if event.reservation_id is not None else None,
                    str(event.funding_route_id), event.channel, event.request_id,
                    event.session_id,
                    event.parent_turn_id, event.provider, event.operation, event.model,
                    event.capability_id, lineage.payer_class, event.usage_state,
                    event.uncached_input_tokens, event.billable_output_tokens,
                    event.reasoning_tokens_observed, event.cache_write_tokens,
                    event.cache_read_tokens, event.is_batch, event.provider_units,
                    event.separately_billed_tool_cost_usd, event.producer_rate_version,
                    shadow_policy_id, pricing_state, event.producer_estimated_cost_usd,
                    event.provider_reported_cost_usd, event.cost_observation_kind,
                    normalized_cost, event.occurred_at,
                ) + lineage_values + identity_values,
            )

    @staticmethod
    def _acceptance(
        event: CommercialUsageEvent,
        status: str,
        reason_code: str | None = None,
        canonical_event_id: str | None = None,
    ) -> UsageAcceptanceV1:
        return UsageAcceptanceV1(
            environment=event.environment,
            source_event_id=event.source_event_id,
            status=status,
            canonical_event_id=canonical_event_id,
            reason_code=reason_code,
        )

    @staticmethod
    def _terminal_result(raw: object, environment: str, reason: str) -> UsageAcceptanceV1:
        source_event_id = "invalid"
        if isinstance(raw, dict) and isinstance(raw.get("source_event_id"), str):
            source_event_id = raw["source_event_id"] or "invalid"
        return UsageAcceptanceV1(
            environment=environment,
            source_event_id=source_event_id,
            status="rejected_terminal",
            reason_code=reason,
        )

    @classmethod
    def _disabled_result(cls, raw: object, environment: str) -> UsageAcceptanceV1:
        return cls._terminal_result(raw, environment, "usage.ingest_disabled")


__all__ = [
    "CommercialUsageIngestService",
    "ReservationUsageEvidence",
    "ReservationUsageVerifier",
    "RetryableUsageIngestError",
    "TerminalUsageIngestError",
]
