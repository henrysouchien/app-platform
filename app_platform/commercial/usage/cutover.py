"""Immutable canonical-ledger cutover and analytics-only legacy import."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from decimal import Decimal, DecimalException, localcontext
import re
from typing import Literal

from ..models import canonical_sha256


_STABLE_CODE = re.compile(r"^[a-z][a-z0-9._:-]{0,127}$")
_COST_MAX = Decimal("9999999999.99999999")
_COST_QUANTUM = Decimal("0.00000001")


class CommercialUsageCutoverError(ValueError):
    pass


def _utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise CommercialUsageCutoverError(f"{label} must be timezone-aware")
    return value.astimezone(timezone.utc)


@dataclass(frozen=True)
class UsageCutover:
    environment: Literal["dev", "staging", "prod"]
    cutover_at: datetime
    reason_code: str
    actor_type: Literal["admin", "service"]
    actor_id: str


@dataclass(frozen=True)
class LegacyUsageFact:
    environment: Literal["dev", "staging", "prod"]
    source_kind: Literal["chat_costs", "api_call_log"]
    legacy_source_pk: str
    occurred_at: datetime
    provider: str
    operation: str | None = None
    model: str | None = None
    estimated_cost_usd: Decimal | None = None
    best_effort_user_id: int | None = None
    best_effort_commercial_account_id: int | None = None
    best_effort_agreement_id: int | None = None
    payer_class: Literal["customer_paid", "hank_paid", "hank_shadow_priced"] | None = (
        None
    )
    payer_evidence_reference: str | None = None


class PostgresCommercialUsageCutoverService:
    def __init__(self, connection) -> None:
        if bool(getattr(connection, "autocommit", False)):
            raise RuntimeError(
                "commercial usage cutover requires an explicit transaction"
            )
        self._connection = connection

    def activate(self, value: UsageCutover) -> tuple[datetime, bool]:
        cutover_at = _utc(value.cutover_at, label="cutover timestamp")
        if not _STABLE_CODE.fullmatch(value.reason_code):
            raise CommercialUsageCutoverError("cutover reason must be a stable code")
        if not 1 <= len(value.actor_id) <= 256:
            raise CommercialUsageCutoverError("cutover actor id length is invalid")
        digest = canonical_sha256(
            {
                "environment": value.environment,
                "cutover_at": cutover_at,
                "reason_code": value.reason_code,
                "actor_type": value.actor_type,
                "actor_id": value.actor_id,
            }
        )
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"commercial-usage-cutover:{value.environment}",),
            )
            cursor.execute(
                """
                SELECT cutover_at, payload_sha256
                  FROM commercial_usage_cutover_gates
                 WHERE environment = %s
                 FOR UPDATE
                """,
                (value.environment,),
            )
            gate = cursor.fetchone()
            if gate is None:
                raise CommercialUsageCutoverError("cutover environment gate is missing")
            cursor.execute(
                """
                SELECT cutover_at, payload_sha256
                  FROM commercial_usage_cutovers
                 WHERE environment = %s
                 FOR SHARE
                """,
                (value.environment,),
            )
            existing = cursor.fetchone()
            history_exists = existing is not None
            if existing is not None:
                stored_cutover = _utc(existing[0], label="stored cutover timestamp")
                if existing[1] != digest or stored_cutover != cutover_at:
                    raise CommercialUsageCutoverError("cutover activation conflicts")
                if gate[0] is not None:
                    if (
                        _utc(gate[0], label="gate cutover timestamp") != cutover_at
                        or gate[1] != digest
                    ):
                        raise CommercialUsageCutoverError(
                            "cutover gate conflicts with immutable history"
                        )
                    return stored_cutover, True
            if gate[0] is not None:
                raise CommercialUsageCutoverError("cutover gate conflicts with history")
            cursor.execute(
                """
                SELECT usage.id
                  FROM commercial_usage_events usage
                 WHERE usage.environment = %s AND usage.occurred_at < %s
                   AND (
                       EXISTS (
                           SELECT 1 FROM commercial_cost_allocations allocation
                            WHERE allocation.usage_event_id = usage.id
                       )
                       OR EXISTS (
                           SELECT 1 FROM commercial_usage_settlement_bindings binding
                            WHERE binding.usage_event_id = usage.event_id
                       )
                       OR EXISTS (
                           SELECT 1 FROM commercial_cost_adjustments adjustment
                            WHERE adjustment.usage_event_id = usage.id
                       )
                   )
                 LIMIT 1
                 FOR SHARE OF usage
                """,
                (value.environment, cutover_at),
            )
            pre_boundary_effect = cursor.fetchone() is not None
            if not pre_boundary_effect:
                cursor.execute(
                    """
                    SELECT to_regclass('commercial_budget_settlements'),
                           to_regclass('commercial_budget_events')
                    """
                )
                budget_tables = cursor.fetchone()
                if budget_tables is not None and all(budget_tables):
                    cursor.execute(
                        """
                        SELECT usage.id
                          FROM commercial_usage_events usage
                         WHERE usage.environment = %s AND usage.occurred_at < %s
                           AND (
                               EXISTS (
                                   SELECT 1 FROM commercial_budget_settlements settlement
                                    WHERE settlement.usage_event_id = usage.id
                               )
                               OR EXISTS (
                                   SELECT 1 FROM commercial_budget_events event
                                    WHERE event.usage_event_id = usage.id
                               )
                           )
                         LIMIT 1
                         FOR SHARE OF usage
                        """,
                        (value.environment, cutover_at),
                    )
                    pre_boundary_effect = cursor.fetchone() is not None
            if pre_boundary_effect:
                raise CommercialUsageCutoverError(
                    "pre-boundary shadow usage already has operational effects"
                )
            if not history_exists:
                cursor.execute(
                    """
                    INSERT INTO commercial_usage_cutovers (
                        environment, cutover_at, payload_sha256, reason_code,
                        actor_type, actor_id
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        value.environment,
                        cutover_at,
                        digest,
                        value.reason_code,
                        value.actor_type,
                        value.actor_id,
                    ),
                )
            cursor.execute(
                """
                UPDATE commercial_usage_cutover_gates
                   SET cutover_at = %s, payload_sha256 = %s, activated_at = NOW()
                 WHERE environment = %s AND cutover_at IS NULL
                """,
                (cutover_at, digest, value.environment),
            )
            if cursor.rowcount != 1:
                raise CommercialUsageCutoverError(
                    "cutover gate activation lost its lock"
                )
        return cutover_at, history_exists

    def import_legacy(self, value: LegacyUsageFact) -> tuple[int, bool]:
        occurred_at = _utc(value.occurred_at, label="legacy usage timestamp")
        provider = value.provider.strip().lower()
        operation = value.operation.strip() if value.operation else None
        if not _STABLE_CODE.fullmatch(provider) or (
            operation is not None and not _STABLE_CODE.fullmatch(operation)
        ):
            raise CommercialUsageCutoverError(
                "legacy provider/operation code is invalid"
            )
        legacy_source_pk = value.legacy_source_pk.strip()
        model = value.model.strip() if value.model else None
        evidence_reference = (
            value.payer_evidence_reference.strip()
            if value.payer_evidence_reference
            else None
        )
        if not 1 <= len(legacy_source_pk) <= 255:
            raise CommercialUsageCutoverError(
                "legacy source identity length is invalid"
            )
        if model is not None and not 1 <= len(model) <= 255:
            raise CommercialUsageCutoverError("legacy model identity length is invalid")
        if any(
            item is not None and item <= 0
            for item in (
                value.best_effort_user_id,
                value.best_effort_commercial_account_id,
                value.best_effort_agreement_id,
            )
        ):
            raise CommercialUsageCutoverError("best-effort identities must be positive")
        if (value.payer_class is None) != (evidence_reference is None) or (
            evidence_reference is not None and len(evidence_reference) > 512
        ):
            raise CommercialUsageCutoverError(
                "legacy payer classification requires an evidence reference"
            )
        cost = value.estimated_cost_usd
        if cost is not None:
            try:
                with localcontext() as context:
                    context.prec = 96
                    invalid_cost = (
                        not cost.is_finite()
                        or cost < 0
                        or cost > _COST_MAX
                        or cost.quantize(_COST_QUANTUM) != cost
                    )
            except DecimalException as exc:
                raise CommercialUsageCutoverError(
                    "legacy estimated cost is invalid"
                ) from exc
            if invalid_cost:
                raise CommercialUsageCutoverError("legacy estimated cost is invalid")
        payload = {
            **value.__dict__,
            "occurred_at": occurred_at,
            "provider": provider,
            "operation": operation,
            "legacy_source_pk": legacy_source_pk,
            "model": model,
            "payer_evidence_reference": evidence_reference,
        }
        digest = canonical_sha256(payload)
        payer_evidence = "observed" if value.payer_class is not None else "unknown"
        with self._connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"{value.environment}:{value.source_kind}:{legacy_source_pk}",),
            )
            cursor.execute(
                """
                SELECT id, source_payload_sha256
                  FROM commercial_legacy_usage_analytics
                 WHERE environment = %s AND source_kind = %s AND legacy_source_pk = %s
                 FOR SHARE
                """,
                (value.environment, value.source_kind, legacy_source_pk),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing[1] != digest:
                    raise CommercialUsageCutoverError("legacy source replay conflicts")
                return int(existing[0]), True
            cursor.execute(
                """
                INSERT INTO commercial_legacy_usage_analytics (
                    environment, source_kind, legacy_source_pk, source_payload_sha256,
                    occurred_at, provider, operation, model, estimated_cost_usd,
                    best_effort_user_id, best_effort_commercial_account_id,
                    best_effort_agreement_id, payer_evidence, payer_class,
                    payer_evidence_reference
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s
                )
                RETURNING id
                """,
                (
                    value.environment,
                    value.source_kind,
                    legacy_source_pk,
                    digest,
                    occurred_at,
                    provider,
                    operation,
                    model,
                    cost,
                    value.best_effort_user_id,
                    value.best_effort_commercial_account_id,
                    value.best_effort_agreement_id,
                    payer_evidence,
                    value.payer_class,
                    evidence_reference,
                ),
            )
            return int(cursor.fetchone()[0]), False


__all__ = [
    "CommercialUsageCutoverError",
    "LegacyUsageFact",
    "PostgresCommercialUsageCutoverService",
    "UsageCutover",
]
