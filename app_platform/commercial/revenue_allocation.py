"""Deterministic revenue timing and audited allocation-run replacement."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone
from functools import wraps
from typing import Annotated, Literal, TypeVar
from uuid import UUID, uuid4

from pydantic import Field, StrictBool, StrictInt

from .agreement_lifecycle import IdempotencyKey
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import CommercialRole
from .authority_store import load_named_operator
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags, get_commercial_flags
from .models import StableCode, StrictCommercialModel, canonical_sha256


REVENUE_ALLOCATION_POLICY_VERSION = "revenue-allocation.v1"
RuntimeEnvironment = Literal["dev", "staging", "prod"]
RevenueItemKind = Literal[
    "recurring",
    "onboarding",
    "implementation",
    "discount",
    "credit",
    "included_allowance",
]
_RATABLE_ITEM_KINDS = frozenset({"recurring", "discount", "credit"})
_FIRST_DAY_ITEM_KINDS = frozenset({"onboarding", "implementation"})


class RevenueAllocationError(ValueError):
    """A revenue line cannot be allocated under the approved policy."""


@dataclass(frozen=True, slots=True)
class RevenueLine:
    billing_line_id: int
    item_kind: RevenueItemKind
    net_consideration_ex_tax_cents: int
    service_period_start_at: datetime
    service_period_end_at: datetime


@dataclass(frozen=True, slots=True)
class RevenuePeriod:
    billing_line_id: int
    period_start_at: datetime
    period_end_at: datetime
    recognized_revenue_cents: int


@dataclass(frozen=True, slots=True)
class DailyCentsPeriod:
    period_start_at: datetime
    period_end_at: datetime
    signed_cents: int


def _duration_microseconds(start: datetime, end: datetime) -> int:
    delta = end - start
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def _utc_day_segments(
    start: datetime, end: datetime
) -> tuple[tuple[datetime, datetime], ...]:
    if start.tzinfo is None or end.tzinfo is None:
        raise RevenueAllocationError("revenue service periods must be timezone-aware")
    start_utc = start.astimezone(timezone.utc)
    end_utc = end.astimezone(timezone.utc)
    if end_utc <= start_utc:
        raise RevenueAllocationError("revenue service period is empty")
    segments: list[tuple[datetime, datetime]] = []
    cursor = start_utc
    while cursor < end_utc:
        next_midnight = datetime.combine(
            cursor.date() + timedelta(days=1), time.min, tzinfo=timezone.utc
        )
        segment_end = min(next_midnight, end_utc)
        segments.append((cursor, segment_end))
        cursor = segment_end
    return tuple(segments)


def _allocate_ratable_cents(
    signed_cents: int, segments: tuple[tuple[datetime, datetime], ...]
) -> tuple[int, ...]:
    if isinstance(signed_cents, bool):
        raise RevenueAllocationError("revenue consideration must be an integer")
    weights = tuple(_duration_microseconds(start, end) for start, end in segments)
    total_weight = sum(weights)
    magnitude = abs(signed_cents)
    bases = [magnitude * weight // total_weight for weight in weights]
    residual = magnitude - sum(bases)
    order = sorted(
        range(len(weights)),
        key=lambda index: (-(magnitude * weights[index] % total_weight), index),
    )
    for index in order[:residual]:
        bases[index] += 1
    sign = -1 if signed_cents < 0 else 1
    return tuple(sign * amount for amount in bases)


def allocate_daily_cents(
    signed_cents: int,
    service_period_start_at: datetime,
    service_period_end_at: datetime,
) -> tuple[DailyCentsPeriod, ...]:
    """Allocate signed cents by exact elapsed time over UTC calendar-day segments."""

    segments = _utc_day_segments(service_period_start_at, service_period_end_at)
    amounts = _allocate_ratable_cents(signed_cents, segments)
    return tuple(
        DailyCentsPeriod(
            period_start_at=start,
            period_end_at=end,
            signed_cents=amount,
        )
        for (start, end), amount in zip(segments, amounts, strict=True)
    )


def allocate_revenue_line(line: RevenueLine) -> tuple[RevenuePeriod, ...]:
    """Allocate one signed line over exact UTC-day segments under policy v1.

    Recurring, discount, and credit consideration is ratable by elapsed time.
    Onboarding and implementation consideration is recognized in the first
    service-day segment. Included allowance lines must carry zero consideration.
    """

    if line.billing_line_id <= 0:
        raise RevenueAllocationError("billing line id must be positive")
    segments = _utc_day_segments(
        line.service_period_start_at, line.service_period_end_at
    )
    if line.item_kind in _RATABLE_ITEM_KINDS:
        daily_periods = allocate_daily_cents(
            line.net_consideration_ex_tax_cents,
            line.service_period_start_at,
            line.service_period_end_at,
        )
        amounts = tuple(period.signed_cents for period in daily_periods)
    elif line.item_kind in _FIRST_DAY_ITEM_KINDS:
        amounts = (line.net_consideration_ex_tax_cents,) + (0,) * (len(segments) - 1)
    elif line.item_kind == "included_allowance":
        if line.net_consideration_ex_tax_cents != 0:
            raise RevenueAllocationError(
                "included allowance lines must have zero consideration"
            )
        amounts = (0,) * len(segments)
    else:
        raise RevenueAllocationError(f"unsupported revenue item kind: {line.item_kind}")
    periods = tuple(
        RevenuePeriod(
            billing_line_id=line.billing_line_id,
            period_start_at=start,
            period_end_at=end,
            recognized_revenue_cents=amount,
        )
        for (start, end), amount in zip(segments, amounts, strict=True)
    )
    if sum(period.recognized_revenue_cents for period in periods) != (
        line.net_consideration_ex_tax_cents
    ):
        raise AssertionError("deterministic revenue allocation did not balance")
    return periods


class RevenueAllocationCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    document_id: Annotated[StrictInt, Field(gt=0)]
    expected_current_run_id: Annotated[StrictInt, Field(gt=0)] | None
    reason_code: StableCode


class RevenueAllocationResult(StrictCommercialModel):
    command_id: UUID
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    document_id: Annotated[StrictInt, Field(gt=0)]
    prior_allocation_run_id: Annotated[StrictInt, Field(gt=0)] | None
    allocation_run_id: Annotated[StrictInt, Field(gt=0)]
    allocation_count: Annotated[StrictInt, Field(gt=0)]
    audit_event_id: UUID
    policy_version: StableCode = REVENUE_ALLOCATION_POLICY_VERSION
    replayed: StrictBool = False


_ResultT = TypeVar("_ResultT")


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class RevenueAllocationService:
    """Create or atomically replace a document's deterministic allocation run."""

    def __init__(
        self, connection: object, *, flags: CommercialFlags | None = None
    ) -> None:
        self._connection = connection
        self._flags = flags or get_commercial_flags()

    @_atomic
    def allocate_document_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: RevenueAllocationCommand,
    ) -> RevenueAllocationResult:
        self._require_operator(operator_user_id, runtime_environment)
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "revenue_allocation",
                "environment": runtime_environment,
                "policy_version": REVENUE_ALLOCATION_POLICY_VERSION,
                "command": command.model_dump(
                    mode="python", exclude={"idempotency_key"}
                ),
            }
        )
        self._advisory_lock(
            "commercial_revenue_allocation_command",
            f"{command.commercial_account_id}:{runtime_environment}:"
            f"{command.idempotency_key}",
        )
        replay = self._load_result(command, runtime_environment, payload_sha256)
        if replay is not None:
            return replay

        document = self._lock_document(command)
        if document is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID)
        current_run_id, current_version = self._load_current_run(command.document_id)
        if current_run_id != command.expected_current_run_id:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT,
                internal_detail="current revenue allocation run changed",
            )

        lines = self._load_revenue_lines(command.document_id)
        allocations = tuple(
            period for line in lines for period in allocate_revenue_line(line)
        )
        next_version = current_version + 1
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_revenue_allocation_runs (
                    event_id, document_id, version, state
                ) VALUES (%s, %s, %s, 'draft') RETURNING id
                """,
                (str(uuid4()), command.document_id, next_version),
            )
            result_run_id = int(cursor.fetchone()[0])
            for allocation in allocations:
                cursor.execute(
                    """
                    INSERT INTO commercial_revenue_allocations (
                        allocation_run_id, document_id, billing_line_id,
                        period_start_at, period_end_at, recognized_revenue_cents
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                    """,
                    (
                        result_run_id,
                        command.document_id,
                        allocation.billing_line_id,
                        allocation.period_start_at,
                        allocation.period_end_at,
                        allocation.recognized_revenue_cents,
                    ),
                )
        finally:
            cursor.close()

        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=command.commercial_account_id,
                agreement_id=command.agreement_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action="commercial.revenue.allocation.apply",
                target_type="commercial_revenue_allocation_run",
                target_id=str(result_run_id),
                reason_code=command.reason_code,
                after={
                    "account_id": command.commercial_account_id,
                    "agreement_id": command.agreement_id,
                    "content_sha256": payload_sha256,
                    "policy_identities": [REVENUE_ALLOCATION_POLICY_VERSION],
                    "result_code": "applied",
                    "version": next_version,
                },
            ),
        )
        command_id = uuid4()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_revenue_allocation_commands (
                    command_id, commercial_account_id, agreement_id, document_id,
                    environment, idempotency_key, payload_sha256, policy_version,
                    reason_code, actor_user_id, prior_allocation_run_id,
                    result_allocation_run_id, audit_event_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(command_id),
                    command.commercial_account_id,
                    command.agreement_id,
                    command.document_id,
                    runtime_environment,
                    command.idempotency_key,
                    payload_sha256,
                    REVENUE_ALLOCATION_POLICY_VERSION,
                    command.reason_code,
                    operator_user_id,
                    current_run_id,
                    result_run_id,
                    str(audit_event_id),
                ),
            )
            if current_run_id is not None:
                cursor.execute(
                    """
                    INSERT INTO commercial_revenue_allocation_reversals (
                        command_id, document_id, prior_allocation_run_id,
                        billing_line_id, period_start_at, period_end_at,
                        reversed_revenue_cents
                    )
                    SELECT %s, allocation.document_id, allocation.allocation_run_id,
                           allocation.billing_line_id, allocation.period_start_at,
                           allocation.period_end_at,
                           -allocation.recognized_revenue_cents
                      FROM commercial_revenue_allocations allocation
                     WHERE allocation.allocation_run_id = %s
                     ORDER BY allocation.billing_line_id, allocation.period_start_at
                    """,
                    (str(command_id), current_run_id),
                )
                cursor.execute(
                    """
                    UPDATE commercial_revenue_allocation_runs
                       SET state = 'superseded'
                     WHERE id = %s AND state = 'final'
                    """,
                    (current_run_id,),
                )
                if cursor.rowcount != 1:
                    raise CommercialError(
                        CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT
                    )
            cursor.execute(
                """
                UPDATE commercial_revenue_allocation_runs
                   SET state = 'final'
                 WHERE id = %s AND state = 'draft'
                """,
                (result_run_id,),
            )
            if cursor.rowcount != 1:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT
                )
        finally:
            cursor.close()
        return RevenueAllocationResult(
            command_id=command_id,
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
            document_id=command.document_id,
            prior_allocation_run_id=current_run_id,
            allocation_run_id=result_run_id,
            allocation_count=len(allocations),
            audit_event_id=audit_event_id,
        )

    def _require_operator(self, user_id: int, environment: RuntimeEnvironment) -> None:
        self._require_transaction()
        if not self._flags.commercial_control_enabled:
            raise RuntimeError("commercial control is disabled")
        if environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            deployment = cursor.fetchone()
        finally:
            cursor.close()
        operator = load_named_operator(
            self._connection, user_id=user_id, environment=environment
        )
        if (
            deployment is None
            or deployment[0] != environment
            or CommercialRole.BILLING_OPERATOR not in operator.roles
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)

    def _lock_document(self, command: RevenueAllocationCommand):
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT id FROM commercial_billing_documents
                 WHERE id = %s AND agreement_id = %s AND commercial_account_id = %s
                 FOR UPDATE
                """,
                (
                    command.document_id,
                    command.agreement_id,
                    command.commercial_account_id,
                ),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def _load_current_run(self, document_id: int) -> tuple[int | None, int]:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT id, version FROM commercial_revenue_allocation_runs
                 WHERE document_id = %s AND state = 'final'
                 FOR UPDATE
                """,
                (document_id,),
            )
            row = cursor.fetchone()
            if row is not None:
                return int(row[0]), int(row[1])
            cursor.execute(
                "SELECT COALESCE(MAX(version), 0) "
                "FROM commercial_revenue_allocation_runs WHERE document_id = %s",
                (document_id,),
            )
            return None, int(cursor.fetchone()[0])
        finally:
            cursor.close()

    def _load_revenue_lines(self, document_id: int) -> tuple[RevenueLine, ...]:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT line.id, line.price_code,
                       line.net_consideration_ex_tax_cents,
                       line.service_period_start_at, line.service_period_end_at,
                       item.id, item.item_kind,
                       item.service_start_at, item.service_end_at
                  FROM commercial_billing_lines line
                  LEFT JOIN commercial_agreement_items item
                    ON item.agreement_terms_id = line.agreement_terms_id
                   AND item.price_code = line.price_code
                 WHERE line.document_id = %s
                 ORDER BY line.id, item.id
                """,
                (document_id,),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        grouped: dict[int, list[tuple]] = {}
        for row in rows:
            grouped.setdefault(int(row[0]), []).append(row)
        if not grouped:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID)
        lines: list[RevenueLine] = []
        for line_id, candidates in grouped.items():
            if (
                len(candidates) != 1
                or candidates[0][1] is None
                or candidates[0][5] is None
            ):
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID,
                    internal_detail="billing line must map to exactly one priced agreement item",
                )
            row = candidates[0]
            service_start, service_end = row[3], row[4]
            item_start, item_end = row[7], row[8]
            if (item_start is not None and service_start < item_start) or (
                item_end is not None and service_end > item_end
            ):
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID
                )
            lines.append(
                RevenueLine(
                    billing_line_id=line_id,
                    item_kind=row[6],
                    net_consideration_ex_tax_cents=int(row[2]),
                    service_period_start_at=service_start,
                    service_period_end_at=service_end,
                )
            )
        return tuple(lines)

    def _load_result(
        self,
        command: RevenueAllocationCommand,
        environment: RuntimeEnvironment,
        payload_sha256: str,
    ) -> RevenueAllocationResult | None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT command.command_id, command.commercial_account_id,
                       command.agreement_id, command.document_id,
                       command.prior_allocation_run_id,
                       command.result_allocation_run_id, command.audit_event_id,
                       command.policy_version, command.payload_sha256,
                       (SELECT COUNT(*)
                          FROM commercial_revenue_allocations allocation
                         WHERE allocation.allocation_run_id
                               = command.result_allocation_run_id)
                  FROM commercial_revenue_allocation_commands command
                 WHERE command.commercial_account_id = %s
                   AND command.environment = %s
                   AND command.idempotency_key = %s
                """,
                (
                    command.commercial_account_id,
                    environment,
                    command.idempotency_key,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[8] != payload_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return RevenueAllocationResult(
            command_id=UUID(str(row[0])),
            commercial_account_id=int(row[1]),
            agreement_id=int(row[2]),
            document_id=int(row[3]),
            prior_allocation_run_id=int(row[4]) if row[4] is not None else None,
            allocation_run_id=int(row[5]),
            audit_event_id=UUID(str(row[6])),
            policy_version=row[7],
            allocation_count=int(row[9]),
            replayed=True,
        )

    def _advisory_lock(self, namespace: str, identity: str) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                (namespace, identity),
            )
        finally:
            cursor.close()

    def _run_atomic(self, operation: Callable[[], _ResultT]) -> _ResultT:
        self._require_transaction()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT commercial_revenue_allocation_command")
            try:
                result = operation()
            except BaseException:
                cursor.execute(
                    "ROLLBACK TO SAVEPOINT commercial_revenue_allocation_command"
                )
                cursor.execute(
                    "RELEASE SAVEPOINT commercial_revenue_allocation_command"
                )
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_revenue_allocation_command")
            return result
        finally:
            cursor.close()

    def _require_transaction(self) -> None:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("revenue allocation commands require a transaction")


__all__ = [
    "DailyCentsPeriod",
    "REVENUE_ALLOCATION_POLICY_VERSION",
    "RevenueAllocationCommand",
    "RevenueAllocationError",
    "RevenueAllocationResult",
    "RevenueAllocationService",
    "RevenueLine",
    "RevenuePeriod",
    "allocate_daily_cents",
    "allocate_revenue_line",
]
