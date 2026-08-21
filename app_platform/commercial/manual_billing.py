"""Replay-safe named-operator commands for manual billing facts."""

from __future__ import annotations

from collections.abc import Callable
from enum import StrEnum
from functools import wraps
from typing import Annotated, Literal, TypeVar
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime,
    Field,
    StrictBool,
    StrictInt,
    StrictStr,
    StringConstraints,
    model_validator,
)

from .agreement_lifecycle import IdempotencyKey
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import CommercialRole
from .authority_store import load_named_operator
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags, get_commercial_flags
from .models import (
    NonNegativeBigInt,
    SignedBigInt,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)


ExternalBillingId = Annotated[
    StrictStr,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=255),
]
CurrencyCode = Annotated[StrictStr, Field(pattern=r"^[A-Z]{3}$")]
RuntimeEnvironment = Literal["dev", "staging", "prod"]


class ManualDocumentKind(StrEnum):
    MANUAL_INVOICE = "manual_invoice"
    CREDIT_NOTE = "credit_note"


class BillingDocumentStatus(StrEnum):
    OPEN = "open"
    PAID = "paid"
    VOID = "void"
    UNCOLLECTIBLE = "uncollectible"
    CREDITED = "credited"


class ManualMovementKind(StrEnum):
    CASH_RECEIPT = "cash_receipt"
    REFUND = "refund"
    CREDIT = "credit"
    PROCESSOR_FEE = "processor_fee"


class ManualRevenueAllocation(StrictCommercialModel):
    period_start_at: AwareDatetime
    period_end_at: AwareDatetime
    recognized_revenue_cents: SignedBigInt

    @model_validator(mode="after")
    def _valid_period(self) -> "ManualRevenueAllocation":
        if self.period_end_at <= self.period_start_at:
            raise ValueError("revenue allocation end must follow its start")
        return self


class ManualBillingLine(StrictCommercialModel):
    external_line_id: ExternalBillingId
    agreement_terms_id: Annotated[StrictInt, Field(gt=0)]
    price_code: StableCode | None = None
    net_consideration_ex_tax_cents: SignedBigInt
    tax_cents: NonNegativeBigInt = 0
    service_period_start_at: AwareDatetime
    service_period_end_at: AwareDatetime
    allocations: tuple[ManualRevenueAllocation, ...]

    @model_validator(mode="after")
    def _complete_schedule(self) -> "ManualBillingLine":
        if self.service_period_end_at <= self.service_period_start_at:
            raise ValueError("billing line service end must follow its start")
        if not self.allocations:
            raise ValueError("billing line requires a revenue allocation schedule")
        ordered = tuple(sorted(self.allocations, key=lambda item: item.period_start_at))
        if ordered != self.allocations:
            raise ValueError("revenue allocations must be ordered by period start")
        if ordered[0].period_start_at != self.service_period_start_at:
            raise ValueError("revenue allocations must begin at the line service start")
        if ordered[-1].period_end_at != self.service_period_end_at:
            raise ValueError("revenue allocations must end at the line service end")
        if any(
            previous.period_end_at != current.period_start_at
            for previous, current in zip(ordered, ordered[1:], strict=False)
        ):
            raise ValueError("revenue allocations must cover the service period without gaps")
        if sum(item.recognized_revenue_cents for item in ordered) != (
            self.net_consideration_ex_tax_cents
        ):
            raise ValueError("revenue allocations must reconcile the billing line")
        return self


class ManualInvoiceCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    external_document_id: ExternalBillingId
    document_kind: ManualDocumentKind = ManualDocumentKind.MANUAL_INVOICE
    status_source_event_id: ExternalBillingId
    status: BillingDocumentStatus
    currency: CurrencyCode
    issued_at: AwareDatetime
    status_effective_at: AwareDatetime
    lines: tuple[ManualBillingLine, ...]
    reason_code: StableCode

    @model_validator(mode="after")
    def _valid_invoice(self) -> "ManualInvoiceCommand":
        if self.status_effective_at < self.issued_at:
            raise ValueError("billing status cannot predate document issuance")
        if not self.lines:
            raise ValueError("manual invoice requires at least one line")
        line_ids = tuple(line.external_line_id for line in self.lines)
        if len(set(line_ids)) != len(line_ids):
            raise ValueError("manual invoice external line ids must be unique")
        if self.document_kind == ManualDocumentKind.CREDIT_NOTE and any(
            line.net_consideration_ex_tax_cents > 0 for line in self.lines
        ):
            raise ValueError("credit-note line consideration cannot be positive")
        return self


class ManualMovementCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    document_id: Annotated[StrictInt, Field(gt=0)] | None = None
    external_object_type: StableCode
    external_object_id: ExternalBillingId
    movement_kind: ManualMovementKind
    signed_amount_cents: SignedBigInt
    currency: CurrencyCode
    occurred_at: AwareDatetime
    reason_code: StableCode

    @model_validator(mode="after")
    def _valid_sign(self) -> "ManualMovementCommand":
        if self.signed_amount_cents == 0:
            raise ValueError("money movement amount cannot be zero")
        if self.movement_kind == ManualMovementKind.CASH_RECEIPT:
            if self.signed_amount_cents <= 0:
                raise ValueError("cash receipts must be positive")
        elif self.signed_amount_cents >= 0:
            raise ValueError("outflow and credit movements must be negative")
        return self


class ManualInvoiceResult(StrictCommercialModel):
    command_id: UUID
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    document_id: Annotated[StrictInt, Field(gt=0)]
    billing_line_ids: tuple[Annotated[StrictInt, Field(gt=0)], ...]
    allocation_run_id: Annotated[StrictInt, Field(gt=0)]
    audit_event_id: UUID
    replayed: StrictBool = False


class ManualMovementResult(StrictCommercialModel):
    command_id: UUID
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    movement_id: Annotated[StrictInt, Field(gt=0)]
    audit_event_id: UUID
    replayed: StrictBool = False


_ResultT = TypeVar("_ResultT")


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class ManualBillingService:
    """Append manual invoice/revenue and money facts under billing-operator authority."""

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags | None = None,
    ) -> None:
        self._connection = connection
        self._flags = flags or get_commercial_flags()

    @_atomic
    def record_invoice_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: ManualInvoiceCommand,
    ) -> ManualInvoiceResult:
        self._require_operator(operator_user_id, runtime_environment)
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "invoice",
                "environment": runtime_environment,
                "command": command.model_dump(mode="python", exclude={"idempotency_key"}),
            }
        )
        self._lock_idempotency(
            command.commercial_account_id,
            runtime_environment,
            command.idempotency_key,
        )
        replay = self._load_invoice_result(
            command.commercial_account_id,
            runtime_environment,
            command.idempotency_key,
            payload_sha256,
        )
        if replay is not None:
            return replay
        self._lock_sources(
            f"document:{command.external_document_id}",
            f"status:{command.status_source_event_id}",
        )
        replay = self._load_invoice_by_source(
            command.external_document_id, payload_sha256
        )
        if replay is not None:
            alias = replay.model_copy(
                update={"command_id": uuid4(), "replayed": True}
            )
            self._insert_command(
                result=alias,
                operator_user_id=operator_user_id,
                environment=runtime_environment,
                idempotency_key=command.idempotency_key,
                payload_sha256=payload_sha256,
                command_kind="invoice",
                replayed_from_command_id=replay.command_id,
            )
            return alias
        self._assert_status_source_available(command.status_source_event_id)
        self._validate_invoice_lineage(command)

        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_billing_documents (
                    event_id, provider, environment, external_document_id,
                    agreement_id, commercial_account_id, document_kind,
                    currency, issued_at, metadata
                ) VALUES (%s, 'manual', 'internal', %s, %s, %s, %s, %s, %s,
                          jsonb_build_object('command_sha256', %s))
                RETURNING id
                """,
                (
                    str(uuid4()),
                    command.external_document_id,
                    command.agreement_id,
                    command.commercial_account_id,
                    command.document_kind.value,
                    command.currency,
                    command.issued_at,
                    payload_sha256,
                ),
            )
            document_id = int(cursor.fetchone()[0])
            cursor.execute(
                """
                INSERT INTO commercial_billing_document_status_events (
                    event_id, document_id, provider, environment,
                    source_event_id, status, effective_at, metadata
                ) VALUES (%s, %s, 'manual', 'internal', %s, %s, %s,
                          jsonb_build_object('command_sha256', %s))
                """,
                (
                    str(uuid4()),
                    document_id,
                    command.status_source_event_id,
                    command.status.value,
                    command.status_effective_at,
                    payload_sha256,
                ),
            )
            line_ids: list[int] = []
            for line in command.lines:
                cursor.execute(
                    """
                    INSERT INTO commercial_billing_lines (
                        event_id, document_id, agreement_id, commercial_account_id,
                        external_line_id, agreement_terms_id, price_code,
                        net_consideration_ex_tax_cents, tax_cents,
                        service_period_start_at, service_period_end_at,
                        metadata
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                              jsonb_build_object('command_sha256', %s))
                    RETURNING id
                    """,
                    (
                        str(uuid4()),
                        document_id,
                        command.agreement_id,
                        command.commercial_account_id,
                        line.external_line_id,
                        line.agreement_terms_id,
                        line.price_code,
                        line.net_consideration_ex_tax_cents,
                        line.tax_cents,
                        line.service_period_start_at,
                        line.service_period_end_at,
                        payload_sha256,
                    ),
                )
                line_ids.append(int(cursor.fetchone()[0]))
            cursor.execute(
                """
                INSERT INTO commercial_revenue_allocation_runs (
                    event_id, document_id, version, state
                ) VALUES (%s, %s, 1, 'draft') RETURNING id
                """,
                (str(uuid4()), document_id),
            )
            allocation_run_id = int(cursor.fetchone()[0])
            for line, line_id in zip(command.lines, line_ids, strict=True):
                for allocation in line.allocations:
                    cursor.execute(
                        """
                        INSERT INTO commercial_revenue_allocations (
                            allocation_run_id, document_id, billing_line_id,
                            period_start_at, period_end_at, recognized_revenue_cents
                        ) VALUES (%s, %s, %s, %s, %s, %s)
                        """,
                        (
                            allocation_run_id,
                            document_id,
                            line_id,
                            allocation.period_start_at,
                            allocation.period_end_at,
                            allocation.recognized_revenue_cents,
                        ),
                    )
            cursor.execute(
                "UPDATE commercial_revenue_allocation_runs "
                "SET state = 'final' WHERE id = %s",
                (allocation_run_id,),
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
                action="commercial.billing.invoice.record",
                target_type="commercial_billing_document",
                target_id=str(document_id),
                reason_code=command.reason_code,
                after={
                    "account_id": command.commercial_account_id,
                    "agreement_id": command.agreement_id,
                    "content_sha256": payload_sha256,
                    "result_code": "applied",
                },
            ),
        )
        result = ManualInvoiceResult(
            command_id=uuid4(),
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
            document_id=document_id,
            billing_line_ids=tuple(line_ids),
            allocation_run_id=allocation_run_id,
            audit_event_id=audit_event_id,
        )
        self._insert_command(
            result=result,
            operator_user_id=operator_user_id,
            environment=runtime_environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            command_kind="invoice",
        )
        return result

    @_atomic
    def record_movement_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: ManualMovementCommand,
    ) -> ManualMovementResult:
        self._require_operator(operator_user_id, runtime_environment)
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "movement",
                "environment": runtime_environment,
                "command": command.model_dump(mode="python", exclude={"idempotency_key"}),
            }
        )
        self._lock_idempotency(
            command.commercial_account_id,
            runtime_environment,
            command.idempotency_key,
        )
        replay = self._load_movement_result(
            command.commercial_account_id,
            runtime_environment,
            command.idempotency_key,
            payload_sha256,
        )
        if replay is not None:
            return replay
        source_key = (
            f"movement:{command.external_object_type}:"
            f"{command.external_object_id}:{command.movement_kind.value}"
        )
        self._lock_sources(source_key)
        replay = self._load_movement_by_source(command, payload_sha256)
        if replay is not None:
            alias = replay.model_copy(
                update={"command_id": uuid4(), "replayed": True}
            )
            self._insert_command(
                result=alias,
                operator_user_id=operator_user_id,
                environment=runtime_environment,
                idempotency_key=command.idempotency_key,
                payload_sha256=payload_sha256,
                command_kind="movement",
                replayed_from_command_id=replay.command_id,
            )
            return alias
        self._validate_movement_lineage(command)

        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_money_movements (
                    event_id, provider, environment, agreement_id,
                    commercial_account_id, document_id, external_object_type,
                    external_object_id, movement_kind, signed_amount_cents,
                    currency, occurred_at, metadata
                ) VALUES (%s, 'manual', 'internal', %s, %s, %s, %s, %s, %s,
                          %s, %s, %s, jsonb_build_object('command_sha256', %s))
                RETURNING id
                """,
                (
                    str(uuid4()),
                    command.agreement_id,
                    command.commercial_account_id,
                    command.document_id,
                    command.external_object_type,
                    command.external_object_id,
                    command.movement_kind.value,
                    command.signed_amount_cents,
                    command.currency,
                    command.occurred_at,
                    payload_sha256,
                ),
            )
            movement_id = int(cursor.fetchone()[0])
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
                action="commercial.billing.movement.record",
                target_type="commercial_money_movement",
                target_id=str(movement_id),
                reason_code=command.reason_code,
                after={
                    "account_id": command.commercial_account_id,
                    "agreement_id": command.agreement_id,
                    "content_sha256": payload_sha256,
                    "result_code": "applied",
                },
            ),
        )
        result = ManualMovementResult(
            command_id=uuid4(),
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
            movement_id=movement_id,
            audit_event_id=audit_event_id,
        )
        self._insert_command(
            result=result,
            operator_user_id=operator_user_id,
            environment=runtime_environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            command_kind="movement",
        )
        return result

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

    def _validate_invoice_lineage(self, command: ManualInvoiceCommand) -> None:
        agreement = self._load_agreement(command.agreement_id, command.commercial_account_id)
        if (
            agreement is None
            or agreement[0] != "manual"
            or agreement[1] != command.currency
            or agreement[2] == "draft"
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID)
        service_start, service_end = agreement[3], agreement[4]
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            for line in command.lines:
                if (
                    (service_start is not None and line.service_period_start_at < service_start)
                    or (service_end is not None and line.service_period_end_at > service_end)
                ):
                    raise CommercialError(
                        CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID
                    )
                cursor.execute(
                    """
                    SELECT EXISTS (
                        SELECT 1
                          FROM commercial_agreement_terms terms
                         WHERE terms.id = %s
                           AND terms.agreement_id = %s
                           AND terms.commercial_account_id = %s
                           AND terms.sealed_at IS NOT NULL
                           AND terms.effective_from <= %s
                           AND (
                               terms.effective_until IS NULL
                               OR terms.effective_until >= %s
                           )
                           AND (
                               %s IS NULL OR EXISTS (
                                   SELECT 1 FROM commercial_agreement_items item
                                    WHERE item.agreement_terms_id = terms.id
                                      AND item.price_code = %s
                               )
                           )
                    )
                    """,
                    (
                        line.agreement_terms_id,
                        command.agreement_id,
                        command.commercial_account_id,
                        line.service_period_start_at,
                        line.service_period_end_at,
                        line.price_code,
                        line.price_code,
                    ),
                )
                if cursor.fetchone() != (True,):
                    raise CommercialError(
                        CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID
                    )
        finally:
            cursor.close()

    def _validate_movement_lineage(self, command: ManualMovementCommand) -> None:
        agreement = self._load_agreement(command.agreement_id, command.commercial_account_id)
        if (
            agreement is None
            or agreement[0] != "manual"
            or agreement[1] != command.currency
            or agreement[2] == "draft"
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID)
        if command.document_id is None:
            return
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT 1 FROM commercial_billing_documents
                 WHERE id = %s AND agreement_id = %s AND commercial_account_id = %s
                   AND provider = 'manual' AND environment = 'internal'
                   AND currency = %s
                """,
                (
                    command.document_id,
                    command.agreement_id,
                    command.commercial_account_id,
                    command.currency,
                ),
            )
            if cursor.fetchone() is None:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID
                )
        finally:
            cursor.close()

    def _load_agreement(self, agreement_id: int, account_id: int):
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT billing_provider, currency, state,
                       service_start_at, service_end_at
                  FROM commercial_agreements
                 WHERE id = %s AND commercial_account_id = %s
                 FOR KEY SHARE
                """,
                (agreement_id, account_id),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def _load_invoice_result(
        self, account_id: int, environment: str, idempotency_key: str, digest: str
    ) -> ManualInvoiceResult | None:
        row = self._load_command(account_id, environment, idempotency_key)
        if row is None:
            return None
        if row[1] != "invoice" or row[2] != digest:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return self._invoice_result_from_row(row, replayed=True)

    def _load_movement_result(
        self, account_id: int, environment: str, idempotency_key: str, digest: str
    ) -> ManualMovementResult | None:
        row = self._load_command(account_id, environment, idempotency_key)
        if row is None:
            return None
        if row[1] != "movement" or row[2] != digest:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return self._movement_result_from_row(row, replayed=True)

    def _load_command(self, account_id: int, environment: str, idempotency_key: str):
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT command.command_id, command.command_kind,
                       command.payload_sha256, command.commercial_account_id,
                       command.agreement_id, command.result_document_id,
                       command.result_movement_id,
                       command.result_allocation_run_id, command.audit_event_id
                  FROM commercial_manual_billing_commands command
                 WHERE command.commercial_account_id = %s
                   AND command.environment = %s
                   AND command.idempotency_key = %s
                """,
                (account_id, environment, idempotency_key),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def _load_invoice_by_source(
        self, external_document_id: str, digest: str
    ) -> ManualInvoiceResult | None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT command.command_id, command.command_kind,
                       command.payload_sha256, command.commercial_account_id,
                       command.agreement_id, command.result_document_id,
                       command.result_movement_id,
                       command.result_allocation_run_id, command.audit_event_id
                  FROM commercial_billing_documents document
                  LEFT JOIN commercial_manual_billing_commands command
                    ON command.result_document_id = document.id
                 WHERE document.provider = 'manual'
                   AND document.environment = 'internal'
                   AND document.external_document_id = %s
                 ORDER BY command.created_at, command.id
                 LIMIT 1
                """,
                (external_document_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[0] is None or row[1] != "invoice" or row[2] != digest:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT)
        return self._invoice_result_from_row(row, replayed=True)

    def _load_movement_by_source(
        self, command: ManualMovementCommand, digest: str
    ) -> ManualMovementResult | None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT command.command_id, command.command_kind,
                       command.payload_sha256, command.commercial_account_id,
                       command.agreement_id, command.result_document_id,
                       command.result_movement_id,
                       command.result_allocation_run_id, command.audit_event_id
                  FROM commercial_money_movements movement
                  LEFT JOIN commercial_manual_billing_commands command
                    ON command.result_movement_id = movement.id
                 WHERE movement.provider = 'manual'
                   AND movement.environment = 'internal'
                   AND movement.external_object_type = %s
                   AND movement.external_object_id = %s
                   AND movement.movement_kind = %s
                 ORDER BY command.created_at, command.id
                 LIMIT 1
                """,
                (
                    command.external_object_type,
                    command.external_object_id,
                    command.movement_kind.value,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[0] is None or row[1] != "movement" or row[2] != digest:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT)
        return self._movement_result_from_row(row, replayed=True)

    def _assert_status_source_available(self, source_event_id: str) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT 1 FROM commercial_billing_document_status_events
                 WHERE provider = 'manual' AND environment = 'internal'
                   AND source_event_id = %s
                """,
                (source_event_id,),
            )
            if cursor.fetchone() is not None:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT
                )
        finally:
            cursor.close()

    def _invoice_result_from_row(self, row, *, replayed: bool) -> ManualInvoiceResult:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT id FROM commercial_billing_lines WHERE document_id = %s ORDER BY id",
                (row[5],),
            )
            line_ids = tuple(int(item[0]) for item in cursor.fetchall())
        finally:
            cursor.close()
        return ManualInvoiceResult(
            command_id=UUID(str(row[0])),
            commercial_account_id=int(row[3]),
            agreement_id=int(row[4]),
            document_id=int(row[5]),
            billing_line_ids=line_ids,
            allocation_run_id=int(row[7]),
            audit_event_id=UUID(str(row[8])),
            replayed=replayed,
        )

    @staticmethod
    def _movement_result_from_row(row, *, replayed: bool) -> ManualMovementResult:
        return ManualMovementResult(
            command_id=UUID(str(row[0])),
            commercial_account_id=int(row[3]),
            agreement_id=int(row[4]),
            movement_id=int(row[6]),
            audit_event_id=UUID(str(row[8])),
            replayed=replayed,
        )

    def _insert_command(
        self,
        *,
        result: ManualInvoiceResult | ManualMovementResult,
        operator_user_id: int,
        environment: str,
        idempotency_key: str,
        payload_sha256: str,
        command_kind: Literal["invoice", "movement"],
        replayed_from_command_id: UUID | None = None,
    ) -> None:
        document_id = result.document_id if isinstance(result, ManualInvoiceResult) else None
        movement_id = result.movement_id if isinstance(result, ManualMovementResult) else None
        allocation_run_id = (
            result.allocation_run_id if isinstance(result, ManualInvoiceResult) else None
        )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_manual_billing_commands (
                    command_id, commercial_account_id, agreement_id,
                    environment, idempotency_key, command_kind, payload_sha256,
                    actor_user_id, result_document_id, result_movement_id,
                    result_allocation_run_id, audit_event_id,
                    replayed_from_command_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(result.command_id),
                    result.commercial_account_id,
                    result.agreement_id,
                    environment,
                    idempotency_key,
                    command_kind,
                    payload_sha256,
                    operator_user_id,
                    document_id,
                    movement_id,
                    allocation_run_id,
                    str(result.audit_event_id),
                    str(replayed_from_command_id)
                    if replayed_from_command_id is not None
                    else None,
                ),
            )
        finally:
            cursor.close()

    def _lock_idempotency(
        self, account_id: int, environment: str, idempotency_key: str
    ) -> None:
        self._advisory_lock(
            "commercial_manual_billing_command",
            f"{account_id}:{environment}:{idempotency_key}",
        )

    def _lock_sources(self, *source_keys: str) -> None:
        for source_key in sorted(source_keys):
            self._advisory_lock("commercial_manual_billing_source", source_key)

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
            cursor.execute("SAVEPOINT commercial_manual_billing_command")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_manual_billing_command")
                cursor.execute("RELEASE SAVEPOINT commercial_manual_billing_command")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_manual_billing_command")
            return result
        finally:
            cursor.close()

    def _require_transaction(self) -> None:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("manual billing commands require a transaction")


__all__ = [
    "BillingDocumentStatus",
    "ManualBillingLine",
    "ManualBillingService",
    "ManualDocumentKind",
    "ManualInvoiceCommand",
    "ManualInvoiceResult",
    "ManualMovementCommand",
    "ManualMovementKind",
    "ManualMovementResult",
    "ManualRevenueAllocation",
]
