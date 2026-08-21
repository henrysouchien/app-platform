"""Management-basis timing for immutable processor-fee cash movements."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime
from functools import wraps
from typing import Annotated, Literal, TypeVar
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, StrictStr

from .agreement_lifecycle import IdempotencyKey
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import CommercialRole
from .authority_store import load_named_operator
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags, get_commercial_flags
from .models import StableCode, StrictCommercialModel, canonical_sha256
from .revenue_allocation import allocate_daily_cents


PROCESSOR_FEE_ALLOCATION_POLICY_VERSION = "processor-fee-allocation.v1"
RuntimeEnvironment = Literal["dev", "staging", "prod"]


class ProcessorFeeAllocationCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    money_movement_id: Annotated[StrictInt, Field(gt=0)]
    reason_code: StableCode


class ProcessorFeeAllocationResult(StrictCommercialModel):
    command_id: UUID
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    document_id: Annotated[StrictInt, Field(gt=0)]
    money_movement_id: Annotated[StrictInt, Field(gt=0)]
    allocation_run_id: Annotated[StrictInt, Field(gt=0)]
    source_revenue_allocation_run_id: Annotated[StrictInt, Field(gt=0)]
    allocation_count: Annotated[StrictInt, Field(gt=0)]
    cash_signed_amount_cents: StrictInt
    management_fee_cents: StrictInt
    currency: StrictStr
    service_period_start_at: AwareDatetime
    service_period_end_at: AwareDatetime
    audit_event_id: UUID
    policy_version: StableCode = PROCESSOR_FEE_ALLOCATION_POLICY_VERSION
    replayed: StrictBool = False


_ResultT = TypeVar("_ResultT")


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class ProcessorFeeAllocationService:
    """Allocate one document-linked fee without changing its cash movement."""

    def __init__(
        self, connection: object, *, flags: CommercialFlags | None = None
    ) -> None:
        self._connection = connection
        self._flags = flags or get_commercial_flags()

    @_atomic
    def allocate_fee_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: ProcessorFeeAllocationCommand,
    ) -> ProcessorFeeAllocationResult:
        self._require_operator(operator_user_id, runtime_environment)
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "processor_fee_allocation",
                "environment": runtime_environment,
                "policy_version": PROCESSOR_FEE_ALLOCATION_POLICY_VERSION,
                "command": command.model_dump(
                    mode="python", exclude={"idempotency_key"}
                ),
            }
        )
        self._advisory_lock(
            "commercial_processor_fee_command",
            f"{command.commercial_account_id}:{runtime_environment}:"
            f"{command.idempotency_key}",
        )
        replay = self._load_by_idempotency(command, runtime_environment, payload_sha256)
        if replay is not None:
            return replay

        movement = self._lock_movement(command)
        if movement is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID)
        document_id, signed_amount_cents, currency = (
            int(movement[0]),
            int(movement[1]),
            str(movement[2]),
        )
        source_replay = self._load_by_movement(
            command.money_movement_id, payload_sha256
        )
        if source_replay is not None:
            alias = source_replay.model_copy(
                update={"command_id": uuid4(), "replayed": True}
            )
            self._insert_command(
                result=alias,
                operator_user_id=operator_user_id,
                environment=runtime_environment,
                idempotency_key=command.idempotency_key,
                payload_sha256=payload_sha256,
                reason_code=command.reason_code,
                replayed_from_command_id=source_replay.command_id,
            )
            return alias

        source_run_id, service_start, service_end = (
            self._lock_final_revenue_service_envelope(document_id)
        )
        if source_run_id is None or service_start is None or service_end is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_BILLING_FACT_INVALID)
        allocations = allocate_daily_cents(
            -signed_amount_cents, service_start, service_end
        )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_processor_fee_allocation_runs (
                    event_id, money_movement_id, document_id,
                    source_revenue_allocation_run_id, service_period_start_at,
                    service_period_end_at, policy_version, state
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, 'draft') RETURNING id
                """,
                (
                    str(uuid4()),
                    command.money_movement_id,
                    document_id,
                    source_run_id,
                    service_start,
                    service_end,
                    PROCESSOR_FEE_ALLOCATION_POLICY_VERSION,
                ),
            )
            allocation_run_id = int(cursor.fetchone()[0])
            for allocation in allocations:
                cursor.execute(
                    """
                    INSERT INTO commercial_processor_fee_allocations (
                        allocation_run_id, money_movement_id,
                        period_start_at, period_end_at, management_fee_cents
                    ) VALUES (%s, %s, %s, %s, %s)
                    """,
                    (
                        allocation_run_id,
                        command.money_movement_id,
                        allocation.period_start_at,
                        allocation.period_end_at,
                        allocation.signed_cents,
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
                action="commercial.processor_fee.allocation.apply",
                target_type="commercial_processor_fee_allocation_run",
                target_id=str(allocation_run_id),
                reason_code=command.reason_code,
                after={
                    "account_id": command.commercial_account_id,
                    "agreement_id": command.agreement_id,
                    "content_sha256": payload_sha256,
                    "policy_identities": [PROCESSOR_FEE_ALLOCATION_POLICY_VERSION],
                    "result_code": "applied",
                },
            ),
        )
        result = ProcessorFeeAllocationResult(
            command_id=uuid4(),
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
            document_id=document_id,
            money_movement_id=command.money_movement_id,
            allocation_run_id=allocation_run_id,
            source_revenue_allocation_run_id=source_run_id,
            allocation_count=len(allocations),
            cash_signed_amount_cents=signed_amount_cents,
            management_fee_cents=-signed_amount_cents,
            currency=currency,
            service_period_start_at=service_start,
            service_period_end_at=service_end,
            audit_event_id=audit_event_id,
        )
        self._insert_command(
            result=result,
            operator_user_id=operator_user_id,
            environment=runtime_environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            reason_code=command.reason_code,
        )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                UPDATE commercial_processor_fee_allocation_runs
                   SET state = 'final'
                 WHERE id = %s AND state = 'draft'
                """,
                (allocation_run_id,),
            )
            if cursor.rowcount != 1:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT
                )
        finally:
            cursor.close()
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

    def _lock_movement(self, command: ProcessorFeeAllocationCommand):
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT movement.document_id, movement.signed_amount_cents,
                       movement.currency
                  FROM commercial_money_movements movement
                 WHERE movement.id = %s
                   AND movement.agreement_id = %s
                   AND movement.commercial_account_id = %s
                   AND movement.movement_kind = 'processor_fee'
                   AND movement.document_id IS NOT NULL
                 FOR UPDATE
                """,
                (
                    command.money_movement_id,
                    command.agreement_id,
                    command.commercial_account_id,
                ),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def _lock_final_revenue_service_envelope(
        self, document_id: int
    ) -> tuple[int | None, datetime | None, datetime | None]:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT id FROM commercial_billing_documents
                 WHERE id = %s FOR UPDATE
                """,
                (document_id,),
            )
            if cursor.fetchone() is None:
                return None, None, None
            cursor.execute(
                """
                SELECT id FROM commercial_revenue_allocation_runs
                 WHERE document_id = %s AND state = 'final'
                 FOR KEY SHARE
                """,
                (document_id,),
            )
            run = cursor.fetchone()
            if run is None:
                return None, None, None
            source_run_id = int(run[0])
            cursor.execute(
                """
                SELECT MIN(period_start_at), MAX(period_end_at)
                  FROM commercial_revenue_allocations
                 WHERE allocation_run_id = %s
                """,
                (source_run_id,),
            )
            service_start, service_end = cursor.fetchone()
            return source_run_id, service_start, service_end
        finally:
            cursor.close()

    def _load_by_idempotency(
        self,
        command: ProcessorFeeAllocationCommand,
        environment: RuntimeEnvironment,
        payload_sha256: str,
    ) -> ProcessorFeeAllocationResult | None:
        row = self._load_command(
            """
            command.commercial_account_id = %s
            AND command.environment = %s
            AND command.idempotency_key = %s
            """,
            (
                command.commercial_account_id,
                environment,
                command.idempotency_key,
            ),
        )
        if row is None:
            return None
        if row[12] != payload_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return self._result_from_row(row, replayed=True)

    def _load_by_movement(
        self, movement_id: int, payload_sha256: str
    ) -> ProcessorFeeAllocationResult | None:
        row = self._load_command(
            """
            command.money_movement_id = %s
            AND command.replayed_from_command_id IS NULL
            """,
            (movement_id,),
        )
        if row is None:
            return None
        if row[12] != payload_sha256:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT
            )
        return self._result_from_row(row, replayed=True)

    def _load_command(self, where_sql: str, params: tuple):
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                f"""
                SELECT command.command_id, command.commercial_account_id,
                       command.agreement_id, command.document_id,
                       command.money_movement_id, command.result_allocation_run_id,
                       (SELECT COUNT(*)
                          FROM commercial_processor_fee_allocations allocation
                         WHERE allocation.allocation_run_id
                               = command.result_allocation_run_id),
                       movement.signed_amount_cents,
                       movement.currency, run.service_period_start_at,
                       run.service_period_end_at,
                       run.source_revenue_allocation_run_id,
                       command.payload_sha256, command.audit_event_id,
                       command.policy_version
                  FROM commercial_processor_fee_allocation_commands command
                  JOIN commercial_money_movements movement
                    ON movement.id = command.money_movement_id
                  JOIN commercial_processor_fee_allocation_runs run
                    ON run.id = command.result_allocation_run_id
                 WHERE {where_sql}
                 ORDER BY command.created_at, command.id
                 LIMIT 1
                """,
                params,
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    @staticmethod
    def _result_from_row(row, *, replayed: bool) -> ProcessorFeeAllocationResult:
        return ProcessorFeeAllocationResult(
            command_id=UUID(str(row[0])),
            commercial_account_id=int(row[1]),
            agreement_id=int(row[2]),
            document_id=int(row[3]),
            money_movement_id=int(row[4]),
            allocation_run_id=int(row[5]),
            source_revenue_allocation_run_id=int(row[11]),
            allocation_count=int(row[6]),
            cash_signed_amount_cents=int(row[7]),
            management_fee_cents=-int(row[7]),
            currency=str(row[8]),
            service_period_start_at=row[9],
            service_period_end_at=row[10],
            audit_event_id=UUID(str(row[13])),
            policy_version=row[14],
            replayed=replayed,
        )

    def _insert_command(
        self,
        *,
        result: ProcessorFeeAllocationResult,
        operator_user_id: int,
        environment: RuntimeEnvironment,
        idempotency_key: str,
        payload_sha256: str,
        reason_code: str,
        replayed_from_command_id: UUID | None = None,
    ) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_processor_fee_allocation_commands (
                    command_id, commercial_account_id, agreement_id, document_id,
                    money_movement_id, environment, idempotency_key,
                    payload_sha256, policy_version, reason_code, actor_user_id,
                    result_allocation_run_id, audit_event_id,
                    replayed_from_command_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(result.command_id),
                    result.commercial_account_id,
                    result.agreement_id,
                    result.document_id,
                    result.money_movement_id,
                    environment,
                    idempotency_key,
                    payload_sha256,
                    PROCESSOR_FEE_ALLOCATION_POLICY_VERSION,
                    reason_code,
                    operator_user_id,
                    result.allocation_run_id,
                    str(result.audit_event_id),
                    str(replayed_from_command_id)
                    if replayed_from_command_id is not None
                    else None,
                ),
            )
        finally:
            cursor.close()

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
            cursor.execute("SAVEPOINT commercial_processor_fee_command")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_processor_fee_command")
                cursor.execute("RELEASE SAVEPOINT commercial_processor_fee_command")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_processor_fee_command")
            return result
        finally:
            cursor.close()

    def _require_transaction(self) -> None:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError(
                "processor-fee allocation commands require a transaction"
            )


__all__ = [
    "PROCESSOR_FEE_ALLOCATION_POLICY_VERSION",
    "ProcessorFeeAllocationCommand",
    "ProcessorFeeAllocationResult",
    "ProcessorFeeAllocationService",
]
