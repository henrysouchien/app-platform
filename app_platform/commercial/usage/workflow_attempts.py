"""Central append-only authority for logical workflow retry chains."""

from __future__ import annotations

from typing import Annotated, Literal, Mapping
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, StrictInt, model_validator

from ..agreement_lifecycle import IdempotencyKey
from ..models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256


WorkflowObservability = Literal[
    "hank_metered", "hank_byok_observed", "external_unobserved", "none"
]
WorkflowAttemptKind = Literal["initial", "user_retry", "automatic_retry"]
_LINEAGE_COLUMNS = (
    "workflow_run_id",
    "execution_context_id",
    "creation_nonce",
    "environment",
    "commercial_account_id",
    "source_product",
    "attempt_group_id",
    "attempt_number",
    "retry_of_workflow_run_id",
    "attempt_kind",
    "idempotency_key",
    "command_sha256",
)
_PREDECESSOR_COLUMNS = (
    "attempt_group_id",
    "attempt_number",
    "state",
    "completed_at",
)


class WorkflowAttemptStartCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    workflow_run_id: UUID
    execution_context_id: UUID
    source_product: StableCode
    workflow_code: StableCode
    primary_inference_observability: WorkflowObservability
    started_at: AwareDatetime
    attempt_kind: WorkflowAttemptKind = "initial"
    retry_of_workflow_run_id: UUID | None = None

    @model_validator(mode="after")
    def _retry_shape(self) -> "WorkflowAttemptStartCommand":
        if self.attempt_kind == "initial" and self.retry_of_workflow_run_id is not None:
            raise ValueError("initial workflow attempt cannot name a predecessor")
        if self.attempt_kind != "initial" and self.retry_of_workflow_run_id is None:
            raise ValueError("workflow retry requires a predecessor")
        if self.retry_of_workflow_run_id == self.workflow_run_id:
            raise ValueError("workflow attempt cannot retry itself")
        return self


class WorkflowAttemptStartResult(StrictCommercialModel):
    workflow_run_id: UUID
    execution_context_id: UUID
    environment: Literal["dev", "staging", "prod"]
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    source_product: StableCode
    attempt_group_id: UUID
    attempt_number: Annotated[StrictInt, Field(gt=0)]
    retry_of_workflow_run_id: UUID | None
    attempt_kind: WorkflowAttemptKind
    idempotency_key: IdempotencyKey
    command_sha256: Sha256Digest
    replayed: bool


class WorkflowAttemptStartError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class PostgresWorkflowAttemptService:
    """Start one workflow attempt inside the caller-owned transaction."""

    def __init__(self, connection: object) -> None:
        if bool(getattr(connection, "autocommit", False)):
            raise RuntimeError(
                "workflow attempt authority requires caller-owned transactions"
            )
        self._connection = connection

    def start(self, command: WorkflowAttemptStartCommand) -> WorkflowAttemptStartResult:
        command_sha256 = canonical_sha256(
            command.model_dump(mode="python", exclude={"idempotency_key", "started_at"})
        )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT environment, commercial_account_id
                  FROM commercial_execution_contexts
                 WHERE id = %s
                 FOR SHARE
                """,
                (str(command.execution_context_id),),
            )
            scope = cursor.fetchone()
            if scope is None:
                raise WorkflowAttemptStartError("workflow_attempt.context_missing")
            if isinstance(scope, Mapping):
                environment = str(scope["environment"])
                commercial_account_id = int(scope["commercial_account_id"])
            else:
                environment = str(scope[0])
                commercial_account_id = int(scope[1])
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (
                    "commercial.workflow_attempt:"
                    + environment
                    + ":"
                    + str(commercial_account_id)
                    + ":"
                    + command.source_product
                    + ":"
                    + command.idempotency_key,
                ),
            )
            cursor.execute(
                """
                SELECT workflow_run_id, execution_context_id, creation_nonce,
                       environment, commercial_account_id, source_product, attempt_group_id,
                       attempt_number, retry_of_workflow_run_id, attempt_kind,
                       idempotency_key, command_sha256
                  FROM commercial_workflow_attempt_lineage
                 WHERE environment = %s AND commercial_account_id = %s
                   AND source_product = %s AND idempotency_key = %s
                 FOR SHARE
                """,
                (
                    environment,
                    commercial_account_id,
                    command.source_product,
                    command.idempotency_key,
                ),
            )
            existing = cursor.fetchone()
            if existing is not None:
                values = self._values(existing, _LINEAGE_COLUMNS)
                if values[11] != command_sha256:
                    raise WorkflowAttemptStartError(
                        "workflow_attempt.idempotency_conflict"
                    )
                return self._result(values, replayed=True)

            attempt_group_id = command.workflow_run_id
            attempt_number = 1
            if command.retry_of_workflow_run_id is not None:
                cursor.execute(
                    """
                    SELECT lineage.attempt_group_id, lineage.attempt_number,
                           workflow.state, workflow.completed_at
                      FROM commercial_workflow_attempt_lineage lineage
                      JOIN commercial_workflow_runs workflow
                        ON workflow.id = lineage.workflow_run_id
                       AND workflow.execution_context_id = lineage.execution_context_id
                     WHERE lineage.workflow_run_id = %s
                     FOR UPDATE OF workflow
                    """,
                    (str(command.retry_of_workflow_run_id),),
                )
                predecessor = cursor.fetchone()
                if predecessor is None:
                    raise WorkflowAttemptStartError(
                        "workflow_attempt.predecessor_lineage_missing"
                    )
                predecessor_values = self._values(predecessor, _PREDECESSOR_COLUMNS)
                if predecessor_values[2] not in {"failed", "canceled", "abandoned"}:
                    raise WorkflowAttemptStartError(
                        "workflow_attempt.predecessor_not_retryable"
                    )
                if predecessor_values[3] is None:
                    raise WorkflowAttemptStartError(
                        "workflow_attempt.predecessor_not_terminal"
                    )
                cursor.execute(
                    """
                    SELECT EXISTS (
                        SELECT 1 FROM commercial_workflow_attempt_lineage
                         WHERE retry_of_workflow_run_id = %s
                    ) AS already_retried
                    """,
                    (str(command.retry_of_workflow_run_id),),
                )
                successor = cursor.fetchone()
                already_retried = (
                    successor["already_retried"]
                    if isinstance(successor, Mapping)
                    else successor[0]
                )
                if already_retried:
                    raise WorkflowAttemptStartError(
                        "workflow_attempt.predecessor_already_retried"
                    )
                attempt_group_id = UUID(str(predecessor_values[0]))
                attempt_number = int(predecessor_values[1]) + 1

            cursor.execute(
                "SELECT 1 FROM commercial_workflow_runs WHERE id = %s",
                (str(command.workflow_run_id),),
            )
            if cursor.fetchone() is not None:
                raise WorkflowAttemptStartError("workflow_attempt.run_id_conflict")
            creation_nonce = uuid4()
            cursor.execute(
                """
                INSERT INTO commercial_workflow_runs (
                    id, execution_context_id, workflow_code,
                    primary_inference_observability, state, started_at,
                    workflow_attempt_creation_nonce
                ) VALUES (%s, %s, %s, %s, 'started', %s, %s)
                """,
                (
                    str(command.workflow_run_id),
                    str(command.execution_context_id),
                    command.workflow_code,
                    command.primary_inference_observability,
                    command.started_at,
                    str(creation_nonce),
                ),
            )
            cursor.execute(
                """
                INSERT INTO commercial_workflow_attempt_lineage (
                    workflow_run_id, execution_context_id, creation_nonce, environment,
                    commercial_account_id, source_product, attempt_group_id,
                    attempt_number, retry_of_workflow_run_id, attempt_kind,
                    idempotency_key, command_sha256
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING workflow_run_id, execution_context_id, creation_nonce, environment,
                          commercial_account_id, source_product, attempt_group_id,
                          attempt_number, retry_of_workflow_run_id, attempt_kind,
                          idempotency_key, command_sha256
                """,
                (
                    str(command.workflow_run_id),
                    str(command.execution_context_id),
                    str(creation_nonce),
                    environment,
                    commercial_account_id,
                    command.source_product,
                    str(attempt_group_id),
                    attempt_number,
                    (
                        str(command.retry_of_workflow_run_id)
                        if command.retry_of_workflow_run_id is not None
                        else None
                    ),
                    command.attempt_kind,
                    command.idempotency_key,
                    command_sha256,
                ),
            )
            return self._result(
                self._values(cursor.fetchone(), _LINEAGE_COLUMNS), replayed=False
            )
        finally:
            cursor.close()

    @staticmethod
    def _result(
        values: tuple[object, ...], *, replayed: bool
    ) -> WorkflowAttemptStartResult:
        return WorkflowAttemptStartResult(
            workflow_run_id=UUID(str(values[0])),
            execution_context_id=UUID(str(values[1])),
            environment=str(values[3]),
            commercial_account_id=int(values[4]),
            source_product=str(values[5]),
            attempt_group_id=UUID(str(values[6])),
            attempt_number=int(values[7]),
            retry_of_workflow_run_id=(
                UUID(str(values[8])) if values[8] is not None else None
            ),
            attempt_kind=str(values[9]),
            idempotency_key=str(values[10]),
            command_sha256=str(values[11]),
            replayed=replayed,
        )

    @staticmethod
    def _values(row: object, names: tuple[str, ...]) -> tuple[object, ...]:
        if isinstance(row, Mapping):
            return tuple(row[name] for name in names)
        return tuple(row)  # type: ignore[arg-type]


__all__ = [
    "PostgresWorkflowAttemptService",
    "WorkflowAttemptKind",
    "WorkflowAttemptStartCommand",
    "WorkflowAttemptStartError",
    "WorkflowAttemptStartResult",
    "WorkflowObservability",
]
