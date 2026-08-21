"""Replay-safe named-operator import and binding of provider cost receipts."""

from __future__ import annotations

from collections.abc import Callable
from decimal import Decimal
from functools import wraps
from typing import Annotated, Literal, TypeVar
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, StrictStr, model_validator

from .agreement_lifecycle import IdempotencyKey
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import CommercialRole
from .authority_store import load_named_operator
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags, get_commercial_flags
from .models import Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256


RuntimeEnvironment = Literal["dev", "staging", "prod"]
ReceiptSourceKind = Literal[
    "provider_invoice", "provider_dashboard", "manual_statement"
]
ExternalReceiptId = Annotated[StrictStr, Field(min_length=1, max_length=255)]
LedgerUsd = Annotated[Decimal, Field(ge=0, max_digits=18, decimal_places=8)]
_ResultT = TypeVar("_ResultT")


class ProviderCostReceiptImportCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    provider: StableCode
    source_kind: ReceiptSourceKind
    external_receipt_id: ExternalReceiptId
    source_revision: Annotated[StrictInt, Field(gt=0)]
    supersedes_receipt_id: Annotated[StrictInt, Field(gt=0)] | None = None
    correction_reason_code: StableCode | None = None
    source_artifact_sha256: Sha256Digest
    currency: Literal["USD"] = "USD"
    cash_cost_usd: LedgerUsd
    period_start_at: AwareDatetime
    period_end_at: AwareDatetime
    observed_at: AwareDatetime
    reason_code: StableCode

    @model_validator(mode="after")
    def _valid_revision(self) -> "ProviderCostReceiptImportCommand":
        if self.period_end_at <= self.period_start_at:
            raise ValueError("provider receipt period is empty")
        if self.external_receipt_id != self.external_receipt_id.strip():
            raise ValueError("external receipt id must not contain edge whitespace")
        first = self.source_revision == 1
        if first is not (self.supersedes_receipt_id is None):
            raise ValueError("provider receipt revision predecessor is invalid")
        if first is not (self.correction_reason_code is None):
            raise ValueError("provider receipt correction reason is invalid")
        return self


class ProviderCostReceiptImportResult(StrictCommercialModel):
    command_id: UUID
    status: Literal["accepted", "conflict"]
    receipt_id: Annotated[StrictInt, Field(gt=0)] | None = None
    receipt_event_id: UUID | None = None
    conflict_id: Annotated[StrictInt, Field(gt=0)] | None = None
    conflict_event_id: UUID | None = None
    audit_event_id: UUID
    durable_replayed: StrictBool = False


class ProviderCostReceiptBindCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    provider_cost_receipt_id: Annotated[StrictInt, Field(gt=0)]
    cost_pool_id: Annotated[StrictInt, Field(gt=0)]
    reason_code: StableCode


class ProviderCostReceiptBindResult(StrictCommercialModel):
    command_id: UUID
    binding_id: Annotated[StrictInt, Field(gt=0)]
    binding_event_id: UUID
    provider_cost_receipt_id: Annotated[StrictInt, Field(gt=0)]
    cost_pool_id: Annotated[StrictInt, Field(gt=0)]
    audit_event_id: UUID
    durable_replayed: StrictBool = False


class ProviderCostReceiptConflictDispositionCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    conflict_id: Annotated[StrictInt, Field(gt=0)]
    disposition_kind: Literal[
        "source_error", "accepted_provider_correction", "duplicate_artifact"
    ]
    reason_code: StableCode
    note_redacted: Annotated[StrictStr, Field(min_length=1, max_length=2000)] | None = (
        None
    )


class ProviderCostReceiptConflictDispositionResult(StrictCommercialModel):
    disposition_id: Annotated[StrictInt, Field(gt=0)]
    disposition_event_id: UUID
    conflict_id: Annotated[StrictInt, Field(gt=0)]
    audit_event_id: UUID
    disposed_at: AwareDatetime
    durable_replayed: StrictBool = False


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class PostgresProviderCostReceiptService:
    """Import normalized source evidence and bind current revisions to cost pools."""

    def __init__(
        self, connection: object, *, flags: CommercialFlags | None = None
    ) -> None:
        self._connection = connection
        self._flags = flags or get_commercial_flags()
        self._flags.validate()

    @_atomic
    def import_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: ProviderCostReceiptImportCommand,
    ) -> ProviderCostReceiptImportResult:
        self._require_operator(operator_user_id, runtime_environment)
        normalized_sha256 = self._normalized_digest(runtime_environment, command)
        semantic_sha256 = canonical_sha256(
            {
                "schema": "commercial.provider-cost-receipt.import-semantic.v1",
                "environment": runtime_environment,
                "provider": command.provider,
                "source_kind": command.source_kind,
                "external_receipt_id": command.external_receipt_id,
                "source_revision": command.source_revision,
                "supersedes_receipt_id": command.supersedes_receipt_id,
                "correction_reason_code": command.correction_reason_code,
                "source_artifact_sha256": command.source_artifact_sha256,
                "normalized_content_sha256": normalized_sha256,
            }
        )
        payload_sha256 = canonical_sha256(
            {
                "schema": "commercial.provider-cost-receipt.import-command.v1",
                "environment": runtime_environment,
                "command": command.model_dump(
                    mode="python", exclude={"idempotency_key"}
                ),
                "semantic_sha256": semantic_sha256,
            }
        )
        self._lock_idempotency(runtime_environment, command.idempotency_key)
        replay = self._load_import_command(
            runtime_environment, command.idempotency_key, payload_sha256
        )
        if replay is not None:
            return replay
        self._lock_source(
            runtime_environment,
            command.provider,
            command.source_kind,
            command.external_receipt_id,
        )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT id, receipt_event_id, source_artifact_sha256,
                       normalized_content_sha256
                  FROM commercial_provider_cost_receipts
                 WHERE environment = %s AND provider = %s AND source_kind = %s
                   AND external_receipt_id = %s AND source_revision = %s
                 FOR SHARE
                """,
                (
                    runtime_environment,
                    command.provider,
                    command.source_kind,
                    command.external_receipt_id,
                    command.source_revision,
                ),
            )
            existing = cursor.fetchone()
        finally:
            cursor.close()
        if existing is not None:
            if (
                existing[2] == command.source_artifact_sha256
                and existing[3] == normalized_sha256
            ):
                original_command_id = self._original_command_id(
                    result_kind="receipt", result_id=int(existing[0])
                )
                return self._record_import_command(
                    operator_user_id=operator_user_id,
                    environment=runtime_environment,
                    command=command,
                    payload_sha256=payload_sha256,
                    semantic_sha256=semantic_sha256,
                    result_kind="receipt",
                    result_id=int(existing[0]),
                    event_id=UUID(str(existing[1])),
                    replayed_from_command_id=original_command_id,
                )
            conflict_event_id = uuid4()
            cursor = self._connection.cursor()  # type: ignore[attr-defined]
            try:
                cursor.execute(
                    """
                    INSERT INTO commercial_provider_cost_receipt_conflicts (
                        conflict_event_id, environment, canonical_receipt_id,
                        claimed_source_artifact_sha256,
                        claimed_normalized_content_sha256
                    ) VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (
                        canonical_receipt_id, claimed_source_artifact_sha256,
                        claimed_normalized_content_sha256
                    ) DO NOTHING
                    RETURNING id, conflict_event_id
                    """,
                    (
                        str(conflict_event_id),
                        runtime_environment,
                        int(existing[0]),
                        command.source_artifact_sha256,
                        normalized_sha256,
                    ),
                )
                conflict = cursor.fetchone()
                if conflict is None:
                    cursor.execute(
                        """
                        SELECT id, conflict_event_id
                          FROM commercial_provider_cost_receipt_conflicts
                         WHERE canonical_receipt_id = %s
                           AND claimed_source_artifact_sha256 = %s
                           AND claimed_normalized_content_sha256 = %s
                        """,
                        (
                            int(existing[0]),
                            command.source_artifact_sha256,
                            normalized_sha256,
                        ),
                    )
                    conflict = cursor.fetchone()
            finally:
                cursor.close()
            original = self._maybe_original_command_id(
                result_kind="conflict", result_id=int(conflict[0])
            )
            return self._record_import_command(
                operator_user_id=operator_user_id,
                environment=runtime_environment,
                command=command,
                payload_sha256=payload_sha256,
                semantic_sha256=semantic_sha256,
                result_kind="conflict",
                result_id=int(conflict[0]),
                event_id=UUID(str(conflict[1])),
                replayed_from_command_id=original,
            )

        receipt_event_id = uuid4()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_provider_cost_receipts (
                    receipt_event_id, environment, provider, source_kind,
                    external_receipt_id, source_revision, supersedes_receipt_id,
                    correction_reason_code, source_artifact_sha256,
                    normalized_content_sha256, currency, cash_cost_usd,
                    period_start_at, period_end_at, observed_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s
                ) RETURNING id
                """,
                (
                    str(receipt_event_id),
                    runtime_environment,
                    command.provider,
                    command.source_kind,
                    command.external_receipt_id,
                    command.source_revision,
                    command.supersedes_receipt_id,
                    command.correction_reason_code,
                    command.source_artifact_sha256,
                    normalized_sha256,
                    command.currency,
                    command.cash_cost_usd,
                    command.period_start_at,
                    command.period_end_at,
                    command.observed_at,
                ),
            )
            receipt_id = int(cursor.fetchone()[0])
        finally:
            cursor.close()
        return self._record_import_command(
            operator_user_id=operator_user_id,
            environment=runtime_environment,
            command=command,
            payload_sha256=payload_sha256,
            semantic_sha256=semantic_sha256,
            result_kind="receipt",
            result_id=receipt_id,
            event_id=receipt_event_id,
            replayed_from_command_id=None,
        )

    @_atomic
    def bind_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: ProviderCostReceiptBindCommand,
    ) -> ProviderCostReceiptBindResult:
        self._require_operator(operator_user_id, runtime_environment)
        semantic_sha256 = canonical_sha256(
            {
                "schema": "commercial.provider-cost-receipt.bind-semantic.v1",
                "environment": runtime_environment,
                "provider_cost_receipt_id": command.provider_cost_receipt_id,
                "cost_pool_id": command.cost_pool_id,
            }
        )
        payload_sha256 = canonical_sha256(
            {
                "schema": "commercial.provider-cost-receipt.bind-command.v1",
                "environment": runtime_environment,
                "command": command.model_dump(
                    mode="python", exclude={"idempotency_key"}
                ),
                "semantic_sha256": semantic_sha256,
            }
        )
        self._lock_idempotency(runtime_environment, command.idempotency_key)
        replay = self._load_bind_command(
            runtime_environment, command.idempotency_key, payload_sha256
        )
        if replay is not None:
            return replay
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT provider, source_kind, external_receipt_id
                  FROM commercial_provider_cost_receipt_current
                 WHERE id = %s AND environment = %s
                 FOR SHARE
                """,
                (command.provider_cost_receipt_id, runtime_environment),
            )
            receipt = cursor.fetchone()
            if receipt is None:
                raise ValueError("provider cost receipt is not the current revision")
        finally:
            cursor.close()
        self._lock_source(runtime_environment, receipt[0], receipt[1], receipt[2])
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT id, binding_event_id, cost_pool_id
                  FROM commercial_provider_cost_receipt_pool_bindings
                 WHERE provider_cost_receipt_id = %s
                 FOR SHARE
                """,
                (command.provider_cost_receipt_id,),
            )
            existing = cursor.fetchone()
        finally:
            cursor.close()
        if existing is not None:
            if int(existing[2]) != command.cost_pool_id:
                raise ValueError("provider cost receipt is already bound to another pool")
            original = self._original_command_id(
                result_kind="binding", result_id=int(existing[0])
            )
            return self._record_bind_command(
                operator_user_id=operator_user_id,
                environment=runtime_environment,
                command=command,
                payload_sha256=payload_sha256,
                semantic_sha256=semantic_sha256,
                binding_id=int(existing[0]),
                binding_event_id=UUID(str(existing[1])),
                replayed_from_command_id=original,
            )
        binding_event_id = uuid4()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_provider_cost_receipt_pool_bindings (
                    binding_event_id, environment, provider_cost_receipt_id,
                    cost_pool_id
                ) VALUES (%s, %s, %s, %s) RETURNING id
                """,
                (
                    str(binding_event_id),
                    runtime_environment,
                    command.provider_cost_receipt_id,
                    command.cost_pool_id,
                ),
            )
            binding_id = int(cursor.fetchone()[0])
        finally:
            cursor.close()
        return self._record_bind_command(
            operator_user_id=operator_user_id,
            environment=runtime_environment,
            command=command,
            payload_sha256=payload_sha256,
            semantic_sha256=semantic_sha256,
            binding_id=binding_id,
            binding_event_id=binding_event_id,
            replayed_from_command_id=None,
        )

    @_atomic
    def dispose_conflict_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: RuntimeEnvironment,
        command: ProviderCostReceiptConflictDispositionCommand,
    ) -> ProviderCostReceiptConflictDispositionResult:
        self._require_operator(operator_user_id, runtime_environment)
        command_sha256 = canonical_sha256(
            {
                "schema": "commercial.provider-cost-receipt.conflict-disposition.v1",
                "environment": runtime_environment,
                "command": command.model_dump(
                    mode="python", exclude={"idempotency_key"}
                ),
            }
        )
        self._lock_idempotency(runtime_environment, command.idempotency_key)
        replay = self._load_conflict_disposition(
            runtime_environment, command.idempotency_key, command_sha256
        )
        if replay is not None:
            return replay
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                ("provider_cost_receipt_conflict", str(command.conflict_id)),
            )
            cursor.execute(
                """
                SELECT id FROM commercial_provider_cost_receipt_conflicts
                 WHERE id = %s AND environment = %s
                 FOR SHARE
                """,
                (command.conflict_id, runtime_environment),
            )
            if cursor.fetchone() is None:
                raise ValueError("provider cost receipt conflict was not found")
            cursor.execute(
                """
                SELECT id FROM commercial_provider_cost_receipt_conflict_dispositions
                 WHERE conflict_id = %s
                """,
                (command.conflict_id,),
            )
            if cursor.fetchone() is not None:
                raise ValueError("provider cost receipt conflict is already disposed")
        finally:
            cursor.close()

        disposition_event_id = uuid4()
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action="commercial.provider_cost_receipt.conflict_dispose",
                target_type="provider_cost_receipt_conflict_disposition",
                target_id=str(disposition_event_id),
                reason_code=command.reason_code,
                after={
                    "content_sha256": command_sha256,
                    "environment": runtime_environment,
                    "role": "billing_operator",
                    "result_code": "applied",
                },
            ),
        )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_provider_cost_receipt_conflict_dispositions (
                    disposition_event_id, environment, conflict_id,
                    disposition_kind, reason_code, note_redacted,
                    idempotency_key, command_sha256, actor_user_id, audit_event_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id, disposed_at
                """,
                (
                    str(disposition_event_id),
                    runtime_environment,
                    command.conflict_id,
                    command.disposition_kind,
                    command.reason_code,
                    command.note_redacted,
                    command.idempotency_key,
                    command_sha256,
                    operator_user_id,
                    str(audit_event_id),
                ),
            )
            disposition_id, disposed_at = cursor.fetchone()
        finally:
            cursor.close()
        return ProviderCostReceiptConflictDispositionResult(
            disposition_id=int(disposition_id),
            disposition_event_id=disposition_event_id,
            conflict_id=command.conflict_id,
            audit_event_id=audit_event_id,
            disposed_at=disposed_at,
        )

    @staticmethod
    def _normalized_digest(
        environment: RuntimeEnvironment, command: ProviderCostReceiptImportCommand
    ) -> str:
        return canonical_sha256(
            {
                "schema": "commercial.provider-cost-receipt.normalized.v1",
                "environment": environment,
                "provider": command.provider,
                "source_kind": command.source_kind,
                "external_receipt_id": command.external_receipt_id,
                "source_revision": command.source_revision,
                "supersedes_receipt_id": command.supersedes_receipt_id,
                "correction_reason_code": command.correction_reason_code,
                "currency": command.currency,
                "cash_cost_usd": command.cash_cost_usd,
                "period_start_at": command.period_start_at,
                "period_end_at": command.period_end_at,
            }
        )

    def _record_import_command(
        self,
        *,
        operator_user_id: int,
        environment: RuntimeEnvironment,
        command: ProviderCostReceiptImportCommand,
        payload_sha256: str,
        semantic_sha256: str,
        result_kind: Literal["receipt", "conflict"],
        result_id: int,
        event_id: UUID,
        replayed_from_command_id: UUID | None,
    ) -> ProviderCostReceiptImportResult:
        command_id, audit_event_id = self._insert_command(
            operator_user_id=operator_user_id,
            environment=environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            semantic_sha256=semantic_sha256,
            command_kind="import",
            result_kind=result_kind,
            result_id=result_id,
            reason_code=command.reason_code,
            replayed_from_command_id=replayed_from_command_id,
        )
        return ProviderCostReceiptImportResult(
            command_id=command_id,
            status="accepted" if result_kind == "receipt" else "conflict",
            receipt_id=result_id if result_kind == "receipt" else None,
            receipt_event_id=event_id if result_kind == "receipt" else None,
            conflict_id=result_id if result_kind == "conflict" else None,
            conflict_event_id=event_id if result_kind == "conflict" else None,
            audit_event_id=audit_event_id,
            durable_replayed=replayed_from_command_id is not None,
        )

    def _record_bind_command(
        self,
        *,
        operator_user_id: int,
        environment: RuntimeEnvironment,
        command: ProviderCostReceiptBindCommand,
        payload_sha256: str,
        semantic_sha256: str,
        binding_id: int,
        binding_event_id: UUID,
        replayed_from_command_id: UUID | None,
    ) -> ProviderCostReceiptBindResult:
        command_id, audit_event_id = self._insert_command(
            operator_user_id=operator_user_id,
            environment=environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            semantic_sha256=semantic_sha256,
            command_kind="bind",
            result_kind="binding",
            result_id=binding_id,
            reason_code=command.reason_code,
            replayed_from_command_id=replayed_from_command_id,
        )
        return ProviderCostReceiptBindResult(
            command_id=command_id,
            binding_id=binding_id,
            binding_event_id=binding_event_id,
            provider_cost_receipt_id=command.provider_cost_receipt_id,
            cost_pool_id=command.cost_pool_id,
            audit_event_id=audit_event_id,
            durable_replayed=replayed_from_command_id is not None,
        )

    def _insert_command(
        self,
        *,
        operator_user_id: int,
        environment: RuntimeEnvironment,
        idempotency_key: str,
        payload_sha256: str,
        semantic_sha256: str,
        command_kind: Literal["import", "bind"],
        result_kind: Literal["receipt", "conflict", "binding"],
        result_id: int,
        reason_code: str,
        replayed_from_command_id: UUID | None,
    ) -> tuple[UUID, UUID]:
        command_id = uuid4()
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action=f"commercial.provider_cost_receipt.{command_kind}",
                target_type="provider_cost_receipt_command",
                target_id=str(command_id),
                reason_code=reason_code,
                after={
                    "content_sha256": payload_sha256,
                    "environment": environment,
                    "role": "billing_operator",
                    "result_code": "applied",
                },
            ),
        )
        values = {
            "receipt": (result_id, None, None),
            "conflict": (None, result_id, None),
            "binding": (None, None, result_id),
        }[result_kind]
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_provider_cost_receipt_commands (
                    command_id, environment, idempotency_key, command_kind,
                    payload_sha256, semantic_sha256, result_kind, result_receipt_id,
                    result_conflict_id, result_binding_id, actor_user_id,
                    audit_event_id, replayed_from_command_id
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(command_id),
                    environment,
                    idempotency_key,
                    command_kind,
                    payload_sha256,
                    semantic_sha256,
                    result_kind,
                    *values,
                    operator_user_id,
                    str(audit_event_id),
                    str(replayed_from_command_id)
                    if replayed_from_command_id
                    else None,
                ),
            )
        finally:
            cursor.close()
        return command_id, audit_event_id

    def _load_import_command(
        self, environment: str, idempotency_key: str, payload_sha256: str
    ) -> ProviderCostReceiptImportResult | None:
        row = self._load_command(environment, idempotency_key, payload_sha256)
        if row is None:
            return None
        if row[1] != "import":
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        if row[2] == "receipt":
            cursor = self._connection.cursor()  # type: ignore[attr-defined]
            try:
                cursor.execute(
                    "SELECT receipt_event_id FROM commercial_provider_cost_receipts WHERE id = %s",
                    (row[3],),
                )
                event_id = UUID(str(cursor.fetchone()[0]))
            finally:
                cursor.close()
            return ProviderCostReceiptImportResult(
                command_id=UUID(str(row[0])), status="accepted",
                receipt_id=int(row[3]), receipt_event_id=event_id,
                audit_event_id=UUID(str(row[6])), durable_replayed=True,
            )
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT conflict_event_id FROM commercial_provider_cost_receipt_conflicts WHERE id = %s",
                (row[4],),
            )
            event_id = UUID(str(cursor.fetchone()[0]))
        finally:
            cursor.close()
        return ProviderCostReceiptImportResult(
            command_id=UUID(str(row[0])), status="conflict",
            conflict_id=int(row[4]), conflict_event_id=event_id,
            audit_event_id=UUID(str(row[6])), durable_replayed=True,
        )

    def _load_bind_command(
        self, environment: str, idempotency_key: str, payload_sha256: str
    ) -> ProviderCostReceiptBindResult | None:
        row = self._load_command(environment, idempotency_key, payload_sha256)
        if row is None:
            return None
        if row[1] != "bind" or row[2] != "binding":
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT binding_event_id, provider_cost_receipt_id, cost_pool_id
                  FROM commercial_provider_cost_receipt_pool_bindings WHERE id = %s
                """,
                (row[5],),
            )
            binding = cursor.fetchone()
        finally:
            cursor.close()
        return ProviderCostReceiptBindResult(
            command_id=UUID(str(row[0])), binding_id=int(row[5]),
            binding_event_id=UUID(str(binding[0])),
            provider_cost_receipt_id=int(binding[1]), cost_pool_id=int(binding[2]),
            audit_event_id=UUID(str(row[6])), durable_replayed=True,
        )

    def _load_command(self, environment: str, idempotency_key: str, payload_sha256: str):
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT command_id, command_kind, result_kind, result_receipt_id,
                       result_conflict_id, result_binding_id, audit_event_id,
                       payload_sha256
                  FROM commercial_provider_cost_receipt_commands
                 WHERE environment = %s AND idempotency_key = %s
                """,
                (environment, idempotency_key),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is not None and row[7] != payload_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return row

    def _load_conflict_disposition(
        self, environment: str, idempotency_key: str, command_sha256: str
    ) -> ProviderCostReceiptConflictDispositionResult | None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT id, disposition_event_id, conflict_id, audit_event_id,
                       disposed_at, command_sha256
                  FROM commercial_provider_cost_receipt_conflict_dispositions
                 WHERE environment = %s AND idempotency_key = %s
                """,
                (environment, idempotency_key),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[5] != command_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return ProviderCostReceiptConflictDispositionResult(
            disposition_id=int(row[0]),
            disposition_event_id=UUID(str(row[1])),
            conflict_id=int(row[2]),
            audit_event_id=UUID(str(row[3])),
            disposed_at=row[4],
            durable_replayed=True,
        )

    def _original_command_id(self, *, result_kind: str, result_id: int) -> UUID:
        value = self._maybe_original_command_id(
            result_kind=result_kind, result_id=result_id
        )
        if value is None:
            raise RuntimeError("provider cost result lacks original command")
        return value

    def _maybe_original_command_id(
        self, *, result_kind: str, result_id: int
    ) -> UUID | None:
        column = {
            "receipt": "result_receipt_id",
            "conflict": "result_conflict_id",
            "binding": "result_binding_id",
        }[result_kind]
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                f"SELECT command_id FROM commercial_provider_cost_receipt_commands "
                f"WHERE {column} = %s AND replayed_from_command_id IS NULL",
                (result_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return None if row is None else UUID(str(row[0]))

    def _require_operator(self, user_id: int, environment: RuntimeEnvironment) -> None:
        self._require_transaction()
        if not self._flags.commercial_control_enabled:
            raise RuntimeError("commercial controls are disabled")
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

    def _lock_idempotency(self, environment: str, idempotency_key: str) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                ("provider_cost_receipt_command", f"{environment}:{idempotency_key}"),
            )
        finally:
            cursor.close()

    def _lock_source(
        self, environment: str, provider: str, source_kind: str, external_id: str
    ) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext(%s), hashtext(%s))",
                (
                    "provider_cost_receipt_source",
                    f"{environment}:{provider}:{source_kind}:{external_id}",
                ),
            )
        finally:
            cursor.close()

    def _run_atomic(self, operation: Callable[[], _ResultT]) -> _ResultT:
        self._require_transaction()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT provider_cost_receipt_command")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT provider_cost_receipt_command")
                cursor.execute("RELEASE SAVEPOINT provider_cost_receipt_command")
                raise
            cursor.execute("RELEASE SAVEPOINT provider_cost_receipt_command")
            return result
        finally:
            cursor.close()

    def _require_transaction(self) -> None:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("provider cost receipt commands require a transaction")


__all__ = [
    "PostgresProviderCostReceiptService",
    "ProviderCostReceiptBindCommand",
    "ProviderCostReceiptBindResult",
    "ProviderCostReceiptConflictDispositionCommand",
    "ProviderCostReceiptConflictDispositionResult",
    "ProviderCostReceiptImportCommand",
    "ProviderCostReceiptImportResult",
]
