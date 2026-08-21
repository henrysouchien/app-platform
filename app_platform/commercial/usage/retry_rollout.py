"""Durable rollout controls for central workflow retry lineage."""

from __future__ import annotations

from datetime import date, datetime, timedelta, timezone
import json
from typing import Annotated, Any, Callable, Literal, Mapping
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, model_validator

from ..agreement_lifecycle import IdempotencyKey
from ..flags import CommercialFlags
from ..models import Sha256Digest, StrictCommercialModel


class RetryLineageRolloutError(RuntimeError):
    """A stable fail-closed retry-lineage rollout error."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class RetryLineageShadowCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    week_start: date
    idempotency_key: IdempotencyKey
    actor_id: Annotated[str, Field(min_length=1, max_length=255)]
    observed_at: AwareDatetime

    @model_validator(mode="after")
    def _completed_utc_week(self) -> "RetryLineageShadowCommand":
        if self.week_start.weekday() != 0:
            raise ValueError("retry-lineage shadow week must start on Monday")
        week_end = datetime.combine(
            self.week_start + timedelta(days=7),
            datetime.min.time(),
            tzinfo=timezone.utc,
        )
        if self.observed_at.astimezone(timezone.utc) < week_end:
            raise ValueError("retry-lineage shadow week must be complete")
        return self


class RetryLineageShadowResult(StrictCommercialModel):
    evidence_id: UUID
    environment: Literal["dev", "staging", "prod"]
    week_start: date
    week_end: date
    status: Literal["passed", "failed"]
    attempt_workflow_count: Annotated[int, Field(ge=0)]
    lineage_observed_attempt_count: Annotated[int, Field(ge=0)]
    reconciled_attempt_count: Annotated[int, Field(ge=0)]
    logical_workflow_count: Annotated[int, Field(ge=0)] | None
    retry_count: Annotated[int, Field(ge=0)] | None
    unreconciled_attempt_count: Annotated[int, Field(ge=0)]
    source_changed_at: datetime | None
    source_snapshot_sha256: Sha256Digest
    observed_at: datetime
    replayed: bool
    authorizes_work: Literal[False] = False


class RetryLineageCutoverCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    cutover_at: AwareDatetime
    first_shadow_evidence_id: UUID
    second_shadow_evidence_id: UUID
    idempotency_key: IdempotencyKey
    actor_id: Annotated[str, Field(min_length=1, max_length=255)]

    @model_validator(mode="after")
    def _utc_week_boundary(self) -> "RetryLineageCutoverCommand":
        boundary = self.cutover_at.astimezone(timezone.utc)
        if (
            boundary.weekday() != 0
            or boundary.hour != 0
            or boundary.minute != 0
            or boundary.second != 0
            or boundary.microsecond != 0
        ):
            raise ValueError("retry-lineage cutover must be a Monday UTC boundary")
        if self.first_shadow_evidence_id == self.second_shadow_evidence_id:
            raise ValueError("retry-lineage cutover requires two distinct windows")
        return self


class RetryLineageCutoverResult(StrictCommercialModel):
    cutover_id: UUID
    environment: Literal["dev", "staging", "prod"]
    cutover_at: datetime
    first_shadow_evidence_id: UUID
    second_shadow_evidence_id: UUID
    activated_at: datetime
    replayed: bool


_RESULT_COLUMNS = (
    "evidence_id",
    "environment",
    "week_start",
    "week_end",
    "status",
    "attempt_workflow_count",
    "lineage_observed_attempt_count",
    "reconciled_attempt_count",
    "logical_workflow_count",
    "retry_count",
    "unreconciled_attempt_count",
    "source_changed_at",
    "source_snapshot_sha256",
    "observed_at",
)
_CUTOVER_RESULT_COLUMNS = (
    "cutover_id",
    "environment",
    "cutover_at",
    "first_shadow_evidence_id",
    "second_shadow_evidence_id",
    "activated_at",
)


def _shadow_lock_key(environment: str, week_start: date) -> str:
    return "\x1f".join(
        (
            "commercial-retry-lineage-shadow",
            environment,
            week_start.isoformat(),
        )
    )


def _cutover_lock_key(environment: str) -> str:
    return "\x1f".join(("commercial-retry-lineage-cutover", environment))


class PostgresRetryLineageRolloutService:
    """Record one database-verified, non-authorizing weekly parity snapshot."""

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        if bool(getattr(connection, "autocommit", False)):
            raise RuntimeError(
                "retry-lineage rollout requires an explicit transaction boundary"
            )
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def observe_shadow(
        self, command: RetryLineageShadowCommand
    ) -> RetryLineageShadowResult:
        self._require_idle()
        if command.environment != self._flags.environment:
            raise RetryLineageRolloutError("retry_lineage.environment_mismatch")
        if not self._flags.commercial_retry_lineage_shadow_mode:
            raise RetryLineageRolloutError("retry_lineage.shadow_disabled")
        trusted_now = self._clock()
        if trusted_now.tzinfo is None or trusted_now.utcoffset() is None:
            raise RetryLineageRolloutError("retry_lineage.clock_not_aware")
        trusted_now = trusted_now.astimezone(timezone.utc)
        week_end_at = datetime.combine(
            command.week_start + timedelta(days=7),
            datetime.min.time(),
            tzinfo=timezone.utc,
        )
        if (
            week_end_at > trusted_now
            or command.observed_at.astimezone(timezone.utc) > trusted_now
        ):
            raise RetryLineageRolloutError("retry_lineage.future_observation")

        command_payload = {
            "schema": "commercial.retry-lineage-shadow-command.v1",
            "environment": command.environment,
            "week_start": command.week_start.isoformat(),
            "actor_id": command.actor_id,
        }
        try:
            with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (_shadow_lock_key(command.environment, command.week_start),),
                )
                command_sha256 = self._database_json_digest(cursor, command_payload)
                existing = self._load_by_idempotency(
                    cursor,
                    environment=command.environment,
                    idempotency_key=command.idempotency_key,
                )
                if existing is not None:
                    if existing[1] != command_sha256:
                        raise RetryLineageRolloutError(
                            "retry_lineage.idempotency_conflict"
                        )
                    result = self._result(existing[0], replayed=True)
                    self._connection.commit()  # type: ignore[attr-defined]
                    return result

                snapshot = self._load_snapshot(
                    cursor,
                    environment=command.environment,
                    week_start=command.week_start,
                )
                source_snapshot = snapshot[9]
                source_snapshot_sha256 = snapshot[10]
                observed_at = command.observed_at.astimezone(timezone.utc)
                if snapshot[8] is not None and observed_at < snapshot[8]:
                    raise RetryLineageRolloutError(
                        "retry_lineage.observation_precedes_source"
                    )

                evidence_id = uuid4()
                cursor.execute(
                    """
                    INSERT INTO commercial_retry_lineage_shadow_evidence (
                        evidence_id, environment, week_start, week_end, status,
                        attempt_workflow_count,
                        lineage_observed_attempt_count,
                        reconciled_attempt_count, logical_workflow_count,
                        retry_count, unreconciled_attempt_count,
                        source_changed_at, source_snapshot_sha256,
                        idempotency_key, command_payload, command_sha256,
                        actor_id, observed_at, payload
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s::jsonb, %s, %s, %s, %s::jsonb
                    )
                    RETURNING evidence_id, environment, week_start, week_end,
                              status, attempt_workflow_count,
                              lineage_observed_attempt_count,
                              reconciled_attempt_count, logical_workflow_count,
                              retry_count, unreconciled_attempt_count,
                              source_changed_at, source_snapshot_sha256,
                              observed_at
                    """,
                    (
                        str(evidence_id),
                        command.environment,
                        command.week_start,
                        snapshot[0],
                        snapshot[1],
                        snapshot[2],
                        snapshot[3],
                        snapshot[4],
                        snapshot[5],
                        snapshot[6],
                        snapshot[7],
                        snapshot[8],
                        source_snapshot_sha256,
                        command.idempotency_key,
                        json.dumps(command_payload, separators=(",", ":"), sort_keys=True),
                        command_sha256,
                        command.actor_id,
                        observed_at,
                        json.dumps(source_snapshot, separators=(",", ":"), sort_keys=True),
                    ),
                )
                inserted = cursor.fetchone()
                if inserted is None:
                    raise RetryLineageRolloutError("retry_lineage.evidence_insert_failed")
            self._connection.commit()  # type: ignore[attr-defined]
            return self._result(inserted, replayed=False)
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise

    def activate_cutover(
        self, command: RetryLineageCutoverCommand
    ) -> RetryLineageCutoverResult:
        self._require_idle()
        if command.environment != self._flags.environment:
            raise RetryLineageRolloutError("retry_lineage.environment_mismatch")
        if not self._flags.commercial_retry_lineage_enforcement_enabled:
            raise RetryLineageRolloutError("retry_lineage.enforcement_disabled")
        trusted_now = self._trusted_now()
        cutover_at = command.cutover_at.astimezone(timezone.utc)
        if cutover_at > trusted_now:
            raise RetryLineageRolloutError("retry_lineage.future_cutover")
        command_payload = {
            "schema": "commercial.retry-lineage-cutover-command.v1",
            "environment": command.environment,
            "cutover_at": cutover_at.isoformat(timespec="microseconds").replace(
                "+00:00", "Z"
            ),
            "first_shadow_evidence_id": str(command.first_shadow_evidence_id),
            "second_shadow_evidence_id": str(command.second_shadow_evidence_id),
            "actor_id": command.actor_id,
        }
        try:
            with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                    (_cutover_lock_key(command.environment),),
                )
                command_sha256 = self._database_json_digest(cursor, command_payload)
                cursor.execute(
                    """
                    SELECT cutover_id, environment, cutover_at,
                           first_shadow_evidence_id, second_shadow_evidence_id,
                           activated_at, command_sha256
                      FROM commercial_retry_lineage_cutovers
                     WHERE environment = %s AND idempotency_key = %s
                     FOR SHARE
                    """,
                    (command.environment, command.idempotency_key),
                )
                existing = cursor.fetchone()
                if existing is not None:
                    values = self._row_values(
                        existing,
                        (*_CUTOVER_RESULT_COLUMNS, "command_sha256"),
                    )
                    if values[6] != command_sha256:
                        raise RetryLineageRolloutError(
                            "retry_lineage.cutover_idempotency_conflict"
                        )
                    result = self._cutover_result(values[:6], replayed=True)
                    self._connection.commit()  # type: ignore[attr-defined]
                    return result
                cursor.execute(
                    "SELECT 1 FROM commercial_retry_lineage_cutovers "
                    "WHERE environment = %s FOR SHARE",
                    (command.environment,),
                )
                if cursor.fetchone() is not None:
                    raise RetryLineageRolloutError(
                        "retry_lineage.cutover_already_active"
                    )

                cutover_id = uuid4()
                cursor.execute(
                    """
                    INSERT INTO commercial_retry_lineage_cutovers (
                        cutover_id, environment, cutover_at,
                        first_shadow_evidence_id, second_shadow_evidence_id,
                        idempotency_key, command_payload, command_sha256, actor_id
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    RETURNING cutover_id, environment, cutover_at,
                              first_shadow_evidence_id,
                              second_shadow_evidence_id, activated_at
                    """,
                    (
                        str(cutover_id),
                        command.environment,
                        cutover_at,
                        str(command.first_shadow_evidence_id),
                        str(command.second_shadow_evidence_id),
                        command.idempotency_key,
                        json.dumps(command_payload, separators=(",", ":"), sort_keys=True),
                        command_sha256,
                        command.actor_id,
                    ),
                )
                inserted = cursor.fetchone()
                if inserted is None:
                    raise RetryLineageRolloutError("retry_lineage.cutover_insert_failed")
                inserted_values = self._row_values(
                    inserted,
                    _CUTOVER_RESULT_COLUMNS,
                )
                cursor.execute(
                    """
                    SELECT cutover_at, cutover_id, activated_at
                      FROM commercial_retry_lineage_cutover_gates
                     WHERE environment = %s
                    """,
                    (command.environment,),
                )
                gate = cursor.fetchone()
                gate_values = (
                    self._row_values(
                        gate,
                        ("cutover_at", "cutover_id", "activated_at"),
                    )
                    if gate is not None
                    else None
                )
                if gate_values != (
                    inserted_values[2],
                    inserted_values[0],
                    inserted_values[5],
                ):
                    raise RetryLineageRolloutError(
                        "retry_lineage.cutover_gate_conflict"
                    )
            self._connection.commit()  # type: ignore[attr-defined]
            return self._cutover_result(inserted_values, replayed=False)
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise

    @staticmethod
    def _load_by_idempotency(
        cursor: object, *, environment: str, idempotency_key: str
    ) -> tuple[Any, str] | None:
        cursor.execute(  # type: ignore[attr-defined]
            """
            SELECT evidence_id, environment, week_start, week_end, status,
                   attempt_workflow_count, lineage_observed_attempt_count,
                   reconciled_attempt_count, logical_workflow_count,
                   retry_count, unreconciled_attempt_count, source_changed_at,
                   source_snapshot_sha256, observed_at, command_sha256
              FROM commercial_retry_lineage_shadow_evidence
             WHERE environment = %s AND idempotency_key = %s
             FOR SHARE
            """,
            (environment, idempotency_key),
        )
        row = cursor.fetchone()  # type: ignore[attr-defined]
        if row is None:
            return None
        if isinstance(row, Mapping):
            return (
                tuple(row[column] for column in _RESULT_COLUMNS),
                str(row["command_sha256"]),
            )
        return tuple(row[:14]), str(row[14])

    @staticmethod
    def _load_snapshot(cursor: object, *, environment: str, week_start: date) -> tuple:
        cursor.execute(  # type: ignore[attr-defined]
            """
            SELECT week_end,
                   CASE WHEN parity_exact THEN 'passed' ELSE 'failed' END AS status,
                   attempt_workflow_count, lineage_observed_attempt_count,
                   reconciled_attempt_count, logical_workflow_count,
                   retry_count, unreconciled_attempt_count, source_changed_at,
                   source_snapshot, source_snapshot_sha256
              FROM commercial_retry_lineage_weekly_shadow
             WHERE environment = %s AND week_start = %s
            """,
            (environment, week_start),
        )
        row = cursor.fetchone()  # type: ignore[attr-defined]
        if row is not None:
            if isinstance(row, Mapping):
                columns = (
                    "week_end",
                    "status",
                    "attempt_workflow_count",
                    "lineage_observed_attempt_count",
                    "reconciled_attempt_count",
                    "logical_workflow_count",
                    "retry_count",
                    "unreconciled_attempt_count",
                    "source_changed_at",
                    "source_snapshot",
                    "source_snapshot_sha256",
                )
                return tuple(row[column] for column in columns)
            return tuple(row)

        week_end = week_start + timedelta(days=7)
        source_snapshot = {
            "schema": "commercial.retry-lineage-shadow-source.v1",
            "environment": environment,
            "week_start": week_start.isoformat(),
            "week_end": week_end.isoformat(),
            "status": "failed",
            "attempt_workflow_count": 0,
            "lineage_observed_attempt_count": 0,
            "reconciled_attempt_count": 0,
            "logical_workflow_count": None,
            "retry_count": None,
            "unreconciled_attempt_count": 0,
            "source_changed_at": None,
        }
        cursor.execute(  # type: ignore[attr-defined]
            """
            SELECT 'sha256:' || encode(
                public.digest(convert_to(%s::jsonb::TEXT, 'UTF8'), 'sha256'), 'hex'
            )
            """,
            (json.dumps(source_snapshot, separators=(",", ":"), sort_keys=True),),
        )
        digest_row = cursor.fetchone()  # type: ignore[attr-defined]
        source_digest = (
            digest_row[0]
            if not isinstance(digest_row, Mapping)
            else next(iter(digest_row.values()))
        )
        return (
            week_end,
            "failed",
            0,
            0,
            0,
            None,
            None,
            0,
            None,
            source_snapshot,
            source_digest,
        )

    @staticmethod
    def _result(row: Any, *, replayed: bool) -> RetryLineageShadowResult:
        if isinstance(row, Mapping):
            values = tuple(row[column] for column in _RESULT_COLUMNS)
        else:
            values = tuple(row)
        return RetryLineageShadowResult(
            **dict(zip(_RESULT_COLUMNS, values, strict=True)),
            replayed=replayed,
            authorizes_work=False,
        )

    @staticmethod
    def _database_json_digest(cursor: object, payload: dict[str, object]) -> str:
        cursor.execute(  # type: ignore[attr-defined]
            """
            SELECT 'sha256:' || encode(
                public.digest(convert_to(%s::jsonb::TEXT, 'UTF8'), 'sha256'), 'hex'
            )
            """,
            (json.dumps(payload, separators=(",", ":"), sort_keys=True),),
        )
        row = cursor.fetchone()  # type: ignore[attr-defined]
        if isinstance(row, Mapping):
            return str(next(iter(row.values())))
        return str(row[0])

    @staticmethod
    def _cutover_result(row: Any, *, replayed: bool) -> RetryLineageCutoverResult:
        values = PostgresRetryLineageRolloutService._row_values(
            row,
            _CUTOVER_RESULT_COLUMNS,
        )
        return RetryLineageCutoverResult(
            cutover_id=values[0],
            environment=values[1],
            cutover_at=values[2],
            first_shadow_evidence_id=values[3],
            second_shadow_evidence_id=values[4],
            activated_at=values[5],
            replayed=replayed,
        )

    @staticmethod
    def _row_values(row: Any, columns: tuple[str, ...]) -> tuple[Any, ...]:
        if isinstance(row, Mapping):
            return tuple(row[column] for column in columns)
        return tuple(row)

    def _trusted_now(self) -> datetime:
        trusted_now = self._clock()
        if trusted_now.tzinfo is None or trusted_now.utcoffset() is None:
            raise RetryLineageRolloutError("retry_lineage.clock_not_aware")
        return trusted_now.astimezone(timezone.utc)

    def _require_idle(self) -> None:
        reader = getattr(self._connection, "get_transaction_status", None)
        if reader is not None and reader() != 0:
            raise RetryLineageRolloutError("retry_lineage.connection_not_idle")


__all__ = [
    "PostgresRetryLineageRolloutService",
    "RetryLineageCutoverCommand",
    "RetryLineageCutoverResult",
    "RetryLineageRolloutError",
    "RetryLineageShadowCommand",
    "RetryLineageShadowResult",
]
