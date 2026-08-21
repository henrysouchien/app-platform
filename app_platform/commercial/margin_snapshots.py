"""Immutable account-period margin snapshot protocol."""

from __future__ import annotations

from datetime import date
import hashlib
import json
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import Field, StrictBool, StrictInt

from .flags import CommercialFlags
from .models import Environment, NonEmptyStr, Sha256Digest, StableCode, StrictCommercialModel


class MarginSnapshotPartition(StrictCommercialModel):
    environment: Environment
    commercial_account_id: StrictInt = Field(gt=0)
    agreement_id: StrictInt = Field(gt=0)
    offer_code: StableCode
    service_month: date


class MarginSnapshotResult(StrictCommercialModel):
    snapshot_id: UUID
    partition: MarginSnapshotPartition
    revision: StrictInt = Field(gt=0)
    snapshot_sha256: Sha256Digest
    status: Literal["complete", "incomplete"]
    snapshot: dict[str, Any]
    durable_replayed: StrictBool = False


class PostgresMarginSnapshotProtocol:
    def __init__(
        self, connection, *, flags: CommercialFlags, freshness_seconds: int = 172_800
    ) -> None:
        self._connection = connection
        self._flags = flags
        if not 1 <= freshness_seconds <= 604_800:
            raise ValueError("margin snapshot freshness is invalid")
        self._freshness_seconds = freshness_seconds

    def list_partitions(
        self,
        *,
        environment: str,
        service_month: date,
        after_account_id: int,
        after_agreement_id: int,
        after_offer_code: str,
        limit: int,
    ) -> tuple[MarginSnapshotPartition, ...]:
        self._require_enabled()
        if environment != self._flags.environment:
            raise ValueError("margin snapshot environment is invalid")
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT commercial_account_id, agreement_id, offer_code, service_month
                  FROM commercial_account_month_economics
                 WHERE service_month = %s
                   AND (commercial_account_id, agreement_id, offer_code)
                       > (%s, %s, %s)
                 ORDER BY commercial_account_id, agreement_id, offer_code
                 LIMIT %s
                """,
                (
                    service_month,
                    after_account_id,
                    after_agreement_id,
                    after_offer_code,
                    limit,
                ),
            )
            return tuple(
                MarginSnapshotPartition(
                    environment=environment,
                    commercial_account_id=row[0],
                    agreement_id=row[1],
                    offer_code=row[2],
                    service_month=row[3],
                )
                for row in cursor.fetchall()
            )
        finally:
            cursor.close()

    def snapshot(self, partition: MarginSnapshotPartition) -> MarginSnapshotResult:
        self._require_enabled()
        if partition.environment != self._flags.environment:
            raise ValueError("margin snapshot environment is invalid")
        if partition.service_month.day != 1:
            raise ValueError("margin snapshot month is invalid")
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(E'\\x1f', %s, %s, %s, %s, %s), 0))",
                (
                    partition.environment,
                    partition.commercial_account_id,
                    partition.agreement_id,
                    partition.offer_code,
                    partition.service_month.isoformat(),
                ),
            )
            cursor.execute(
                """
                SELECT to_jsonb(month)::text,
                       month.unknown_management_cost_event_count,
                       month.unallocated_processor_fee_count,
                       month.management_technical_cogs_usd,
                       FLOOR(EXTRACT(EPOCH FROM statement_timestamp()) / %s)::BIGINT
                  FROM commercial_account_month_economics month
                 WHERE month.commercial_account_id = %s
                   AND month.agreement_id = %s
                   AND month.offer_code = %s
                   AND month.service_month = %s
                """,
                (
                    max(1, self._freshness_seconds // 2),
                    partition.commercial_account_id,
                    partition.agreement_id,
                    partition.offer_code,
                    partition.service_month,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError("margin snapshot partition has no economics evidence")
            snapshot_text = str(row[0])
            snapshot = json.loads(snapshot_text)
            complete = int(row[1]) == 0 and int(row[2]) == 0 and row[3] is not None
            capture_partition = int(row[4])
            snapshot_sha256 = "sha256:" + hashlib.sha256(
                (
                    "commercial.margin-snapshot.v1\n"
                    + partition.environment
                    + "\n"
                    + str(capture_partition)
                    + "\n"
                    + snapshot_text
                ).encode("utf-8")
            ).hexdigest()
            identity = (
                partition.environment,
                partition.commercial_account_id,
                partition.agreement_id,
                partition.offer_code,
                partition.service_month,
            )
            cursor.execute(
                """
                SELECT snapshot_id, revision, complete, snapshot, snapshot_sha256
                  FROM commercial_margin_snapshots
                 WHERE environment = %s AND commercial_account_id = %s
                   AND agreement_id = %s AND offer_code = %s
                   AND service_month = %s
                 ORDER BY revision DESC
                 LIMIT 1
                """,
                identity,
            )
            replay = cursor.fetchone()
            if replay is not None and replay[4] == snapshot_sha256:
                return MarginSnapshotResult(
                    snapshot_id=replay[0], partition=partition, revision=replay[1],
                    snapshot_sha256=snapshot_sha256,
                    status="complete" if replay[2] else "incomplete",
                    snapshot=replay[3], durable_replayed=True,
                )
            cursor.execute(
                """
                SELECT COALESCE(MAX(revision), 0) + 1
                  FROM commercial_margin_snapshots
                 WHERE environment = %s AND commercial_account_id = %s
                   AND agreement_id = %s AND offer_code = %s AND service_month = %s
                """,
                identity,
            )
            revision = int(cursor.fetchone()[0])
            snapshot_id = uuid4()
            cursor.execute(
                """
                INSERT INTO commercial_margin_snapshots (
                    snapshot_id, environment, commercial_account_id, agreement_id,
                    offer_code, service_month, revision, snapshot_sha256,
                    capture_partition, complete, stale_after_at, snapshot
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                          statement_timestamp() + make_interval(secs => %s), %s::jsonb)
                """,
                (
                    str(snapshot_id), *identity, revision, snapshot_sha256,
                    capture_partition, complete, self._freshness_seconds, snapshot_text,
                ),
            )
            return MarginSnapshotResult(
                snapshot_id=snapshot_id, partition=partition, revision=revision,
                snapshot_sha256=snapshot_sha256,
                status="complete" if complete else "incomplete",
                snapshot=snapshot,
            )
        finally:
            cursor.close()

    def _require_enabled(self) -> None:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_reconciliation_enabled
        ):
            raise RuntimeError("commercial margin snapshots are disabled")


class MarginRollupSnapshotPartition(StrictCommercialModel):
    environment: Environment
    snapshot_kind: Literal[
        "offer_cohort_month", "account_workflow_month", "offer_workflow_month"
    ]
    scope_key: NonEmptyStr
    service_month: date


class MarginRollupSnapshotResult(StrictCommercialModel):
    snapshot_id: UUID
    partition: MarginRollupSnapshotPartition
    revision: StrictInt = Field(gt=0)
    snapshot_sha256: Sha256Digest
    status: Literal["complete", "incomplete"]
    snapshot: dict[str, Any]
    durable_replayed: StrictBool = False


class PostgresMarginRollupSnapshotProtocol:
    _SOURCES = {
        "offer_cohort_month": (
            "commercial_offer_cohort_month_economics",
            "concat_ws('|', source.offer_code, source.cohort_month::text)",
            "source.management_technical_gross_margin_usd IS NOT NULL",
        ),
        "account_workflow_month": (
            "commercial_workflow_month_economics",
            "concat_ws('|', source.commercial_account_id::text, "
            "source.agreement_id::text, source.offer_code, source.surface_code, "
            "source.workflow_code)",
            "source.unknown_management_cost_event_count = 0",
        ),
        "offer_workflow_month": (
            "commercial_offer_workflow_month_economics",
            "concat_ws('|', source.offer_code, source.surface_code, source.workflow_code)",
            "source.unknown_management_cost_event_count = 0",
        ),
    }

    def __init__(
        self, connection, *, flags: CommercialFlags, freshness_seconds: int = 172_800
    ) -> None:
        self._connection = connection
        self._flags = flags
        if not 1 <= freshness_seconds <= 604_800:
            raise ValueError("margin snapshot freshness is invalid")
        self._freshness_seconds = freshness_seconds

    def list_partitions(
        self,
        *,
        environment: str,
        service_month: date,
        after_kind: str,
        after_scope_key: str,
        limit: int,
    ) -> tuple[MarginRollupSnapshotPartition, ...]:
        self._require_enabled()
        if environment != self._flags.environment:
            raise ValueError("margin snapshot environment is invalid")
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                WITH partition AS (
                    SELECT 'offer_cohort_month'::TEXT AS snapshot_kind,
                           concat_ws('|', offer_code, cohort_month::text) AS scope_key,
                           service_month
                      FROM commercial_offer_cohort_month_economics
                     WHERE service_month = %s
                    UNION ALL
                    SELECT 'account_workflow_month',
                           concat_ws('|', commercial_account_id::text,
                                     agreement_id::text, offer_code, surface_code,
                                     workflow_code), service_month
                      FROM commercial_workflow_month_economics
                     WHERE service_month = %s
                    UNION ALL
                    SELECT 'offer_workflow_month',
                           concat_ws('|', offer_code, surface_code, workflow_code),
                           service_month
                      FROM commercial_offer_workflow_month_economics
                     WHERE service_month = %s
                )
                SELECT snapshot_kind, scope_key, service_month
                  FROM partition
                 WHERE (snapshot_kind, scope_key) > (%s, %s)
                 ORDER BY snapshot_kind, scope_key
                 LIMIT %s
                """,
                (
                    service_month, service_month, service_month,
                    after_kind, after_scope_key, limit,
                ),
            )
            return tuple(
                MarginRollupSnapshotPartition(
                    environment=environment, snapshot_kind=row[0],
                    scope_key=row[1], service_month=row[2],
                )
                for row in cursor.fetchall()
            )
        finally:
            cursor.close()

    def snapshot(
        self, partition: MarginRollupSnapshotPartition
    ) -> MarginRollupSnapshotResult:
        self._require_enabled()
        if partition.environment != self._flags.environment:
            raise ValueError("margin snapshot environment is invalid")
        source_view, key_expression, complete_expression = self._SOURCES[
            partition.snapshot_kind
        ]
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(E'\\x1f', %s, %s, %s, %s), 0))",
                (
                    partition.environment, partition.snapshot_kind,
                    partition.scope_key, partition.service_month.isoformat(),
                ),
            )
            cursor.execute(
                f"SELECT to_jsonb(source)::text, ({complete_expression}), "
                f"FLOOR(EXTRACT(EPOCH FROM statement_timestamp()) / %s)::BIGINT "
                f"FROM {source_view} source WHERE source.service_month = %s "
                f"AND {key_expression} = %s",
                (
                    max(1, self._freshness_seconds // 2),
                    partition.service_month,
                    partition.scope_key,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError("margin rollup partition has no economics evidence")
            snapshot_text = str(row[0])
            snapshot = json.loads(snapshot_text)
            complete = bool(row[1])
            capture_partition = int(row[2])
            snapshot_sha256 = "sha256:" + hashlib.sha256(
                (
                    "commercial.margin-rollup-snapshot.v1\n"
                    + partition.environment + "\n" + partition.snapshot_kind
                    + "\n" + str(capture_partition) + "\n" + snapshot_text
                ).encode("utf-8")
            ).hexdigest()
            identity = (
                partition.environment, partition.snapshot_kind,
                partition.scope_key, partition.service_month,
            )
            cursor.execute(
                """
                SELECT snapshot_id, revision, complete, snapshot, snapshot_sha256
                  FROM commercial_margin_rollup_snapshots
                 WHERE environment = %s AND snapshot_kind = %s
                   AND scope_key = %s AND service_month = %s
                 ORDER BY revision DESC
                 LIMIT 1
                """,
                identity,
            )
            replay = cursor.fetchone()
            if replay is not None and replay[4] == snapshot_sha256:
                return MarginRollupSnapshotResult(
                    snapshot_id=replay[0], partition=partition,
                    revision=replay[1], snapshot_sha256=snapshot_sha256,
                    status="complete" if replay[2] else "incomplete",
                    snapshot=replay[3], durable_replayed=True,
                )
            cursor.execute(
                """
                SELECT COALESCE(MAX(revision), 0) + 1
                  FROM commercial_margin_rollup_snapshots
                 WHERE environment = %s AND snapshot_kind = %s
                   AND scope_key = %s AND service_month = %s
                """,
                identity,
            )
            revision = int(cursor.fetchone()[0])
            snapshot_id = uuid4()
            cursor.execute(
                """
                INSERT INTO commercial_margin_rollup_snapshots (
                    snapshot_id, environment, snapshot_kind, scope_key,
                    service_month, revision, capture_partition, snapshot_sha256, complete,
                    stale_after_at, snapshot
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s,
                          statement_timestamp() + make_interval(secs => %s), %s::jsonb)
                """,
                (
                    str(snapshot_id), *identity, revision, capture_partition, snapshot_sha256,
                    complete, self._freshness_seconds, snapshot_text,
                ),
            )
            return MarginRollupSnapshotResult(
                snapshot_id=snapshot_id, partition=partition,
                revision=revision, snapshot_sha256=snapshot_sha256,
                status="complete" if complete else "incomplete", snapshot=snapshot,
            )
        finally:
            cursor.close()

    def _require_enabled(self) -> None:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_reconciliation_enabled
        ):
            raise RuntimeError("commercial margin snapshots are disabled")


__all__ = [
    "MarginSnapshotPartition",
    "MarginRollupSnapshotPartition",
    "MarginRollupSnapshotResult",
    "MarginSnapshotResult",
    "PostgresMarginSnapshotProtocol",
    "PostgresMarginRollupSnapshotProtocol",
]
