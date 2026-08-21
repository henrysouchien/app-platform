"""Durable daily gateway usage reconciliation snapshots."""

from __future__ import annotations

from datetime import date
from decimal import Decimal
import json
from typing import Literal
from uuid import UUID, uuid4

from pydantic import Field, StrictBool, StrictInt

from app_platform.commercial.flags import CommercialFlags
from app_platform.commercial.models import (
    Environment,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)


_COUNT_FINDINGS = {
    "source_missing_canonical_count": "usage.gateway_source_missing_canonical",
    "canonical_missing_source_count": "usage.gateway_canonical_missing_source",
    "digest_mismatch_count": "usage.gateway_source_digest_mismatch",
    "identity_mismatch_count": "usage.gateway_source_identity_mismatch",
    "fact_mismatch_count": "usage.gateway_source_fact_mismatch",
    "nonmatching_report_count": "usage.gateway_session_mismatch",
    "report_revision_conflict_count": "usage.gateway_report_revision_conflict",
}
_PARITY_FINDINGS = {
    ("source_event_count", "canonical_event_count"): "usage.gateway_event_count_mismatch",
    ("source_input_tokens", "canonical_input_tokens"): "usage.gateway_input_token_mismatch",
    ("source_output_tokens", "canonical_output_tokens"): "usage.gateway_output_token_mismatch",
    (
        "source_cache_read_tokens",
        "canonical_cache_read_tokens",
    ): "usage.gateway_cache_read_token_mismatch",
    (
        "source_cache_write_tokens",
        "canonical_cache_write_tokens",
    ): "usage.gateway_cache_write_token_mismatch",
    (
        "source_estimated_cost_usd",
        "canonical_estimated_cost_usd",
    ): "usage.gateway_estimated_cost_mismatch",
}
_COVERAGE_COLUMNS = (
    "source_event_count",
    "canonical_event_count",
    "source_missing_canonical_count",
    "canonical_missing_source_count",
    "digest_mismatch_count",
    "identity_mismatch_count",
    "fact_mismatch_count",
    "nonmatching_report_count",
    "report_revision_conflict_count",
    "source_input_tokens",
    "canonical_input_tokens",
    "source_output_tokens",
    "canonical_output_tokens",
    "source_cache_read_tokens",
    "canonical_cache_read_tokens",
    "source_cache_write_tokens",
    "canonical_cache_write_tokens",
    "source_estimated_cost_usd",
    "canonical_estimated_cost_usd",
    "coverage_exact",
)


class UsageReconciliationPartition(StrictCommercialModel):
    environment: Environment
    source_product: StableCode
    usage_date: date


class UsageReconciliationFinding(StrictCommercialModel):
    code: StableCode
    observed_count: StrictInt = Field(gt=0)
    expected: dict[str, int | str]
    observed: dict[str, int | str]


class UsageReconciliationRunResult(StrictCommercialModel):
    run_id: UUID
    partition: UsageReconciliationPartition
    revision: StrictInt = Field(gt=0)
    snapshot_sha256: Sha256Digest
    status: Literal["green", "drift"]
    coverage_exact: StrictBool
    findings: tuple[UsageReconciliationFinding, ...]
    durable_replayed: StrictBool = False


def _json_value(value):
    if isinstance(value, Decimal):
        normalized = value.normalize()
        return format(normalized, "f")
    return value


class PostgresUsageReconciliationRunner:
    def __init__(self, connection, *, flags: CommercialFlags) -> None:
        self._connection = connection
        self._flags = flags

    def list_partitions(
        self,
        *,
        environment: str,
        usage_date: date,
        after_source_product: str | None,
        limit: int,
    ) -> tuple[UsageReconciliationPartition, ...]:
        self._require_enabled()
        if environment != self._flags.environment:
            raise ValueError("usage reconciliation partition environment is invalid")
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT environment, source_product, usage_date
                  FROM commercial_gateway_usage_reconciliation_daily_coverage
                 WHERE environment = %s AND usage_date = %s
                   AND source_product > %s
                 ORDER BY source_product
                 LIMIT %s
                """,
                (environment, usage_date, after_source_product or "", limit),
            )
            return tuple(
                UsageReconciliationPartition(
                    environment=row[0], source_product=row[1], usage_date=row[2]
                )
                for row in cursor.fetchall()
            )
        finally:
            cursor.close()

    def reconcile(
        self, partition: UsageReconciliationPartition
    ) -> UsageReconciliationRunResult:
        self._require_enabled()
        if partition.environment != self._flags.environment:
            raise ValueError("usage reconciliation partition environment is invalid")
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(E'\\x1f', %s, %s, %s), 0))",
                (
                    partition.environment,
                    partition.source_product,
                    partition.usage_date.isoformat(),
                ),
            )
            cursor.execute(
                """
                SELECT source_event_count, canonical_event_count,
                       source_missing_canonical_count, canonical_missing_source_count,
                       digest_mismatch_count, identity_mismatch_count,
                       fact_mismatch_count, nonmatching_report_count,
                       report_revision_conflict_count, source_input_tokens,
                       canonical_input_tokens, source_output_tokens,
                       canonical_output_tokens, source_cache_read_tokens,
                       canonical_cache_read_tokens, source_cache_write_tokens,
                       canonical_cache_write_tokens, source_estimated_cost_usd,
                       canonical_estimated_cost_usd, coverage_exact
                  FROM commercial_gateway_usage_reconciliation_daily_coverage
                 WHERE environment = %s AND source_product = %s AND usage_date = %s
                """,
                (
                    partition.environment,
                    partition.source_product,
                    partition.usage_date,
                ),
            )
            row = cursor.fetchone()
            if row is None:
                raise ValueError("usage reconciliation partition has no source evidence")
            snapshot = {
                name: _json_value(value)
                for name, value in zip(_COVERAGE_COLUMNS, row, strict=True)
            }
            snapshot_sha256 = canonical_sha256(
                {
                    "schema": "commercial.usage-reconciliation-snapshot.v1",
                    "partition": partition.model_dump(mode="json"),
                    "coverage": snapshot,
                }
            )
            findings = self._findings(snapshot)
            cursor.execute(
                """
                SELECT run_id, revision, status
                  FROM commercial_usage_reconciliation_runs
                 WHERE environment = %s AND source_product = %s AND usage_date = %s
                   AND snapshot_sha256 = %s
                """,
                (
                    partition.environment,
                    partition.source_product,
                    partition.usage_date,
                    snapshot_sha256,
                ),
            )
            replay = cursor.fetchone()
            if replay is not None:
                return UsageReconciliationRunResult(
                    run_id=replay[0], partition=partition, revision=replay[1],
                    snapshot_sha256=snapshot_sha256, status=replay[2],
                    coverage_exact=bool(snapshot["coverage_exact"]), findings=findings,
                    durable_replayed=True,
                )
            cursor.execute(
                """
                SELECT COALESCE(MAX(revision), 0) + 1
                  FROM commercial_usage_reconciliation_runs
                 WHERE environment = %s AND source_product = %s AND usage_date = %s
                """,
                (
                    partition.environment,
                    partition.source_product,
                    partition.usage_date,
                ),
            )
            revision = int(cursor.fetchone()[0])
            run_id = uuid4()
            status = "green" if not findings else "drift"
            cursor.execute(
                """
                INSERT INTO commercial_usage_reconciliation_runs (
                    run_id, environment, source_product, usage_date, revision,
                    snapshot_sha256, status, finding_count, snapshot
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb)
                """,
                (
                    str(run_id), partition.environment, partition.source_product,
                    partition.usage_date, revision, snapshot_sha256, status,
                    len(findings), json.dumps(snapshot, sort_keys=True, separators=(",", ":")),
                ),
            )
            for finding in findings:
                cursor.execute(
                    """
                    INSERT INTO commercial_usage_reconciliation_findings (
                        run_id, code, observed_count, expected, observed
                    ) VALUES (%s, %s, %s, %s::jsonb, %s::jsonb)
                    """,
                    (
                        str(run_id), finding.code, finding.observed_count,
                        json.dumps(finding.expected, sort_keys=True),
                        json.dumps(finding.observed, sort_keys=True),
                    ),
                )
            return UsageReconciliationRunResult(
                run_id=run_id, partition=partition, revision=revision,
                snapshot_sha256=snapshot_sha256, status=status,
                coverage_exact=bool(snapshot["coverage_exact"]), findings=findings,
            )
        finally:
            cursor.close()

    def _require_enabled(self) -> None:
        if not (
            self._flags.commercial_control_enabled
            and self._flags.commercial_usage_ingest_enabled
            and self._flags.commercial_reconciliation_enabled
        ):
            raise RuntimeError("commercial usage reconciliation is disabled")

    @staticmethod
    def _findings(snapshot: dict) -> tuple[UsageReconciliationFinding, ...]:
        findings = []
        for field, code in _COUNT_FINDINGS.items():
            count = int(snapshot[field])
            if count:
                findings.append(UsageReconciliationFinding(
                    code=code, observed_count=count,
                    expected={field: 0}, observed={field: count},
                ))
        for (source, canonical), code in _PARITY_FINDINGS.items():
            if snapshot[source] != snapshot[canonical]:
                findings.append(UsageReconciliationFinding(
                    code=code, observed_count=1,
                    expected={canonical: snapshot[canonical]},
                    observed={source: snapshot[source]},
                ))
        return tuple(findings)


__all__ = [
    "PostgresUsageReconciliationRunner",
    "UsageReconciliationFinding",
    "UsageReconciliationPartition",
    "UsageReconciliationRunResult",
]
