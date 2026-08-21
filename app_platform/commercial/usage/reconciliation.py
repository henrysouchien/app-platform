"""Gateway usage-reconciliation evidence contract and durable ingest service."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
import hashlib
import json
import math
from typing import Annotated, Any, Literal, TypeAlias
from uuid import NAMESPACE_URL, UUID, uuid5

from agent_gateway import CapabilityBind
from pydantic import (
    Field,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)

from app_platform.commercial.flags import CommercialFlags
from app_platform.commercial.models import (
    Environment,
    NonEmptyStr,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
)
from app_platform.commercial.usage.auth import AuthenticatedUsageProducer


DecimalText = Annotated[
    StrictStr, StringConstraints(pattern=r"^[0-9]+(?:\.[0-9]+)?$")
]
SignedDecimalText = Annotated[
    StrictStr, StringConstraints(pattern=r"^-?[0-9]+(?:\.[0-9]+)?$")
]
NonNegativeInt = Annotated[StrictInt, Field(ge=0, le=2**63 - 1)]
SignedInt = Annotated[StrictInt, Field(ge=-(2**63), le=2**63 - 1)]
IdentityText255 = Annotated[
    StrictStr, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)
]
IdentityList = Annotated[tuple[IdentityText255, ...], Field(max_length=10_000)]


def _sha256_json(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class GatewayUsageReconciliationEventLineV1(StrictCommercialModel):
    source_event_id: IdentityText255
    source_payload_sha256: Sha256Digest
    event_kind: Literal["provider_call", "separate_unit"]
    durability: Literal["outbox", "emergency_spool", "lost"]
    late: StrictBool
    occurred_at: NonEmptyStr
    uncached_input_tokens: NonNegativeInt
    billable_output_tokens: NonNegativeInt
    cache_read_tokens: NonNegativeInt
    cache_write_tokens: NonNegativeInt
    reasoning_tokens_observed: NonNegativeInt | None
    provider_units: DecimalText | None
    producer_estimated_cost_usd: DecimalText | None

    @field_validator("occurred_at")
    @classmethod
    def _validate_occurred_at(cls, value: str) -> str:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (ValueError, OverflowError):
            raise ValueError("occurred_at must be an ISO-8601 timestamp") from None
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("occurred_at must be timezone-aware")
        return value


class GatewayUsageReconciliationEvidenceV1(StrictCommercialModel):
    evidence_schema_version: Literal[1]
    evidence_revision: Annotated[StrictInt, Field(ge=1)]
    supersedes_report_sha256: Sha256Digest | None
    content_sha256: Sha256Digest
    environment: Environment
    source_product: StableCode
    request_id: IdentityText255
    session_id: IdentityText255
    execution_context_id: IdentityText255
    workflow_run_id: IdentityText255
    status: Literal["match", "mismatch", "incomplete"]
    commercial_event_count: NonNegativeInt
    provider_call_event_count: NonNegativeInt
    durable_provider_call_event_count: NonNegativeInt
    separate_unit_event_count: NonNegativeInt
    expected_provider_call_count: NonNegativeInt
    provider_call_count_delta: SignedInt
    missing_event_id_count: NonNegativeInt
    missing_source_event_ids: IdentityList
    emergency_spooled_event_count: NonNegativeInt
    durability_lost_event_count: NonNegativeInt
    conflicting_event_id_count: NonNegativeInt
    conflicting_source_event_ids: IdentityList
    late_event_count: NonNegativeInt
    late_source_event_ids: IdentityList
    observed_source_event_ids: IdentityList
    summary_usage_event_ids: IdentityList
    event_lines: Annotated[
        tuple[GatewayUsageReconciliationEventLineV1, ...], Field(max_length=10_000)
    ]
    commercial_input_tokens: NonNegativeInt
    summary_input_tokens: NonNegativeInt
    input_token_delta: SignedInt
    commercial_output_tokens: NonNegativeInt
    summary_output_tokens: NonNegativeInt
    output_token_delta: SignedInt
    commercial_cache_read_tokens: NonNegativeInt
    summary_cache_read_tokens: NonNegativeInt
    cache_read_token_delta: SignedInt
    commercial_cache_write_tokens: NonNegativeInt
    summary_cache_write_tokens: NonNegativeInt
    cache_write_token_delta: SignedInt
    reasoning_tokens_observed: NonNegativeInt
    provider_units: DecimalText
    commercial_producer_estimate_usd: DecimalText
    summary_estimate_usd: DecimalText
    estimate_delta_usd: SignedDecimalText
    drain_complete: StrictBool
    in_flight_task_count: NonNegativeInt
    summary_started_at: StrictFloat
    summary_ended_at: StrictFloat
    summary_emitted_as_cost_event: StrictBool

    def content_document(self) -> dict[str, Any]:
        document = self.model_dump(mode="json")
        for field in (
            "evidence_schema_version",
            "evidence_revision",
            "supersedes_report_sha256",
            "content_sha256",
        ):
            document.pop(field)
        return document

    @property
    def report_sha256(self) -> str:
        return _sha256_json(self.model_dump(mode="json"))

    @model_validator(mode="after")
    def _validate_evidence(self) -> "GatewayUsageReconciliationEvidenceV1":
        if self.summary_emitted_as_cost_event is not False:
            raise ValueError("session summary cannot be emitted as a cost event")
        if (self.evidence_revision == 1) != (self.supersedes_report_sha256 is None):
            raise ValueError("evidence revision predecessor is inconsistent")
        if not math.isfinite(self.summary_started_at) or not math.isfinite(
            self.summary_ended_at
        ) or not 0 <= self.summary_started_at <= self.summary_ended_at <= 32_503_680_000:
            raise ValueError("summary timestamps must be finite and ordered")
        for values in (
            self.missing_source_event_ids,
            self.conflicting_source_event_ids,
            self.late_source_event_ids,
            self.observed_source_event_ids,
            self.summary_usage_event_ids,
        ):
            if tuple(sorted(set(values))) != values:
                raise ValueError("reconciliation identity lists must be sorted and unique")
        line_ids = tuple(line.source_event_id for line in self.event_lines)
        if tuple(sorted(set(line_ids))) != line_ids or line_ids != self.observed_source_event_ids:
            raise ValueError("event lines must exactly match the observed source manifest")
        provider_lines = tuple(
            line for line in self.event_lines if line.event_kind == "provider_call"
        )
        durable_provider_ids = {
            line.source_event_id for line in provider_lines if line.durability != "lost"
        }
        summary_ids = set(self.summary_usage_event_ids)
        missing_ids = tuple(sorted(summary_ids - durable_provider_ids))
        late_ids = tuple(sorted(line.source_event_id for line in self.event_lines if line.late))
        expected_missing_count = max(
            len(missing_ids),
            self.expected_provider_call_count - len(durable_provider_ids),
            0,
        )

        def integer_total(field: str) -> int:
            return sum(int(getattr(line, field) or 0) for line in self.event_lines)

        def decimal_total(field: str) -> Decimal:
            return sum(
                (
                    Decimal(str(getattr(line, field)))
                    for line in self.event_lines
                    if getattr(line, field) is not None
                ),
                Decimal("0"),
            )

        commercial_estimate = decimal_total("producer_estimated_cost_usd")
        estimate_delta = commercial_estimate - Decimal(self.summary_estimate_usd)
        expected_values = {
            "commercial_event_count": len(self.event_lines),
            "provider_call_event_count": len(provider_lines),
            "durable_provider_call_event_count": len(durable_provider_ids),
            "separate_unit_event_count": sum(
                line.event_kind == "separate_unit" for line in self.event_lines
            ),
            "provider_call_count_delta": (
                len(provider_lines) - self.expected_provider_call_count
            ),
            "missing_event_id_count": expected_missing_count,
            "emergency_spooled_event_count": sum(
                line.durability == "emergency_spool" for line in self.event_lines
            ),
            "durability_lost_event_count": sum(
                line.durability == "lost" for line in self.event_lines
            ),
            "conflicting_event_id_count": len(self.conflicting_source_event_ids),
            "late_event_count": len(late_ids),
            "commercial_input_tokens": integer_total("uncached_input_tokens"),
            "commercial_output_tokens": integer_total("billable_output_tokens"),
            "commercial_cache_read_tokens": integer_total("cache_read_tokens"),
            "commercial_cache_write_tokens": integer_total("cache_write_tokens"),
            "reasoning_tokens_observed": integer_total("reasoning_tokens_observed"),
        }
        expected_values.update({
            "input_token_delta": (
                expected_values["commercial_input_tokens"] - self.summary_input_tokens
            ),
            "output_token_delta": (
                expected_values["commercial_output_tokens"] - self.summary_output_tokens
            ),
            "cache_read_token_delta": (
                expected_values["commercial_cache_read_tokens"]
                - self.summary_cache_read_tokens
            ),
            "cache_write_token_delta": (
                expected_values["commercial_cache_write_tokens"]
                - self.summary_cache_write_tokens
            ),
        })
        if (
            self.missing_source_event_ids != missing_ids
            or self.late_source_event_ids != late_ids
            or not set(self.conflicting_source_event_ids).issubset(line_ids)
            or any(getattr(self, name) != value for name, value in expected_values.items())
            or Decimal(self.provider_units) != decimal_total("provider_units")
            or Decimal(self.commercial_producer_estimate_usd) != commercial_estimate
            or Decimal(self.estimate_delta_usd) != estimate_delta
        ):
            raise ValueError("reconciliation derived evidence is inconsistent")
        is_match = (
            not any(
                getattr(self, field)
                for field in (
                    "input_token_delta",
                    "output_token_delta",
                    "cache_read_token_delta",
                    "cache_write_token_delta",
                    "missing_event_id_count",
                    "provider_call_count_delta",
                    "conflicting_event_id_count",
                    "durability_lost_event_count",
                    "late_event_count",
                )
            )
            and abs(estimate_delta) <= Decimal("0.00000001")
            and durable_provider_ids == summary_ids
        )
        expected_status = (
            "incomplete"
            if not self.drain_complete or self.in_flight_task_count
            else "match" if is_match else "mismatch"
        )
        if self.status != expected_status:
            raise ValueError("reconciliation status is inconsistent")
        if self.content_sha256 != _sha256_json(self.content_document()):
            raise ValueError("reconciliation content digest is invalid")
        return self


class GatewayUsageReconciliationEnvelopeV1(StrictCommercialModel):
    report_sha256: Sha256Digest
    evidence: GatewayUsageReconciliationEvidenceV1

    @model_validator(mode="after")
    def _validate_report_digest(self) -> "GatewayUsageReconciliationEnvelopeV1":
        if self.report_sha256 != self.evidence.report_sha256:
            raise ValueError("reconciliation report digest is invalid")
        return self


class GatewayUsageReconciliationEventLineV2(
    GatewayUsageReconciliationEventLineV1
):
    source_schema_version: Literal[2]
    workflow_attempt_group_id: UUID
    workflow_attempt_number: Annotated[StrictInt, Field(gt=0)]
    retry_of_workflow_run_id: UUID | None
    workflow_attempt_kind: Literal["initial", "user_retry", "automatic_retry"]
    work_authorization_id: UUID


class GatewayUsageReconciliationEvidenceV2(
    GatewayUsageReconciliationEvidenceV1
):
    evidence_schema_version: Literal[2]
    execution_context_id: UUID
    workflow_run_id: UUID
    workflow_attempt_group_id: UUID
    workflow_attempt_number: Annotated[StrictInt, Field(gt=0)]
    retry_of_workflow_run_id: UUID | None
    workflow_attempt_kind: Literal["initial", "user_retry", "automatic_retry"]
    work_authorization_id: UUID
    event_lines: Annotated[
        tuple[GatewayUsageReconciliationEventLineV2, ...], Field(max_length=10_000)
    ]

    @model_validator(mode="after")
    def _validate_attempt_lineage(self) -> "GatewayUsageReconciliationEvidenceV2":
        attempt_identity = (
            self.workflow_attempt_group_id,
            self.workflow_attempt_number,
            self.retry_of_workflow_run_id,
            self.workflow_attempt_kind,
            self.work_authorization_id,
        )
        if any(
            (
                line.workflow_attempt_group_id,
                line.workflow_attempt_number,
                line.retry_of_workflow_run_id,
                line.workflow_attempt_kind,
                line.work_authorization_id,
            )
            != attempt_identity
            for line in self.event_lines
        ):
            raise ValueError("reconciliation attempt lineage is inconsistent")
        is_initial = self.workflow_attempt_kind == "initial"
        if (
            is_initial
            and (
                self.workflow_attempt_number != 1
                or self.retry_of_workflow_run_id is not None
                or self.workflow_attempt_group_id != self.workflow_run_id
            )
        ) or (
            not is_initial
            and (
                self.workflow_attempt_number <= 1
                or self.retry_of_workflow_run_id is None
                or self.workflow_attempt_group_id == self.workflow_run_id
                or self.retry_of_workflow_run_id == self.workflow_run_id
            )
        ):
            raise ValueError("reconciliation attempt lineage shape is invalid")
        return self


class GatewayUsageReconciliationEnvelopeV2(StrictCommercialModel):
    report_sha256: Sha256Digest
    evidence: GatewayUsageReconciliationEvidenceV2

    @model_validator(mode="after")
    def _validate_report_digest(self) -> "GatewayUsageReconciliationEnvelopeV2":
        if self.report_sha256 != self.evidence.report_sha256:
            raise ValueError("reconciliation report digest is invalid")
        return self


class GatewayUsageReconciliationEventLineV3(
    GatewayUsageReconciliationEventLineV1
):
    source_schema_version: Literal[3]
    workflow_attempt_group_id: UUID | None
    workflow_attempt_number: Annotated[StrictInt, Field(gt=0)] | None
    retry_of_workflow_run_id: UUID | None
    workflow_attempt_kind: (
        Literal["initial", "user_retry", "automatic_retry"] | None
    )
    work_authorization_id: UUID | None
    capability_bind: CapabilityBind
    provider_reported_model: NonEmptyStr | None
    provider: StableCode
    model: NonEmptyStr
    capability_id: NonEmptyStr

    @model_validator(mode="after")
    def _validate_model_identity(self) -> "GatewayUsageReconciliationEventLineV3":
        bind = self.capability_bind
        if (
            self.provider != bind.provider
            or self.model != bind.upstream_model
            or self.capability_id != bind.capability_id
        ):
            raise ValueError(
                "reconciliation model projections differ from capability bind"
            )
        return self


class GatewayUsageReconciliationEvidenceV3(
    GatewayUsageReconciliationEvidenceV1
):
    evidence_schema_version: Literal[3]
    source_usage_schema_version: Literal[3]
    execution_context_id: NonEmptyStr
    workflow_run_id: NonEmptyStr
    workflow_attempt_group_id: UUID | None
    workflow_attempt_number: Annotated[StrictInt, Field(gt=0)] | None
    retry_of_workflow_run_id: UUID | None
    workflow_attempt_kind: (
        Literal["initial", "user_retry", "automatic_retry"] | None
    )
    work_authorization_id: UUID | None
    event_lines: Annotated[
        tuple[GatewayUsageReconciliationEventLineV3, ...], Field(max_length=10_000)
    ]

    @model_validator(mode="after")
    def _validate_v3_lineage(self) -> "GatewayUsageReconciliationEvidenceV3":
        attempt_identity = (
            self.workflow_attempt_group_id,
            self.workflow_attempt_number,
            self.retry_of_workflow_run_id,
            self.workflow_attempt_kind,
            self.work_authorization_id,
        )
        if any(
            (
                line.workflow_attempt_group_id,
                line.workflow_attempt_number,
                line.retry_of_workflow_run_id,
                line.workflow_attempt_kind,
                line.work_authorization_id,
            )
            != attempt_identity
            for line in self.event_lines
        ):
            raise ValueError("reconciliation V3 attempt lineage is inconsistent")
        if all(value is None for value in attempt_identity):
            return self
        if (
            self.workflow_attempt_group_id is None
            or self.workflow_attempt_number is None
            or self.workflow_attempt_kind is None
        ):
            raise ValueError(
                "reconciliation V3 attempt lineage must be complete or all-null"
            )
        try:
            UUID(str(self.execution_context_id))
            workflow_run_id = UUID(str(self.workflow_run_id))
        except (TypeError, ValueError):
            raise ValueError(
                "reconciliation V3 attempt mode requires UUID lineage"
            ) from None
        is_initial = self.workflow_attempt_kind == "initial"
        if (
            is_initial
            and (
                self.workflow_attempt_number != 1
                or self.retry_of_workflow_run_id is not None
                or self.workflow_attempt_group_id != workflow_run_id
            )
        ) or (
            not is_initial
            and (
                self.workflow_attempt_number <= 1
                or self.retry_of_workflow_run_id is None
                or self.workflow_attempt_group_id == workflow_run_id
                or self.retry_of_workflow_run_id == workflow_run_id
            )
        ):
            raise ValueError("reconciliation V3 attempt lineage shape is invalid")
        if self.source_product == "hank-agent-gateway":
            if self.work_authorization_id is None:
                raise ValueError(
                    "gateway reconciliation V3 attempt requires work authorization"
                )
        elif self.work_authorization_id is not None:
            raise ValueError(
                "direct reconciliation V3 cannot assert gateway work authorization"
            )
        return self


class GatewayUsageReconciliationEnvelopeV3(StrictCommercialModel):
    report_sha256: Sha256Digest
    evidence: GatewayUsageReconciliationEvidenceV3

    @model_validator(mode="after")
    def _validate_report_digest(self) -> "GatewayUsageReconciliationEnvelopeV3":
        if self.report_sha256 != self.evidence.report_sha256:
            raise ValueError("reconciliation report digest is invalid")
        return self


GatewayUsageReconciliationEnvelope: TypeAlias = (
    GatewayUsageReconciliationEnvelopeV1
    | GatewayUsageReconciliationEnvelopeV2
    | GatewayUsageReconciliationEnvelopeV3
)


def validate_gateway_usage_reconciliation_envelope(
    value: dict[str, Any],
) -> GatewayUsageReconciliationEnvelope:
    evidence = value.get("evidence")
    version = evidence.get("evidence_schema_version") if isinstance(evidence, dict) else None
    if version == 1:
        return GatewayUsageReconciliationEnvelopeV1.model_validate(value)
    if version == 2:
        return GatewayUsageReconciliationEnvelopeV2.model_validate(value)
    if version == 3:
        return GatewayUsageReconciliationEnvelopeV3.model_validate(value)
    raise ValueError("reconciliation evidence version is unsupported")


class GatewayUsageReconciliationAcceptanceV1(StrictCommercialModel):
    schema_version: Literal[1] = 1
    environment: Environment
    source_product: StableCode
    request_id: IdentityText255
    session_id: IdentityText255
    evidence_revision: Annotated[StrictInt, Field(ge=1)]
    report_sha256: Sha256Digest
    status: Literal["accepted", "duplicate", "conflict", "rejected_retryable"]
    reason_code: StableCode | None = None

    @model_validator(mode="after")
    def _validate_reason(self) -> "GatewayUsageReconciliationAcceptanceV1":
        if (self.status in {"conflict", "rejected_retryable"}) != (
            self.reason_code is not None
        ):
            raise ValueError("reconciliation acceptance reason is inconsistent")
        return self


class PostgresGatewayUsageReconciliationIngestService:
    def __init__(self, connection_factory, *, flags: CommercialFlags) -> None:
        self._connection_factory = connection_factory
        self._flags = flags

    def ingest_batch(
        self,
        reports: list[dict[str, Any]],
        *,
        producer: AuthenticatedUsageProducer,
    ) -> tuple[GatewayUsageReconciliationAcceptanceV1, ...]:
        if not self._flags.commercial_reconciliation_enabled:
            raise RuntimeError("commercial usage reconciliation ingest is disabled")
        envelopes = tuple(
            validate_gateway_usage_reconciliation_envelope(report)
            for report in reports
        )
        for envelope in envelopes:
            evidence = envelope.evidence
            if (
                evidence.environment != producer.environment
                or evidence.source_product not in producer.source_products
            ):
                raise ValueError("reconciliation producer scope is invalid")
        connection = self._connection_factory()
        try:
            results = tuple(
                self._ingest_one(connection, envelope, producer=producer)
                for envelope in envelopes
            )
            connection.commit()
            return results
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _ingest_one(
        connection,
        envelope: GatewayUsageReconciliationEnvelope,
        *,
        producer: AuthenticatedUsageProducer,
    ) -> GatewayUsageReconciliationAcceptanceV1:
        evidence = envelope.evidence
        identity = (
            evidence.environment,
            evidence.source_product,
            evidence.request_id,
            evidence.session_id,
        )
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(concat_ws(E'\\x1f', %s, %s, %s, %s), 0))",
                identity,
            )
            cursor.execute(
                """
                SELECT report_id
                  FROM commercial_gateway_usage_reconciliation_reports
                 WHERE environment = %s AND source_product = %s
                   AND request_id = %s AND session_id = %s
                   AND report_sha256 = %s
                """,
                (*identity, envelope.report_sha256),
            )
            replay = cursor.fetchone()
            if replay is not None:
                return GatewayUsageReconciliationAcceptanceV1(
                    environment=evidence.environment,
                    source_product=evidence.source_product,
                    request_id=evidence.request_id,
                    session_id=evidence.session_id,
                    evidence_revision=evidence.evidence_revision,
                    report_sha256=envelope.report_sha256,
                    status="duplicate",
                )
            cursor.execute(
                """
                SELECT report_id, evidence_revision, report_sha256
                  FROM commercial_gateway_usage_reconciliation_reports
                 WHERE environment = %s AND source_product = %s
                   AND request_id = %s AND session_id = %s
                 ORDER BY evidence_revision DESC LIMIT 1
                 FOR UPDATE
                """,
                identity,
            )
            current = cursor.fetchone()
            if current is not None and current[1] >= evidence.evidence_revision:
                status = "conflict"
                reason_code = "usage_reconciliation.revision_conflict"
                cursor.execute(
                    """
                    SELECT report_id, report_sha256
                      FROM commercial_gateway_usage_reconciliation_reports
                     WHERE environment = %s AND source_product = %s
                       AND request_id = %s AND session_id = %s
                       AND evidence_revision = %s
                    """,
                    (*identity, evidence.evidence_revision),
                )
                existing = cursor.fetchone()
                if existing is None:
                    raise RuntimeError(
                        "commercial reconciliation revision history is not linear"
                    )
                cursor.execute(
                    """
                    INSERT INTO commercial_gateway_usage_reconciliation_conflicts (
                        conflict_id, environment, source_product, request_id, session_id,
                        evidence_revision, report_sha256, existing_report_id,
                        existing_report_sha256, payload, producer_key_id, request_body_sha256
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb, %s, %s)
                    ON CONFLICT (environment, source_product, request_id, session_id,
                                 evidence_revision, report_sha256) DO NOTHING
                    """,
                    (
                        str(uuid5(
                            NAMESPACE_URL,
                            "reconciliation-conflict:" + envelope.report_sha256,
                        )),
                        *identity,
                        evidence.evidence_revision,
                        envelope.report_sha256,
                        existing[0],
                        existing[1],
                        json.dumps(evidence.model_dump(mode="json"), allow_nan=False),
                        producer.key_id,
                        producer.body_sha256,
                    ),
                )
            elif (
                evidence.evidence_revision != (1 if current is None else current[1] + 1)
                or evidence.supersedes_report_sha256
                != (None if current is None else current[2])
            ):
                status = "rejected_retryable"
                reason_code = "usage_reconciliation.predecessor_missing"
            else:
                report_id = uuid5(
                    NAMESPACE_URL,
                    "commercial-usage-reconciliation:"
                    f"{evidence.request_id}:{evidence.session_id}:{envelope.report_sha256}",
                )
                report_values = (
                    str(report_id),
                    *identity,
                    evidence.evidence_revision,
                    evidence.supersedes_report_sha256,
                    evidence.content_sha256,
                    envelope.report_sha256,
                    evidence.status,
                    str(evidence.execution_context_id),
                    str(evidence.workflow_run_id),
                    json.dumps(evidence.model_dump(mode="json"), allow_nan=False),
                    producer.key_id,
                    producer.body_sha256,
                )
                if isinstance(evidence, GatewayUsageReconciliationEvidenceV3):
                    cursor.execute(
                        """
                        INSERT INTO commercial_gateway_usage_reconciliation_reports (
                            report_id, environment, source_product, request_id,
                            session_id, evidence_revision,
                            supersedes_report_sha256, content_sha256, report_sha256,
                            status, execution_context_id, workflow_run_id, payload,
                            producer_key_id, request_body_sha256,
                            evidence_schema_version, source_usage_schema_version,
                            workflow_attempt_group_id, workflow_attempt_number,
                            retry_of_workflow_run_id, workflow_attempt_kind,
                            work_authorization_id
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s::jsonb, %s, %s, 3, 3, %s, %s, %s, %s, %s
                        )
                        """,
                        (
                            *report_values,
                            str(evidence.workflow_attempt_group_id)
                            if evidence.workflow_attempt_group_id is not None
                            else None,
                            evidence.workflow_attempt_number,
                            str(evidence.retry_of_workflow_run_id)
                            if evidence.retry_of_workflow_run_id is not None else None,
                            evidence.workflow_attempt_kind,
                            str(evidence.work_authorization_id)
                            if evidence.work_authorization_id is not None else None,
                        ),
                    )
                    cursor.executemany(
                        """
                        INSERT INTO commercial_gateway_usage_reconciliation_lines (
                            report_id, source_event_id, source_payload_sha256,
                            event_kind, durability, late, occurred_at,
                            uncached_input_tokens, billable_output_tokens,
                            cache_read_tokens, cache_write_tokens,
                            reasoning_tokens_observed, provider_units,
                            producer_estimated_cost_usd, source_schema_version,
                            workflow_attempt_group_id, workflow_attempt_number,
                            retry_of_workflow_run_id, workflow_attempt_kind,
                            work_authorization_id, capability_bind,
                            provider_reported_model, provider, model, capability_id
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s::timestamptz, %s, %s,
                            %s, %s, %s, %s, %s, 3, %s, %s, %s, %s, %s,
                            %s::jsonb, %s, %s, %s, %s
                        )
                        """,
                        [
                            (
                                str(report_id), line.source_event_id,
                                line.source_payload_sha256, line.event_kind,
                                line.durability, line.late, line.occurred_at,
                                line.uncached_input_tokens,
                                line.billable_output_tokens,
                                line.cache_read_tokens, line.cache_write_tokens,
                                line.reasoning_tokens_observed,
                                line.provider_units,
                                line.producer_estimated_cost_usd,
                                str(line.workflow_attempt_group_id)
                                if line.workflow_attempt_group_id is not None else None,
                                line.workflow_attempt_number,
                                str(line.retry_of_workflow_run_id)
                                if line.retry_of_workflow_run_id is not None else None,
                                line.workflow_attempt_kind,
                                str(line.work_authorization_id)
                                if line.work_authorization_id is not None else None,
                                json.dumps(
                                    line.capability_bind.model_dump(mode="json")
                                ),
                                line.provider_reported_model,
                                line.provider,
                                line.model,
                                line.capability_id,
                            )
                            for line in evidence.event_lines
                        ],
                    )
                elif isinstance(evidence, GatewayUsageReconciliationEvidenceV2):
                    cursor.execute(
                        """
                        INSERT INTO commercial_gateway_usage_reconciliation_reports (
                            report_id, environment, source_product, request_id,
                            session_id, evidence_revision,
                            supersedes_report_sha256, content_sha256, report_sha256,
                            status, execution_context_id, workflow_run_id, payload,
                            producer_key_id, request_body_sha256,
                            evidence_schema_version, workflow_attempt_group_id,
                            workflow_attempt_number, retry_of_workflow_run_id,
                            workflow_attempt_kind, work_authorization_id
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s::jsonb, %s, %s, 2, %s, %s, %s, %s, %s
                        )
                        """,
                        (
                            *report_values,
                            str(evidence.workflow_attempt_group_id),
                            evidence.workflow_attempt_number,
                            str(evidence.retry_of_workflow_run_id)
                            if evidence.retry_of_workflow_run_id is not None else None,
                            evidence.workflow_attempt_kind,
                            str(evidence.work_authorization_id),
                        ),
                    )
                    cursor.executemany(
                        """
                        INSERT INTO commercial_gateway_usage_reconciliation_lines (
                            report_id, source_event_id, source_payload_sha256,
                            event_kind, durability, late, occurred_at,
                            uncached_input_tokens, billable_output_tokens,
                            cache_read_tokens, cache_write_tokens,
                            reasoning_tokens_observed, provider_units,
                            producer_estimated_cost_usd, source_schema_version,
                            workflow_attempt_group_id, workflow_attempt_number,
                            retry_of_workflow_run_id, workflow_attempt_kind,
                            work_authorization_id
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s::timestamptz, %s, %s,
                            %s, %s, %s, %s, %s, 2, %s, %s, %s, %s, %s
                        )
                        """,
                        [
                            (
                                str(report_id), line.source_event_id,
                                line.source_payload_sha256, line.event_kind,
                                line.durability, line.late, line.occurred_at,
                                line.uncached_input_tokens,
                                line.billable_output_tokens,
                                line.cache_read_tokens, line.cache_write_tokens,
                                line.reasoning_tokens_observed,
                                line.provider_units,
                                line.producer_estimated_cost_usd,
                                str(line.workflow_attempt_group_id),
                                line.workflow_attempt_number,
                                str(line.retry_of_workflow_run_id)
                                if line.retry_of_workflow_run_id is not None else None,
                                line.workflow_attempt_kind,
                                str(line.work_authorization_id),
                            )
                            for line in evidence.event_lines
                        ],
                    )
                else:
                    cursor.execute(
                        """
                        INSERT INTO commercial_gateway_usage_reconciliation_reports (
                            report_id, environment, source_product, request_id,
                            session_id, evidence_revision,
                            supersedes_report_sha256, content_sha256, report_sha256,
                            status, execution_context_id, workflow_run_id, payload,
                            producer_key_id, request_body_sha256
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                            %s::jsonb, %s, %s
                        )
                        """,
                        report_values,
                    )
                    cursor.executemany(
                        """
                        INSERT INTO commercial_gateway_usage_reconciliation_lines (
                            report_id, source_event_id, source_payload_sha256,
                            event_kind, durability, late, occurred_at,
                            uncached_input_tokens, billable_output_tokens,
                            cache_read_tokens, cache_write_tokens,
                            reasoning_tokens_observed, provider_units,
                            producer_estimated_cost_usd
                        ) VALUES (
                            %s, %s, %s, %s, %s, %s, %s::timestamptz, %s, %s,
                            %s, %s, %s, %s, %s
                        )
                        """,
                        [
                            (
                                str(report_id), line.source_event_id,
                                line.source_payload_sha256, line.event_kind,
                                line.durability, line.late, line.occurred_at,
                                line.uncached_input_tokens,
                                line.billable_output_tokens,
                                line.cache_read_tokens, line.cache_write_tokens,
                                line.reasoning_tokens_observed,
                                line.provider_units,
                                line.producer_estimated_cost_usd,
                            )
                            for line in evidence.event_lines
                        ],
                    )
                status = "accepted"
                reason_code = None
        return GatewayUsageReconciliationAcceptanceV1(
            environment=evidence.environment,
            source_product=evidence.source_product,
            request_id=evidence.request_id,
            session_id=evidence.session_id,
            evidence_revision=evidence.evidence_revision,
            report_sha256=envelope.report_sha256,
            status=status,
            reason_code=reason_code,
        )


__all__ = [
    "GatewayUsageReconciliationEnvelope",
    "GatewayUsageReconciliationAcceptanceV1",
    "GatewayUsageReconciliationEnvelopeV1",
    "GatewayUsageReconciliationEnvelopeV2",
    "GatewayUsageReconciliationEnvelopeV3",
    "GatewayUsageReconciliationEvidenceV1",
    "GatewayUsageReconciliationEvidenceV2",
    "GatewayUsageReconciliationEvidenceV3",
    "GatewayUsageReconciliationEventLineV1",
    "GatewayUsageReconciliationEventLineV2",
    "GatewayUsageReconciliationEventLineV3",
    "PostgresGatewayUsageReconciliationIngestService",
    "validate_gateway_usage_reconciliation_envelope",
]
