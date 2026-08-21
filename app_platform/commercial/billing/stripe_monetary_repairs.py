"""Approved, attested repair of one missing Stripe processor-fee fact."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
import hmac
import json
import secrets
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import Field, PrivateAttr, StrictBool, model_validator

from ..audit import CommercialAuditEvent, insert_commercial_audit_event
from ..authority import CommercialRole, record_change_execution
from ..authority_store import PostgresChangeRequestStore, load_named_operator
from ..flags import CommercialFlags
from ..models import Sha256Digest, StrictCommercialModel, canonical_sha256
from ..processor_fee_allocation import (
    ProcessorFeeAllocationCommand,
    ProcessorFeeAllocationService,
)
from .stripe_reconciliation import (
    StripeMonetaryObservation,
    StripeMonetaryReconciliationExpectation,
    StripeMoneyMovementObservation,
    StripeReconciliationAuthority,
    load_stripe_reconciliation_authority,
)


_PROCESS_ATTESTATION_KEY = secrets.token_bytes(32)
_PROCESS_ATTESTATION_CAPABILITY = object()


class StripeProcessorFeeRepairError(RuntimeError):
    """Approved processor-fee repair authority is absent, stale, or unsafe."""


class StripeProcessorFeeRepairPreparation(StrictCommercialModel):
    request_id: UUID
    intent_id: UUID
    source_finding_id: UUID
    authority_sha256: Sha256Digest
    environment: Literal["dev", "staging", "prod"]
    billing_environment: Literal["test", "live"]
    commercial_account_id: int = Field(gt=0)
    external_object_type: Literal["balance_transaction"]
    external_object_id: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{4,254}$")
    movement_kind: Literal["processor_fee"]
    expected_remote_digest: Sha256Digest
    monetary_expectation: StripeMonetaryReconciliationExpectation
    subscription_ids_by_agreement: dict[UUID, str]


class StripeProcessorFeeRepairObservation(StrictCommercialModel):
    provider_observation: StripeMonetaryObservation
    movement: StripeMoneyMovementObservation
    database_attestation_document: dict
    database_attestation_key_id: UUID
    database_attestation_sha256: Sha256Digest
    _process_attestation: str | None = PrivateAttr(default=None)

    @classmethod
    def _from_provider(
        cls,
        *,
        provider_observation: StripeMonetaryObservation,
        movement: StripeMoneyMovementObservation,
        database_attestation_document: dict,
        database_attestation_key_id: UUID,
        database_attestation_sha256: str,
        capability: object,
    ) -> "StripeProcessorFeeRepairObservation":
        if capability is not _PROCESS_ATTESTATION_CAPABILITY:
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair provider authority is invalid"
            )
        result = cls(
            provider_observation=provider_observation,
            movement=movement,
            database_attestation_document=database_attestation_document,
            database_attestation_key_id=database_attestation_key_id,
            database_attestation_sha256=database_attestation_sha256,
        )
        result._process_attestation = hmac.digest(
            _PROCESS_ATTESTATION_KEY, result._attestation_body(), "sha256"
        ).hex()
        return result

    def has_provider_attestation(self) -> bool:
        expected = hmac.digest(
            _PROCESS_ATTESTATION_KEY, self._attestation_body(), "sha256"
        ).hex()
        return self._process_attestation is not None and hmac.compare_digest(
            self._process_attestation, expected
        )

    def _attestation_body(self) -> bytes:
        movement_key = (
            f"{self.movement.external_object_type}:"
            f"{self.movement.external_object_id}:{self.movement.movement_kind}"
        )
        return (
            f"{self.provider_observation.content_sha256}|{movement_key}|"
            f"{self.provider_observation.observed_at.isoformat()}"
        ).encode("ascii")


class StripeProcessorFeeRepairResult(StrictCommercialModel):
    execution_id: UUID
    request_id: UUID
    intent_id: UUID
    commercial_account_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    document_id: int = Field(gt=0)
    money_movement_id: int = Field(gt=0)
    processor_fee_allocation_run_id: int | None = Field(default=None, gt=0)
    signed_amount_cents: int
    audit_event_id: UUID
    durable_replayed: StrictBool = False

    @model_validator(mode="after")
    def _allocation_matches_sign(self) -> "StripeProcessorFeeRepairResult":
        if self.signed_amount_cents == 0 or (
            (self.signed_amount_cents < 0)
            != (self.processor_fee_allocation_run_id is not None)
        ):
            raise ValueError(
                "processor fees require allocation and fee credits forbid allocation"
            )
        return self


class StripeProcessorFeeRepairProvider:
    """Fetch complete provider money evidence with no mutation transaction open."""

    def __init__(
        self,
        provider: Any,
        *,
        connection: Any,
        attestation_connection: Any,
    ) -> None:
        self._provider = provider
        self._connection = connection
        self._attestation_connection = attestation_connection

    def observe(
        self, preparation: StripeProcessorFeeRepairPreparation
    ) -> StripeProcessorFeeRepairObservation:
        self._require_idle_connections()
        provider_observation = self._provider.observe(
            preparation.monetary_expectation,
            subscription_ids_by_agreement=preparation.subscription_ids_by_agreement,
        )
        if (
            provider_observation.evidence_completeness != "complete"
            or not provider_observation.has_provider_attestation()
            or provider_observation.environment != preparation.billing_environment
            or provider_observation.commercial_account_public_id
            != preparation.monetary_expectation.commercial_account_public_id
        ):
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair provider evidence is invalid"
            )
        matching = tuple(
            movement
            for movement in provider_observation.movements
            if (
                movement.external_object_type == preparation.external_object_type
                and movement.external_object_id == preparation.external_object_id
                and movement.movement_kind == preparation.movement_kind
            )
        )
        if len(matching) != 1:
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair provider movement is unavailable"
            )
        movement = matching[0]
        if _movement_remote_digest(movement) != preparation.expected_remote_digest:
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair provider movement changed"
            )
        provider_json = provider_observation.model_dump(mode="json")
        document = {
            "schema": "commercial.stripe-processor-fee-repair-attestation.v1",
            "request_id": str(preparation.request_id),
            "intent_id": str(preparation.intent_id),
            "source_finding_id": str(preparation.source_finding_id),
            "authority_sha256": preparation.authority_sha256,
            "runtime_environment": preparation.environment,
            "billing_environment": preparation.billing_environment,
            "commercial_account_id": preparation.commercial_account_id,
            "external_object_type": movement.external_object_type,
            "external_object_id": movement.external_object_id,
            "movement_kind": movement.movement_kind,
            "observation_content_sha256": provider_observation.content_sha256,
            "observed_at": provider_json["observed_at"],
        }
        cursor = self._attestation_connection.cursor()
        try:
            cursor.execute(
                """SELECT attestation_document, key_id, attestation_sha256
                     FROM commercial_attest_stripe_repair_snapshot(
                         %s::jsonb, %s::jsonb
                     )""",
                (json.dumps(document, sort_keys=True), json.dumps(provider_json)),
            )
            attestation = cursor.fetchone()
        finally:
            cursor.close()
        if attestation is None:
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair database attestation is unavailable"
            )
        return StripeProcessorFeeRepairObservation._from_provider(
            provider_observation=provider_observation,
            movement=movement,
            database_attestation_document=attestation[0],
            database_attestation_key_id=UUID(str(attestation[1])),
            database_attestation_sha256=str(attestation[2]),
            capability=_PROCESS_ATTESTATION_CAPABILITY,
        )

    def _require_idle_connections(self) -> None:
        status = getattr(self._connection, "get_transaction_status", None)
        attestation_status = getattr(
            self._attestation_connection, "get_transaction_status", None
        )
        if status is None or status() != 0:
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair provider I/O requires an idle database connection"
            )
        if (
            attestation_status is None
            or attestation_status() != 0
            or not bool(getattr(self._attestation_connection, "autocommit", False))
        ):
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair attestation requires an idle autocommit connection"
            )


def _movement_remote_digest(movement: StripeMoneyMovementObservation) -> str:
    return canonical_sha256(
        {
            "external_invoice_id": movement.external_invoice_id,
            "signed_amount_cents": movement.signed_amount_cents,
            "currency": movement.currency,
            "occurred_at": movement.occurred_at,
        }
    )


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class StripeProcessorFeeRepairService:
    """Execute one approved missing processor-fee repair exactly once."""

    def __init__(self, connection: Any, *, flags: CommercialFlags, clock=None) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if not (
            flags.commercial_control_enabled
            and flags.commercial_reconciliation_enabled
            and flags.stripe_billing_enabled
        ):
            raise StripeProcessorFeeRepairError("Stripe fee repair is disabled")

    @_atomic
    def load_replay_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        step_up_event_id: UUID,
        request_id: UUID,
    ) -> StripeProcessorFeeRepairResult | None:
        """Return a prior durable execution after rechecking operator authority."""

        self._require_operator(operator_user_id, runtime_environment, step_up_event_id)
        result = self._load_execution(
            request_id,
            environment=runtime_environment,
            billing_environment=self._billing_environment(),
        )
        return (
            result.model_copy(update={"durable_replayed": True})
            if result is not None
            else None
        )

    @_atomic
    def prepare_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        step_up_event_id: UUID,
        request_id: UUID,
    ) -> StripeProcessorFeeRepairPreparation:
        self._require_operator(operator_user_id, runtime_environment, step_up_event_id)
        row = self._load_authority(request_id, runtime_environment, lock=True)
        if row is None or row[2] != "approved" or row[5] <= self._clock():
            raise StripeProcessorFeeRepairError(
                "Approved Stripe fee repair is unavailable"
            )
        authority = load_stripe_reconciliation_authority(
            self._connection,
            commercial_account_id=int(row[9]),
            environment=row[22],
        )
        return self._preparation(row, authority)

    @_atomic
    def execute_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        step_up_event_id: UUID,
        request_id: UUID,
        observation: StripeProcessorFeeRepairObservation,
    ) -> StripeProcessorFeeRepairResult:
        operator = self._require_operator(
            operator_user_id, runtime_environment, step_up_event_id
        )
        billing_environment = self._billing_environment()
        replay = self._load_execution(
            request_id,
            environment=runtime_environment,
            billing_environment=billing_environment,
        )
        if replay is not None:
            return replay.model_copy(update={"durable_replayed": True})
        now = self._clock()
        provider_observation = StripeMonetaryObservation.model_validate(
            observation.provider_observation.model_dump(mode="python")
        )
        movement = StripeMoneyMovementObservation.model_validate(
            observation.movement.model_dump(mode="python")
        )
        if (
            not observation.has_provider_attestation()
            or provider_observation.observed_at < now - timedelta(minutes=15)
            or provider_observation.observed_at > now + timedelta(minutes=5)
            or provider_observation.evidence_completeness != "complete"
        ):
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair observation is not fresh"
            )
        row = self._load_authority(request_id, runtime_environment, lock=True)
        if row is not None and row[2] == "executed":
            replay = self._load_execution(
                request_id,
                environment=runtime_environment,
                billing_environment=billing_environment,
            )
            if replay is not None:
                return replay.model_copy(update={"durable_replayed": True})
        if row is None or row[2] != "approved" or row[5] <= now:
            raise StripeProcessorFeeRepairError(
                "Approved Stripe fee repair is unavailable"
            )
        authority = load_stripe_reconciliation_authority(
            self._connection,
            commercial_account_id=int(row[9]),
            environment=row[22],
        )
        preparation = self._preparation(row, authority)
        self._validate_observation(preparation, provider_observation, movement)
        document = self._lock_document(preparation, movement)
        if document is None:
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair billing document is unavailable"
            )
        document_id, agreement_id = int(document[0]), int(document[1])
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT id FROM commercial_money_movements
                    WHERE provider = 'stripe' AND environment = %s
                      AND external_object_type = 'balance_transaction'
                      AND external_object_id = %s
                      AND movement_kind = 'processor_fee'
                    FOR UPDATE""",
                (billing_environment, movement.external_object_id),
            )
            if cursor.fetchone() is not None:
                raise StripeProcessorFeeRepairError(
                    "Stripe fee repair movement already exists"
                )
            execution_id = uuid4()
            cursor.execute(
                """INSERT INTO commercial_money_movements (
                       event_id, provider, environment, agreement_id,
                       commercial_account_id, document_id, external_object_type,
                       external_object_id, movement_kind, signed_amount_cents,
                       currency, occurred_at, metadata
                   ) VALUES (%s, 'stripe', %s, %s, %s, %s,
                             'balance_transaction', %s, 'processor_fee', %s,
                             %s, %s, jsonb_build_object(
                                 'repair_execution_id', %s,
                                 'repair_request_id', %s,
                                 'observation_sha256', %s
                             )) RETURNING id""",
                (
                    str(uuid4()),
                    billing_environment,
                    agreement_id,
                    preparation.commercial_account_id,
                    document_id,
                    movement.external_object_id,
                    movement.signed_amount_cents,
                    movement.currency,
                    movement.occurred_at,
                    str(execution_id),
                    str(request_id),
                    provider_observation.content_sha256,
                ),
            )
            money_movement_id = int(cursor.fetchone()[0])
        finally:
            cursor.close()
        allocation_run_id = None
        if movement.signed_amount_cents < 0:
            allocation = ProcessorFeeAllocationService(
                self._connection, flags=self._flags
            ).allocate_fee_as_operator(
                operator_user_id=operator_user_id,
                runtime_environment=runtime_environment,
                command=ProcessorFeeAllocationCommand(
                    idempotency_key=f"stripe-fee-repair-{request_id}",
                    commercial_account_id=preparation.commercial_account_id,
                    agreement_id=agreement_id,
                    money_movement_id=money_movement_id,
                    reason_code=row[4],
                ),
            )
            allocation_run_id = allocation.allocation_run_id
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=preparation.commercial_account_id,
                agreement_id=agreement_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action="commercial.stripe_processor_fee_repair.execute",
                target_type="commercial_stripe_repair_intent",
                target_id=str(preparation.intent_id),
                reason_code=row[4],
                after={
                    "account_id": preparation.commercial_account_id,
                    "agreement_id": agreement_id,
                    "content_sha256": provider_observation.content_sha256,
                    "request_id": str(request_id),
                    "result_code": "applied",
                },
                request_id=str(request_id),
            ),
        )
        provider_json = provider_observation.model_dump(mode="json")
        movement_json = movement.model_dump(
            mode="json",
            include={
                "external_invoice_id",
                "external_object_type",
                "external_object_id",
                "movement_kind",
                "signed_amount_cents",
                "currency",
                "occurred_at",
            },
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO commercial_stripe_monetary_repair_executions (
                       execution_id, request_id, intent_id, source_finding_id,
                       commercial_account_id, agreement_id, document_id,
                       money_movement_id, processor_fee_allocation_run_id,
                       environment, billing_environment, external_invoice_id,
                       external_object_type, external_object_id, movement_kind,
                       signed_amount_cents, currency, occurred_at,
                       provider_observation_json, observation_content_sha256,
                       movement_snapshot_json, movement_remote_sha256,
                       provider_observed_at, provider_attestation_document,
                       provider_attestation_key_id, provider_attestation_sha256,
                       actor_user_id, executor_step_up_event_id, audit_event_id
                   ) VALUES (
                       %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                       %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                   )""",
                (
                    str(execution_id),
                    str(request_id),
                    str(preparation.intent_id),
                    str(preparation.source_finding_id),
                    preparation.commercial_account_id,
                    agreement_id,
                    document_id,
                    money_movement_id,
                    allocation_run_id,
                    runtime_environment,
                    billing_environment,
                    movement.external_invoice_id,
                    movement.external_object_type,
                    movement.external_object_id,
                    movement.movement_kind,
                    movement.signed_amount_cents,
                    movement.currency,
                    movement.occurred_at,
                    json.dumps(provider_json),
                    provider_observation.content_sha256,
                    json.dumps(movement_json),
                    _movement_remote_digest(movement),
                    provider_observation.observed_at,
                    json.dumps(observation.database_attestation_document),
                    str(observation.database_attestation_key_id),
                    observation.database_attestation_sha256,
                    operator_user_id,
                    str(step_up_event_id),
                    str(audit_event_id),
                ),
            )
        finally:
            cursor.close()
        record_change_execution(
            request_id,
            store=PostgresChangeRequestStore(self._connection),
            operator=operator,
            succeeded=True,
            result_code="applied",
            audit_event_id=audit_event_id,
            now=now,
        )
        return StripeProcessorFeeRepairResult(
            execution_id=execution_id,
            request_id=request_id,
            intent_id=preparation.intent_id,
            commercial_account_id=preparation.commercial_account_id,
            agreement_id=agreement_id,
            document_id=document_id,
            money_movement_id=money_movement_id,
            processor_fee_allocation_run_id=allocation_run_id,
            signed_amount_cents=movement.signed_amount_cents,
            audit_event_id=audit_event_id,
        )

    def _preparation(
        self, row: tuple, authority: StripeReconciliationAuthority
    ) -> StripeProcessorFeeRepairPreparation:
        if authority.monetary is None:
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair monetary authority is unavailable"
            )
        parts = str(row[11]).split(":")
        if len(parts) != 3:
            raise StripeProcessorFeeRepairError("Stripe fee repair subject is invalid")
        observed = row[20]
        if (
            row[10] != "stripe.money_movement_drift"
            or row[12] != "stripe_monetary.v1"
            or row[19] != {"present": False, "digest": None}
            or set(observed) != {"present", "digest"}
            or observed.get("present") is not True
            or not isinstance(observed.get("digest"), str)
        ):
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair source evidence is invalid"
            )
        return StripeProcessorFeeRepairPreparation(
            request_id=row[0],
            intent_id=row[6],
            source_finding_id=row[7],
            authority_sha256=row[8],
            environment=row[21],
            billing_environment=row[22],
            commercial_account_id=int(row[9]),
            external_object_type=parts[0],
            external_object_id=parts[1],
            movement_kind=parts[2],
            expected_remote_digest=observed["digest"],
            monetary_expectation=authority.monetary,
            subscription_ids_by_agreement=authority.subscription_ids_by_agreement,
        )

    def _validate_observation(
        self,
        preparation: StripeProcessorFeeRepairPreparation,
        provider_observation: StripeMonetaryObservation,
        movement: StripeMoneyMovementObservation,
    ) -> None:
        matching = tuple(
            item
            for item in provider_observation.movements
            if item == movement
            and item.external_object_type == preparation.external_object_type
            and item.external_object_id == preparation.external_object_id
            and item.movement_kind == preparation.movement_kind
        )
        if (
            len(matching) != 1
            or provider_observation.environment != preparation.billing_environment
            or provider_observation.commercial_account_public_id
            != preparation.monetary_expectation.commercial_account_public_id
            or _movement_remote_digest(movement) != preparation.expected_remote_digest
            or movement.movement_kind != "processor_fee"
            or movement.external_object_type != "balance_transaction"
            or movement.signed_amount_cents == 0
            or movement.currency != "USD"
        ):
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair observation authority changed"
            )

    def _load_authority(self, request_id: UUID, environment: str, *, lock: bool):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT request.request_id, request.target_id, request.state,
                          request.payload_sha256, request.reason_code,
                          request.expires_at, intent.intent_id,
                          intent.source_finding_id, intent.authority_sha256,
                          intent.commercial_account_id, intent.finding_code,
                          intent.subject_id, intent.suite_code,
                          intent.fingerprint_sha256, intent.expected_sha256,
                          intent.observed_sha256, intent.source_last_seen_at,
                          finding.finding_id, finding.resolution_state,
                          finding.expected, finding.observed,
                          request.environment, customer.environment
                     FROM commercial_change_requests request
                     JOIN commercial_stripe_repair_intents intent
                       ON intent.intent_id::TEXT = request.target_id
                      AND intent.environment = request.environment
                     JOIN commercial_reconciliation_current_findings finding
                       ON finding.finding_id = intent.source_finding_id
                      AND finding.environment = intent.environment
                      AND finding.commercial_account_id = intent.commercial_account_id
                      AND finding.fingerprint_sha256 = intent.fingerprint_sha256
                      AND finding.last_seen_at = intent.source_last_seen_at
                      AND finding.resolution_state = 'open'
                     JOIN billing_provider_customers customer
                       ON customer.commercial_account_id = intent.commercial_account_id
                      AND customer.provider = 'stripe'
                    WHERE request.request_id = %s
                      AND request.environment = %s
                      AND request.action = 'live_stripe_repair'
                      AND request.target_type = 'commercial_stripe_repair_intent'
                      AND request.payload_sha256 = intent.authority_sha256
                      AND request.state IN ('approved', 'executed')
                      AND intent.suite_code = 'stripe_monetary.v1'
                      AND intent.finding_code = 'stripe.money_movement_drift'
                      AND intent.repair_code =
                          'stripe.money_movement_projection_repair'
                      AND intent.subject_type = 'stripe_movement'
                      AND customer.environment = %s"""
                + (" FOR UPDATE OF request" if lock else ""),
                (str(request_id), environment, self._billing_environment()),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def _lock_document(
        self,
        preparation: StripeProcessorFeeRepairPreparation,
        movement: StripeMoneyMovementObservation,
    ):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT document.id, document.agreement_id
                     FROM commercial_billing_documents document
                     JOIN commercial_agreements agreement
                       ON agreement.id = document.agreement_id
                      AND agreement.commercial_account_id =
                          document.commercial_account_id
                    WHERE document.commercial_account_id = %s
                      AND document.provider = 'stripe'
                      AND document.environment = %s
                      AND document.external_document_id = %s
                      AND document.currency = %s
                      AND agreement.billing_provider = 'stripe'
                      AND agreement.billing_environment = document.environment
                    FOR UPDATE OF document""",
                (
                    preparation.commercial_account_id,
                    preparation.billing_environment,
                    movement.external_invoice_id,
                    movement.currency,
                ),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def _require_operator(self, user_id: int, environment: str, step_up_event_id: UUID):
        if environment != self._flags.environment:
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair environment mismatch"
            )
        operator = load_named_operator(
            self._connection,
            user_id=user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        if CommercialRole.BILLING_OPERATOR not in operator.roles:
            raise StripeProcessorFeeRepairError(
                "Stripe fee repair operator is unauthorized"
            )
        return operator

    def _billing_environment(self) -> Literal["test", "live"]:
        return "live" if self._flags.stripe_live_mode_enabled else "test"

    def _load_execution(self, request_id, *, environment, billing_environment):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT execution_id, request_id, intent_id,
                          commercial_account_id, agreement_id, document_id,
                          money_movement_id, processor_fee_allocation_run_id,
                          signed_amount_cents, audit_event_id
                     FROM commercial_stripe_monetary_repair_executions
                    WHERE request_id = %s AND environment = %s
                      AND billing_environment = %s""",
                (str(request_id), environment, billing_environment),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        return StripeProcessorFeeRepairResult(
            execution_id=row[0],
            request_id=row[1],
            intent_id=row[2],
            commercial_account_id=int(row[3]),
            agreement_id=int(row[4]),
            document_id=int(row[5]),
            money_movement_id=int(row[6]),
            processor_fee_allocation_run_id=(None if row[7] is None else int(row[7])),
            signed_amount_cents=int(row[8]),
            audit_event_id=row[9],
        )

    def _run_atomic(self, operation):
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe fee repairs require a transaction")
        cursor = self._connection.cursor()
        try:
            cursor.execute("SAVEPOINT commercial_stripe_fee_repair")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_stripe_fee_repair")
                cursor.execute("RELEASE SAVEPOINT commercial_stripe_fee_repair")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_fee_repair")
            return result
        finally:
            cursor.close()


__all__ = [
    "StripeProcessorFeeRepairError",
    "StripeProcessorFeeRepairObservation",
    "StripeProcessorFeeRepairPreparation",
    "StripeProcessorFeeRepairProvider",
    "StripeProcessorFeeRepairResult",
    "StripeProcessorFeeRepairService",
]
