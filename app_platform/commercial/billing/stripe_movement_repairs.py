"""Approved, attested repair of one missing Stripe movement fact."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
import hmac
import json
import secrets
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import Field, PrivateAttr, StrictBool

from ..audit import CommercialAuditEvent, insert_commercial_audit_event
from ..authority import CommercialRole, record_change_execution
from ..authority_store import PostgresChangeRequestStore, load_named_operator
from ..flags import CommercialFlags
from ..models import Sha256Digest, StrictCommercialModel, canonical_sha256
from .stripe_reconciliation import (
    StripeMonetaryObservation,
    StripeMonetaryReconciliationExpectation,
    StripeMoneyMovementObservation,
    StripeReconciliationAuthority,
    load_stripe_reconciliation_authority,
)


_PROCESS_ATTESTATION_KEY = secrets.token_bytes(32)
_PROCESS_ATTESTATION_CAPABILITY = object()


class StripeMovementRepairError(RuntimeError):
    """Approved movement repair authority is absent, stale, or unsafe."""


class StripeMovementRepairPreparation(StrictCommercialModel):
    request_id: UUID
    intent_id: UUID
    source_finding_id: UUID
    authority_sha256: Sha256Digest
    environment: Literal["dev", "staging", "prod"]
    billing_environment: Literal["test", "live"]
    commercial_account_id: int = Field(gt=0)
    external_object_type: Literal["payment_intent", "refund", "dispute"]
    external_object_id: str = Field(pattern=r"^(pi|re|dp)_[A-Za-z0-9]{4,252}$")
    movement_kind: Literal["cash_receipt", "refund", "dispute_hold", "dispute_release"]
    expected_remote_digest: Sha256Digest
    monetary_expectation: StripeMonetaryReconciliationExpectation
    subscription_ids_by_agreement: dict[UUID, str]


class StripeMovementRepairObservation(StrictCommercialModel):
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
    ) -> "StripeMovementRepairObservation":
        if capability is not _PROCESS_ATTESTATION_CAPABILITY:
            raise StripeMovementRepairError(
                "Stripe movement repair provider authority is invalid"
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


class StripeMovementRepairResult(StrictCommercialModel):
    execution_id: UUID
    request_id: UUID
    intent_id: UUID
    commercial_account_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    document_id: int = Field(gt=0)
    money_movement_id: int = Field(gt=0)
    signed_amount_cents: int
    audit_event_id: UUID
    durable_replayed: StrictBool = False


class StripeMovementRepairProvider:
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
        self, preparation: StripeMovementRepairPreparation
    ) -> StripeMovementRepairObservation:
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
            raise StripeMovementRepairError(
                "Stripe movement repair provider evidence is invalid"
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
            raise StripeMovementRepairError(
                "Stripe movement repair provider movement is unavailable"
            )
        movement = matching[0]
        if (
            _movement_remote_digest(movement) != preparation.expected_remote_digest
            or movement.external_invoice_payment_id is None
            or movement.external_payment_intent_id is None
            or movement.external_charge_id is None
        ):
            raise StripeMovementRepairError(
                "Stripe movement repair provider movement or lineage changed"
            )
        provider_json = provider_observation.model_dump(mode="json")
        document = {
            "schema": "commercial.stripe-movement-repair-attestation.v1",
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
            raise StripeMovementRepairError(
                "Stripe movement repair database attestation is unavailable"
            )
        return StripeMovementRepairObservation._from_provider(
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
            raise StripeMovementRepairError(
                "Stripe movement repair provider I/O requires an idle database connection"
            )
        if (
            attestation_status is None
            or attestation_status() != 0
            or not bool(getattr(self._attestation_connection, "autocommit", False))
        ):
            raise StripeMovementRepairError(
                "Stripe movement repair attestation requires an idle autocommit connection"
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


class StripeMovementRepairService:
    """Execute one approved missing movement repair exactly once."""

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
            raise StripeMovementRepairError("Stripe movement repair is disabled")

    @_atomic
    def load_replay_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        step_up_event_id: UUID,
        request_id: UUID,
    ) -> StripeMovementRepairResult | None:
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
    ) -> StripeMovementRepairPreparation:
        self._require_operator(operator_user_id, runtime_environment, step_up_event_id)
        row = self._load_authority(request_id, runtime_environment, lock=True)
        if row is None or row[2] != "approved" or row[5] <= self._clock():
            raise StripeMovementRepairError(
                "Approved Stripe movement repair is unavailable"
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
        observation: StripeMovementRepairObservation,
    ) -> StripeMovementRepairResult:
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
            raise StripeMovementRepairError(
                "Stripe movement repair observation is not fresh"
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
            raise StripeMovementRepairError(
                "Approved Stripe movement repair is unavailable"
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
            raise StripeMovementRepairError(
                "Stripe movement repair billing document is unavailable"
            )
        document_id, agreement_id = int(document[0]), int(document[1])
        payment_lineage = self._lock_payment_lineage(
            movement,
            document_id=document_id,
            agreement_id=agreement_id,
            commercial_account_id=preparation.commercial_account_id,
            billing_environment=billing_environment,
        )
        if (movement.movement_kind == "cash_receipt") == (payment_lineage is not None):
            raise StripeMovementRepairError(
                "Stripe movement repair payment lineage conflicts"
            )
        if payment_lineage is not None:
            self._validate_payment_bounds(movement, payment_lineage)
        if movement.movement_kind == "dispute_release":
            self._require_dispute_hold(
                movement,
                document_id=document_id,
                agreement_id=agreement_id,
                commercial_account_id=preparation.commercial_account_id,
                billing_environment=billing_environment,
            )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT id FROM commercial_money_movements
                    WHERE provider = 'stripe' AND environment = %s
                      AND external_object_type = %s
                      AND external_object_id = %s
                      AND movement_kind = %s
                    FOR UPDATE""",
                (
                    billing_environment,
                    movement.external_object_type,
                    movement.external_object_id,
                    movement.movement_kind,
                ),
            )
            if cursor.fetchone() is not None:
                raise StripeMovementRepairError(
                    "Stripe movement repair movement already exists"
                )
            execution_id = uuid4()
            cursor.execute(
                """INSERT INTO commercial_money_movements (
                       event_id, provider, environment, agreement_id,
                       commercial_account_id, document_id, external_object_type,
                       external_object_id, movement_kind, signed_amount_cents,
                       currency, occurred_at, metadata
                   ) VALUES (%s, 'stripe', %s, %s, %s, %s,
                             %s, %s, %s, %s, %s, %s, jsonb_build_object(
                                 'repair_execution_id', %s,
                                 'repair_request_id', %s,
                                 'observation_sha256', %s,
                                 'invoice_payment_id', %s,
                                 'payment_intent_id', %s,
                                 'charge_id', %s
                             )) RETURNING id""",
                (
                    str(uuid4()),
                    billing_environment,
                    agreement_id,
                    preparation.commercial_account_id,
                    document_id,
                    movement.external_object_type,
                    movement.external_object_id,
                    movement.movement_kind,
                    movement.signed_amount_cents,
                    movement.currency,
                    movement.occurred_at,
                    str(execution_id),
                    str(request_id),
                    provider_observation.content_sha256,
                    movement.external_invoice_payment_id,
                    movement.external_payment_intent_id,
                    movement.external_charge_id,
                ),
            )
            money_movement_id = int(cursor.fetchone()[0])
        finally:
            cursor.close()
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=preparation.commercial_account_id,
                agreement_id=agreement_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action="commercial.stripe_movement_repair.execute",
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
                "external_invoice_payment_id",
                "external_payment_intent_id",
                "external_charge_id",
            },
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO commercial_stripe_movement_repair_executions (
                       execution_id, request_id, intent_id, source_finding_id,
                       commercial_account_id, agreement_id, document_id,
                       money_movement_id, environment, billing_environment,
                       external_invoice_id,
                       external_object_type, external_object_id, movement_kind,
                       signed_amount_cents, currency, occurred_at,
                       external_invoice_payment_id,
                       external_payment_intent_id, external_charge_id,
                       provider_observation_json, observation_content_sha256,
                       movement_snapshot_json, movement_remote_sha256,
                       provider_observed_at, provider_attestation_document,
                       provider_attestation_key_id, provider_attestation_sha256,
                       actor_user_id, executor_step_up_event_id, audit_event_id
                   ) VALUES (
                       %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                       %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                       %s,%s,%s
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
                    runtime_environment,
                    billing_environment,
                    movement.external_invoice_id,
                    movement.external_object_type,
                    movement.external_object_id,
                    movement.movement_kind,
                    movement.signed_amount_cents,
                    movement.currency,
                    movement.occurred_at,
                    movement.external_invoice_payment_id,
                    movement.external_payment_intent_id,
                    movement.external_charge_id,
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
            if movement.movement_kind == "cash_receipt":
                cursor.execute(
                    """INSERT INTO commercial_stripe_repaired_payment_lineage (
                           repair_execution_id, money_movement_id, document_id,
                           commercial_account_id, agreement_id, environment,
                           external_invoice_id, external_invoice_payment_id,
                           external_payment_intent_id, external_charge_id,
                           amount_paid_cents, paid_at,
                           observation_content_sha256
                       ) VALUES (
                           %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s
                       )""",
                    (
                        str(execution_id),
                        money_movement_id,
                        document_id,
                        preparation.commercial_account_id,
                        agreement_id,
                        billing_environment,
                        movement.external_invoice_id,
                        movement.external_invoice_payment_id,
                        movement.external_payment_intent_id,
                        movement.external_charge_id,
                        movement.signed_amount_cents,
                        movement.occurred_at,
                        provider_observation.content_sha256,
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
        return StripeMovementRepairResult(
            execution_id=execution_id,
            request_id=request_id,
            intent_id=preparation.intent_id,
            commercial_account_id=preparation.commercial_account_id,
            agreement_id=agreement_id,
            document_id=document_id,
            money_movement_id=money_movement_id,
            signed_amount_cents=movement.signed_amount_cents,
            audit_event_id=audit_event_id,
        )

    def _preparation(
        self, row: tuple, authority: StripeReconciliationAuthority
    ) -> StripeMovementRepairPreparation:
        if authority.monetary is None:
            raise StripeMovementRepairError(
                "Stripe movement repair monetary authority is unavailable"
            )
        parts = str(row[11]).split(":")
        if len(parts) != 3:
            raise StripeMovementRepairError("Stripe movement repair subject is invalid")
        observed = row[20]
        if (
            row[10] != "stripe.money_movement_drift"
            or row[12] != "stripe_monetary.v1"
            or row[19] != {"present": False, "digest": None}
            or set(observed) != {"present", "digest"}
            or observed.get("present") is not True
            or not isinstance(observed.get("digest"), str)
        ):
            raise StripeMovementRepairError(
                "Stripe movement repair source evidence is invalid"
            )
        return StripeMovementRepairPreparation(
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
        preparation: StripeMovementRepairPreparation,
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
            or movement.movement_kind
            not in {"cash_receipt", "refund", "dispute_hold", "dispute_release"}
            or movement.external_object_type
            not in {"payment_intent", "refund", "dispute"}
            or movement.external_invoice_payment_id is None
            or movement.external_payment_intent_id is None
            or movement.external_charge_id is None
            or movement.currency != "USD"
        ):
            raise StripeMovementRepairError(
                "Stripe movement repair observation authority changed"
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

    def _lock_payment_lineage(
        self,
        movement: StripeMoneyMovementObservation,
        *,
        document_id: int,
        agreement_id: int,
        commercial_account_id: int,
        billing_environment: str,
    ):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT id, signed_amount_cents, occurred_at,
                          metadata->>'invoice_payment_id',
                          metadata->>'charge_id'
                     FROM commercial_money_movements
                    WHERE provider = 'stripe' AND environment = %s
                      AND document_id = %s AND agreement_id = %s
                      AND commercial_account_id = %s
                      AND external_object_type = 'payment_intent'
                      AND external_object_id = %s
                      AND movement_kind = 'cash_receipt'
                    FOR UPDATE""",
                (
                    billing_environment,
                    document_id,
                    agreement_id,
                    commercial_account_id,
                    movement.external_payment_intent_id,
                ),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        if not rows:
            return None
        if len(rows) != 1 or rows[0][3:] != (
            movement.external_invoice_payment_id,
            movement.external_charge_id,
        ):
            raise StripeMovementRepairError(
                "Stripe movement repair payment lineage is ambiguous"
            )
        return rows[0]

    def _validate_payment_bounds(
        self,
        movement: StripeMoneyMovementObservation,
        payment_lineage: tuple,
    ) -> None:
        payment_amount = int(payment_lineage[1])
        payment_occurred_at = payment_lineage[2]
        if movement.occurred_at < payment_occurred_at:
            raise StripeMovementRepairError(
                "Stripe movement repair predates its payment"
            )
        if movement.movement_kind in {"dispute_hold", "dispute_release"} and (
            abs(movement.signed_amount_cents) > payment_amount
        ):
            raise StripeMovementRepairError(
                "Stripe dispute movement exceeds payment authority"
            )
        if movement.movement_kind != "refund":
            return
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT COALESCE(SUM(-signed_amount_cents), 0)
                     FROM commercial_money_movements
                    WHERE provider = 'stripe'
                      AND environment = %s
                      AND movement_kind = 'refund'
                      AND metadata->>'payment_intent_id' = %s
                      AND metadata->>'charge_id' = %s""",
                (
                    self._billing_environment(),
                    movement.external_payment_intent_id,
                    movement.external_charge_id,
                ),
            )
            prior_refund_cents = int(cursor.fetchone()[0])
        finally:
            cursor.close()
        if prior_refund_cents - movement.signed_amount_cents > payment_amount:
            raise StripeMovementRepairError(
                "Stripe cumulative refunds exceed payment authority"
            )

    def _require_dispute_hold(
        self,
        movement: StripeMoneyMovementObservation,
        *,
        document_id: int,
        agreement_id: int,
        commercial_account_id: int,
        billing_environment: str,
    ) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT signed_amount_cents, occurred_at
                     FROM commercial_money_movements
                    WHERE provider = 'stripe' AND environment = %s
                      AND document_id = %s AND agreement_id = %s
                      AND commercial_account_id = %s
                      AND external_object_type = 'dispute'
                      AND external_object_id = %s
                      AND movement_kind = 'dispute_hold'
                    FOR UPDATE""",
                (
                    billing_environment,
                    document_id,
                    agreement_id,
                    commercial_account_id,
                    movement.external_object_id,
                ),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        if (
            len(rows) != 1
            or int(rows[0][0]) != -movement.signed_amount_cents
            or rows[0][1] > movement.occurred_at
        ):
            raise StripeMovementRepairError(
                "Stripe dispute release lacks exact hold lineage"
            )

    def _lock_document(
        self,
        preparation: StripeMovementRepairPreparation,
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
            raise StripeMovementRepairError(
                "Stripe movement repair environment mismatch"
            )
        operator = load_named_operator(
            self._connection,
            user_id=user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        if CommercialRole.BILLING_OPERATOR not in operator.roles:
            raise StripeMovementRepairError(
                "Stripe movement repair operator is unauthorized"
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
                          money_movement_id, signed_amount_cents, audit_event_id
                     FROM commercial_stripe_movement_repair_executions
                    WHERE request_id = %s AND environment = %s
                      AND billing_environment = %s""",
                (str(request_id), environment, billing_environment),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        return StripeMovementRepairResult(
            execution_id=row[0],
            request_id=row[1],
            intent_id=row[2],
            commercial_account_id=int(row[3]),
            agreement_id=int(row[4]),
            document_id=int(row[5]),
            money_movement_id=int(row[6]),
            signed_amount_cents=int(row[7]),
            audit_event_id=row[8],
        )

    def _run_atomic(self, operation):
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe movement repairs require a transaction")
        cursor = self._connection.cursor()
        try:
            cursor.execute("SAVEPOINT commercial_stripe_movement_repair")
            try:
                result = operation()
            except BaseException:
                cursor.execute(
                    "ROLLBACK TO SAVEPOINT commercial_stripe_movement_repair"
                )
                cursor.execute("RELEASE SAVEPOINT commercial_stripe_movement_repair")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_movement_repair")
            return result
        finally:
            cursor.close()


__all__ = [
    "StripeMovementRepairError",
    "StripeMovementRepairObservation",
    "StripeMovementRepairPreparation",
    "StripeMovementRepairProvider",
    "StripeMovementRepairResult",
    "StripeMovementRepairService",
]
