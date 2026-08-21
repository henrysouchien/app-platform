"""Approved, attested repair of local Stripe Subscription lifecycle projection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from functools import wraps
import hmac
import json
import secrets
from typing import Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, PrivateAttr, StrictBool

from ..agreements import AgreementState
from ..audit import CommercialAuditEvent, insert_commercial_audit_event
from ..authority import CommercialRole, record_change_execution
from ..authority_store import PostgresChangeRequestStore, load_named_operator
from ..entitlement_store import AccountProjectionRequest, persist_account_entitlements
from ..flags import CommercialFlags
from ..models import Sha256Digest, StableCode, StrictCommercialModel
from .stripe_projection_provider import (
    StripeProjectionExpectation,
    StripeProjectionProvider,
    StripeSubscriptionSnapshot,
)
from .stripe_subscription_lifecycle import decide_stripe_subscription_lifecycle


_ATTESTATION_KEY = secrets.token_bytes(32)
_ATTESTATION_CAPABILITY = object()
_REPAIR_CODES = frozenset(
    {
        "stripe.subscription_state_drift",
        "stripe.subscription_cancellation_drift",
        "stripe.subscription_period_drift",
    }
)


class StripeSubscriptionRepairError(RuntimeError):
    """An approved repair is missing, stale, or outside bounded authority."""


class StripeSubscriptionRepairPreparation(StrictCommercialModel):
    request_id: UUID
    intent_id: UUID
    source_finding_id: UUID
    authority_sha256: Sha256Digest
    environment: Literal["dev", "staging", "prod"]
    commercial_account_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    agreement_version: int = Field(gt=0)
    finding_code: Literal[
        "stripe.subscription_state_drift",
        "stripe.subscription_cancellation_drift",
        "stripe.subscription_period_drift",
    ]
    external_subscription_id: str = Field(pattern=r"^sub_[A-Za-z0-9]{4,251}$")
    expectation: StripeProjectionExpectation
    already_executed: StrictBool = False


class StripeSubscriptionRepairObservation(StrictCommercialModel):
    snapshot: StripeSubscriptionSnapshot
    observed_at: AwareDatetime
    database_attestation_document: dict
    database_attestation_key_id: UUID
    database_attestation_sha256: Sha256Digest
    _attestation: str | None = PrivateAttr(default=None)

    @classmethod
    def _from_provider(
        cls,
        *,
        snapshot: StripeSubscriptionSnapshot,
        observed_at: datetime,
        database_attestation_document: dict,
        database_attestation_key_id: UUID,
        database_attestation_sha256: str,
        capability: object,
    ) -> "StripeSubscriptionRepairObservation":
        if capability is not _ATTESTATION_CAPABILITY:
            raise StripeSubscriptionRepairError(
                "Stripe repair provider authority is invalid"
            )
        result = cls(
            snapshot=snapshot,
            observed_at=observed_at,
            database_attestation_document=database_attestation_document,
            database_attestation_key_id=database_attestation_key_id,
            database_attestation_sha256=database_attestation_sha256,
        )
        result._attestation = hmac.digest(
            _ATTESTATION_KEY, result._attestation_body(), "sha256"
        ).hex()
        return result

    def has_provider_attestation(self) -> bool:
        expected = hmac.digest(
            _ATTESTATION_KEY, self._attestation_body(), "sha256"
        ).hex()
        return self._attestation is not None and hmac.compare_digest(
            self._attestation, expected
        )

    def _attestation_body(self) -> bytes:
        return (
            f"{self.snapshot.snapshot_sha256}|{self.observed_at.isoformat()}"
        ).encode("ascii")


class StripeSubscriptionRepairResult(StrictCommercialModel):
    execution_id: UUID
    request_id: UUID
    intent_id: UUID
    commercial_account_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    prior_state: AgreementState
    result_state: AgreementState
    prior_version: int = Field(gt=0)
    result_version: int = Field(gt=0)
    finding_code: StableCode
    snapshot_sha256: Sha256Digest
    audit_event_id: UUID
    entitlement_revision: int | None = Field(default=None, gt=0)
    changed: StrictBool
    durable_replayed: StrictBool = False


class StripeSubscriptionRepairProvider:
    """Fetch a fresh normalized Subscription outside any database transaction."""

    def __init__(
        self,
        provider: StripeProjectionProvider,
        *,
        connection,
        attestation_connection,
    ) -> None:
        self._provider = provider
        self._connection = connection
        self._attestation_connection = attestation_connection

    def observe(
        self,
        preparation: StripeSubscriptionRepairPreparation,
    ) -> StripeSubscriptionRepairObservation:
        """Fetch only after the preparation transaction has been committed."""

        transaction_status = getattr(self._connection, "get_transaction_status", None)
        if transaction_status is None or transaction_status() != 0:
            raise StripeSubscriptionRepairError(
                "Stripe repair provider I/O requires an idle database connection"
            )
        attestation_status = getattr(
            self._attestation_connection, "get_transaction_status", None
        )
        if (
            attestation_status is None
            or attestation_status() != 0
            or not bool(getattr(self._attestation_connection, "autocommit", False))
        ):
            raise StripeSubscriptionRepairError(
                "Stripe repair attestation requires an idle autocommit connection"
            )
        fetched = self._provider.fetch_subscription(
            preparation.external_subscription_id,
            expected=preparation.expectation,
        )
        snapshot = StripeSubscriptionSnapshot.model_validate(
            fetched.model_dump(mode="python")
        )
        observed_at = datetime.now(timezone.utc)
        snapshot_json = snapshot.model_dump(mode="json")
        document = {
            "schema": "commercial.stripe-repair-provider-attestation.v1",
            "request_id": str(preparation.request_id),
            "intent_id": str(preparation.intent_id),
            "source_finding_id": str(preparation.source_finding_id),
            "authority_sha256": preparation.authority_sha256,
            "runtime_environment": preparation.environment,
            "billing_environment": preparation.expectation.environment,
            "commercial_account_id": preparation.commercial_account_id,
            "agreement_id": preparation.agreement_id,
            "external_subscription_id": preparation.external_subscription_id,
            "snapshot_sha256": snapshot.snapshot_sha256,
            "authoritative_fetched_at": snapshot_json["authoritative_fetched_at"],
            "observed_at": observed_at.isoformat().replace("+00:00", "Z"),
        }
        cursor = self._attestation_connection.cursor()
        try:
            cursor.execute(
                """SELECT attestation_document, key_id, attestation_sha256
                     FROM commercial_attest_stripe_repair_snapshot(
                         %s::jsonb, %s::jsonb
                     )""",
                (
                    json.dumps(document, sort_keys=True),
                    json.dumps(snapshot_json, sort_keys=True),
                ),
            )
            attestation = cursor.fetchone()
        finally:
            cursor.close()
        if attestation is None:
            raise StripeSubscriptionRepairError(
                "Stripe repair provider attestation is unavailable"
            )
        return StripeSubscriptionRepairObservation._from_provider(
            snapshot=snapshot,
            observed_at=observed_at,
            database_attestation_document=attestation[0],
            database_attestation_key_id=UUID(str(attestation[1])),
            database_attestation_sha256=str(attestation[2]),
            capability=_ATTESTATION_CAPABILITY,
        )


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class StripeSubscriptionRepairService:
    """Prepare and execute one exact approved local projection repair."""

    def __init__(self, connection, *, flags: CommercialFlags, clock=None) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if not (
            flags.commercial_control_enabled
            and flags.commercial_reconciliation_enabled
            and flags.stripe_billing_enabled
        ):
            raise StripeSubscriptionRepairError("Stripe repair is disabled")

    @_atomic
    def load_replay_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        step_up_event_id: UUID,
        request_id: UUID,
    ) -> StripeSubscriptionRepairResult | None:
        """Return a prior durable execution after rechecking operator authority."""

        self._require_operator(operator_user_id, runtime_environment, step_up_event_id)
        result = self._load_execution(
            request_id,
            environment=runtime_environment,
            billing_environment=(
                "live" if self._flags.stripe_live_mode_enabled else "test"
            ),
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
    ) -> StripeSubscriptionRepairPreparation:
        """Lock and revalidate authority; caller commits before provider I/O."""

        self._require_operator(operator_user_id, runtime_environment, step_up_event_id)
        row = self._load_authority(request_id, runtime_environment, lock=True)
        if row is None:
            raise StripeSubscriptionRepairError("Approved Stripe repair is unavailable")
        return self._preparation_from_row(row)

    @_atomic
    def execute_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: str,
        step_up_event_id: UUID,
        request_id: UUID,
        observation: StripeSubscriptionRepairObservation,
    ) -> StripeSubscriptionRepairResult:
        operator = self._require_operator(
            operator_user_id, runtime_environment, step_up_event_id
        )
        replay = self._load_execution(
            request_id,
            environment=runtime_environment,
            billing_environment=(
                "live" if self._flags.stripe_live_mode_enabled else "test"
            ),
        )
        if replay is not None:
            return replay.model_copy(update={"durable_replayed": True})
        now = self._clock()
        try:
            snapshot = StripeSubscriptionSnapshot.model_validate(
                observation.snapshot.model_dump(mode="python")
            )
        except ValueError as exc:
            raise StripeSubscriptionRepairError(
                "Stripe repair observation integrity is invalid"
            ) from exc
        if (
            not observation.has_provider_attestation()
            or observation.observed_at > now + timedelta(minutes=5)
            or observation.observed_at < now - timedelta(minutes=15)
            or observation.snapshot.authoritative_fetched_at
            > observation.observed_at + timedelta(minutes=5)
            or observation.snapshot.authoritative_fetched_at
            < now - timedelta(minutes=15)
        ):
            raise StripeSubscriptionRepairError(
                "Stripe repair observation is not fresh"
            )
        row = self._load_authority(request_id, runtime_environment, lock=True)
        if row is None or row[2] != "approved" or row[5] <= now:
            raise StripeSubscriptionRepairError("Approved Stripe repair is unavailable")
        preparation = self._preparation_from_row(row)
        if (
            snapshot.environment != preparation.expectation.environment
            or snapshot.commercial_account_public_id
            != preparation.expectation.commercial_account_public_id
            or snapshot.agreement_public_id
            != preparation.expectation.agreement_public_id
            or snapshot.external_customer_id
            != preparation.expectation.external_customer_id
            or snapshot.external_object_id != preparation.external_subscription_id
            or snapshot.price_code != preparation.expectation.price_code
        ):
            raise StripeSubscriptionRepairError(
                "Stripe repair observation authority changed"
            )
        finding_expected, finding_observed = row[19], row[20]
        self._validate_source_values(
            preparation.finding_code,
            finding_expected,
            finding_observed,
            local_state=row[26],
            local_cancel=row[31],
            local_period_start=row[28],
            local_period_end=row[29],
            snapshot=snapshot,
        )
        self._validate_unapproved_dimensions(
            preparation.finding_code,
            local_state=row[26],
            local_cancel=row[31],
            local_period_start=row[28],
            local_period_end=row[29],
            snapshot=snapshot,
        )
        prior_state = AgreementState(row[26])
        prior_version = int(row[27])
        if prior_version != preparation.agreement_version:
            raise StripeSubscriptionRepairError(
                "Stripe repair agreement version changed"
            )
        decision = decide_stripe_subscription_lifecycle(
            local_state=prior_state,
            snapshot=snapshot,
            evaluated_at=now,
        )
        is_state_repair = preparation.finding_code == "stripe.subscription_state_drift"
        is_period_repair = (
            preparation.finding_code == "stripe.subscription_period_drift"
        )
        if is_state_repair and decision.target_state is None:
            raise StripeSubscriptionRepairError(
                "Stripe state drift has no safe lifecycle transition"
            )
        if is_state_repair and snapshot.status not in {
            "past_due",
            "unpaid",
            "paused",
        }:
            raise StripeSubscriptionRepairError(
                "Stripe state drift requires additional boundary approval"
            )
        if is_state_repair and (
            snapshot.canceled_at is not None or snapshot.ended_at is not None
        ):
            raise StripeSubscriptionRepairError(
                "Stripe state drift carries unapproved terminal boundaries"
            )
        if is_period_repair and not decision.reconcile_period:
            raise StripeSubscriptionRepairError(
                "Stripe period drift has no safe period authority"
            )
        result_state = decision.target_state if is_state_repair else prior_state
        if result_state is None:
            result_state = prior_state
        state_effective_at = row[30]
        if is_state_repair and decision.target_state is not None:
            state_effective_at = (
                decision.canceled_at
                if decision.target_state == AgreementState.CANCELED
                else snapshot.trial_start
                if decision.target_state == AgreementState.TRIALING
                else now
                if decision.target_state == AgreementState.EXPIRED
                else now
            )
            if state_effective_at is None or state_effective_at <= row[30]:
                raise StripeSubscriptionRepairError(
                    "Stripe repair state boundary is not monotonic"
                )
        period_start = snapshot.current_period_start_at if is_period_repair else row[28]
        period_end = snapshot.current_period_end_at if is_period_repair else row[29]
        trial_end = row[32]
        cancel_at_period_end = (
            snapshot.cancel_at_period_end
            if preparation.finding_code == "stripe.subscription_cancellation_drift"
            else bool(row[31])
        )
        canceled_at = (
            decision.canceled_at
            if is_state_repair and decision.target_state == AgreementState.CANCELED
            else row[33]
        )
        if is_state_repair and result_state in {
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }:
            cancel_at_period_end = False
        changed = (
            result_state != prior_state
            or state_effective_at != row[30]
            or period_start != row[28]
            or period_end != row[29]
            or trial_end != row[32]
            or cancel_at_period_end != row[31]
            or canceled_at != row[33]
        )
        cursor = self._connection.cursor()
        try:
            result_version = prior_version
            if changed:
                cursor.execute(
                    """UPDATE commercial_agreements
                          SET state = %s, state_effective_at = %s,
                              current_period_start_at = %s,
                              current_period_end_at = %s, trial_end_at = %s,
                              cancel_at_period_end = %s, canceled_at = %s,
                              version = version + 1, updated_at = clock_timestamp()
                        WHERE id = %s AND commercial_account_id = %s AND version = %s
                    RETURNING version""",
                    (
                        result_state.value,
                        state_effective_at,
                        period_start,
                        period_end,
                        trial_end,
                        cancel_at_period_end,
                        canceled_at,
                        preparation.agreement_id,
                        preparation.commercial_account_id,
                        prior_version,
                    ),
                )
                updated = cursor.fetchone()
                if updated is None:
                    raise StripeSubscriptionRepairError(
                        "Stripe repair agreement version changed"
                    )
                result_version = int(updated[0])
        finally:
            cursor.close()
        entitlement_revision = None
        should_reproject = is_period_repair or (
            is_state_repair and decision.reproject_entitlements
        )
        if should_reproject:
            if not self._flags.commercial_entitlement_projection_enabled:
                raise StripeSubscriptionRepairError(
                    "Stripe repair entitlement projection is disabled"
                )
            projection = persist_account_entitlements(
                self._connection,
                flags=self._flags,
                request=AccountProjectionRequest(
                    commercial_account_id=preparation.commercial_account_id,
                    projected_at=now,
                ),
            )
            entitlement_revision = projection.revision
        execution_id, audit_event_id = uuid4(), uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=preparation.commercial_account_id,
                agreement_id=preparation.agreement_id,
                actor_type="admin",
                actor_id=str(operator.user_id),
                action="commercial.stripe_repair.execute",
                target_type="commercial_stripe_repair_intent",
                target_id=str(preparation.intent_id),
                reason_code=row[4],
                before={
                    "account_id": preparation.commercial_account_id,
                    "agreement_id": preparation.agreement_id,
                    "state": prior_state.value,
                    "version": prior_version,
                },
                after={
                    "account_id": preparation.commercial_account_id,
                    "agreement_id": preparation.agreement_id,
                    "state": result_state.value,
                    "version": result_version,
                    "content_sha256": snapshot.snapshot_sha256,
                    "request_id": str(request_id),
                    "result_code": "applied",
                },
                request_id=str(request_id),
            ),
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO commercial_stripe_repair_executions (
                       execution_id, request_id, intent_id, source_finding_id,
                       commercial_account_id, agreement_id, environment,
                       billing_environment, finding_code,
                       external_subscription_id, snapshot_sha256,
                       snapshot_json, snapshot_evidence_sha256,
                       provider_observed_at, provider_attestation_document,
                       provider_attestation_key_id, provider_attestation_sha256,
                       prior_state, result_state, prior_version, result_version,
                       prior_state_effective_at,
                       prior_current_period_start_at,
                       prior_current_period_end_at, prior_trial_end_at,
                       prior_cancel_at_period_end, prior_canceled_at,
                       result_state_effective_at,
                       result_current_period_start_at,
                       result_current_period_end_at, result_trial_end_at,
                       result_cancel_at_period_end, result_canceled_at,
                       changed, entitlement_revision, actor_user_id,
                       executor_step_up_event_id, audit_event_id
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                             %s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,
                             %s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    str(execution_id),
                    str(request_id),
                    str(preparation.intent_id),
                    str(preparation.source_finding_id),
                    preparation.commercial_account_id,
                    preparation.agreement_id,
                    runtime_environment,
                    preparation.expectation.environment,
                    preparation.finding_code,
                    preparation.external_subscription_id,
                    snapshot.snapshot_sha256,
                    json.dumps(snapshot.model_dump(mode="json"), sort_keys=True),
                    observation.database_attestation_document[
                        "snapshot_evidence_sha256"
                    ],
                    observation.observed_at,
                    json.dumps(
                        observation.database_attestation_document, sort_keys=True
                    ),
                    str(observation.database_attestation_key_id),
                    observation.database_attestation_sha256,
                    prior_state.value,
                    result_state.value,
                    prior_version,
                    result_version,
                    row[30],
                    row[28],
                    row[29],
                    row[32],
                    bool(row[31]),
                    row[33],
                    state_effective_at,
                    period_start,
                    period_end,
                    trial_end,
                    cancel_at_period_end,
                    canceled_at,
                    changed,
                    entitlement_revision,
                    operator.user_id,
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
        return StripeSubscriptionRepairResult(
            execution_id=execution_id,
            request_id=request_id,
            intent_id=preparation.intent_id,
            commercial_account_id=preparation.commercial_account_id,
            agreement_id=preparation.agreement_id,
            prior_state=prior_state,
            result_state=result_state,
            prior_version=prior_version,
            result_version=result_version,
            finding_code=preparation.finding_code,
            snapshot_sha256=snapshot.snapshot_sha256,
            audit_event_id=audit_event_id,
            entitlement_revision=entitlement_revision,
            changed=changed,
        )

    def _require_operator(self, user_id, environment, step_up_event_id):
        if environment != self._flags.environment:
            raise StripeSubscriptionRepairError("Stripe repair environment mismatch")
        operator = load_named_operator(
            self._connection,
            user_id=user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        if CommercialRole.BILLING_OPERATOR not in operator.roles:
            raise StripeSubscriptionRepairError(
                "Stripe repair operator is unauthorized"
            )
        return operator

    def _load_authority(self, request_id, environment, *, lock):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT request.request_id, request.target_id, request.state,
                          request.payload_sha256, request.reason_code,
                          request.expires_at, intent.intent_id,
                          intent.source_finding_id, intent.authority_sha256,
                          intent.commercial_account_id, intent.finding_code,
                          intent.subject_id, intent.fingerprint_sha256,
                          intent.expected_sha256, intent.observed_sha256,
                          intent.source_last_seen_at, finding.finding_id,
                          finding.resolution_state, finding.last_seen_at,
                          finding.expected, finding.observed,
                          account.public_id, agreement.id, agreement.public_id,
                          customer.external_customer_id, terms.price_code,
                          agreement.state, agreement.version,
                          agreement.current_period_start_at,
                          agreement.current_period_end_at,
                          agreement.state_effective_at,
                          agreement.cancel_at_period_end, agreement.trial_end_at,
                          agreement.canceled_at, request.environment,
                          agreement.billing_environment
                     FROM commercial_change_requests request
                     JOIN commercial_stripe_repair_intents intent
                       ON intent.intent_id::TEXT = request.target_id
                      AND intent.environment = request.environment
                     JOIN commercial_reconciliation_current_findings finding
                       ON finding.finding_id = intent.source_finding_id
                      AND finding.environment = intent.environment
                      AND finding.commercial_account_id = intent.commercial_account_id
                      AND finding.fingerprint_sha256 = intent.fingerprint_sha256
                     JOIN commercial_accounts account
                       ON account.id = intent.commercial_account_id
                     JOIN commercial_agreements agreement
                       ON agreement.commercial_account_id = account.id
                      AND agreement.external_subscription_id = intent.subject_id
                      AND agreement.billing_provider = 'stripe'
                     JOIN billing_provider_customers customer
                       ON customer.commercial_account_id = account.id
                      AND customer.provider = 'stripe'
                      AND customer.environment = agreement.billing_environment
                     JOIN commercial_agreement_terms terms
                       ON terms.agreement_id = agreement.id
                      AND terms.effective_until IS NULL
                    WHERE request.request_id = %s
                      AND request.environment = %s
                      AND request.action = 'live_stripe_repair'
                      AND request.target_type = 'commercial_stripe_repair_intent'
                      AND request.payload_sha256 = intent.authority_sha256
                      AND request.state IN ('approved', 'executed')
                      AND finding.resolution_state = 'open'
                      AND finding.last_seen_at = intent.source_last_seen_at
                      AND agreement.billing_environment = %s
                """
                + (" FOR UPDATE OF request, agreement" if lock else ""),
                (
                    str(request_id),
                    environment,
                    "live" if self._flags.stripe_live_mode_enabled else "test",
                ),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    @staticmethod
    def _preparation_from_row(row):
        if row[10] not in _REPAIR_CODES:
            raise StripeSubscriptionRepairError("Stripe repair code is unsupported")
        return StripeSubscriptionRepairPreparation(
            request_id=row[0],
            intent_id=row[6],
            source_finding_id=row[7],
            authority_sha256=row[8],
            environment=row[34],
            commercial_account_id=int(row[9]),
            agreement_id=int(row[22]),
            agreement_version=int(row[27]),
            finding_code=row[10],
            external_subscription_id=row[11],
            expectation=StripeProjectionExpectation(
                environment=row[35],
                commercial_account_public_id=row[21],
                agreement_public_id=row[23],
                external_customer_id=row[24],
                price_code=row[25],
            ),
            already_executed=row[2] == "executed",
        )

    @staticmethod
    def _validate_source_values(
        code,
        expected,
        observed,
        *,
        local_state,
        local_cancel,
        local_period_start,
        local_period_end,
        snapshot,
    ):
        if code == "stripe.subscription_state_drift":
            valid = expected == {"agreement_state": local_state} and observed == {
                "subscription_status": snapshot.status
            }
        elif code == "stripe.subscription_cancellation_drift":
            valid = expected == {
                "cancel_at_period_end": bool(local_cancel)
            } and observed == {"cancel_at_period_end": snapshot.cancel_at_period_end}
        elif code == "stripe.subscription_period_drift":
            try:
                valid = (
                    set(expected)
                    == {
                        "current_period_start_at",
                        "current_period_end_at",
                    }
                    and set(observed)
                    == {
                        "current_period_start_at",
                        "current_period_end_at",
                    }
                    and datetime.fromisoformat(expected["current_period_start_at"])
                    == local_period_start
                    and datetime.fromisoformat(expected["current_period_end_at"])
                    == local_period_end
                    and datetime.fromisoformat(observed["current_period_start_at"])
                    == snapshot.current_period_start_at
                    and datetime.fromisoformat(observed["current_period_end_at"])
                    == snapshot.current_period_end_at
                )
            except (KeyError, TypeError, ValueError):
                valid = False
        else:
            valid = False
        if not valid:
            raise StripeSubscriptionRepairError("Stripe repair source evidence changed")

    @staticmethod
    def _validate_unapproved_dimensions(
        code,
        *,
        local_state,
        local_cancel,
        local_period_start,
        local_period_end,
        snapshot,
    ):
        compatible_states = {
            "pending_payment": {"incomplete"},
            "trialing": {"trialing"},
            "active": {"active"},
            "past_due": {"past_due"},
            "grace": {"past_due", "unpaid"},
            "paused": {"paused"},
            "canceled": {"canceled"},
            "expired": {"canceled", "incomplete_expired"},
        }
        if code != "stripe.subscription_state_drift" and snapshot.status not in (
            compatible_states.get(local_state, set())
        ):
            raise StripeSubscriptionRepairError(
                "Stripe repair has unapproved state drift"
            )
        if (
            code != "stripe.subscription_cancellation_drift"
            and snapshot.cancel_at_period_end != bool(local_cancel)
        ):
            raise StripeSubscriptionRepairError(
                "Stripe repair has unapproved cancellation drift"
            )
        if code != "stripe.subscription_period_drift" and (
            snapshot.current_period_start_at != local_period_start
            or snapshot.current_period_end_at != local_period_end
        ):
            raise StripeSubscriptionRepairError(
                "Stripe repair has unapproved period drift"
            )

    def _load_execution(self, request_id, *, environment, billing_environment):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT execution_id, request_id, intent_id,
                          commercial_account_id, agreement_id, prior_state,
                          result_state, prior_version, result_version, finding_code,
                          snapshot_sha256, audit_event_id, entitlement_revision, changed
                     FROM commercial_stripe_repair_executions
                    WHERE request_id = %s AND environment = %s
                      AND billing_environment = %s""",
                (str(request_id), environment, billing_environment),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        return StripeSubscriptionRepairResult(
            execution_id=row[0],
            request_id=row[1],
            intent_id=row[2],
            commercial_account_id=int(row[3]),
            agreement_id=int(row[4]),
            prior_state=row[5],
            result_state=row[6],
            prior_version=int(row[7]),
            result_version=int(row[8]),
            finding_code=row[9],
            snapshot_sha256=row[10],
            audit_event_id=row[11],
            entitlement_revision=row[12],
            changed=bool(row[13]),
        )

    def _run_atomic(self, operation):
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Stripe repairs require a transaction")
        cursor = self._connection.cursor()
        try:
            cursor.execute("SAVEPOINT commercial_stripe_repair")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_stripe_repair")
                cursor.execute("RELEASE SAVEPOINT commercial_stripe_repair")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_stripe_repair")
            return result
        finally:
            cursor.close()


__all__ = [
    "StripeSubscriptionRepairError",
    "StripeSubscriptionRepairObservation",
    "StripeSubscriptionRepairPreparation",
    "StripeSubscriptionRepairProvider",
    "StripeSubscriptionRepairResult",
    "StripeSubscriptionRepairService",
]
