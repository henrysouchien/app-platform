"""Idempotent, audited commercial agreement lifecycle service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Annotated, Callable, Literal, Protocol
from uuid import UUID, uuid4

from pydantic import (
    AwareDatetime,
    Field,
    StrictBool,
    StringConstraints,
    model_validator,
)

from .agreement_store import PostgresAgreementRepository
from .agreements import (
    AgreementChannel,
    AgreementState,
    CommercialAgreementItemCreate,
    CommercialAgreementRecord,
    CommercialAgreementTermsCreate,
    CommercialAgreementTermsRecord,
)
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import (
    ACTION_AUTHORITY,
    CommercialAction,
    CommercialRole,
    NamedOperator,
    record_change_execution,
)
from .authority_store import PostgresChangeRequestStore, load_named_operator
from .errors import CommercialError, CommercialErrorCode
from .models import NonEmptyStr, StableCode, StrictCommercialModel, canonical_sha256


IdempotencyKey = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=255, pattern=r"^\S+$"
    ),
]


_ALLOWED_TRANSITIONS: dict[AgreementState, frozenset[AgreementState]] = {
    AgreementState.DRAFT: frozenset(
        {
            AgreementState.PENDING_PAYMENT,
            AgreementState.TRIALING,
            AgreementState.ACTIVE,
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }
    ),
    AgreementState.PENDING_PAYMENT: frozenset(
        {
            AgreementState.TRIALING,
            AgreementState.ACTIVE,
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }
    ),
    AgreementState.TRIALING: frozenset(
        {
            AgreementState.ACTIVE,
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }
    ),
    AgreementState.ACTIVE: frozenset(
        {
            AgreementState.PAST_DUE,
            AgreementState.GRACE,
            AgreementState.PAUSED,
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }
    ),
    AgreementState.PAST_DUE: frozenset(
        {
            AgreementState.ACTIVE,
            AgreementState.GRACE,
            AgreementState.PAUSED,
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }
    ),
    AgreementState.GRACE: frozenset(
        {
            AgreementState.ACTIVE,
            AgreementState.PAUSED,
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }
    ),
    AgreementState.PAUSED: frozenset(
        {
            AgreementState.ACTIVE,
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }
    ),
}
_ENTITLEMENT_BEARING_STATES = frozenset(
    {
        AgreementState.TRIALING,
        AgreementState.ACTIVE,
        AgreementState.PAST_DUE,
        AgreementState.GRACE,
        AgreementState.PAUSED,
    }
)
INVITE_TRIAL_EXPIRER_ACTOR_ID = "invite-trial-expiry"


class AgreementTransitionCommand(StrictCommercialModel):
    commercial_account_id: Annotated[int, Field(gt=0)]
    agreement_id: Annotated[int, Field(gt=0)]
    expected_version: Annotated[int, Field(gt=0)]
    target_state: AgreementState
    idempotency_key: IdempotencyKey
    reason_code: StableCode
    effective_at: AwareDatetime


class AgreementScheduleCancelCommand(StrictCommercialModel):
    commercial_account_id: Annotated[int, Field(gt=0)]
    agreement_id: Annotated[int, Field(gt=0)]
    expected_version: Annotated[int, Field(gt=0)]
    idempotency_key: IdempotencyKey
    reason_code: StableCode


class AgreementCommandResult(StrictCommercialModel):
    command_id: UUID
    agreement_id: Annotated[int, Field(gt=0)]
    commercial_account_id: Annotated[int, Field(gt=0)]
    state: AgreementState
    version: Annotated[int, Field(gt=0)]
    audit_event_id: UUID
    replayed: StrictBool = False


class AgreementTermsChangeCommand(StrictCommercialModel):
    commercial_account_id: Annotated[int, Field(gt=0)]
    agreement_id: Annotated[int, Field(gt=0)]
    expected_version: Annotated[int, Field(gt=0)]
    change_timing: Literal["immediate", "period_end"]
    idempotency_key: IdempotencyKey
    reason_code: StableCode
    change_request_ids: tuple[UUID, ...] = ()
    step_up_event_id: UUID | None = None
    terms: CommercialAgreementTermsCreate
    items: tuple[CommercialAgreementItemCreate, ...]

    @model_validator(mode="after")
    def _tenant_bound_terms(self) -> "AgreementTermsChangeCommand":
        if (
            self.terms.commercial_account_id != self.commercial_account_id
            or self.terms.agreement_id != self.agreement_id
        ):
            raise ValueError("terms change tenant identity must match the command")
        if not self.items:
            raise ValueError("terms change requires at least one immutable item")
        if self.terms.source_event_id is None:
            raise ValueError("terms change requires a durable source event identity")
        if self.terms.effective_until is not None:
            raise ValueError("replacement terms must remain open-ended")
        if len(set(self.change_request_ids)) != len(self.change_request_ids):
            raise ValueError("terms change request identities must be unique")
        return self


class AgreementTermsCommandResult(AgreementCommandResult):
    prior_terms_id: Annotated[int, Field(gt=0)]
    result_terms_id: Annotated[int, Field(gt=0)]
    change_timing: Literal["immediate", "period_end"]
    result_terms_revision: Annotated[int, Field(gt=1)]
    effective_from: AwareDatetime


class _AgreementActorContext(StrictCommercialModel):
    actor_type: Literal["user", "admin", "service", "stripe", "reconciler"]
    actor_id: NonEmptyStr | None = None
    environment: Literal["dev", "staging", "prod"]

    @model_validator(mode="after")
    def _named_human(self) -> "_AgreementActorContext":
        if self.actor_type in {"user", "admin"} and self.actor_id is None:
            raise ValueError("human agreement command actors must be named")
        return self


class AgreementProjectionHook(Protocol):
    def agreement_changed(
        self,
        connection: object,
        *,
        before: CommercialAgreementRecord,
        after: CommercialAgreementRecord,
        effective_at: datetime,
    ) -> None: ...


def agreement_terms_change_authority_digest(
    command: AgreementTermsChangeCommand,
    *,
    prior_terms_id: int,
    action: CommercialAction,
) -> str:
    """Digest the exact terms mutation a high-risk approval authorizes."""

    return canonical_sha256(
        {
            "action": action.value,
            "prior_terms_id": prior_terms_id,
            "command": command.model_dump(
                mode="python",
                exclude={
                    "change_request_ids",
                    "step_up_event_id",
                    "idempotency_key",
                },
            ),
        }
    )


class CommercialAgreementLifecycleService:
    def __init__(
        self,
        connection: object,
        *,
        projection_hook: AgreementProjectionHook,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._repository = PostgresAgreementRepository(connection)
        self._projection_hook = projection_hook
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def transition_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: AgreementTransitionCommand,
    ) -> AgreementCommandResult:
        self._require_operator(operator_user_id, runtime_environment)
        return self._transition(
            actor=_AgreementActorContext(
                actor_type="admin",
                actor_id=str(operator_user_id),
                environment=runtime_environment,
            ),
            command=command,
        )

    def expire_invite_trial_as_service(
        self,
        *,
        runtime_environment: Literal["dev", "staging", "prod"],
        activation_id: UUID,
        command: AgreementTransitionCommand,
    ) -> AgreementCommandResult:
        """Expire one exact invite trial at its persisted service boundary."""

        self._require_deployment_environment(runtime_environment)
        return self._run_command_atomic(
            lambda: self._expire_invite_trial_core(
                runtime_environment=runtime_environment,
                activation_id=activation_id,
                command=command,
            )
        )

    def _expire_invite_trial_core(
        self,
        *,
        runtime_environment: Literal["dev", "staging", "prod"],
        activation_id: UUID,
        command: AgreementTransitionCommand,
    ) -> AgreementCommandResult:
        if command.target_state != AgreementState.EXPIRED:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "transition",
                "trial_activation_id": activation_id,
                **command.model_dump(mode="python"),
            }
        )
        self._lock_idempotency(command.commercial_account_id, command.idempotency_key)
        replay = self._load_command_result(
            commercial_account_id=command.commercial_account_id,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        mutation_at = self._clock()
        before = self._repository.get_by_id_for_update(
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
        )
        if before is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_REQUIRED)
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT environment, trial_expires_at
                     FROM commercial_trial_activations
                    WHERE activation_id = %s
                      AND commercial_account_id = %s
                      AND agreement_id = %s
                    FOR SHARE""",
                (
                    str(activation_id),
                    command.commercial_account_id,
                    command.agreement_id,
                ),
            )
            activation = cursor.fetchone()
        finally:
            cursor.close()
        if (
            activation is None
            or activation[0] != runtime_environment
            or before.channel != AgreementChannel.INVITE_TRIAL
            or before.state != AgreementState.TRIALING
            or before.version != command.expected_version
            or before.service_end_at is None
            or before.trial_end_at != before.service_end_at
            or activation[1] != before.service_end_at
            or command.effective_at != before.service_end_at
            or mutation_at < before.service_end_at
            or mutation_at <= before.updated_at
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        after = self._repository.transition_state(
            expected=before,
            target_state=AgreementState.EXPIRED,
            changed_at=mutation_at,
            effective_at=command.effective_at,
        )
        if after is None:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
            )
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=after.commercial_account_id,
                agreement_id=after.id,
                actor_type="service",
                actor_id=INVITE_TRIAL_EXPIRER_ACTOR_ID,
                action="commercial.agreement.transition",
                target_type="commercial_agreement",
                target_id=str(after.public_id),
                reason_code=command.reason_code,
                before={
                    "account_id": before.commercial_account_id,
                    "agreement_id": before.id,
                    "state": before.state.value,
                    "version": before.version,
                    "cancel_at_period_end": before.cancel_at_period_end,
                },
                after={
                    "account_id": after.commercial_account_id,
                    "agreement_id": after.id,
                    "state": after.state.value,
                    "version": after.version,
                    "cancel_at_period_end": after.cancel_at_period_end,
                    "result_code": "applied",
                },
            ),
        )
        result = AgreementCommandResult(
            command_id=uuid4(),
            agreement_id=after.id,
            commercial_account_id=after.commercial_account_id,
            state=after.state,
            version=after.version,
            audit_event_id=audit_event_id,
        )
        self._insert_command_result(
            result=result,
            before=before,
            actor=_AgreementActorContext(
                actor_type="service",
                actor_id=INVITE_TRIAL_EXPIRER_ACTOR_ID,
                environment=runtime_environment,
            ),
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            effective_at=command.effective_at,
        )
        self._repository.close_terms_at_terminal_boundary(
            commercial_account_id=after.commercial_account_id,
            agreement_id=after.id,
            effective_until=command.effective_at,
            terminal_closed_at=mutation_at,
            terminal_command_id=result.command_id,
        )
        self._projection_hook.agreement_changed(
            self._connection,
            before=before,
            after=after,
            effective_at=command.effective_at,
        )
        return result

    def _transition(
        self,
        *,
        actor: _AgreementActorContext,
        command: AgreementTransitionCommand,
    ) -> AgreementCommandResult:
        """Execute the channel-neutral transition core in the caller transaction."""

        return self._run_command_atomic(
            lambda: self._transition_core(actor=actor, command=command)
        )

    def _transition_core(
        self,
        *,
        actor: _AgreementActorContext,
        command: AgreementTransitionCommand,
    ) -> AgreementCommandResult:
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "transition",
                **command.model_dump(mode="python"),
            }
        )
        self._lock_idempotency(command.commercial_account_id, command.idempotency_key)
        replay = self._load_command_result(
            commercial_account_id=command.commercial_account_id,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        mutation_at = self._clock()

        before = self._repository.get_by_id_for_update(
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
        )
        if before is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_REQUIRED)
        if before.version != command.expected_version:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
            )
        if (
            command.effective_at <= before.updated_at
            or command.effective_at < mutation_at - timedelta(minutes=5)
            or command.effective_at > mutation_at + timedelta(minutes=5)
            or mutation_at <= before.updated_at
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        if command.target_state not in _ALLOWED_TRANSITIONS.get(
            before.state, frozenset()
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        if command.target_state in _ENTITLEMENT_BEARING_STATES:
            self._assert_effective_terms(before, command.effective_at)
        future_terms_count = 0
        if command.target_state in {
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }:
            future_terms_count = self._future_terms_count(
                before, command.effective_at
            )
            if (
                future_terms_count
                and not self._repository.supports_scheduled_terms_voiding()
            ):
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
                )

        after = self._repository.transition_state(
            expected=before,
            target_state=command.target_state,
            changed_at=mutation_at,
            effective_at=command.effective_at,
        )
        if after is None:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
            )
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=after.commercial_account_id,
                agreement_id=after.id,
                actor_type=actor.actor_type,
                actor_id=actor.actor_id,
                action="commercial.agreement.transition",
                target_type="commercial_agreement",
                target_id=str(after.public_id),
                reason_code=command.reason_code,
                before={
                    "account_id": before.commercial_account_id,
                    "agreement_id": before.id,
                    "state": before.state.value,
                    "version": before.version,
                    "cancel_at_period_end": before.cancel_at_period_end,
                },
                after={
                    "account_id": after.commercial_account_id,
                    "agreement_id": after.id,
                    "state": after.state.value,
                    "version": after.version,
                    "cancel_at_period_end": after.cancel_at_period_end,
                    "result_code": "applied",
                },
            ),
        )
        result = AgreementCommandResult(
            command_id=uuid4(),
            agreement_id=after.id,
            commercial_account_id=after.commercial_account_id,
            state=after.state,
            version=after.version,
            audit_event_id=audit_event_id,
        )
        self._insert_command_result(
            result=result,
            before=before,
            actor=actor,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            effective_at=command.effective_at,
        )
        if command.target_state in {
            AgreementState.CANCELED,
            AgreementState.EXPIRED,
        }:
            self._repository.close_terms_at_terminal_boundary(
                commercial_account_id=after.commercial_account_id,
                agreement_id=after.id,
                effective_until=command.effective_at,
                terminal_closed_at=mutation_at,
                terminal_command_id=result.command_id,
            )
            if future_terms_count:
                voided_ids = self._repository.void_future_terms_for_terminal(
                    commercial_account_id=after.commercial_account_id,
                    agreement_id=after.id,
                    effective_at=command.effective_at,
                    voided_at=mutation_at,
                    void_command_id=result.command_id,
                )
                if len(voided_ids) != future_terms_count:
                    raise CommercialError(
                        CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
                    )
        self._projection_hook.agreement_changed(
            self._connection,
            before=before,
            after=after,
            effective_at=command.effective_at,
        )
        return result

    def schedule_cancel_at_period_end_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: AgreementScheduleCancelCommand,
    ) -> AgreementCommandResult:
        self._require_operator(operator_user_id, runtime_environment)
        return self._schedule_cancel_at_period_end(
            actor=_AgreementActorContext(
                actor_type="admin",
                actor_id=str(operator_user_id),
                environment=runtime_environment,
            ),
            command=command,
        )

    def change_terms_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: AgreementTermsChangeCommand,
    ) -> AgreementTermsCommandResult:
        self._require_operator(operator_user_id, runtime_environment)
        return self._change_terms(
            actor=_AgreementActorContext(
                actor_type="admin",
                actor_id=str(operator_user_id),
                environment=runtime_environment,
            ),
            command=command,
        )

    def _change_terms(
        self,
        *,
        actor: _AgreementActorContext,
        command: AgreementTermsChangeCommand,
    ) -> AgreementTermsCommandResult:
        result = self._run_command_atomic(
            lambda: self._change_terms_core(actor=actor, command=command)
        )
        if not isinstance(result, AgreementTermsCommandResult):
            raise RuntimeError("terms command returned an invalid result contract")
        return result

    def _change_terms_core(
        self,
        *,
        actor: _AgreementActorContext,
        command: AgreementTermsChangeCommand,
    ) -> AgreementTermsCommandResult:
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "schedule_terms",
                **command.model_dump(mode="python"),
            }
        )
        self._lock_idempotency(command.commercial_account_id, command.idempotency_key)
        replay = self._load_terms_command_result(
            commercial_account_id=command.commercial_account_id,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        mutation_at = self._clock()
        before = self._repository.get_by_id_for_update(
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
        )
        if before is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_REQUIRED)
        if before.version != command.expected_version:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
            )
        if (
            before.state not in _ENTITLEMENT_BEARING_STATES
            or mutation_at <= before.updated_at
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        current_terms = self._repository.get_effective_terms_for_update(
            commercial_account_id=before.commercial_account_id,
            agreement_id=before.id,
            effective_at=mutation_at,
        )
        if (
            current_terms is None
            or current_terms.effective_until is not None
            or command.terms.revision != current_terms.revision + 1
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        current_offer = self._repository.get_offer_transition_metadata(
            catalog_policy_id=current_terms.catalog_policy_id,
            offer_code=current_terms.offer_code,
        )
        proposed_offer = self._repository.get_offer_transition_metadata(
            catalog_policy_id=command.terms.catalog_policy_id,
            offer_code=command.terms.offer_code,
        )
        if (
            current_offer is None
            or proposed_offer is None
            or current_offer.transition_family != proposed_offer.transition_family
            or before.channel.value not in current_offer.channels
            or before.channel.value not in proposed_offer.channels
            or current_terms.entitlement_policy_id
            != current_offer.entitlement_policy_id
            or current_terms.payer_policy_id != current_offer.payer_policy_id
            or current_terms.budget_policy_id != current_offer.budget_policy_id
            or command.terms.entitlement_policy_id
            != proposed_offer.entitlement_policy_id
            or command.terms.payer_policy_id != proposed_offer.payer_policy_id
            or command.terms.budget_policy_id != proposed_offer.budget_policy_id
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        current_rank = current_offer.commercial_tier_rank
        proposed_rank = proposed_offer.commercial_tier_rank
        expected_timing = (
            "immediate"
            if proposed_rank > current_rank
            else "period_end"
            if proposed_rank < current_rank
            else None
        )
        if expected_timing is None or command.change_timing != expected_timing:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        approval_operator, approval_request_ids = self._authorize_terms_policy_change(
            actor=actor,
            agreement=before,
            current_terms=current_terms,
            command=command,
            checked_at=mutation_at,
        )
        if command.change_timing == "immediate":
            if (
                command.terms.effective_from <= current_terms.effective_from
                or command.terms.effective_from < mutation_at - timedelta(minutes=5)
                or command.terms.effective_from > mutation_at + timedelta(minutes=5)
            ):
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
                )
        elif (
            before.current_period_end_at is None
            or before.current_period_end_at <= mutation_at
            or command.terms.effective_from != before.current_period_end_at
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        if not self._repository.close_terms_for_replacement(
            expected=current_terms,
            effective_until=command.terms.effective_from,
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
            )
        stored = self._repository.add_terms_revision(command.terms, command.items)
        after = self._repository.record_terms_change(
            expected=before,
            changed_at=mutation_at,
        )
        if after is None:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
            )
        audit_event_id = uuid4()
        before_audit = {
            "account_id": before.commercial_account_id,
            "agreement_id": before.id,
            "state": before.state.value,
            "version": before.version,
            "cancel_at_period_end": before.cancel_at_period_end,
            "offer_code": current_terms.offer_code,
        }
        after_audit = {
            "account_id": after.commercial_account_id,
            "agreement_id": after.id,
            "state": after.state.value,
            "version": after.version,
            "cancel_at_period_end": after.cancel_at_period_end,
            "offer_code": stored.terms.offer_code,
            "result_code": "applied",
        }
        if current_terms.price_code is not None:
            before_audit["price_code"] = current_terms.price_code
        if stored.terms.price_code is not None:
            after_audit["price_code"] = stored.terms.price_code
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=after.commercial_account_id,
                agreement_id=after.id,
                actor_type=actor.actor_type,
                actor_id=actor.actor_id,
                action="commercial.agreement.schedule_terms",
                target_type="commercial_agreement",
                target_id=str(after.public_id),
                reason_code=command.reason_code,
                before=before_audit,
                after=after_audit,
            ),
        )
        if approval_operator is not None:
            store = PostgresChangeRequestStore(self._connection)
            for request_id in approval_request_ids:
                record_change_execution(
                    request_id,
                    store=store,
                    operator=approval_operator,
                    succeeded=True,
                    result_code="applied",
                    audit_event_id=audit_event_id,
                    now=mutation_at,
                )
        result = AgreementTermsCommandResult(
            command_id=uuid4(),
            agreement_id=after.id,
            commercial_account_id=after.commercial_account_id,
            state=after.state,
            version=after.version,
            audit_event_id=audit_event_id,
            prior_terms_id=current_terms.id,
            result_terms_id=stored.terms.id,
            change_timing=command.change_timing,
            result_terms_revision=stored.terms.revision,
            effective_from=stored.terms.effective_from,
        )
        self._insert_command_result(
            result=result,
            before=before,
            actor=actor,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            effective_at=stored.terms.effective_from,
            command_kind="schedule_terms",
            prior_terms_id=current_terms.id,
            result_terms_id=stored.terms.id,
            terms_change_timing=command.change_timing,
        )
        self._projection_hook.agreement_changed(
            self._connection,
            before=before,
            after=after,
            effective_at=stored.terms.effective_from,
        )
        return result

    def _authorize_terms_policy_change(
        self,
        *,
        actor: _AgreementActorContext,
        agreement: CommercialAgreementRecord,
        current_terms: CommercialAgreementTermsRecord,
        command: AgreementTermsChangeCommand,
        checked_at: datetime,
    ) -> tuple[NamedOperator | None, tuple[UUID, ...]]:
        policy_identity_changes = (
            command.terms.budget_policy_id != current_terms.budget_policy_id
            or command.terms.payer_policy_id != current_terms.payer_policy_id
        )
        if actor.actor_type == "stripe":
            return None, ()
        if actor.actor_type != "admin":
            if policy_identity_changes:
                raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
            return None, ()
        required_actions: list[CommercialAction] = []
        budget_increase = False
        if command.terms.budget_policy_id != current_terms.budget_policy_id:
            current_envelope = self._repository.get_budget_policy_envelope(
                budget_policy_id=current_terms.budget_policy_id
            )
            proposed_envelope = self._repository.get_budget_policy_envelope(
                budget_policy_id=command.terms.budget_policy_id
            )
            budget_increase = (
                current_envelope is None
                or proposed_envelope is None
                or proposed_envelope.model_budget_microusd
                > current_envelope.model_budget_microusd
                or proposed_envelope.max_period_overdraft_microusd
                > current_envelope.max_period_overdraft_microusd
                or self._budget_map_increases(
                    current_envelope.technical_by_price_code,
                    proposed_envelope.technical_by_price_code,
                )
                or self._budget_map_increases(
                    current_envelope.non_model_by_price_code,
                    proposed_envelope.non_model_by_price_code,
                )
            )
        if budget_increase:
            required_actions.append(CommercialAction.BUDGET_INCREASE)
        if command.terms.payer_policy_id != current_terms.payer_policy_id:
            required_actions.append(CommercialAction.PAYER_SWITCH)
        if not required_actions:
            if command.change_request_ids or command.step_up_event_id is not None:
                raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
            return None, ()
        if len(command.change_request_ids) != len(required_actions):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        if actor.actor_id is None or not actor.actor_id.isdigit():
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        operator = load_named_operator(
            self._connection,
            user_id=int(actor.actor_id),
            environment=actor.environment,
            step_up_event_id=command.step_up_event_id,
        )
        store = PostgresChangeRequestStore(self._connection)
        requests_by_action = {}
        for request_id in command.change_request_ids:
            request = store.get(request_id)
            if request is None or request.action in requests_by_action:
                raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
            requests_by_action[request.action] = request
        target_id = f"{agreement.public_id}:{command.terms.revision}"
        for action in required_actions:
            authority = ACTION_AUTHORITY[action]
            if authority.required_role not in operator.roles:
                raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
            if (
                operator.step_up_verified_at is None
                or operator.step_up_event_id is None
                or operator.step_up_verified_at < checked_at - timedelta(minutes=15)
                or operator.step_up_verified_at > checked_at
            ):
                raise CommercialError(CommercialErrorCode.COMMERCIAL_STEP_UP_REQUIRED)
            request = requests_by_action.get(action)
            if (
                request is None
                or request.environment != actor.environment
                or request.state != "approved"
                or request.expires_at <= checked_at
                or request.target_type != "commercial_agreement_terms"
                or request.target_id != target_id
                or request.payload_sha256
                != agreement_terms_change_authority_digest(
                    command,
                    prior_terms_id=current_terms.id,
                    action=action,
                )
            ):
                raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        return operator, command.change_request_ids

    @staticmethod
    def _budget_map_increases(
        current: dict[str, int], proposed: dict[str, int]
    ) -> bool:
        return any(
            price_code not in current or ceiling > current[price_code]
            for price_code, ceiling in proposed.items()
        )

    def _schedule_cancel_at_period_end(
        self,
        *,
        actor: _AgreementActorContext,
        command: AgreementScheduleCancelCommand,
    ) -> AgreementCommandResult:
        """Execute channel-neutral period-end cancellation scheduling."""

        return self._run_command_atomic(
            lambda: self._schedule_cancel_at_period_end_core(
                actor=actor, command=command
            )
        )

    def _schedule_cancel_at_period_end_core(
        self,
        *,
        actor: _AgreementActorContext,
        command: AgreementScheduleCancelCommand,
    ) -> AgreementCommandResult:
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "schedule_cancel",
                **command.model_dump(mode="python"),
            }
        )
        self._lock_idempotency(command.commercial_account_id, command.idempotency_key)
        replay = self._load_command_result(
            commercial_account_id=command.commercial_account_id,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        mutation_at = self._clock()
        before = self._repository.get_by_id_for_update(
            commercial_account_id=command.commercial_account_id,
            agreement_id=command.agreement_id,
        )
        if before is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_REQUIRED)
        if before.version != command.expected_version:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
            )
        if (
            before.state
            not in {
                AgreementState.TRIALING,
                AgreementState.ACTIVE,
                AgreementState.PAST_DUE,
                AgreementState.GRACE,
                AgreementState.PAUSED,
            }
            or before.current_period_end_at is None
            or before.current_period_end_at <= mutation_at
            or mutation_at <= before.updated_at
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        after = self._repository.schedule_cancel_at_period_end(
            expected=before,
            changed_at=mutation_at,
        )
        if after is None:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
            )
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=after.commercial_account_id,
                agreement_id=after.id,
                actor_type=actor.actor_type,
                actor_id=actor.actor_id,
                action="commercial.agreement.schedule_cancel",
                target_type="commercial_agreement",
                target_id=str(after.public_id),
                reason_code=command.reason_code,
                before={
                    "account_id": before.commercial_account_id,
                    "agreement_id": before.id,
                    "state": before.state.value,
                    "version": before.version,
                    "cancel_at_period_end": before.cancel_at_period_end,
                },
                after={
                    "account_id": after.commercial_account_id,
                    "agreement_id": after.id,
                    "state": after.state.value,
                    "version": after.version,
                    "cancel_at_period_end": after.cancel_at_period_end,
                    "result_code": "applied",
                },
            ),
        )
        result = AgreementCommandResult(
            command_id=uuid4(),
            agreement_id=after.id,
            commercial_account_id=after.commercial_account_id,
            state=after.state,
            version=after.version,
            audit_event_id=audit_event_id,
        )
        self._insert_command_result(
            result=result,
            before=before,
            actor=actor,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            effective_at=mutation_at,
            command_kind="schedule_cancel",
        )
        return result

    def _run_command_atomic(
        self,
        operation: Callable[[], AgreementCommandResult],
    ) -> AgreementCommandResult:
        if getattr(self._connection, "autocommit", False):
            raise ValueError("agreement lifecycle commands require autocommit disabled")
        cursor = self._connection.cursor()
        try:
            cursor.execute("SAVEPOINT commercial_agreement_command")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_agreement_command")
                cursor.execute("RELEASE SAVEPOINT commercial_agreement_command")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_agreement_command")
            return result
        finally:
            cursor.close()

    def _require_operator(self, user_id: int, environment: str) -> None:
        self._require_deployment_environment(environment)
        operator = load_named_operator(
            self._connection,
            user_id=user_id,
            environment=environment,
        )
        if CommercialRole.COMMERCIAL_ADMIN not in operator.roles:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)

    def _require_deployment_environment(self, environment: str) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None or row[0] != environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)

    def _lock_idempotency(self, account_id: int, idempotency_key: str) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext('commercial_agreement_command'), hashtext(%s))",
                (f"{account_id}:{idempotency_key}",),
            )
        finally:
            cursor.close()

    def _load_command_result(
        self,
        *,
        commercial_account_id: int,
        idempotency_key: str,
        payload_sha256: str,
    ) -> AgreementCommandResult | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT command_id, payload_sha256, agreement_id,
                       result_state, result_version, audit_event_id
                FROM commercial_agreement_commands
                WHERE commercial_account_id = %s AND idempotency_key = %s
                """,
                (commercial_account_id, idempotency_key),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[1] != payload_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return AgreementCommandResult(
            command_id=UUID(str(row[0])),
            agreement_id=row[2],
            commercial_account_id=commercial_account_id,
            state=AgreementState(row[3]),
            version=row[4],
            audit_event_id=UUID(str(row[5])),
            replayed=True,
        )

    def _load_terms_command_result(
        self,
        *,
        commercial_account_id: int,
        idempotency_key: str,
        payload_sha256: str,
    ) -> AgreementTermsCommandResult | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT command.command_id, command.payload_sha256,
                       command.agreement_id, command.result_state,
                       command.result_version, command.audit_event_id,
                       command.prior_terms_id, command.result_terms_id,
                       command.terms_change_timing,
                       terms.revision, terms.effective_from
                  FROM commercial_agreement_commands AS command
                  JOIN commercial_agreement_terms AS terms
                    ON terms.id = command.result_terms_id
                   AND terms.agreement_id = command.agreement_id
                   AND terms.commercial_account_id = command.commercial_account_id
                 WHERE command.commercial_account_id = %s
                   AND command.idempotency_key = %s
                """,
                (commercial_account_id, idempotency_key),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            existing = self._load_command_result(
                commercial_account_id=commercial_account_id,
                idempotency_key=idempotency_key,
                payload_sha256=payload_sha256,
            )
            if existing is not None:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT
                )
            return None
        if row[1] != payload_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return AgreementTermsCommandResult(
            command_id=UUID(str(row[0])),
            agreement_id=row[2],
            commercial_account_id=commercial_account_id,
            state=AgreementState(row[3]),
            version=row[4],
            audit_event_id=UUID(str(row[5])),
            prior_terms_id=row[6],
            result_terms_id=row[7],
            change_timing=row[8],
            result_terms_revision=row[9],
            effective_from=row[10],
            replayed=True,
        )

    def _insert_command_result(
        self,
        *,
        result: AgreementCommandResult,
        before: CommercialAgreementRecord,
        actor: _AgreementActorContext,
        idempotency_key: str,
        payload_sha256: str,
        effective_at: datetime,
        command_kind: str = "transition",
        prior_terms_id: int | None = None,
        result_terms_id: int | None = None,
        terms_change_timing: str | None = None,
    ) -> None:
        cursor = self._connection.cursor()
        try:
            common_params = (
                str(result.command_id),
                result.commercial_account_id,
                result.agreement_id,
                actor.environment,
                idempotency_key,
                command_kind,
                payload_sha256,
                actor.actor_type,
                actor.actor_id,
                effective_at,
                before.state.value,
                before.version,
                result.state.value,
                result.version,
            )
            if command_kind == "schedule_terms":
                cursor.execute(
                    """
                    INSERT INTO commercial_agreement_commands (
                        command_id, commercial_account_id, agreement_id, environment,
                        idempotency_key, command_kind, payload_sha256,
                        actor_type, actor_id, effective_at,
                        prior_state, prior_version, result_state, result_version,
                        prior_terms_id, result_terms_id, terms_change_timing,
                        audit_event_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (
                        *common_params,
                        prior_terms_id,
                        result_terms_id,
                        terms_change_timing,
                        str(result.audit_event_id),
                    ),
                )
            else:
                cursor.execute(
                    """
                    INSERT INTO commercial_agreement_commands (
                        command_id, commercial_account_id, agreement_id, environment,
                        idempotency_key, command_kind, payload_sha256,
                        actor_type, actor_id, effective_at,
                        prior_state, prior_version, result_state, result_version,
                        audit_event_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s, %s, %s
                    )
                    """,
                    (*common_params, str(result.audit_event_id)),
                )
        finally:
            cursor.close()

    def _future_terms_count(
        self,
        agreement: CommercialAgreementRecord,
        effective_at: datetime,
    ) -> int:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM commercial_agreement_terms
                WHERE commercial_account_id = %s AND agreement_id = %s
                  AND effective_from >= %s
                  AND (to_jsonb(commercial_agreement_terms)->>'voided_at') IS NULL
                """,
                (agreement.commercial_account_id, agreement.id, effective_at),
            )
            future_count = cursor.fetchone()[0]
        finally:
            cursor.close()
        return int(future_count)

    def _assert_effective_terms(
        self,
        agreement: CommercialAgreementRecord,
        effective_at: datetime,
    ) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT COUNT(*)
                  FROM commercial_agreement_terms
                 WHERE commercial_account_id = %s
                   AND agreement_id = %s
                   AND sealed_at IS NOT NULL
                   AND (to_jsonb(commercial_agreement_terms)->>'voided_at') IS NULL
                   AND effective_from <= %s
                   AND (effective_until IS NULL OR effective_until > %s)
                """,
                (
                    agreement.commercial_account_id,
                    agreement.id,
                    effective_at,
                    effective_at,
                ),
            )
            effective_count = cursor.fetchone()[0]
        finally:
            cursor.close()
        if effective_count != 1:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )


__all__ = [
    "AgreementCommandResult",
    "AgreementProjectionHook",
    "AgreementScheduleCancelCommand",
    "AgreementTermsChangeCommand",
    "AgreementTermsCommandResult",
    "AgreementTransitionCommand",
    "CommercialAgreementLifecycleService",
    "INVITE_TRIAL_EXPIRER_ACTOR_ID",
    "agreement_terms_change_authority_digest",
]
