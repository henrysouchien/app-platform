"""Durably idempotent named-operator request and approval commands."""

from __future__ import annotations

from datetime import datetime, timedelta
from functools import wraps
from typing import Annotated, Literal
from uuid import UUID, uuid4

from pydantic import Field, StrictBool, TypeAdapter

from .agreement_lifecycle import IdempotencyKey
from .authority import (
    CommercialAction,
    CommercialChangeRequestV1,
    approve_change_request,
    create_change_request,
)
from .authority_store import PostgresChangeRequestStore, load_named_operator
from .errors import CommercialError, CommercialErrorCode
from .manual_agreements import (
    ManualAgreementActivationIntent,
    ManualAgreementService,
    manual_agreement_activation_digest,
)
from .models import (
    NonEmptyStr,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)


_IDEMPOTENCY_KEY = TypeAdapter(IdempotencyKey)


def _atomic_command(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class ChangeRequestCommandResult(StrictCommercialModel):
    command_id: UUID
    request: CommercialChangeRequestV1
    replayed: StrictBool = False


class ChangeRequestCommandService:
    def __init__(
        self,
        connection,
        *,
        manual_agreement_service: ManualAgreementService | None = None,
    ):
        self._connection = connection
        self._store = PostgresChangeRequestStore(connection)
        self._manual_agreement_service = manual_agreement_service

    @_atomic_command
    def request_manual_activation(
        self,
        *,
        operator_user_id: int,
        environment: Literal["dev", "staging", "prod"],
        step_up_event_id: UUID,
        idempotency_key: IdempotencyKey,
        intent: ManualAgreementActivationIntent,
        expires_in_seconds: Annotated[int, Field(ge=60, le=86400)],
        now: datetime,
    ) -> ChangeRequestCommandResult:
        idempotency_key = _IDEMPOTENCY_KEY.validate_python(idempotency_key)
        if not 60 <= expires_in_seconds <= 86400:
            raise ValueError("expires_in_seconds must be between 60 and 86400")
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "request",
                "environment": environment,
                "expires_in_seconds": expires_in_seconds,
                "intent": intent.model_dump(mode="python"),
            }
        )
        self._lock(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="request",
            idempotency_key=idempotency_key,
        )
        replay = self._load(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="request",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        if self._manual_agreement_service is None:
            raise RuntimeError("manual agreement service is required")
        agreement = (
            self._manual_agreement_service.validate_activation_intent_as_operator(
                operator_user_id=operator_user_id,
                runtime_environment=environment,
                intent=intent,
            )
        )
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        authority_sha256 = manual_agreement_activation_digest(intent)
        request = create_change_request(
            store=self._store,
            operator=operator,
            action=CommercialAction.MANUAL_AGREEMENT_ACTIVATION,
            environment=environment,
            target_type="commercial_agreement",
            target_id=str(agreement.public_id),
            payload_sha256=authority_sha256,
            reason_code=intent.reason_code,
            expires_at=now + timedelta(seconds=expires_in_seconds),
            now=now,
        )
        result = ChangeRequestCommandResult(command_id=uuid4(), request=request)
        self._insert(
            result=result,
            environment=environment,
            command_kind="request",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
            authority_sha256=authority_sha256,
            actor_user_id=operator_user_id,
        )
        return result

    @_atomic_command
    def request_execution_scope_override(
        self,
        *,
        operator_user_id: int,
        environment: Literal["dev", "staging", "prod"],
        step_up_event_id: UUID,
        idempotency_key: IdempotencyKey,
        target_type: StableCode,
        target_id: NonEmptyStr,
        authority_sha256: Sha256Digest,
        reason_code: StableCode,
        expires_in_seconds: Annotated[int, Field(ge=60, le=86400)],
        now: datetime,
    ) -> ChangeRequestCommandResult:
        idempotency_key = _IDEMPOTENCY_KEY.validate_python(idempotency_key)
        if not 60 <= expires_in_seconds <= 86400:
            raise ValueError("expires_in_seconds must be between 60 and 86400")
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "request",
                "action": CommercialAction.EXECUTION_SCOPE_OVERRIDE,
                "environment": environment,
                "target_type": target_type,
                "target_id": target_id,
                "authority_sha256": authority_sha256,
                "reason_code": reason_code,
                "expires_in_seconds": expires_in_seconds,
            }
        )
        self._lock(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="request",
            idempotency_key=idempotency_key,
        )
        replay = self._load(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="request",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        request = create_change_request(
            store=self._store,
            operator=operator,
            action=CommercialAction.EXECUTION_SCOPE_OVERRIDE,
            environment=environment,
            target_type=target_type,
            target_id=target_id,
            payload_sha256=authority_sha256,
            reason_code=reason_code,
            expires_at=now + timedelta(seconds=expires_in_seconds),
            now=now,
        )
        result = ChangeRequestCommandResult(command_id=uuid4(), request=request)
        self._insert(
            result=result,
            environment=environment,
            command_kind="request",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
            authority_sha256=authority_sha256,
            actor_user_id=operator_user_id,
        )
        return result

    @_atomic_command
    def approve_execution_scope_override(
        self,
        *,
        operator_user_id: int,
        environment: Literal["dev", "staging", "prod"],
        step_up_event_id: UUID,
        idempotency_key: IdempotencyKey,
        request_id: UUID,
        now: datetime,
    ) -> ChangeRequestCommandResult:
        idempotency_key = _IDEMPOTENCY_KEY.validate_python(idempotency_key)
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "approve",
                "action": CommercialAction.EXECUTION_SCOPE_OVERRIDE,
                "environment": environment,
                "request_id": request_id,
            }
        )
        self._lock(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="approve",
            idempotency_key=idempotency_key,
        )
        replay = self._load(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="approve",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        request = self._store.get(request_id)
        if (
            request is None
            or request.environment != environment
            or request.action != CommercialAction.EXECUTION_SCOPE_OVERRIDE
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        approved = approve_change_request(
            request_id, store=self._store, operator=operator, now=now
        )
        result = ChangeRequestCommandResult(command_id=uuid4(), request=approved)
        self._insert(
            result=result,
            environment=environment,
            command_kind="approve",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
            authority_sha256=approved.payload_sha256,
            actor_user_id=operator_user_id,
        )
        return result

    @_atomic_command
    def request_live_stripe_repair(
        self,
        *,
        operator_user_id: int,
        environment: Literal["dev", "staging", "prod"],
        step_up_event_id: UUID,
        idempotency_key: IdempotencyKey,
        finding_id: UUID,
        reason_code: StableCode,
        expires_in_seconds: Annotated[int, Field(ge=60, le=86400)],
        now: datetime,
    ) -> ChangeRequestCommandResult:
        """Request approval for one exact reconciliation-finding repair."""

        idempotency_key = _IDEMPOTENCY_KEY.validate_python(idempotency_key)
        if not 60 <= expires_in_seconds <= 86400:
            raise ValueError("expires_in_seconds must be between 60 and 86400")
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "request",
                "action": CommercialAction.LIVE_STRIPE_REPAIR,
                "environment": environment,
                "finding_id": str(finding_id),
                "reason_code": reason_code,
                "expires_in_seconds": expires_in_seconds,
            }
        )
        self._lock(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="request",
            idempotency_key=idempotency_key,
        )
        replay = self._load(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="request",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        intent_id = uuid4()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO commercial_stripe_repair_intents (
                       intent_id, environment, commercial_account_id,
                       source_finding_id, suite_code, fingerprint_sha256,
                       finding_code, repair_code, subject_type, subject_id,
                       expected_sha256, observed_sha256, source_last_seen_at,
                       authority_sha256, created_by_user_id
                   )
                   SELECT %s, finding.environment, finding.commercial_account_id,
                          finding.finding_id, finding.suite_code,
                          finding.fingerprint_sha256, finding.code,
                          finding.suggested_repair, finding.subject_type,
                          finding.subject_id,
                          'sha256:' || encode(public.digest(
                              convert_to(finding.expected::TEXT, 'UTF8'), 'sha256'
                          ), 'hex'),
                          'sha256:' || encode(public.digest(
                              convert_to(finding.observed::TEXT, 'UTF8'), 'sha256'
                          ), 'hex'),
                          finding.last_seen_at,
                          commercial_stripe_repair_intent_sha256(
                              %s, finding.finding_id
                          ), %s
                     FROM commercial_reconciliation_current_findings finding
                    WHERE finding.finding_id = %s
                      AND finding.environment = %s
                      AND finding.scope_type = 'account'
                      AND finding.commercial_account_id IS NOT NULL
                      AND finding.resolution_state = 'open'
                      AND finding.repair_kind = 'operator'
                      AND (
                          (
                              finding.suite_code = 'stripe_provider.v1'
                              AND finding.suggested_repair =
                                  'stripe.subscription_projection_repair'
                              AND finding.subject_type = 'stripe_subscription'
                              AND finding.code IN (
                                  'stripe.subscription_state_drift',
                                  'stripe.subscription_cancellation_drift',
                                  'stripe.subscription_period_drift'
                              )
                          ) OR (
                              finding.suite_code = 'stripe_monetary.v1'
                              AND (
                                  (
                                      finding.code = 'stripe.money_movement_drift'
                                      AND finding.suggested_repair =
                                          'stripe.money_movement_projection_repair'
                                      AND finding.subject_type = 'stripe_movement'
                                      AND finding.subject_id ~ (
                                          '^(payment_intent:pi_[A-Za-z0-9]{4,252}:cash_receipt'
                                          || '|refund:re_[A-Za-z0-9]{4,252}:refund'
                                          || '|dispute:dp_[A-Za-z0-9]{4,252}:'
                                          || '(dispute_hold|dispute_release)'
                                          || '|balance_transaction:'
                                          || '[A-Za-z][A-Za-z0-9_]{4,254}:'
                                          || 'processor_fee)$'
                                      )
                                  ) OR (
                                      finding.code = 'stripe.invoice_missing_local'
                                      AND finding.suggested_repair =
                                          'stripe.invoice_projection_repair'
                                      AND finding.subject_type = 'stripe_invoice'
                                      AND finding.subject_id ~
                                          '^in_[A-Za-z0-9]{5,252}$'
                                  )
                              )
                              AND finding.expected = jsonb_build_object(
                                  'present', FALSE, 'digest', NULL
                              )
                              AND finding.observed ?& ARRAY['present', 'digest']
                              AND (SELECT COUNT(*) FROM jsonb_object_keys(
                                  finding.observed
                              )) = 2
                              AND finding.observed->'present' = 'true'::jsonb
                              AND finding.observed->>'digest' ~
                                  '^sha256:[0-9a-f]{64}$'
                          )
                      )
                RETURNING authority_sha256""",
                (
                    str(intent_id),
                    str(intent_id),
                    operator_user_id,
                    str(finding_id),
                    environment,
                ),
            )
            intent = cursor.fetchone()
        finally:
            cursor.close()
        if intent is None:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_BILLING_SOURCE_CONFLICT,
                internal_detail=(
                    "live Stripe repair source is not a current actionable finding"
                ),
            )
        authority_sha256 = str(intent[0])
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        request = create_change_request(
            store=self._store,
            operator=operator,
            action=CommercialAction.LIVE_STRIPE_REPAIR,
            environment=environment,
            target_type="commercial_stripe_repair_intent",
            target_id=str(intent_id),
            payload_sha256=authority_sha256,
            reason_code=reason_code,
            expires_at=now + timedelta(seconds=expires_in_seconds),
            now=now,
        )
        result = ChangeRequestCommandResult(command_id=uuid4(), request=request)
        self._insert(
            result=result,
            environment=environment,
            command_kind="request",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
            authority_sha256=authority_sha256,
            actor_user_id=operator_user_id,
        )
        return result

    @_atomic_command
    def approve_live_stripe_repair(
        self,
        *,
        operator_user_id: int,
        environment: Literal["dev", "staging", "prod"],
        step_up_event_id: UUID,
        idempotency_key: IdempotencyKey,
        request_id: UUID,
        now: datetime,
    ) -> ChangeRequestCommandResult:
        """Approve one exact live-Stripe repair request."""

        idempotency_key = _IDEMPOTENCY_KEY.validate_python(idempotency_key)
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "approve",
                "action": CommercialAction.LIVE_STRIPE_REPAIR,
                "environment": environment,
                "request_id": str(request_id),
            }
        )
        self._lock(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="approve",
            idempotency_key=idempotency_key,
        )
        replay = self._load(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="approve",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        request = self._store.get(request_id)
        if (
            request is None
            or request.environment != environment
            or request.action != CommercialAction.LIVE_STRIPE_REPAIR
            or request.target_type != "commercial_stripe_repair_intent"
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        approved = approve_change_request(
            request_id, store=self._store, operator=operator, now=now
        )
        result = ChangeRequestCommandResult(command_id=uuid4(), request=approved)
        self._insert(
            result=result,
            environment=environment,
            command_kind="approve",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
            authority_sha256=approved.payload_sha256,
            actor_user_id=operator_user_id,
        )
        return result

    @_atomic_command
    def approve_manual_activation(
        self,
        *,
        operator_user_id: int,
        environment: Literal["dev", "staging", "prod"],
        step_up_event_id: UUID,
        idempotency_key: IdempotencyKey,
        request_id: UUID,
        now: datetime,
    ) -> ChangeRequestCommandResult:
        idempotency_key = _IDEMPOTENCY_KEY.validate_python(idempotency_key)
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "approve",
                "environment": environment,
                "request_id": request_id,
            }
        )
        self._lock(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="approve",
            idempotency_key=idempotency_key,
        )
        replay = self._load(
            operator_user_id=operator_user_id,
            environment=environment,
            command_kind="approve",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        request = self._store.get(request_id)
        if (
            request is None
            or request.environment != environment
            or request.action != CommercialAction.MANUAL_AGREEMENT_ACTIVATION
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=environment,
            step_up_event_id=step_up_event_id,
        )
        approved = approve_change_request(
            request_id, store=self._store, operator=operator, now=now
        )
        result = ChangeRequestCommandResult(command_id=uuid4(), request=approved)
        self._insert(
            result=result,
            environment=environment,
            command_kind="approve",
            idempotency_key=idempotency_key,
            payload_sha256=payload_sha256,
            authority_sha256=approved.payload_sha256,
            actor_user_id=operator_user_id,
        )
        return result

    def _lock(self, *, operator_user_id, environment, command_kind, idempotency_key):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                (
                    operator_user_id,
                    f"{environment}:{command_kind}:{idempotency_key}",
                ),
            )
        finally:
            cursor.close()

    def _load(
        self,
        *,
        operator_user_id,
        environment,
        command_kind,
        idempotency_key,
        payload_sha256,
    ) -> ChangeRequestCommandResult | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT command_id, payload_sha256, request_id,
                       result_state, result_version
                  FROM commercial_change_request_commands
                 WHERE actor_user_id = %s AND environment = %s
                   AND command_kind = %s AND idempotency_key = %s
                """,
                (operator_user_id, environment, command_kind, idempotency_key),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[1] != payload_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        current = self._store.get(UUID(str(row[2])))
        if current is None:
            raise RuntimeError("durable change request command lost its request")
        request = self._reconstruct_result(
            current=current, result_state=row[3], result_version=row[4]
        )
        return ChangeRequestCommandResult(
            command_id=UUID(str(row[0])), request=request, replayed=True
        )

    def _insert(
        self,
        *,
        result,
        environment,
        command_kind,
        idempotency_key,
        payload_sha256,
        authority_sha256,
        actor_user_id,
    ) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO commercial_change_request_commands (
                    command_id, environment, command_kind, idempotency_key,
                    payload_sha256, authority_sha256, actor_user_id, request_id,
                    result_state, result_version
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    str(result.command_id),
                    environment,
                    command_kind,
                    idempotency_key,
                    payload_sha256,
                    authority_sha256,
                    actor_user_id,
                    str(result.request.request_id),
                    result.request.state,
                    result.request.version,
                ),
            )
        finally:
            cursor.close()

    @staticmethod
    def _reconstruct_result(
        *, current: CommercialChangeRequestV1, result_state: str, result_version: int
    ) -> CommercialChangeRequestV1:
        payload = current.model_dump(mode="python")
        payload.update(
            {
                "state": result_state,
                "version": result_version,
                "execution_succeeded": None,
                "execution_result_code": None,
                "executed_at": None,
                "executor_user_id": None,
                "executor_step_up_at": None,
                "executor_step_up_event_id": None,
                "audit_event_id": None,
            }
        )
        if result_state == "pending":
            payload.update(
                {
                    "approver_user_id": None,
                    "approved_at": None,
                    "approver_step_up_at": None,
                    "approver_step_up_event_id": None,
                }
            )
        return CommercialChangeRequestV1.model_validate(payload)

    def _run_atomic(self, operation):
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("change request commands require a transaction")
        cursor = self._connection.cursor()
        try:
            cursor.execute("SAVEPOINT commercial_change_request_command")
            try:
                result = operation()
            except BaseException:
                cursor.execute(
                    "ROLLBACK TO SAVEPOINT commercial_change_request_command"
                )
                cursor.execute("RELEASE SAVEPOINT commercial_change_request_command")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_change_request_command")
            return result
        finally:
            cursor.close()


__all__ = ["ChangeRequestCommandResult", "ChangeRequestCommandService"]
