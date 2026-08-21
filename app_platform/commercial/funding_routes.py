"""Idempotent durable funding-route classification and persistence."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Annotated, Any, Callable, Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator

from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .flags import CommercialFlags, get_commercial_flags
from .models import NonEmptyStr, Sha256Digest, StableCode, StrictCommercialModel, canonical_sha256
from .payer import (
    ObservedCredentialRoute,
    PayerClass,
    PayerDecisionState,
    PostgresPayerClassifier,
)


logger = logging.getLogger(__name__)


class FundingRouteCreateCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    idempotency_key: Annotated[NonEmptyStr, Field(max_length=255, pattern=r"^\S+$")]
    agreement_terms_id: Annotated[StrictInt, Field(gt=0)]
    observed_route: ObservedCredentialRoute
    credential_owner_user_id: Annotated[StrictInt, Field(gt=0)] | None = None
    effective_from: AwareDatetime
    effective_until: AwareDatetime | None = None

    @model_validator(mode="after")
    def _valid_command(self) -> "FundingRouteCreateCommand":
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("funding route effective range is empty")
        is_customer = self.observed_route.credential_owner == "customer"
        if is_customer != (self.credential_owner_user_id is not None):
            raise ValueError("only customer funding routes require an owner user")
        return self


class FundingRouteRecord(StrictCommercialModel):
    id: UUID
    environment: Literal["dev", "staging", "prod"]
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    agreement_terms_id: Annotated[StrictInt, Field(gt=0)]
    payer_policy_id: Annotated[StrictInt, Field(gt=0)]
    provider: StableCode
    cost_class: StableCode
    credential_route: StableCode
    credential_owner_kind: Literal["customer", "hank", "flat_subscription"]
    credential_owner_user_id: Annotated[StrictInt, Field(gt=0)] | None = None
    credential_binding_hash: Sha256Digest
    billing_mode: Literal["byok", "metered"]
    classification_state: Literal["active", "quarantined"]
    payer_class: PayerClass | None = None
    classification_reason_code: StableCode
    effective_from: AwareDatetime
    effective_until: AwareDatetime | None = None
    revoked_at: AwareDatetime | None = None
    revocation_reason_code: StableCode | None = None
    revocation_audit_event_id: UUID | None = None
    audit_event_id: UUID
    replayed: StrictBool = False

    @model_validator(mode="after")
    def _coherent_revocation(self) -> "FundingRouteRecord":
        evidence = (
            self.revoked_at,
            self.revocation_reason_code,
            self.revocation_audit_event_id,
        )
        if any(value is not None for value in evidence) and not all(
            value is not None for value in evidence
        ):
            raise ValueError("funding route revocation evidence is incomplete")
        return self


class FundingRouteRevokeCommand(StrictCommercialModel):
    environment: Literal["dev", "staging", "prod"]
    funding_route_id: UUID
    reason_code: StableCode
    revoked_at: AwareDatetime


class FundingRouteService:
    """Reclassify from durable terms and persist exact observed route evidence."""

    def __init__(
        self,
        connection: Any,
        *,
        flags: CommercialFlags | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._flags = flags or get_commercial_flags()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def create(self, command: FundingRouteCreateCommand) -> FundingRouteRecord:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("funding route creation requires a transaction")
        if not self._flags.commercial_control_enabled:
            raise RuntimeError("commercial control is disabled")
        if command.environment != self._flags.environment:
            raise ValueError("funding route environment does not match deployment")
        payload_sha256 = canonical_sha256(command.model_dump(mode="python"))
        self._lock_idempotency(command.environment, command.idempotency_key)
        replay = self._load_replay(
            environment=command.environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        decision = PostgresPayerClassifier(self._connection).classify(
            agreement_terms_id=command.agreement_terms_id,
            observed_route=command.observed_route,
            evaluated_at=command.effective_from,
        )
        route_id = uuid4()
        audit_event_id = uuid4()
        result_code = (
            "applied"
            if decision.state is PayerDecisionState.CLASSIFIED
            else "rejected"
        )
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=decision.commercial_account_id,
                agreement_id=decision.agreement_id,
                actor_type="service",
                actor_id="commercial-control",
                action="commercial.funding_route.classify",
                target_type="commercial_funding_route",
                target_id=str(route_id),
                reason_code=decision.reason_code,
                after={
                    "account_id": decision.commercial_account_id,
                    "agreement_id": decision.agreement_id,
                    "result_code": result_code,
                },
            ),
        )
        record = FundingRouteRecord(
            id=route_id,
            environment=command.environment,
            commercial_account_id=decision.commercial_account_id,
            agreement_id=decision.agreement_id,
            agreement_terms_id=decision.agreement_terms_id,
            payer_policy_id=decision.payer_policy.policy_id,
            provider=command.observed_route.provider,
            cost_class=command.observed_route.cost_class,
            credential_route=command.observed_route.credential_route,
            credential_owner_kind=command.observed_route.credential_owner,
            credential_owner_user_id=command.credential_owner_user_id,
            credential_binding_hash=(
                command.observed_route.credential_reference_sha256
            ),
            billing_mode=(
                "byok"
                if command.observed_route.credential_owner == "customer"
                else "metered"
            ),
            classification_state=(
                "active"
                if decision.state is PayerDecisionState.CLASSIFIED
                else "quarantined"
            ),
            payer_class=decision.payer_class,
            classification_reason_code=decision.reason_code,
            effective_from=command.effective_from,
            effective_until=command.effective_until,
            audit_event_id=audit_event_id,
        )
        self._insert(record, command=command, payload_sha256=payload_sha256)
        if record.classification_state == "quarantined":
            logger.warning(
                "Commercial funding route quarantined reason=%s provider=%s cost_class=%s",
                record.classification_reason_code,
                record.provider,
                record.cost_class,
            )
        return record

    def revoke(self, command: FundingRouteRevokeCommand) -> FundingRouteRecord:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("funding route revocation requires a transaction")
        if not self._flags.commercial_control_enabled:
            raise RuntimeError("commercial control is disabled")
        if command.environment != self._flags.environment:
            raise ValueError("funding route environment does not match deployment")
        if command.revoked_at > self._clock():
            raise ValueError("funding route revocation cannot be future-dated")
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT commercial_account_id, agreement_id, revoked_at,
                       revocation_reason_code
                  FROM commercial_funding_routes
                 WHERE id = %s AND environment = %s
                 FOR UPDATE
                """,
                (str(command.funding_route_id), command.environment),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise ValueError("funding route does not exist")
        if row[2] is not None:
            if row[2] != command.revoked_at or row[3] != command.reason_code:
                raise ValueError("funding route revocation conflicts with prior facts")
            record = self._get_by_id(command.funding_route_id)
            return record.model_copy(update={"replayed": True})
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=int(row[0]),
                agreement_id=int(row[1]),
                actor_type="service",
                actor_id="commercial-control",
                action="commercial.funding_route.revoke",
                target_type="commercial_funding_route",
                target_id=str(command.funding_route_id),
                reason_code=command.reason_code,
                after={
                    "account_id": int(row[0]),
                    "agreement_id": int(row[1]),
                    "result_code": "revoked",
                },
            ),
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE commercial_funding_routes
                   SET revoked_at = %s, revocation_reason_code = %s,
                       revocation_audit_event_id = %s
                 WHERE id = %s AND revoked_at IS NULL
                """,
                (
                    command.revoked_at,
                    command.reason_code,
                    str(audit_event_id),
                    str(command.funding_route_id),
                ),
            )
            if cursor.rowcount != 1:
                raise RuntimeError("funding route revocation lost its row lock")
        finally:
            cursor.close()
        return self._get_by_id(command.funding_route_id)

    def _lock_idempotency(self, environment: str, key: str) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"commercial-funding-route:{environment}:{key}",),
            )
        finally:
            cursor.close()

    def _load_replay(
        self, *, environment: str, idempotency_key: str, payload_sha256: str
    ) -> FundingRouteRecord | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT id, payload_sha256, environment, commercial_account_id,
                       agreement_id, agreement_terms_id, payer_policy_id, provider,
                       cost_class, credential_route, credential_owner_kind,
                       credential_owner_user_id, credential_binding_hash, billing_mode,
                       classification_state, payer_class, classification_reason_code,
                       effective_from, effective_until, revoked_at,
                       revocation_reason_code, revocation_audit_event_id,
                       audit_event_id
                  FROM commercial_funding_routes
                 WHERE environment = %s AND idempotency_key = %s
                """,
                (environment, idempotency_key),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[1] != payload_sha256:
            raise ValueError("funding route idempotency key conflicts with prior payload")
        return FundingRouteRecord(
            id=row[0],
            environment=row[2],
            commercial_account_id=row[3],
            agreement_id=row[4],
            agreement_terms_id=row[5],
            payer_policy_id=row[6],
            provider=row[7],
            cost_class=row[8],
            credential_route=row[9],
            credential_owner_kind=row[10],
            credential_owner_user_id=row[11],
            credential_binding_hash=row[12],
            billing_mode=row[13],
            classification_state=row[14],
            payer_class=row[15],
            classification_reason_code=row[16],
            effective_from=row[17],
            effective_until=row[18],
            revoked_at=row[19],
            revocation_reason_code=row[20],
            revocation_audit_event_id=row[21],
            audit_event_id=row[22],
            replayed=True,
        )

    def _get_by_id(self, route_id: UUID) -> FundingRouteRecord:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT id, environment, commercial_account_id, agreement_id,
                       agreement_terms_id, payer_policy_id, provider, cost_class,
                       credential_route, credential_owner_kind,
                       credential_owner_user_id, credential_binding_hash, billing_mode,
                       classification_state, payer_class, classification_reason_code,
                       effective_from, effective_until, revoked_at,
                       revocation_reason_code, revocation_audit_event_id, audit_event_id
                  FROM commercial_funding_routes WHERE id = %s
                """,
                (str(route_id),),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise ValueError("funding route does not exist")
        return FundingRouteRecord(
            id=row[0],
            environment=row[1],
            commercial_account_id=row[2],
            agreement_id=row[3],
            agreement_terms_id=row[4],
            payer_policy_id=row[5],
            provider=row[6],
            cost_class=row[7],
            credential_route=row[8],
            credential_owner_kind=row[9],
            credential_owner_user_id=row[10],
            credential_binding_hash=row[11],
            billing_mode=row[12],
            classification_state=row[13],
            payer_class=row[14],
            classification_reason_code=row[15],
            effective_from=row[16],
            effective_until=row[17],
            revoked_at=row[18],
            revocation_reason_code=row[19],
            revocation_audit_event_id=row[20],
            audit_event_id=row[21],
        )

    def _insert(
        self,
        record: FundingRouteRecord,
        *,
        command: FundingRouteCreateCommand,
        payload_sha256: str,
    ) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO commercial_funding_routes (
                    id, environment, idempotency_key, payload_sha256,
                    commercial_account_id, agreement_id, agreement_terms_id,
                    payer_policy_id, provider, cost_class, credential_route,
                    credential_owner_kind, credential_owner_user_id,
                    credential_binding_hash, billing_mode, classification_state,
                    payer_class, classification_reason_code, effective_from,
                    effective_until, audit_event_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(record.id),
                    record.environment,
                    command.idempotency_key,
                    payload_sha256,
                    record.commercial_account_id,
                    record.agreement_id,
                    record.agreement_terms_id,
                    record.payer_policy_id,
                    record.provider,
                    record.cost_class,
                    record.credential_route,
                    record.credential_owner_kind,
                    record.credential_owner_user_id,
                    record.credential_binding_hash,
                    record.billing_mode,
                    record.classification_state,
                    record.payer_class.value if record.payer_class else None,
                    record.classification_reason_code,
                    record.effective_from,
                    record.effective_until,
                    str(record.audit_event_id),
                ),
            )
        finally:
            cursor.close()


__all__ = [
    "FundingRouteCreateCommand",
    "FundingRouteRecord",
    "FundingRouteRevokeCommand",
    "FundingRouteService",
]
