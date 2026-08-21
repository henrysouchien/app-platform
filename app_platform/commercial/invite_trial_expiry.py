"""Fenced automatic expiry for invite-only trial agreements and tokens."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, StrictBool, StrictInt

from .agreement_lifecycle import (
    AgreementTransitionCommand,
    CommercialAgreementLifecycleService,
)
from .agreements import AgreementState
from .entitlement_store import AccountEntitlementProjectionHook
from .flags import CommercialFlags
from .mcp_token_lifecycle import McpTokenLifecycleService
from .models import StrictCommercialModel


PositiveInt = Annotated[StrictInt, Field(gt=0)]


class InviteTrialExpiryCandidate(StrictCommercialModel):
    activation_id: UUID
    commercial_account_id: PositiveInt
    agreement_id: PositiveInt
    expected_agreement_version: PositiveInt
    observed_entitlement_revision: PositiveInt
    trial_expires_at: AwareDatetime


class InviteTrialExpiryResult(StrictCommercialModel):
    activation_id: UUID
    commercial_account_id: PositiveInt
    agreement_id: PositiveInt
    disposition: Literal["expired", "superseded"]
    agreement_version: PositiveInt | None = None
    entitlement_revision: PositiveInt | None = None
    token_expiration_count: Annotated[StrictInt, Field(ge=0)] = 0
    projection_changed: StrictBool = False


class _InviteTrialExpiryFenceSuperseded(RuntimeError):
    pass


class PostgresInviteTrialExpiryProtocol:
    """Terminalize one due trial and expire its token in one transaction."""

    def __init__(self, connection: object, *, flags: CommercialFlags, clock) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._clock = clock

    def find_due(
        self, *, partition: str, limit: int
    ) -> tuple[InviteTrialExpiryCandidate, ...]:
        if not partition.isdigit() or partition.startswith("0") or len(partition) > 16:
            raise ValueError("invite trial expiry partition is invalid")
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("invite trial expiry limit is invalid")
        now = self._now()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_try_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"commercial.invite_trial.expiry:{partition}",),
            )
            if not bool(cursor.fetchone()[0]):
                self._connection.rollback()  # type: ignore[attr-defined]
                return ()
            cursor.execute(
                """SELECT activation.activation_id,
                          activation.commercial_account_id,
                          activation.agreement_id, agreement.version,
                          revision.revision, activation.trial_expires_at
                     FROM commercial_trial_activations AS activation
                     JOIN commercial_agreements AS agreement
                       ON agreement.id = activation.agreement_id
                      AND agreement.commercial_account_id =
                          activation.commercial_account_id
                     JOIN commercial_entitlement_revisions AS revision
                       ON revision.commercial_account_id =
                          activation.commercial_account_id
                    WHERE activation.environment = %s
                      AND agreement.channel = 'invite_trial'
                      AND agreement.state = 'trialing'
                      AND agreement.trial_end_at = activation.trial_expires_at
                      AND activation.trial_expires_at <= %s
                    ORDER BY activation.trial_expires_at, activation.activation_id
                    LIMIT %s""",
                (self._flags.environment, now, limit),
            )
            rows = cursor.fetchall()
            self._connection.commit()  # type: ignore[attr-defined]
            return tuple(
                InviteTrialExpiryCandidate(
                    activation_id=row[0],
                    commercial_account_id=row[1],
                    agreement_id=row[2],
                    expected_agreement_version=row[3],
                    observed_entitlement_revision=row[4],
                    trial_expires_at=row[5],
                )
                for row in rows
            )
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        finally:
            cursor.close()

    def find_due_account_ids(
        self,
        commercial_account_ids: tuple[int, ...],
    ) -> frozenset[int]:
        """Return every supplied account that still has due trial authority."""

        if len(commercial_account_ids) > 1000 or any(
            isinstance(value, bool) or type(value) is not int or value <= 0
            for value in commercial_account_ids
        ):
            raise ValueError("invite trial expiry account filter is invalid")
        if not commercial_account_ids:
            return frozenset()
        now = self._now()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT DISTINCT activation.commercial_account_id
                     FROM commercial_trial_activations AS activation
                     JOIN commercial_agreements AS agreement
                       ON agreement.id = activation.agreement_id
                      AND agreement.commercial_account_id =
                          activation.commercial_account_id
                    WHERE activation.environment = %s
                      AND activation.commercial_account_id = ANY(%s)
                      AND agreement.channel = 'invite_trial'
                      AND agreement.state = 'trialing'
                      AND agreement.trial_end_at = activation.trial_expires_at
                      AND activation.trial_expires_at <= %s""",
                (
                    self._flags.environment,
                    list(commercial_account_ids),
                    now,
                ),
            )
            rows = cursor.fetchall()
            self._connection.commit()  # type: ignore[attr-defined]
            return frozenset(int(row[0]) for row in rows)
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise
        finally:
            cursor.close()

    def expire(self, candidate: InviteTrialExpiryCandidate) -> InviteTrialExpiryResult:
        if getattr(self._connection, "autocommit", False):
            raise ValueError("invite trial expiry requires autocommit disabled")
        try:
            token_service = McpTokenLifecycleService(
                self._connection,
                flags=self._flags,
            )
            token_service.lock_expiration_scope_for_transaction(
                commercial_account_id=candidate.commercial_account_id,
            )
            prior_revision = self._lock_and_validate(candidate)
            prepared_tokens = token_service.prepare_expire_due_for_account(
                runtime_environment=self._flags.environment,
                commercial_account_id=candidate.commercial_account_id,
                agreement_id=candidate.agreement_id,
            )
            lifecycle = CommercialAgreementLifecycleService(
                self._connection,
                projection_hook=AccountEntitlementProjectionHook(flags=self._flags),
                clock=self._database_now,
            )
            agreement = lifecycle.expire_invite_trial_as_service(
                runtime_environment=self._flags.environment,
                activation_id=candidate.activation_id,
                command=AgreementTransitionCommand(
                    commercial_account_id=candidate.commercial_account_id,
                    agreement_id=candidate.agreement_id,
                    expected_version=candidate.expected_agreement_version,
                    target_state=AgreementState.EXPIRED,
                    idempotency_key=(
                        f"invite-trial.expire.v1.{candidate.activation_id}"
                    ),
                    reason_code="invite_trial.expired",
                    effective_at=candidate.trial_expires_at,
                ),
            )
            current_revision = self._current_entitlement_revision(
                candidate.commercial_account_id
            )
            token_results = token_service.finalize_prepared_expiration(
                prepared_tokens,
                runtime_environment=self._flags.environment,
                entitlement_revision=current_revision,
                projection_changed=current_revision != prior_revision,
            )
            self._connection.commit()  # type: ignore[attr-defined]
            return InviteTrialExpiryResult(
                activation_id=candidate.activation_id,
                commercial_account_id=candidate.commercial_account_id,
                agreement_id=candidate.agreement_id,
                disposition="expired",
                agreement_version=agreement.version,
                entitlement_revision=current_revision,
                token_expiration_count=len(token_results),
                projection_changed=current_revision != prior_revision,
            )
        except _InviteTrialExpiryFenceSuperseded:
            self._connection.rollback()  # type: ignore[attr-defined]
            return InviteTrialExpiryResult(
                activation_id=candidate.activation_id,
                commercial_account_id=candidate.commercial_account_id,
                agreement_id=candidate.agreement_id,
                disposition="superseded",
            )
        except Exception:
            self._connection.rollback()  # type: ignore[attr-defined]
            raise

    def _lock_and_validate(self, candidate: InviteTrialExpiryCandidate) -> int:
        now = self._database_now()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE",
                (candidate.commercial_account_id,),
            )
            if cursor.fetchone() is None:
                raise _InviteTrialExpiryFenceSuperseded()
            cursor.execute(
                """SELECT revision FROM commercial_entitlement_revisions
                    WHERE commercial_account_id = %s FOR UPDATE""",
                (candidate.commercial_account_id,),
            )
            revision = cursor.fetchone()
            cursor.execute(
                """SELECT agreement.version, agreement.state,
                          agreement.channel, agreement.trial_end_at,
                          activation.trial_expires_at, activation.environment
                     FROM commercial_trial_activations AS activation
                     JOIN commercial_agreements AS agreement
                       ON agreement.id = activation.agreement_id
                      AND agreement.commercial_account_id =
                          activation.commercial_account_id
                    WHERE activation.activation_id = %s
                      AND activation.commercial_account_id = %s
                      AND activation.agreement_id = %s
                    FOR UPDATE OF agreement""",
                (
                    str(candidate.activation_id),
                    candidate.commercial_account_id,
                    candidate.agreement_id,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if (
            revision is None
            or int(revision[0]) != candidate.observed_entitlement_revision
            or row is None
            or int(row[0]) != candidate.expected_agreement_version
            or row[1] != "trialing"
            or row[2] != "invite_trial"
            or row[3] != candidate.trial_expires_at
            or row[4] != candidate.trial_expires_at
            or row[5] != self._flags.environment
            or now < candidate.trial_expires_at
        ):
            raise _InviteTrialExpiryFenceSuperseded()
        return int(revision[0])

    def _current_entitlement_revision(self, account_id: int) -> int:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT revision FROM commercial_entitlement_revisions
                    WHERE commercial_account_id = %s""",
                (account_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise RuntimeError("invite trial expiry projection did not persist")
        return int(row[0])

    def _database_now(self) -> datetime:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SELECT clock_timestamp()")
            return cursor.fetchone()[0]
        finally:
            cursor.close()

    def _now(self) -> datetime:
        now = self._clock()
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("invite trial expiry clock must be aware")
        return now


__all__ = [
    "InviteTrialExpiryCandidate",
    "InviteTrialExpiryResult",
    "PostgresInviteTrialExpiryProtocol",
]
