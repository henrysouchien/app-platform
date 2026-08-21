"""Invite issuance and authenticated activation for hard-capped Standard trials."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from functools import wraps
from typing import Annotated, Any, Callable, Literal, Protocol
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, StrictBool, StringConstraints

from .account_service import CommercialAccountService
from .accounts import CommercialAccountKind
from .agreement_store import PostgresAgreementRepository
from .agreements import (
    AgreementChannel,
    AgreementItemKind,
    AgreementState,
    BillingProvider,
    CommercialAgreementCreate,
    CommercialAgreementItemCreate,
    CommercialAgreementTermsCreate,
)
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import CommercialRole
from .authority_store import load_named_operator
from .catalog import CatalogBody
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags
from .models import StableCode, StrictCommercialModel, canonical_sha256


TrialIdempotencyKey = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    ),
]
ConsentVersion = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
        max_length=127,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]*$",
    ),
]
Environment = Literal["dev", "staging", "prod"]
TRIAL_DURATION = timedelta(days=14)
_STANDARD_OFFER = "hp1_standard"
_STANDARD_PRICE = "hp1_standard_monthly_usd_v1"


class TrialProjectionHook(Protocol):
    def agreement_changed(
        self,
        connection: Any,
        *,
        before: Any,
        after: Any,
        effective_at: datetime,
    ) -> None: ...


class TrialInviteCommand(StrictCommercialModel):
    idempotency_key: TrialIdempotencyKey
    target_user_id: int = Field(gt=0)
    reason_code: StableCode
    expires_in_seconds: int = Field(default=604800, ge=3600, le=2592000)


class TrialInviteResult(StrictCommercialModel):
    invitation_id: UUID
    environment: Environment
    target_user_id: int = Field(gt=0)
    identity_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    state: Literal["invited", "consumed", "revoked"]
    expires_at: AwareDatetime
    audit_event_id: UUID
    replayed: StrictBool = False


class TrialActivationCommand(StrictCommercialModel):
    idempotency_key: TrialIdempotencyKey
    invitation_id: UUID
    terms_version: ConsentVersion
    privacy_version: ConsentVersion
    terms_accepted: Literal[True]
    privacy_accepted: Literal[True]


class TrialActivationResult(StrictCommercialModel):
    activation_id: UUID
    invitation_id: UUID
    commercial_account_id: int = Field(gt=0)
    agreement_id: int = Field(gt=0)
    agreement_public_id: UUID
    agreement_terms_id: int = Field(gt=0)
    state: Literal["trialing"]
    trial_started_at: AwareDatetime
    trial_expires_at: AwareDatetime
    audit_event_id: UUID
    replayed: StrictBool = False


class InviteTrialError(RuntimeError):
    """The invitation or authenticated trial authority is unavailable."""


def _atomic(operation):
    @wraps(operation)
    def wrapped(self, *args, **kwargs):
        return self._run_atomic(lambda: operation(self, *args, **kwargs))

    return wrapped


class InviteTrialService:
    """Issue exact invitations and consume them into one non-billing Standard trial."""

    def __init__(
        self,
        connection: Any,
        *,
        flags: CommercialFlags,
        projection_hook: TrialProjectionHook,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags
        self._projection_hook = projection_hook
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._repository = PostgresAgreementRepository(connection)
        if not flags.invite_trial_enabled:
            raise InviteTrialError("Invite trials are disabled")

    @_atomic
    def issue_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Environment,
        command: TrialInviteCommand,
    ) -> TrialInviteResult:
        self._require_environment(runtime_environment)
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=runtime_environment,
        )
        if CommercialRole.COMMERCIAL_ADMIN not in operator.roles:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "issue_invite_trial",
                "environment": runtime_environment,
                **command.model_dump(mode="python"),
            }
        )
        self._command_lock(
            operator_user_id, runtime_environment, command.idempotency_key
        )
        replay = self._load_invite_replay(
            operator_user_id=operator_user_id,
            environment=runtime_environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay.model_copy(update={"replayed": True})
        identity_sha256 = self._verified_identity(command.target_user_id)
        self._identity_lock(runtime_environment, identity_sha256)
        now = self._clock()
        self._revoke_expired_invitation(
            environment=runtime_environment,
            identity_sha256=identity_sha256,
            now=now,
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT 1 FROM commercial_trial_activations
                    WHERE environment = %s AND identity_sha256 = %s""",
                (runtime_environment, identity_sha256),
            )
            already_activated = cursor.fetchone() is not None
        finally:
            cursor.close()
        if already_activated:
            raise InviteTrialError("Trial identity has already been used")
        invitation_id = uuid4()
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action="commercial.trial_invite.issue",
                target_type="user",
                target_id=str(command.target_user_id),
                reason_code=command.reason_code,
                after={
                    "user_id": command.target_user_id,
                    "content_sha256": payload_sha256,
                    "result_code": "applied",
                },
            ),
        )
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """INSERT INTO commercial_trial_invites (
                       invitation_id, environment, target_user_id, identity_sha256,
                       idempotency_key, payload_sha256, reason_code,
                       issued_by_user_id, expires_at, audit_event_id
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    str(invitation_id),
                    runtime_environment,
                    command.target_user_id,
                    identity_sha256,
                    command.idempotency_key,
                    payload_sha256,
                    command.reason_code,
                    operator_user_id,
                    now + timedelta(seconds=command.expires_in_seconds),
                    str(audit_event_id),
                ),
            )
        finally:
            cursor.close()
        result = self._load_invitation(invitation_id)
        if result is None:
            raise InviteTrialError("Trial invitation persistence failed")
        return result

    @_atomic
    def activate_as_user(
        self,
        *,
        authenticated_user_id: int,
        runtime_environment: Environment,
        command: TrialActivationCommand,
    ) -> TrialActivationResult:
        self._require_environment(runtime_environment)
        if isinstance(authenticated_user_id, bool) or authenticated_user_id <= 0:
            raise InviteTrialError("Authenticated trial identity is invalid")
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "activate_invite_trial",
                "environment": runtime_environment,
                "authenticated_user_id": authenticated_user_id,
                **command.model_dump(mode="python"),
            }
        )
        self._command_lock(
            authenticated_user_id, runtime_environment, command.idempotency_key
        )
        replay = self._load_activation_replay(
            authenticated_user_id=authenticated_user_id,
            environment=runtime_environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay.model_copy(update={"replayed": True})
        invitation = self._lock_invitation(command.invitation_id)
        now = self._clock()
        if (
            invitation is None
            or invitation[0] != runtime_environment
            or int(invitation[1]) != authenticated_user_id
            or invitation[3] != "invited"
            or invitation[4] <= now
            or invitation[2] != self._verified_identity(authenticated_user_id)
        ):
            raise InviteTrialError("Trial invitation is unavailable")
        identity_sha256 = str(invitation[2])
        account_id = self._resolve_or_create_individual_account(authenticated_user_id)
        self._lock_surface(account_id)
        self._reject_existing_agreement(account_id)
        catalog_policy_id, catalog = self._load_active_catalog(now)
        offer, price = self._resolve_standard_trial(catalog)
        transition = self._repository.get_offer_transition_metadata(
            catalog_policy_id=catalog_policy_id,
            offer_code=offer.offer_code,
        )
        if transition is None or not self._repository.policies_are_effective(
            policy_ids=(
                transition.entitlement_policy_id,
                transition.payer_policy_id,
                transition.budget_policy_id,
            ),
            effective_at=now,
        ):
            raise InviteTrialError("Trial policies are not effective")
        expires_at = now + TRIAL_DURATION
        agreement = self._repository.create_agreement(
            CommercialAgreementCreate(
                commercial_account_id=account_id,
                surface_code=offer.surface_code,
                channel=AgreementChannel.INVITE_TRIAL,
                billing_provider=BillingProvider.NONE,
                state=AgreementState.TRIALING,
                currency=catalog.currency,
                service_start_at=now,
                service_end_at=expires_at,
                current_period_start_at=now,
                current_period_end_at=expires_at,
                trial_end_at=expires_at,
                metadata={"trial_invitation_id": str(command.invitation_id)},
            )
        )
        terms = self._repository.add_terms_revision(
            CommercialAgreementTermsCreate(
                agreement_id=agreement.id,
                commercial_account_id=account_id,
                revision=1,
                offer_code=offer.offer_code,
                price_code=price.price_code,
                catalog_policy_id=catalog_policy_id,
                entitlement_policy_id=transition.entitlement_policy_id,
                payer_policy_id=transition.payer_policy_id,
                budget_policy_id=transition.budget_policy_id,
                contracted_service_period_cents=0,
                effective_from=now,
                effective_until=expires_at,
                source_event_id=f"invite-trial:{command.invitation_id}",
            ),
            (
                CommercialAgreementItemCreate(
                    item_code="hp1_standard_trial_allowance",
                    item_kind=AgreementItemKind.INCLUDED_ALLOWANCE,
                    price_code=price.price_code,
                    quantity=Decimal("1"),
                    unit_amount_cents=0,
                    billing_interval="fixed_term",
                    service_start_at=now,
                    service_end_at=expires_at,
                    metadata={"source": "invite_trial"},
                ),
            ),
        )
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=account_id,
                agreement_id=agreement.id,
                actor_type="user",
                actor_id=str(authenticated_user_id),
                action="commercial.trial.activate",
                target_type="commercial_agreement",
                target_id=str(agreement.public_id),
                reason_code="invite_trial.accepted",
                after={
                    "account_id": account_id,
                    "agreement_id": agreement.id,
                    "state": "trialing",
                    "version": agreement.version,
                    "content_sha256": payload_sha256,
                    "result_code": "applied",
                },
            ),
        )
        activation_id = uuid4()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """UPDATE commercial_trial_invites
                      SET state = 'consumed', consumed_at = %s
                    WHERE invitation_id = %s AND state = 'invited'""",
                (now, str(command.invitation_id)),
            )
            if cursor.rowcount != 1:
                raise InviteTrialError("Trial invitation changed concurrently")
            cursor.execute(
                """INSERT INTO commercial_trial_activations (
                       activation_id, invitation_id, environment, identity_sha256,
                       activated_by_user_id, commercial_account_id, agreement_id,
                       agreement_terms_id, terms_version, privacy_version,
                       idempotency_key, payload_sha256, trial_started_at,
                       trial_expires_at, audit_event_id
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    str(activation_id),
                    str(command.invitation_id),
                    runtime_environment,
                    identity_sha256,
                    authenticated_user_id,
                    account_id,
                    agreement.id,
                    terms.terms.id,
                    command.terms_version,
                    command.privacy_version,
                    command.idempotency_key,
                    payload_sha256,
                    now,
                    expires_at,
                    str(audit_event_id),
                ),
            )
        finally:
            cursor.close()
        before = agreement.model_copy(update={"state": AgreementState.DRAFT})
        self._projection_hook.agreement_changed(
            self._connection,
            before=before,
            after=agreement,
            effective_at=max(now, agreement.state_effective_at),
        )
        return TrialActivationResult(
            activation_id=activation_id,
            invitation_id=command.invitation_id,
            commercial_account_id=account_id,
            agreement_id=agreement.id,
            agreement_public_id=agreement.public_id,
            agreement_terms_id=terms.terms.id,
            state="trialing",
            trial_started_at=now,
            trial_expires_at=expires_at,
            audit_event_id=audit_event_id,
        )

    def _verified_identity(self, user_id: int) -> str:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT commercial_trial_user_identity_sha256(%s)", (user_id,)
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None or row[0] is None:
            raise InviteTrialError("Trial identity is not verified")
        return str(row[0])

    def _resolve_or_create_individual_account(self, user_id: int) -> int:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT account.id
                     FROM commercial_accounts account
                     JOIN commercial_account_members member
                       ON member.commercial_account_id = account.id
                    WHERE account.kind = 'individual' AND account.status = 'active'
                      AND member.user_id = %s AND member.role = 'owner'
                      AND member.status = 'active'
                    FOR UPDATE OF account, member""",
                (user_id,),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        if len(rows) > 1:
            raise InviteTrialError("Trial account identity is ambiguous")
        if rows:
            return int(rows[0][0])
        account = CommercialAccountService(self._connection).create_account(
            authenticated_user_id=user_id,
            kind=CommercialAccountKind.INDIVIDUAL,
            display_name="Hank Trial",
            reason_code="invite_trial.account_created",
        )
        return account.account.id

    def _load_active_catalog(self, now: datetime) -> tuple[int, CatalogBody]:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT id, body_json FROM commercial_policy_versions
                    WHERE policy_kind = 'catalog' AND state = 'active'
                      AND activated_at <= %s
                      AND (retired_at IS NULL OR retired_at > %s)
                    ORDER BY id FOR SHARE""",
                (now, now),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        if len(rows) != 1:
            raise InviteTrialError("Exactly one active trial catalog is required")
        try:
            return int(rows[0][0]), CatalogBody.model_validate(rows[0][1])
        except ValueError as exc:
            raise InviteTrialError("Active trial catalog is invalid") from exc

    @staticmethod
    def _resolve_standard_trial(catalog: CatalogBody):
        offers = {item.offer_code: item for item in catalog.offers}
        prices = {item.price_code: item for item in catalog.prices}
        offer = offers.get(_STANDARD_OFFER)
        price = prices.get(_STANDARD_PRICE)
        if (
            offer is None
            or price is None
            or "invite_trial" not in offer.channels
            or offer.surface_code != "hp1"
            or offer.entitlement_policy.policy_code != "hp1_standard"
            or offer.payer_policy.policy_code != "hp1_customer_host"
            or offer.budget_policy.policy_code != "hp1_standard_budget"
            or price.offer_code != offer.offer_code
            or price.price_code not in offer.price_codes
            or price.billing_interval != "month"
        ):
            raise InviteTrialError("Standard trial catalog authority is invalid")
        return offer, price

    def _lock_surface(self, account_id: int) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                (account_id, "invite_trial_surface:hp1"),
            )
        finally:
            cursor.close()

    def _reject_existing_agreement(self, account_id: int) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT 1 FROM commercial_agreements
                    WHERE commercial_account_id = %s AND surface_code = 'hp1'
                      AND state NOT IN ('canceled', 'expired')
                    LIMIT 1 FOR UPDATE""",
                (account_id,),
            )
            exists = cursor.fetchone() is not None
        finally:
            cursor.close()
        if exists:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )

    def _lock_invitation(self, invitation_id: UUID):
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT environment, target_user_id, identity_sha256, state, expires_at
                     FROM commercial_trial_invites WHERE invitation_id = %s FOR UPDATE""",
                (str(invitation_id),),
            )
            return cursor.fetchone()
        finally:
            cursor.close()

    def _load_invitation(self, invitation_id: UUID) -> TrialInviteResult | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT invitation_id, environment, target_user_id, identity_sha256,
                          state, expires_at, audit_event_id
                     FROM commercial_trial_invites WHERE invitation_id = %s""",
                (str(invitation_id),),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        return TrialInviteResult(
            invitation_id=row[0],
            environment=row[1],
            target_user_id=row[2],
            identity_sha256=row[3],
            state=row[4],
            expires_at=row[5],
            audit_event_id=row[6],
        )

    def _load_invite_replay(
        self, *, operator_user_id, environment, idempotency_key, payload_sha256
    ) -> TrialInviteResult | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT invitation_id, payload_sha256
                     FROM commercial_trial_invites
                    WHERE issued_by_user_id = %s AND environment = %s
                      AND idempotency_key = %s FOR UPDATE""",
                (operator_user_id, environment, idempotency_key),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[1] != payload_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return self._load_invitation(UUID(str(row[0])))

    def _load_activation_replay(
        self, *, authenticated_user_id, environment, idempotency_key, payload_sha256
    ) -> TrialActivationResult | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT activation.activation_id, activation.invitation_id,
                          activation.commercial_account_id, activation.agreement_id,
                          agreement.public_id, activation.agreement_terms_id,
                          activation.trial_started_at, activation.trial_expires_at,
                          activation.audit_event_id, activation.payload_sha256
                     FROM commercial_trial_activations activation
                     JOIN commercial_agreements agreement
                       ON agreement.id = activation.agreement_id
                    WHERE activation.activated_by_user_id = %s
                      AND activation.environment = %s
                      AND activation.idempotency_key = %s FOR UPDATE OF activation""",
                (authenticated_user_id, environment, idempotency_key),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[9] != payload_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return TrialActivationResult(
            activation_id=row[0],
            invitation_id=row[1],
            commercial_account_id=row[2],
            agreement_id=row[3],
            agreement_public_id=row[4],
            agreement_terms_id=row[5],
            state="trialing",
            trial_started_at=row[6],
            trial_expires_at=row[7],
            audit_event_id=row[8],
        )

    def _command_lock(self, actor_id: int, environment: str, key: str) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                (actor_id, f"invite_trial:{environment}:{key}"),
            )
        finally:
            cursor.close()

    def _identity_lock(self, environment: str, identity_sha256: str) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtextextended(%s, 0))",
                (f"invite_trial_identity:{environment}:{identity_sha256}",),
            )
        finally:
            cursor.close()

    def _revoke_expired_invitation(
        self, *, environment: str, identity_sha256: str, now: datetime
    ) -> None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """SELECT invitation_id, target_user_id
                     FROM commercial_trial_invites
                    WHERE environment = %s AND identity_sha256 = %s
                      AND state = 'invited' AND expires_at <= %s
                    FOR UPDATE""",
                (environment, identity_sha256, now),
            )
            expired = cursor.fetchall()
            for invitation_id, target_user_id in expired:
                cursor.execute(
                    """UPDATE commercial_trial_invites
                          SET state = 'revoked', revoked_at = %s
                        WHERE invitation_id = %s AND state = 'invited'""",
                    (now, str(invitation_id)),
                )
                if cursor.rowcount != 1:
                    raise InviteTrialError("Expired trial invitation changed concurrently")
                insert_commercial_audit_event(
                    self._connection,
                    CommercialAuditEvent(
                        actor_type="service",
                        actor_id="invite-trial-expiry",
                        action="commercial.trial_invite.expire",
                        target_type="trial_invitation",
                        target_id=str(invitation_id),
                        reason_code="invite_trial.invitation_expired",
                        after={
                            "user_id": int(target_user_id),
                            "state": "revoked",
                            "result_code": "revoked",
                        },
                    ),
                )
            cursor.execute(
                """SELECT 1 FROM commercial_trial_invites
                    WHERE environment = %s AND identity_sha256 = %s
                      AND state = 'invited'
                    LIMIT 1""",
                (environment, identity_sha256),
            )
            if cursor.fetchone() is not None:
                raise InviteTrialError("Trial identity already has an open invitation")
        finally:
            cursor.close()

    def _require_environment(self, runtime_environment: str) -> None:
        if runtime_environment != self._flags.environment:
            raise InviteTrialError("Trial runtime environment mismatch")
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None or row[0] != runtime_environment:
            raise InviteTrialError("Trial deployment environment mismatch")

    def _run_atomic(self, operation):
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Invite trial commands require a transaction")
        cursor = self._connection.cursor()
        try:
            cursor.execute("SAVEPOINT commercial_invite_trial")
            try:
                result = operation()
            except BaseException:
                cursor.execute("ROLLBACK TO SAVEPOINT commercial_invite_trial")
                cursor.execute("RELEASE SAVEPOINT commercial_invite_trial")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_invite_trial")
            return result
        finally:
            cursor.close()


__all__ = [
    "InviteTrialError",
    "InviteTrialService",
    "TRIAL_DURATION",
    "TrialActivationCommand",
    "TrialActivationResult",
    "TrialInviteCommand",
    "TrialInviteResult",
]
