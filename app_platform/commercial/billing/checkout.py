"""Durable local preparation authority for self-serve Stripe Checkout."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import re
from typing import Annotated, Callable, Literal
from uuid import UUID, uuid4

from pydantic import AwareDatetime, Field, StrictBool, StringConstraints

from ..account_service import CommercialAccountService
from ..accounts import CommercialAccountKind
from ..agreement_store import PostgresAgreementRepository
from ..agreements import (
    AgreementChannel,
    AgreementItemKind,
    AgreementState,
    BillingProvider,
    CommercialAgreementCreate,
    CommercialAgreementItemCreate,
    CommercialAgreementTermsCreate,
)
from ..audit import CommercialAuditEvent, insert_commercial_audit_event
from ..catalog import CatalogBody
from ..errors import CommercialError, CommercialErrorCode
from ..flags import CommercialFlags
from ..models import StableCode, StrictCommercialModel, canonical_sha256
from .stripe_config import StripeDeploymentManifest


CheckoutIdempotencyKey = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=8,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]+$",
    ),
]
BillingEnvironment = Literal["test", "live"]
_STRIPE_CUSTOMER_ID = re.compile(r"^cus_[A-Za-z0-9]{6,250}$")
_STRIPE_SESSION_ID = re.compile(r"^cs_(test|live)_[A-Za-z0-9]{1,247}$")


class CheckoutPreparationRequest(StrictCommercialModel):
    idempotency_key: CheckoutIdempotencyKey
    price_code: StableCode


class PreparedCheckout(StrictCommercialModel):
    command_id: UUID
    actor_user_id: Annotated[int, Field(gt=0)]
    environment: BillingEnvironment
    commercial_account_id: Annotated[int, Field(gt=0)]
    account_public_id: UUID
    agreement_id: Annotated[int, Field(gt=0)]
    agreement_public_id: UUID
    offer_code: StableCode
    surface_code: StableCode
    price_code: StableCode
    stripe_price_id: str
    provider_idempotency_key: str
    pending_expires_at: AwareDatetime
    state: Literal["provider_pending", "session_created", "terminal_failed"]
    external_customer_id: str | None = None
    external_checkout_session_id: str | None = None
    checkout_expires_at: AwareDatetime | None = None
    replayed: StrictBool = False
    provider_call_authorized: StrictBool = False


class CheckoutPreparationError(RuntimeError):
    """Safe local failure that cannot authorize a provider call."""


_ATTEMPT_COLUMNS = (
    "attempt.command_id, attempt.actor_user_id, attempt.environment, "
    "attempt.commercial_account_id, attempt.account_public_id, "
    "attempt.agreement_id, attempt.agreement_public_id, "
    "agreement.metadata->>'checkout_offer_code', agreement.surface_code, "
    "attempt.price_code, attempt.stripe_price_id, attempt.provider_idempotency_key, "
    "agreement.pending_expires_at, attempt.state, attempt.external_customer_id, "
    "attempt.external_checkout_session_id, attempt.checkout_expires_at"
)


class PostgresCheckoutPreparationService:
    """Prepare or replay one pending Checkout command in a caller transaction."""

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags,
        deployment: StripeDeploymentManifest,
        clock: Callable[[], datetime] | None = None,
        pending_lifetime: timedelta = timedelta(hours=23),
    ) -> None:
        self._connection = connection
        self._flags = flags
        self._deployment = deployment
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        if not timedelta(minutes=30) <= pending_lifetime <= timedelta(hours=24):
            raise ValueError("Checkout pending lifetime must be between 30 minutes and 24 hours")
        self._pending_lifetime = pending_lifetime
        self._repository = PostgresAgreementRepository(connection)

    def prepare(
        self,
        *,
        actor_user_id: int,
        request: CheckoutPreparationRequest,
    ) -> PreparedCheckout:
        self._require_transaction()
        self._require_enabled()
        if isinstance(actor_user_id, bool) or actor_user_id <= 0:
            raise CheckoutPreparationError("authenticated user identity is invalid")
        billing_environment = self._deployment.billing_environment
        payload_sha256 = canonical_sha256(
            {
                "command_kind": "create_checkout_session",
                "actor_user_id": actor_user_id,
                "environment": billing_environment,
                "price_code": request.price_code,
            }
        )
        self._lock_command(actor_user_id, billing_environment, request.idempotency_key)
        replay = self._load_attempt(
            actor_user_id=actor_user_id,
            environment=billing_environment,
            idempotency_key=request.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            self._revalidate_attempt_authority(replay)
            if replay.state == "terminal_failed":
                raise CheckoutPreparationError("Checkout attempt is terminally unavailable")
            return replay.model_copy(
                update={
                    "replayed": True,
                    "provider_call_authorized": replay.state == "provider_pending",
                }
            )

        account_id, account_public_id = self._resolve_or_create_individual_account(
            actor_user_id
        )
        now = self._clock()
        catalog_policy_id, catalog = self._load_active_catalog(now)
        offer, price = self._resolve_public_price(catalog, request.price_code)
        binding = self._deployment.resolve_price(request.price_code)
        if binding.lookup_key != price.stripe_lookup_keys[billing_environment]:
            raise CheckoutPreparationError("Stripe deployment lookup binding is stale")
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
            raise CheckoutPreparationError("Checkout policies are not effective")
        self._lock_surface(account_id, offer.surface_code)
        self._reject_existing_base_agreement(account_id, offer.surface_code)
        pending_expires_at = now + self._pending_lifetime
        agreement = self._repository.create_agreement(
            CommercialAgreementCreate(
                commercial_account_id=account_id,
                surface_code=offer.surface_code,
                channel=AgreementChannel.SELF_SERVE,
                billing_provider=BillingProvider.STRIPE,
                billing_environment=billing_environment,
                state=AgreementState.PENDING_PAYMENT,
                currency=catalog.currency,
                pending_expires_at=pending_expires_at,
                metadata={
                    "checkout_offer_code": offer.offer_code,
                    "checkout_price_code": price.price_code,
                    "checkout_catalog_policy_id": catalog_policy_id,
                },
            )
        )
        self._repository.add_terms_revision(
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
                contracted_service_period_cents=price.amount_cents,
                effective_from=now,
                source_event_id=f"checkout:{agreement.public_id}",
            ),
            (
                CommercialAgreementItemCreate(
                    item_code=price.price_code,
                    item_kind=AgreementItemKind(price.item_kind),
                    price_code=price.price_code,
                    unit_amount_cents=price.amount_cents,
                    billing_interval=price.billing_interval,
                    metadata={"source": "self_serve_checkout"},
                ),
            ),
        )
        command_id = uuid4()
        provider_key = "hank_checkout_" + canonical_sha256(
            {"command_id": str(command_id), "agreement_public_id": str(agreement.public_id)}
        ).removeprefix("sha256:")
        self._insert_attempt(
            command_id=command_id,
            actor_user_id=actor_user_id,
            environment=billing_environment,
            idempotency_key=request.idempotency_key,
            payload_sha256=payload_sha256,
            account_id=account_id,
            account_public_id=account_public_id,
            agreement_id=agreement.id,
            agreement_public_id=agreement.public_id,
            price_code=price.price_code,
            stripe_price_id=binding.price_id,
            provider_key=provider_key,
        )
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                commercial_account_id=account_id,
                agreement_id=agreement.id,
                actor_type="user",
                actor_id=str(actor_user_id),
                action="commercial.checkout.prepare",
                target_type="commercial_agreement",
                target_id=str(agreement.public_id),
                reason_code="self_serve_checkout",
                after={
                    "account_id": account_id,
                    "agreement_id": agreement.id,
                    "offer_code": offer.offer_code,
                    "price_code": price.price_code,
                    "state": agreement.state.value,
                    "version": agreement.version,
                    "content_sha256": payload_sha256,
                    "result_code": "applied",
                },
            ),
        )
        result = self._load_attempt(
            actor_user_id=actor_user_id,
            environment=billing_environment,
            idempotency_key=request.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if result is None:
            raise CheckoutPreparationError("Checkout preparation was not durable")
        return result

    def load_customer_binding(self, prepared: PreparedCheckout) -> str | None:
        self._require_transaction()
        self._require_provider_authority(prepared)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT external_customer_id
                     FROM billing_provider_customers
                    WHERE commercial_account_id = %s AND provider = 'stripe'
                      AND environment = %s FOR UPDATE""",
                (prepared.commercial_account_id, prepared.environment),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return None if row is None else str(row[0])

    def record_customer_binding(
        self,
        prepared: PreparedCheckout,
        *,
        customer_id: str,
    ) -> str:
        self._require_transaction()
        self._require_provider_authority(prepared)
        if not _STRIPE_CUSTOMER_ID.fullmatch(customer_id):
            raise CheckoutPreparationError("Stripe customer identity is invalid")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """INSERT INTO billing_provider_customers (
                       commercial_account_id, provider, environment, external_customer_id
                   ) VALUES (%s, 'stripe', %s, %s)
                   ON CONFLICT (commercial_account_id, provider, environment) DO NOTHING""",
                (prepared.commercial_account_id, prepared.environment, customer_id),
            )
            cursor.execute(
                """SELECT external_customer_id
                     FROM billing_provider_customers
                    WHERE commercial_account_id = %s AND provider = 'stripe'
                      AND environment = %s FOR UPDATE""",
                (prepared.commercial_account_id, prepared.environment),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None or row[0] != customer_id:
            raise CheckoutPreparationError("Stripe customer binding conflicts with local authority")
        return customer_id

    def finalize_session(
        self,
        prepared: PreparedCheckout,
        *,
        customer_id: str,
        session_id: str,
        expires_at: datetime,
    ) -> None:
        self._require_transaction()
        self._require_provider_authority(prepared)
        if not _STRIPE_CUSTOMER_ID.fullmatch(customer_id):
            raise CheckoutPreparationError("Stripe customer identity is invalid")
        session_match = _STRIPE_SESSION_ID.fullmatch(session_id)
        if session_match is None or session_match.group(1) != prepared.environment:
            raise CheckoutPreparationError("Stripe Checkout identity is invalid")
        if (
            expires_at.tzinfo is None
            or expires_at <= self._clock()
            or expires_at > prepared.pending_expires_at
        ):
            raise CheckoutPreparationError("Stripe Checkout expiry exceeds local authority")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT external_customer_id
                     FROM billing_provider_customers
                    WHERE commercial_account_id = %s AND provider = 'stripe'
                      AND environment = %s FOR UPDATE""",
                (prepared.commercial_account_id, prepared.environment),
            )
            binding = cursor.fetchone()
            if binding is None or binding[0] != customer_id:
                raise CheckoutPreparationError("Stripe customer binding is not authoritative")
            cursor.execute(
                """UPDATE commercial_checkout_attempts
                      SET state = 'session_created', external_customer_id = %s,
                          external_checkout_session_id = %s, checkout_expires_at = %s
                    WHERE command_id = %s AND actor_user_id = %s
                      AND commercial_account_id = %s AND agreement_id = %s
                      AND environment = %s AND state = 'provider_pending'""",
                (
                    customer_id,
                    session_id,
                    expires_at,
                    str(prepared.command_id),
                    prepared.actor_user_id,
                    prepared.commercial_account_id,
                    prepared.agreement_id,
                    prepared.environment,
                ),
            )
            changed = cursor.rowcount
        finally:
            cursor.close()
        if changed != 1:
            raise CheckoutPreparationError("Checkout session finalization lost authority")

    def _require_provider_authority(self, prepared: PreparedCheckout) -> None:
        if prepared.state != "provider_pending" or not prepared.provider_call_authorized:
            raise CheckoutPreparationError("fresh provider authority is required")
        self._revalidate_attempt_authority(prepared)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT state FROM commercial_checkout_attempts
                    WHERE command_id = %s AND actor_user_id = %s
                      AND commercial_account_id = %s AND agreement_id = %s
                      AND environment = %s FOR UPDATE""",
                (
                    str(prepared.command_id),
                    prepared.actor_user_id,
                    prepared.commercial_account_id,
                    prepared.agreement_id,
                    prepared.environment,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row != ("provider_pending",):
            raise CheckoutPreparationError("Checkout attempt is not provider-pending")

    def _revalidate_attempt_authority(self, prepared: PreparedCheckout) -> None:
        """Lock and recheck every mutable fact before provider recovery is authorized."""

        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT account.status, member.role, member.status
                     FROM commercial_accounts account
                     JOIN commercial_account_members member
                       ON member.commercial_account_id = account.id
                    WHERE account.id = %s AND account.public_id = %s
                      AND member.user_id = %s
                    FOR UPDATE OF account, member""",
                (
                    prepared.commercial_account_id,
                    str(prepared.account_public_id),
                    prepared.actor_user_id,
                ),
            )
            authority = cursor.fetchone()
            if authority != ("active", "owner", "active"):
                raise CheckoutPreparationError("Checkout account authority is no longer active")
            cursor.execute(
                """SELECT state, pending_expires_at, billing_environment,
                          metadata->>'checkout_price_code'
                     FROM commercial_agreements
                    WHERE id = %s AND commercial_account_id = %s AND public_id = %s
                    FOR UPDATE""",
                (
                    prepared.agreement_id,
                    prepared.commercial_account_id,
                    str(prepared.agreement_public_id),
                ),
            )
            agreement = cursor.fetchone()
        finally:
            cursor.close()
        if (
            agreement is None
            or agreement[0] != "pending_payment"
            or agreement[1] is None
            or agreement[1] <= self._clock()
            or agreement[2] != prepared.environment
            or agreement[3] != prepared.price_code
        ):
            raise CheckoutPreparationError("Checkout agreement authority is no longer active")

    def _require_enabled(self) -> None:
        try:
            self._flags.validate()
        except ValueError as exc:
            raise CheckoutPreparationError("commercial flags are invalid") from exc
        if (
            not self._flags.self_serve_checkout_enabled
            or not self._flags.stripe_billing_enabled
            or self._flags.environment != self._deployment.runtime_environment
            or self._flags.stripe_live_mode_enabled
            != (self._deployment.billing_environment == "live")
        ):
            raise CheckoutPreparationError("self-serve Checkout is disabled")

    def _resolve_or_create_individual_account(self, actor_user_id: int) -> tuple[int, UUID]:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT account.id, account.public_id
                     FROM commercial_accounts account
                     JOIN commercial_account_members member
                       ON member.commercial_account_id = account.id
                    WHERE account.kind = 'individual' AND account.status = 'active'
                      AND member.user_id = %s AND member.role = 'owner'
                      AND member.status = 'active'
                    ORDER BY account.id FOR UPDATE OF account, member""",
                (actor_user_id,),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        if len(rows) > 1:
            raise CheckoutPreparationError("multiple active individual accounts exist")
        if rows:
            return int(rows[0][0]), UUID(str(rows[0][1]))
        try:
            visible = CommercialAccountService(self._connection).create_account(
                authenticated_user_id=actor_user_id,
                kind=CommercialAccountKind.INDIVIDUAL,
                display_name="Hank individual account",
                reason_code="self_serve_checkout",
            )
        except CommercialError as exc:
            if exc.code != CommercialErrorCode.COMMERCIAL_ACCOUNT_ALREADY_EXISTS:
                raise
            # A different Checkout key may have committed the individual account
            # while this transaction waited on the account service's user lock.
            return self._resolve_or_create_individual_account(actor_user_id)
        return visible.account.id, visible.account.public_id

    def _load_active_catalog(self, now: datetime) -> tuple[int, CatalogBody]:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
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
            raise CheckoutPreparationError("exactly one active catalog is required")
        try:
            return int(rows[0][0]), CatalogBody.model_validate(rows[0][1])
        except ValueError as exc:
            raise CheckoutPreparationError("active catalog is invalid") from exc

    @staticmethod
    def _resolve_public_price(catalog: CatalogBody, price_code: str):
        prices = {item.price_code: item for item in catalog.prices}
        offers = {item.offer_code: item for item in catalog.offers}
        price = prices.get(price_code)
        offer = offers.get(price.offer_code) if price else None
        if (
            price is None
            or offer is None
            or not price.public_checkout_enabled
            or offer.availability != "public"
            or "self_serve" not in offer.channels
            or price.price_code not in offer.price_codes
            or price.item_kind != "recurring"
            or price.billing_interval not in {"month", "year"}
            or not price.funds_service_period
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION)
        return offer, price

    def _lock_command(self, actor: int, environment: str, key: str) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                (actor, f"checkout:{environment}:{key}"),
            )
        finally:
            cursor.close()

    def _lock_surface(self, account_id: int, surface_code: str) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s, hashtext(%s))",
                (account_id, f"checkout_surface:{surface_code}"),
            )
        finally:
            cursor.close()

    def _reject_existing_base_agreement(self, account_id: int, surface: str) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT 1 FROM commercial_agreements
                    WHERE commercial_account_id = %s AND surface_code = %s
                      AND state NOT IN ('canceled', 'expired') LIMIT 1 FOR UPDATE""",
                (account_id, surface),
            )
            exists = cursor.fetchone() is not None
        finally:
            cursor.close()
        if exists:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION)

    def _load_attempt(self, *, actor_user_id, environment, idempotency_key, payload_sha256):
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                f"""SELECT {_ATTEMPT_COLUMNS}, attempt.payload_sha256
                      FROM commercial_checkout_attempts attempt
                      JOIN commercial_agreements agreement ON agreement.id = attempt.agreement_id
                     WHERE attempt.actor_user_id = %s AND attempt.environment = %s
                       AND attempt.idempotency_key = %s FOR UPDATE OF attempt""",
                (actor_user_id, environment, idempotency_key),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        if row[-1] != payload_sha256:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_IDEMPOTENCY_CONFLICT)
        return PreparedCheckout.model_validate(
            dict(
                zip(
                    (
                        "command_id", "actor_user_id", "environment", "commercial_account_id",
                        "account_public_id", "agreement_id", "agreement_public_id", "offer_code",
                        "surface_code", "price_code", "stripe_price_id", "provider_idempotency_key",
                        "pending_expires_at", "state", "external_customer_id",
                        "external_checkout_session_id", "checkout_expires_at",
                    ),
                    row[:-1],
                    strict=True,
                )
            )
        )

    def _insert_attempt(self, **values) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """INSERT INTO commercial_checkout_attempts (
                       command_id, environment, actor_user_id, idempotency_key,
                       payload_sha256, commercial_account_id, account_public_id,
                       agreement_id, agreement_public_id, price_code, stripe_price_id,
                       provider_idempotency_key
                   ) VALUES (
                       %(command_id)s, %(environment)s, %(actor_user_id)s,
                       %(idempotency_key)s, %(payload_sha256)s, %(account_id)s,
                       %(account_public_id)s, %(agreement_id)s, %(agreement_public_id)s,
                       %(price_code)s, %(stripe_price_id)s, %(provider_key)s)""",
                {key: str(value) if isinstance(value, UUID) else value for key, value in values.items()},
            )
        finally:
            cursor.close()

    def _require_transaction(self) -> None:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("Checkout preparation requires a transaction")


__all__ = [
    "CheckoutIdempotencyKey",
    "CheckoutPreparationError",
    "CheckoutPreparationRequest",
    "PostgresCheckoutPreparationService",
    "PreparedCheckout",
]
