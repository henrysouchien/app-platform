"""Customer-safe billing read model and Stripe Customer Portal boundary."""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import AwareDatetime, Field

from ..models import StableCode, StrictCommercialModel, canonical_sha256
from .stripe_config import StripeDeploymentManifest


class CustomerBillingUnavailable(RuntimeError):
    """The customer billing surface cannot safely serve this request."""


class CustomerBillingProviderUnavailable(RuntimeError):
    """A provider operation may have succeeded but could not be confirmed."""


class CustomerBillingForbidden(RuntimeError):
    """The actor is not authorized for the requested billing operation."""


class BillingHistoryItem(StrictCommercialModel):
    document_id: UUID
    kind: Literal["invoice", "credit_note", "manual_invoice"]
    status: Literal["open", "paid", "void", "uncollectible", "credited"]
    currency: Literal["USD"]
    total_cents: int
    issued_at: AwareDatetime
    service_period_start_at: AwareDatetime | None = None
    service_period_end_at: AwareDatetime | None = None


class CustomerAgreementSummary(StrictCommercialModel):
    agreement_id: UUID
    offer_code: StableCode | None = None
    price_code: StableCode | None = None
    state: Literal[
        "draft", "pending_payment", "trialing", "active", "past_due",
        "grace", "paused", "canceled", "expired",
    ]
    billing_provider: Literal["stripe", "manual", "none"]
    currency: Literal["USD"]
    service_start_at: AwareDatetime | None = None
    service_end_at: AwareDatetime | None = None
    current_period_start_at: AwareDatetime | None = None
    current_period_end_at: AwareDatetime | None = None
    cancel_at_period_end: bool


class CustomerBillingAccount(StrictCommercialModel):
    account_id: UUID
    display_name: str = Field(min_length=1, max_length=512)
    member_role: Literal["owner", "admin", "billing", "member"]
    agreement: CustomerAgreementSummary | None = None
    history: tuple[BillingHistoryItem, ...] = ()
    plan_options: tuple["CustomerPlanOption", ...] = ()
    synchronization: "CustomerBillingSynchronization | None" = None


class CustomerPlanOption(StrictCommercialModel):
    offer_code: StableCode
    display_name: str = Field(min_length=1, max_length=512)
    price_code: StableCode
    amount_cents: int = Field(ge=0)
    billing_interval: Literal["month", "year"]
    direction: Literal["upgrade", "downgrade", "interval_change"]
    change_timing: Literal["immediate", "period_end"]


class CustomerBillingSynchronization(StrictCommercialModel):
    action: Literal["cancel", "reactivate", "change_plan"]
    status: Literal["scheduled", "synchronization_pending"]
    effective_at: AwareDatetime
    requested_price_code: StableCode | None = None


class CustomerBillingSummary(StrictCommercialModel):
    accounts: tuple[CustomerBillingAccount, ...]


class PortalSessionRequest(StrictCommercialModel):
    account_id: UUID


class PortalSessionResult(StrictCommercialModel):
    url: str = Field(min_length=1, max_length=4096)
    expires_at: AwareDatetime | None = None


class BillingLifecycleRequest(StrictCommercialModel):
    account_id: UUID
    idempotency_key: UUID


class BillingChangePlanRequest(BillingLifecycleRequest):
    price_code: StableCode


class BillingLifecycleResult(StrictCommercialModel):
    status: Literal["scheduled", "synchronization_pending", "projected"] = "synchronization_pending"
    action: Literal["cancel", "reactivate", "change_plan"]
    effective_at: AwareDatetime | None = None


class BillingReceiptRequest(StrictCommercialModel):
    account_id: UUID
    document_id: UUID


class BillingReceiptResult(StrictCommercialModel):
    url: str = Field(min_length=1, max_length=4096)


@dataclass(frozen=True, slots=True)
class BillingSubscriptionAuthority:
    commercial_account_id: int
    agreement_internal_id: int
    account_id: UUID
    agreement_id: UUID
    customer_id: str
    subscription_id: str
    current_offer_code: str
    current_price_code: str
    agreement_version: int
    current_period_end_at: datetime
    direction: Literal["upgrade", "downgrade", "interval_change"] | None = None


@dataclass(frozen=True, slots=True)
class BillingReceiptAuthority:
    customer_id: str
    external_invoice_id: str


@dataclass(frozen=True, slots=True)
class PreparedBillingCommand:
    authority: BillingSubscriptionAuthority
    command_id: UUID
    action: Literal["cancel", "reactivate", "change_plan"]
    requested_price_code: str | None
    effective_at: datetime
    provider_idempotency_key: str
    provider_submitted: bool
    synchronization_status: Literal["scheduled", "synchronization_pending", "projected"]

    @property
    def scheduled(self) -> bool:
        return self.authority.direction == "downgrade" and not self.provider_submitted


class PortalProvider(Protocol):
    def create_session(self, *, customer_id: str, return_url: str) -> PortalSessionResult: ...


class SubscriptionMutationProvider(Protocol):
    def mutate(
        self, *, authority: BillingSubscriptionAuthority,
        action: Literal["cancel", "reactivate", "change_plan"],
        provider_idempotency_key: str, price_code: str | None = None,
    ) -> BillingLifecycleResult: ...


class ReceiptProvider(Protocol):
    def receipt(self, *, authority: BillingReceiptAuthority) -> BillingReceiptResult: ...


class PostgresCustomerBillingService:
    """Read only customer-safe projections; never return provider identities or costs."""

    def __init__(self, connection: object) -> None:
        self._connection = connection

    def summarize(
        self, *, actor_user_id: int, billing_environment: str,
        available_price_codes: tuple[str, ...], history_limit: int = 24,
    ) -> CustomerBillingSummary:
        if (
            actor_user_id <= 0
            or billing_environment not in {"test", "live"}
            or not available_price_codes
            or not 1 <= history_limit <= 100
        ):
            raise ValueError("Customer billing query is invalid")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT account.id, account.public_id, account.display_name, member.role,
                          agreement.id, agreement.public_id, agreement.state,
                          agreement.billing_provider, agreement.currency,
                          agreement.service_start_at, agreement.service_end_at,
                          agreement.current_period_start_at, agreement.current_period_end_at,
                          agreement.cancel_at_period_end, terms.offer_code, terms.price_code,
                          sync.action, sync.synchronization_status, sync.effective_at,
                          sync.requested_price_code
                     FROM commercial_account_members member
                     JOIN commercial_accounts account ON account.id = member.commercial_account_id
                LEFT JOIN LATERAL (
                           SELECT candidate.*
                             FROM commercial_agreements candidate
                            WHERE candidate.commercial_account_id = account.id
                              AND candidate.state <> 'expired'
                              AND (candidate.billing_provider <> 'stripe'
                                   OR candidate.billing_environment = %s)
                         ORDER BY CASE WHEN candidate.state IN (
                                      'pending_payment','trialing','active','past_due','grace','paused'
                                  ) THEN 0 ELSE 1 END,
                                  candidate.state_effective_at DESC, candidate.id DESC
                            LIMIT 1
                          ) agreement ON TRUE
                LEFT JOIN commercial_agreement_terms terms
                       ON terms.agreement_id = agreement.id AND terms.effective_until IS NULL
                LEFT JOIN LATERAL (
                           SELECT command.action, command.synchronization_status,
                                  command.effective_at, command.requested_price_code
                             FROM commercial_customer_billing_command_status command
                            WHERE command.agreement_id = agreement.id
                              AND command.synchronization_status <> 'projected'
                         ORDER BY command.created_at DESC, command.id DESC LIMIT 1
                          ) sync ON TRUE
                    WHERE member.user_id = %s AND member.status = 'active'
                      AND account.status <> 'closed'
                 ORDER BY account.id""",
                (billing_environment, actor_user_id),
            )
            rows = cursor.fetchall()
            accounts: list[CustomerBillingAccount] = []
            for row in rows:
                agreement = None
                history: tuple[BillingHistoryItem, ...] = ()
                if row[4] is not None:
                    agreement = CustomerAgreementSummary(
                        agreement_id=row[5], state=row[6], billing_provider=row[7],
                        currency=row[8], service_start_at=row[9], service_end_at=row[10],
                        current_period_start_at=row[11], current_period_end_at=row[12],
                        cancel_at_period_end=row[13], offer_code=row[14], price_code=row[15],
                    )
                    history = self._history(cursor, agreement_id=int(row[4]), limit=history_limit)
                accounts.append(CustomerBillingAccount(
                    account_id=row[1], display_name=row[2], member_role=row[3],
                    agreement=agreement, history=history,
                    synchronization=(
                        CustomerBillingSynchronization(
                            action=row[16], status=row[17], effective_at=row[18],
                            requested_price_code=row[19],
                        ) if row[16] is not None else None
                    ),
                ))
            cursor.execute(
                """SELECT current_offer->>'offer_code', target_offer->>'offer_code',
                          target_offer->>'display_name', target_price->>'price_code',
                          (target_price->>'amount_cents')::BIGINT,
                          target_price->>'billing_interval',
                          CASE
                            WHEN (target_offer->>'commercial_tier_rank')::INTEGER
                               > (current_offer->>'commercial_tier_rank')::INTEGER THEN 'upgrade'
                            WHEN (target_offer->>'commercial_tier_rank')::INTEGER
                               < (current_offer->>'commercial_tier_rank')::INTEGER THEN 'downgrade'
                            ELSE 'interval_change'
                          END AS direction
                     FROM commercial_policy_versions policy
                     CROSS JOIN LATERAL jsonb_array_elements(policy.body_json->'offers') current_offer
                     CROSS JOIN LATERAL jsonb_array_elements(policy.body_json->'offers') target_offer
                     CROSS JOIN LATERAL jsonb_array_elements(policy.body_json->'prices') target_price
                    WHERE policy.policy_kind = 'catalog' AND policy.state = 'active'
                      AND current_offer->>'offer_code' = ANY(%s)
                      AND target_price->>'offer_code' = target_offer->>'offer_code'
                      AND (target_price->>'public_checkout_enabled')::BOOLEAN IS TRUE
                      AND target_price->>'billing_interval' IN ('month','year')
                      AND target_price->>'price_code' = ANY(%s)
                      AND target_offer->>'surface_code' = current_offer->>'surface_code'
                      AND target_offer->>'transition_family' = current_offer->>'transition_family'
                 ORDER BY current_offer->>'offer_code',
                          (target_offer->>'commercial_tier_rank')::INTEGER,
                          target_price->>'billing_interval', target_price->>'price_code'""",
                (
                    [item.agreement.offer_code for item in accounts if item.agreement and item.agreement.offer_code],
                    list(available_price_codes),
                ),
            )
            by_offer: dict[str, list[CustomerPlanOption]] = {}
            for row in cursor.fetchall():
                by_offer.setdefault(str(row[0]), []).append(CustomerPlanOption(
                    offer_code=row[1], display_name=row[2], price_code=row[3],
                    amount_cents=int(row[4]), billing_interval=row[5], direction=row[6],
                    change_timing="period_end" if row[6] == "downgrade" else "immediate",
                ))
            return CustomerBillingSummary(accounts=tuple(
                item.model_copy(update={
                    "plan_options": tuple(by_offer.get(
                        item.agreement.offer_code if item.agreement else "", []
                    ))
                }) for item in accounts
            ))
        finally:
            cursor.close()

    @staticmethod
    def _history(cursor: Any, *, agreement_id: int, limit: int) -> tuple[BillingHistoryItem, ...]:
        cursor.execute(
            """SELECT document.event_id, document.document_kind, document.status,
                      document.currency, COALESCE(SUM(line.net_consideration_ex_tax_cents
                                                      + line.tax_cents), 0),
                      document.issued_at, MIN(line.service_period_start_at),
                      MAX(line.service_period_end_at)
                 FROM commercial_billing_documents_current document
            LEFT JOIN commercial_billing_lines line ON line.document_id = document.id
                WHERE document.agreement_id = %s
             GROUP BY document.id, document.event_id, document.document_kind,
                      document.status, document.currency, document.issued_at
             ORDER BY document.issued_at DESC, document.id DESC LIMIT %s""",
            (agreement_id, limit),
        )
        return tuple(BillingHistoryItem(
            document_id=row[0], kind=row[1], status=row[2], currency=row[3],
            total_cents=int(row[4]), issued_at=row[5],
            service_period_start_at=row[6], service_period_end_at=row[7],
        ) for row in cursor.fetchall())

    def portal_customer(self, *, actor_user_id: int, account_id: UUID, environment: str) -> str:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT customer.external_customer_id
                     FROM commercial_accounts account
                     JOIN commercial_account_members member
                       ON member.commercial_account_id = account.id
                     JOIN billing_provider_customers customer
                       ON customer.commercial_account_id = account.id
                      AND customer.provider = 'stripe' AND customer.environment = %s
                    WHERE account.public_id = %s AND member.user_id = %s
                      AND member.status = 'active'
                      AND member.role IN ('owner', 'admin', 'billing')
                      AND account.status = 'active'""",
                (environment, str(account_id), actor_user_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise CustomerBillingForbidden("Billing portal access is unavailable")
            return str(row[0])
        finally:
            cursor.close()

    def subscription_authority(
        self, *, actor_user_id: int, account_id: UUID, environment: str,
        requested_price_code: str | None = None,
    ) -> BillingSubscriptionAuthority:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT account.id, agreement.id, account.public_id, agreement.public_id,
                          customer.external_customer_id,
                          agreement.external_subscription_id, terms.offer_code,
                          terms.price_code, agreement.version,
                          agreement.current_period_end_at
                     FROM commercial_accounts account
                     JOIN commercial_account_members member
                       ON member.commercial_account_id = account.id
                     JOIN commercial_agreements agreement
                       ON agreement.commercial_account_id = account.id
                      AND agreement.billing_provider = 'stripe'
                      AND agreement.billing_environment = %s
                      AND agreement.state IN ('trialing','active','past_due','grace','paused')
                     JOIN commercial_agreement_terms terms
                       ON terms.agreement_id = agreement.id AND terms.effective_until IS NULL
                     JOIN billing_provider_customers customer
                       ON customer.commercial_account_id = account.id
                      AND customer.provider = 'stripe' AND customer.environment = %s
                    WHERE account.public_id = %s AND account.status = 'active'
                      AND member.user_id = %s AND member.status = 'active'
                      AND member.role IN ('owner', 'admin', 'billing')""",
                (environment, environment, str(account_id), actor_user_id),
            )
            rows = cursor.fetchall()
            if len(rows) != 1 or any(rows[0][index] is None for index in (5, 6, 7, 9)):
                raise CustomerBillingForbidden("Subscription management is unavailable")
            row = rows[0]
            direction = None
            if requested_price_code is not None:
                cursor.execute(
                    """SELECT CASE
                                 WHEN (target_offer->>'commercial_tier_rank')::INTEGER
                                    > (current_offer->>'commercial_tier_rank')::INTEGER THEN 'upgrade'
                                 WHEN (target_offer->>'commercial_tier_rank')::INTEGER
                                    < (current_offer->>'commercial_tier_rank')::INTEGER THEN 'downgrade'
                                 ELSE 'interval_change'
                               END
                         FROM commercial_policy_versions policy
                         CROSS JOIN LATERAL jsonb_array_elements(policy.body_json->'offers') current_offer
                         CROSS JOIN LATERAL jsonb_array_elements(policy.body_json->'offers') target_offer
                         CROSS JOIN LATERAL jsonb_array_elements(policy.body_json->'prices') target_price
                        WHERE policy.policy_kind = 'catalog' AND policy.state = 'active'
                          AND current_offer->>'offer_code' = %s
                          AND target_price->>'price_code' = %s
                          AND target_price->>'offer_code' = target_offer->>'offer_code'
                          AND (target_price->>'public_checkout_enabled')::BOOLEAN IS TRUE
                          AND target_price->>'billing_interval' IN ('month','year')
                          AND target_offer->>'surface_code' = current_offer->>'surface_code'
                          AND target_offer->>'transition_family' = current_offer->>'transition_family'""",
                    (str(row[6]), requested_price_code),
                )
                allowed_rows = cursor.fetchall()
                if len(allowed_rows) != 1:
                    raise CustomerBillingForbidden("Requested plan change is unavailable")
                direction = str(allowed_rows[0][0])
            return BillingSubscriptionAuthority(
                commercial_account_id=int(row[0]), agreement_internal_id=int(row[1]),
                account_id=row[2], agreement_id=row[3], customer_id=str(row[4]),
                subscription_id=str(row[5]), current_offer_code=str(row[6]),
                current_price_code=str(row[7]), agreement_version=int(row[8]),
                current_period_end_at=row[9], direction=direction,
            )
        finally:
            cursor.close()

    def prepare_command(
        self, *, actor_user_id: int, account_id: UUID, environment: str,
        command_id: UUID, action: Literal["cancel", "reactivate", "change_plan"],
        requested_price_code: str | None = None,
    ) -> PreparedBillingCommand:
        authority = self.subscription_authority(
            actor_user_id=actor_user_id, account_id=account_id,
            environment=environment, requested_price_code=requested_price_code,
        )
        if (action == "change_plan") != (requested_price_code is not None):
            raise CustomerBillingUnavailable("Billing command shape is invalid")
        payload = {
            "account_id": str(authority.account_id),
            "agreement_id": str(authority.agreement_id),
            "subscription_id": authority.subscription_id,
            "action": action,
            "price_code": requested_price_code,
        }
        payload_sha = canonical_sha256(payload)
        provider_key = "hank_billing_" + canonical_sha256({
            **payload, "command_id": str(command_id),
        }).removeprefix("sha256:")
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT version FROM commercial_agreements
                    WHERE id = %s AND commercial_account_id = %s FOR UPDATE""",
                (authority.agreement_internal_id, authority.commercial_account_id),
            )
            version = cursor.fetchone()
            if version is None or int(version[0]) != authority.agreement_version:
                raise CustomerBillingUnavailable("Agreement changed during billing command")
            cursor.execute(
                """SELECT command_id
                     FROM commercial_customer_billing_command_status
                    WHERE agreement_id = %s AND synchronization_status <> 'projected'
                    ORDER BY created_at DESC, id DESC LIMIT 1""",
                (authority.agreement_internal_id,),
            )
            pending = cursor.fetchone()
            if pending is not None and str(pending[0]) != str(command_id):
                raise CustomerBillingUnavailable("Another billing change is still pending")
            cursor.execute(
                """INSERT INTO commercial_customer_billing_commands (
                       command_id, commercial_account_id, agreement_id, actor_user_id,
                       environment, external_subscription_id, action, direction,
                       requested_price_code, effective_at, payload_sha256,
                       provider_idempotency_key
                   ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,
                       CASE WHEN %s = 'downgrade' THEN %s ELSE statement_timestamp() END,
                       %s,%s)
                ON CONFLICT (command_id) DO NOTHING""",
                (
                    str(command_id), authority.commercial_account_id,
                    authority.agreement_internal_id, actor_user_id, environment,
                    authority.subscription_id, action, authority.direction,
                    requested_price_code, authority.direction,
                    authority.current_period_end_at, payload_sha, provider_key,
                ),
            )
            cursor.execute(
                """SELECT command.payload_sha256, command.provider_idempotency_key,
                          command.effective_at, command.provider_submitted_at,
                          command.action, command.direction, command.requested_price_code,
                          status.synchronization_status
                     FROM commercial_customer_billing_commands command
                     JOIN commercial_customer_billing_command_status status
                       ON status.id = command.id
                    WHERE command.command_id = %s""",
                (str(command_id),),
            )
            row = cursor.fetchone()
            if row is None or row[0] != payload_sha or row[1] != provider_key:
                raise CustomerBillingUnavailable("Billing command idempotency conflict")
            stored_action, stored_direction, stored_price = row[4], row[5], row[6]
            return PreparedBillingCommand(
                authority=replace(authority, direction=stored_direction),
                command_id=command_id, action=stored_action,
                requested_price_code=stored_price, effective_at=row[2],
                provider_idempotency_key=str(row[1]), provider_submitted=row[3] is not None,
                synchronization_status=row[7],
            )
        finally:
            cursor.close()

    def mark_provider_submitted(self, *, command_id: UUID) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """UPDATE commercial_customer_billing_commands
                      SET provider_submitted_at = statement_timestamp()
                    WHERE command_id = %s AND provider_submitted_at IS NULL""",
                (str(command_id),),
            )
        finally:
            cursor.close()

    def receipt_authority(
        self, *, actor_user_id: int, account_id: UUID, document_id: UUID,
        environment: str,
    ) -> BillingReceiptAuthority:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """SELECT customer.external_customer_id, document.external_document_id
                     FROM commercial_accounts account
                     JOIN commercial_account_members member
                       ON member.commercial_account_id = account.id
                     JOIN billing_provider_customers customer
                       ON customer.commercial_account_id = account.id
                      AND customer.provider = 'stripe' AND customer.environment = %s
                     JOIN commercial_billing_documents document
                       ON document.commercial_account_id = account.id
                      AND document.provider = 'stripe' AND document.environment = %s
                      AND document.document_kind = 'invoice'
                    WHERE account.public_id = %s AND document.event_id = %s
                      AND member.user_id = %s AND member.status = 'active'
                      AND account.status <> 'closed'""",
                (environment, environment, str(account_id), str(document_id), actor_user_id),
            )
            rows = cursor.fetchall()
            if len(rows) != 1:
                raise CustomerBillingForbidden("Billing receipt is unavailable")
            return BillingReceiptAuthority(
                customer_id=str(rows[0][0]), external_invoice_id=str(rows[0][1])
            )
        finally:
            cursor.close()


class StripeSdkPortalProvider:
    _CUSTOMER = re.compile(r"^cus_[A-Za-z0-9]{6,250}$")

    def __init__(self, client: Any, *, livemode: bool) -> None:
        self._client = client
        self._livemode = livemode

    def create_session(self, *, customer_id: str, return_url: str) -> PortalSessionResult:
        if not self._CUSTOMER.fullmatch(customer_id) or not _canonical_https(
            return_url, allow_path=True
        ):
            raise CustomerBillingUnavailable("Customer portal request is invalid")
        try:
            session = self._client.v1.billing_portal.sessions.create(
                params={"customer": customer_id, "return_url": return_url}
            )
            url = _field(session, "url")
            livemode = _field(session, "livemode")
        except Exception as exc:
            raise CustomerBillingUnavailable("Customer portal operation failed") from exc
        if livemode is not None and bool(livemode) != self._livemode:
            raise CustomerBillingUnavailable("Customer portal environment mismatch")
        if (
            not isinstance(url, str)
            or not _canonical_https(url, allow_path=True)
            or urlsplit(url).hostname != "billing.stripe.com"
        ):
            raise CustomerBillingUnavailable("Customer portal response is invalid")
        return PortalSessionResult(url=url)


class StripeSdkSubscriptionMutationProvider:
    _SUBSCRIPTION = re.compile(r"^sub_[A-Za-z0-9]{4,251}$")
    _ITEM = re.compile(r"^si_[A-Za-z0-9]{4,252}$")

    def __init__(self, client: Any, *, deployment: StripeDeploymentManifest) -> None:
        self._client = client
        self._deployment = deployment

    def mutate(
        self, *, authority: BillingSubscriptionAuthority,
        action: Literal["cancel", "reactivate", "change_plan"],
        provider_idempotency_key: str, price_code: str | None = None,
    ) -> BillingLifecycleResult:
        if not self._SUBSCRIPTION.fullmatch(authority.subscription_id):
            raise CustomerBillingUnavailable("Subscription identity is invalid")
        current_price = self._deployment.resolve_price(authority.current_price_code).price_id
        try:
            current = self._client.v1.subscriptions.retrieve(
                authority.subscription_id, params={"expand": ["items.data.price"]}
            )
            self._validate_subscription(current, authority, expected_price=current_price)
            if (
                action == "change_plan"
                and authority.direction == "downgrade"
                and price_code is not None
            ):
                target = self._deployment.resolve_price(price_code).price_id
                result = self._schedule_downgrade(
                    authority=authority, current=current, target_price=target,
                    provider_idempotency_key=provider_idempotency_key,
                )
                return result
            params: dict[str, Any]
            if action == "cancel":
                params = {"cancel_at_period_end": True}
            elif action == "reactivate":
                params = {"cancel_at_period_end": False}
            else:
                if price_code is None:
                    raise CustomerBillingUnavailable("Plan change is invalid")
                target = self._deployment.resolve_price(price_code).price_id
                item = _only_subscription_item(current)
                item_id = _field(item, "id")
                if not isinstance(item_id, str) or not self._ITEM.fullmatch(item_id):
                    raise CustomerBillingUnavailable("Subscription item is invalid")
                params = {
                    "items": [{"id": item_id, "price": target, "quantity": 1}],
                    "payment_behavior": "error_if_incomplete",
                    "proration_behavior": "create_prorations",
                }
            if not re.fullmatch(r"hank_billing_[0-9a-f]{64}", provider_idempotency_key):
                raise CustomerBillingUnavailable("Provider command identity is invalid")
            updated = self._client.v1.subscriptions.update(
                authority.subscription_id, params=params,
                options={"idempotency_key": provider_idempotency_key},
            )
            expected = (
                self._deployment.resolve_price(price_code).price_id
                if action == "change_plan" and price_code is not None else current_price
            )
            self._validate_subscription(updated, authority, expected_price=expected)
            cancel_at_period_end = _field(updated, "cancel_at_period_end")
            if (
                action == "cancel" and cancel_at_period_end is not True
                or action == "reactivate" and cancel_at_period_end is not False
            ):
                raise CustomerBillingUnavailable("Subscription cancellation state mismatch")
        except CustomerBillingUnavailable:
            raise
        except Exception as exc:
            raise CustomerBillingProviderUnavailable(
                "Subscription operation could not be confirmed"
            ) from exc
        return BillingLifecycleResult(action=action)

    def _schedule_downgrade(
        self, *, authority: BillingSubscriptionAuthority, current: Any,
        target_price: str, provider_idempotency_key: str,
    ) -> BillingLifecycleResult:
        if not re.fullmatch(r"hank_billing_[0-9a-f]{64}", provider_idempotency_key):
            raise CustomerBillingUnavailable("Provider command identity is invalid")
        current_item = _only_subscription_item(current)
        created = self._client.v1.subscription_schedules.create(
            params={"from_subscription": authority.subscription_id},
            options={"idempotency_key": provider_idempotency_key + "_create"},
        )
        schedule_id = _field(created, "id")
        if (
            not isinstance(schedule_id, str)
            or not re.fullmatch(r"sub_sched_[A-Za-z0-9]{4,246}", schedule_id)
            or _identity(_field(created, "subscription")) != authority.subscription_id
            or _identity(_field(created, "customer")) != authority.customer_id
        ):
            raise CustomerBillingUnavailable("Subscription schedule authority mismatch")
        current_price = _field(current_item, "price")
        current_price_id = _identity(current_price)
        updated = self._client.v1.subscription_schedules.update(
            schedule_id,
            params={
                "end_behavior": "release",
                "proration_behavior": "none",
                "phases": [
                    {
                        "start_date": int(_field(current, "current_period_start")),
                        "end_date": int(_field(current, "current_period_end")),
                        "items": [{"price": current_price_id, "quantity": 1}],
                        "proration_behavior": "none",
                    },
                    {
                        "start_date": int(_field(current, "current_period_end")),
                        "iterations": 1,
                        "items": [{"price": target_price, "quantity": 1}],
                        "proration_behavior": "none",
                    },
                ],
            },
            options={"idempotency_key": provider_idempotency_key + "_update"},
        )
        if (
            _field(updated, "id") != schedule_id
            or _identity(_field(updated, "subscription")) != authority.subscription_id
            or _identity(_field(updated, "customer")) != authority.customer_id
            or _field(updated, "status") not in {"active", "not_started"}
        ):
            raise CustomerBillingUnavailable("Subscription schedule response mismatch")
        return BillingLifecycleResult(
            status="scheduled", action="change_plan",
            effective_at=authority.current_period_end_at,
        )

    def _validate_subscription(
        self, value: Any, authority: BillingSubscriptionAuthority, *, expected_price: str
    ) -> None:
        livemode = _field(value, "livemode")
        expected_live = self._deployment.billing_environment == "live"
        item = _only_subscription_item(value)
        price = _field(item, "price")
        price_id = _field(price, "id") if not isinstance(price, str) else price
        if (
            _field(value, "id") != authority.subscription_id
            or _identity(_field(value, "customer")) != authority.customer_id
            or not isinstance(livemode, bool)
            or bool(livemode) != expected_live
            or price_id != expected_price
            or _field(item, "quantity") != 1
            or _field(value, "current_period_end")
               != int(authority.current_period_end_at.timestamp())
        ):
            raise CustomerBillingUnavailable("Subscription authority mismatch")


class StripeSdkReceiptProvider:
    _INVOICE = re.compile(r"^in_[A-Za-z0-9]{5,252}$")

    def __init__(self, client: Any, *, livemode: bool) -> None:
        self._client = client
        self._livemode = livemode

    def receipt(self, *, authority: BillingReceiptAuthority) -> BillingReceiptResult:
        if not self._INVOICE.fullmatch(authority.external_invoice_id):
            raise CustomerBillingUnavailable("Invoice identity is invalid")
        try:
            invoice = self._client.v1.invoices.retrieve(authority.external_invoice_id)
            url = _field(invoice, "hosted_invoice_url")
            if (
                _field(invoice, "id") != authority.external_invoice_id
                or _identity(_field(invoice, "customer")) != authority.customer_id
                or bool(_field(invoice, "livemode")) != self._livemode
                or not isinstance(url, str)
                or not _canonical_https(url, allow_path=True)
                or urlsplit(url).hostname != "invoice.stripe.com"
            ):
                raise CustomerBillingUnavailable("Invoice receipt authority mismatch")
            return BillingReceiptResult(url=url)
        except CustomerBillingUnavailable:
            raise
        except Exception as exc:
            raise CustomerBillingUnavailable("Invoice receipt operation failed") from exc


def _field(value: Any, name: str) -> Any:
    return value.get(name) if isinstance(value, dict) else getattr(value, name, None)


def _identity(value: Any) -> Any:
    return value if isinstance(value, str) else _field(value, "id")


def _only_subscription_item(value: Any) -> Any:
    items = _field(value, "items")
    data = _field(items, "data")
    if not isinstance(data, (list, tuple)) or len(data) != 1:
        raise CustomerBillingUnavailable("Subscription item shape is invalid")
    return data[0]


def _canonical_https(value: str, *, allow_path: bool = False) -> bool:
    try:
        parts = urlsplit(value)
        return bool(
            parts.scheme == "https" and parts.hostname and parts.username is None
            and parts.password is None and parts.port is None and not parts.fragment
            and (allow_path or not parts.path) and (allow_path or not parts.query)
        )
    except ValueError:
        return False


__all__ = [
    "CustomerBillingForbidden", "CustomerBillingSummary", "CustomerBillingUnavailable",
    "BillingChangePlanRequest", "BillingLifecycleRequest", "BillingLifecycleResult",
    "BillingReceiptAuthority", "BillingReceiptRequest", "BillingReceiptResult",
    "BillingSubscriptionAuthority", "CustomerBillingProviderUnavailable",
    "PortalSessionRequest", "PortalSessionResult",
    "PostgresCustomerBillingService", "StripeSdkPortalProvider",
    "StripeSdkReceiptProvider", "StripeSdkSubscriptionMutationProvider",
]
