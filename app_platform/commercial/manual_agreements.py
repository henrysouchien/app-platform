"""Catalog-resolved previews for manual commercial agreements."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Annotated, Callable, Literal, TypeVar
from uuid import UUID, uuid4

from dateutil.relativedelta import relativedelta
from pydantic import AwareDatetime, Field, StrictBool, StrictInt, model_validator

from .agreement_store import PostgresAgreementRepository
from .agreements import (
    AgreementChannel,
    AgreementItemKind,
    AgreementState,
    BillingProvider,
    CommercialAgreementCreate,
    CommercialAgreementItemCreate,
    CommercialAgreementRecord,
    CommercialAgreementTermsCreate,
)
from .audit import CommercialAuditEvent, insert_commercial_audit_event
from .authority import (
    ACTION_AUTHORITY,
    CommercialAction,
    NamedOperator,
    CommercialRole,
    record_change_execution,
)
from .authority_store import PostgresChangeRequestStore, load_named_operator
from .catalog import CatalogBody
from .errors import CommercialError, CommercialErrorCode
from .flags import CommercialFlags, get_commercial_flags
from .models import (
    MAX_SIGNED_BIGINT,
    NonEmptyStr,
    NonNegativeBigInt,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)
from .agreement_lifecycle import (
    AgreementProjectionHook,
    AgreementTransitionCommand,
    CommercialAgreementLifecycleService,
    IdempotencyKey,
)


class ManualAgreementPreviewRequest(StrictCommercialModel):
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    catalog_policy_id: Annotated[StrictInt, Field(gt=0)]
    offer_code: StableCode
    price_codes: tuple[StableCode, ...]
    channel: AgreementChannel
    service_start_at: AwareDatetime
    service_end_at: AwareDatetime
    contract_reference: NonEmptyStr
    source_event_id: NonEmptyStr
    negotiated_amount_cents_by_price_code: dict[
        StableCode, NonNegativeBigInt
    ] = Field(default_factory=dict)

    @model_validator(mode="after")
    def _valid_request(self) -> "ManualAgreementPreviewRequest":
        if self.service_end_at <= self.service_start_at:
            raise ValueError("manual agreement service end must follow its start")
        if not self.price_codes or len(set(self.price_codes)) != len(self.price_codes):
            raise ValueError("manual agreement price codes must be non-empty and unique")
        if not set(self.negotiated_amount_cents_by_price_code).issubset(
            self.price_codes
        ):
            raise ValueError("negotiated amounts must reference selected price codes")
        return self


class ManualBudgetEnvelope(StrictCommercialModel):
    model_budget_microusd: Annotated[StrictInt, Field(ge=0)]
    technical_ceiling_microusd_by_price_code: dict[
        StableCode, Annotated[StrictInt, Field(ge=0)]
    ]
    non_model_ceiling_microusd_by_price_code: dict[
        StableCode, Annotated[StrictInt, Field(ge=0)]
    ]
    max_period_overdraft_microusd: Annotated[StrictInt, Field(ge=0)]


class ManualAgreementPreview(StrictCommercialModel):
    preview_sha256: Sha256Digest
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    catalog_policy_id: Annotated[StrictInt, Field(gt=0)]
    entitlement_policy_id: Annotated[StrictInt, Field(gt=0)]
    payer_policy_id: Annotated[StrictInt, Field(gt=0)]
    budget_policy_id: Annotated[StrictInt, Field(gt=0)]
    offer_code: StableCode
    primary_price_code: StableCode
    surface_code: StableCode
    channel: AgreementChannel
    currency: NonEmptyStr
    service_start_at: AwareDatetime
    service_end_at: AwareDatetime
    current_period_start_at: AwareDatetime
    current_period_end_at: AwareDatetime
    contract_reference: NonEmptyStr
    source_event_id: NonEmptyStr
    contracted_service_period_cents: NonNegativeBigInt
    total_contract_value_cents: NonNegativeBigInt
    items: tuple[CommercialAgreementItemCreate, ...]
    budget: ManualBudgetEnvelope

    @model_validator(mode="after")
    def _digest_matches(self) -> "ManualAgreementPreview":
        payload = self.model_dump(mode="python", exclude={"preview_sha256"})
        if self.preview_sha256 != canonical_sha256(payload):
            raise ValueError("manual agreement preview digest does not match its facts")
        return self


class ManualAgreementDraftCommand(StrictCommercialModel):
    idempotency_key: IdempotencyKey
    reason_code: StableCode
    preview: ManualAgreementPreview


class ManualAgreementActivationIntent(StrictCommercialModel):
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    expected_version: Annotated[StrictInt, Field(gt=0)]
    idempotency_key: IdempotencyKey
    reason_code: StableCode
    preview: ManualAgreementPreview


class ManualAgreementActivationCommand(ManualAgreementActivationIntent):
    change_request_id: UUID
    step_up_event_id: UUID


class ManualAgreementCommandResult(StrictCommercialModel):
    command_id: UUID
    commercial_account_id: Annotated[StrictInt, Field(gt=0)]
    agreement_id: Annotated[StrictInt, Field(gt=0)]
    public_id: UUID
    state: Literal["draft", "active"]
    version: Annotated[StrictInt, Field(gt=0)]
    result_terms_id: Annotated[StrictInt, Field(gt=0)] | None = None
    audit_event_id: UUID
    replayed: StrictBool = False


def manual_agreement_activation_digest(
    command: ManualAgreementActivationIntent,
) -> str:
    return canonical_sha256(
        {
            "action": CommercialAction.MANUAL_AGREEMENT_ACTIVATION.value,
            "agreement_id": command.agreement_id,
            "expected_version": command.expected_version,
            "preview_sha256": command.preview.preview_sha256,
            "reason_code": command.reason_code,
        }
    )


_ITEM_KIND = {
    "recurring": AgreementItemKind.RECURRING,
    "onboarding": AgreementItemKind.ONBOARDING,
    "implementation": AgreementItemKind.IMPLEMENTATION,
}
_MANUAL_CHANNELS = frozenset(
    {AgreementChannel.PILOT, AgreementChannel.MANAGED, AgreementChannel.ADMIN_TEST}
)


class ManualAgreementPreviewService:
    """Resolve immutable manual agreement facts from one active durable catalog."""

    def __init__(
        self,
        connection: object,
        *,
        flags: CommercialFlags | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._repository = PostgresAgreementRepository(connection)
        self._flags = flags or get_commercial_flags()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def preview_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        request: ManualAgreementPreviewRequest,
    ) -> ManualAgreementPreview:
        self._require_transaction()
        if not self._flags.commercial_control_enabled:
            raise RuntimeError("commercial control is disabled")
        if runtime_environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=runtime_environment,
        )
        if CommercialRole.COMMERCIAL_ADMIN not in operator.roles:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        self._require_active_account(request.commercial_account_id)
        return self._resolve(request, preview_at=self._clock())

    def _resolve(
        self,
        request: ManualAgreementPreviewRequest,
        *,
        preview_at: datetime,
    ) -> ManualAgreementPreview:
        body_json = self._repository.get_active_catalog_body(
            catalog_policy_id=request.catalog_policy_id,
            effective_at=preview_at,
        )
        effective_body_json = self._repository.get_active_catalog_body(
            catalog_policy_id=request.catalog_policy_id,
            effective_at=request.service_start_at,
        )
        if body_json is None or effective_body_json != body_json:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        catalog = CatalogBody.model_validate(body_json)
        offers = {offer.offer_code: offer for offer in catalog.offers}
        offer = offers.get(request.offer_code)
        if (
            offer is None
            or offer.availability != "manual"
            or request.channel not in _MANUAL_CHANNELS
            or request.channel.value not in offer.channels
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        self._validate_service_period(request, offer)
        selected_codes = set(request.price_codes)
        if not selected_codes.issubset(offer.price_codes):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        prices = {price.price_code: price for price in catalog.prices}
        selected = [prices.get(code) for code in request.price_codes]
        if any(
            price is None
            or price.offer_code != offer.offer_code
            or price.currency != catalog.currency
            for price in selected
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        funding_prices = [price for price in selected if price and price.funds_service_period]
        if len(funding_prices) != 1:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        metadata = self._repository.get_offer_transition_metadata(
            catalog_policy_id=request.catalog_policy_id,
            offer_code=offer.offer_code,
        )
        if metadata is None:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        policy_ids = (
            metadata.entitlement_policy_id,
            metadata.payer_policy_id,
            metadata.budget_policy_id,
        )
        if not self._repository.policies_are_effective(
            policy_ids=policy_ids,
            effective_at=preview_at,
        ) or not self._repository.policies_are_effective(
            policy_ids=policy_ids,
            effective_at=request.service_start_at,
        ):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        budget = self._repository.get_budget_policy_envelope(
            budget_policy_id=metadata.budget_policy_id
        )
        if budget is None:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        billing_period_count, current_period_end_at = self._billing_schedule(
            request=request,
            funding_price=funding_prices[0],
        )
        items: list[CommercialAgreementItemCreate] = []
        contracted_cents = 0
        total_cents = 0
        for price in selected:
            assert price is not None
            item_kind = _ITEM_KIND.get(price.item_kind)
            if item_kind is None:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
                )
            amount_cents = request.negotiated_amount_cents_by_price_code.get(
                price.price_code, price.amount_cents
            )
            quantity = billing_period_count if price.funds_service_period else 1
            line_total_cents = amount_cents * quantity
            if line_total_cents > MAX_SIGNED_BIGINT - total_cents:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
                )
            total_cents += line_total_cents
            if price.funds_service_period:
                contracted_cents = amount_cents
            items.append(
                CommercialAgreementItemCreate(
                    item_code=price.price_code,
                    item_kind=item_kind,
                    price_code=price.price_code,
                    quantity=Decimal(quantity),
                    unit_amount_cents=amount_cents,
                    billing_interval=price.billing_interval,
                    service_start_at=request.service_start_at,
                    service_end_at=(
                        request.service_end_at
                        if price.funds_service_period
                        else current_period_end_at
                    ),
                    metadata={"catalog_price_code": price.price_code},
                )
            )
        budget_preview = ManualBudgetEnvelope(
            model_budget_microusd=budget.model_budget_microusd,
            technical_ceiling_microusd_by_price_code=(
                budget.technical_by_price_code
            ),
            non_model_ceiling_microusd_by_price_code=(
                budget.non_model_by_price_code
            ),
            max_period_overdraft_microusd=(budget.max_period_overdraft_microusd),
        )
        facts = {
            "commercial_account_id": request.commercial_account_id,
            "catalog_policy_id": request.catalog_policy_id,
            "entitlement_policy_id": metadata.entitlement_policy_id,
            "payer_policy_id": metadata.payer_policy_id,
            "budget_policy_id": metadata.budget_policy_id,
            "offer_code": offer.offer_code,
            "primary_price_code": funding_prices[0].price_code,
            "surface_code": offer.surface_code,
            "channel": request.channel.value,
            "currency": catalog.currency,
            "service_start_at": request.service_start_at,
            "service_end_at": request.service_end_at,
            "current_period_start_at": request.service_start_at,
            "current_period_end_at": current_period_end_at,
            "contract_reference": request.contract_reference,
            "source_event_id": request.source_event_id,
            "contracted_service_period_cents": contracted_cents,
            "total_contract_value_cents": total_cents,
            "items": [item.model_dump(mode="python") for item in items],
            "budget": budget_preview.model_dump(mode="python"),
        }
        return ManualAgreementPreview(
            preview_sha256=canonical_sha256(facts),
            **facts,
        )

    @staticmethod
    def _validate_service_period(request, offer) -> None:
        if offer.fixed_service_days is not None:
            expected_end = request.service_start_at + timedelta(
                days=offer.fixed_service_days
            )
            if request.service_end_at != expected_end:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
                )
        if offer.minimum_service_months is not None:
            minimum_end = request.service_start_at + relativedelta(
                months=offer.minimum_service_months
            )
            if request.service_end_at < minimum_end:
                raise CommercialError(
                    CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
                )

    @staticmethod
    def _billing_schedule(*, request, funding_price) -> tuple[int, datetime]:
        if funding_price.billing_interval == "fixed_term":
            return 1, request.service_end_at
        if funding_price.billing_interval == "month":
            def boundary_for(count: int) -> datetime:
                return request.service_start_at + relativedelta(months=count)
        elif funding_price.billing_interval == "year":
            def boundary_for(count: int) -> datetime:
                return request.service_start_at + relativedelta(years=count)
        else:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        first_period_end = boundary_for(1)
        for period_count in range(1, 1201):
            boundary = boundary_for(period_count)
            if boundary == request.service_end_at:
                return period_count, first_period_end
            if boundary > request.service_end_at:
                break
        raise CommercialError(
            CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
        )

    def _require_active_account(self, commercial_account_id: int) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT status FROM commercial_accounts
                 WHERE id = %s
                 FOR SHARE
                """,
                (commercial_account_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND)
        if row[0] != "active":
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_INACTIVE)

    def _require_transaction(self) -> None:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("manual agreement preview requires a transaction")


_ResultT = TypeVar("_ResultT")


class ManualAgreementService:
    """Create inert manual drafts and activate approved immutable terms."""

    def __init__(
        self,
        connection: object,
        *,
        projection_hook: AgreementProjectionHook,
        flags: CommercialFlags | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._connection = connection
        self._repository = PostgresAgreementRepository(connection)
        self._projection_hook = projection_hook
        self._flags = flags or get_commercial_flags()
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def create_draft_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: ManualAgreementDraftCommand,
    ) -> ManualAgreementCommandResult:
        self._require_operator(
            user_id=operator_user_id,
            environment=runtime_environment,
        )
        return self._run_atomic(
            lambda: self._create_draft_core(
                operator_user_id=operator_user_id,
                environment=runtime_environment,
                command=command,
            )
        )

    def _create_draft_core(
        self,
        *,
        operator_user_id: int,
        environment: Literal["dev", "staging", "prod"],
        command: ManualAgreementDraftCommand,
    ) -> ManualAgreementCommandResult:
        payload_sha256 = canonical_sha256(
            {"command_kind": "create_draft", **command.model_dump(mode="python")}
        )
        preview = command.preview
        self._lock_idempotency(preview.commercial_account_id, command.idempotency_key)
        replay = self._load_result(
            commercial_account_id=preview.commercial_account_id,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        self._assert_preview_resolves(preview, checked_at=self._clock())
        self._lock_surface(preview.commercial_account_id, preview.surface_code)
        self._require_active_account(preview.commercial_account_id)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT 1 FROM commercial_agreements
                 WHERE commercial_account_id = %s
                   AND surface_code = %s
                   AND state NOT IN ('canceled', 'expired')
                """,
                (preview.commercial_account_id, preview.surface_code),
            )
            duplicate_draft = cursor.fetchone() is not None
        finally:
            cursor.close()
        if duplicate_draft:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        agreement = self._repository.create_agreement(
            CommercialAgreementCreate(
                commercial_account_id=preview.commercial_account_id,
                surface_code=preview.surface_code,
                channel=preview.channel,
                billing_provider=BillingProvider.MANUAL,
                state=AgreementState.DRAFT,
                currency=preview.currency,
                service_start_at=preview.service_start_at,
                service_end_at=preview.service_end_at,
                current_period_start_at=preview.current_period_start_at,
                current_period_end_at=preview.current_period_end_at,
                external_contract_id=preview.contract_reference,
                metadata={"preview_sha256": preview.preview_sha256},
            )
        )
        audit_event_id = uuid4()
        insert_commercial_audit_event(
            self._connection,
            CommercialAuditEvent(
                event_id=audit_event_id,
                commercial_account_id=agreement.commercial_account_id,
                agreement_id=agreement.id,
                actor_type="admin",
                actor_id=str(operator_user_id),
                action="commercial.agreement.create",
                target_type="commercial_agreement",
                target_id=str(agreement.public_id),
                reason_code=command.reason_code,
                after={
                    "account_id": agreement.commercial_account_id,
                    "agreement_id": agreement.id,
                    "state": agreement.state.value,
                    "version": agreement.version,
                    "content_sha256": payload_sha256,
                    "result_code": "applied",
                },
            ),
        )
        result = ManualAgreementCommandResult(
            command_id=uuid4(),
            commercial_account_id=agreement.commercial_account_id,
            agreement_id=agreement.id,
            public_id=agreement.public_id,
            state="draft",
            version=agreement.version,
            audit_event_id=audit_event_id,
        )
        self._insert_result(
            result=result,
            environment=environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            actor_user_id=operator_user_id,
            command_kind="create_draft",
        )
        return result

    def activate_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        command: ManualAgreementActivationCommand,
    ) -> ManualAgreementCommandResult:
        self._require_operator(
            user_id=operator_user_id,
            environment=runtime_environment,
        )
        return self._run_atomic(
            lambda: self._activate_core(
                operator_user_id=operator_user_id,
                environment=runtime_environment,
                command=command,
            )
        )

    def validate_activation_intent_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
        intent: ManualAgreementActivationIntent,
    ) -> CommercialAgreementRecord:
        """Validate and lock the exact draft before an approval request is created."""

        self._require_operator(
            user_id=operator_user_id,
            environment=runtime_environment,
        )
        checked_at = self._clock()
        self._assert_preview_resolves(intent.preview, checked_at=checked_at)
        agreement = self._repository.get_by_id_for_update(
            commercial_account_id=intent.preview.commercial_account_id,
            agreement_id=intent.agreement_id,
        )
        if agreement is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_REQUIRED)
        if agreement.version != intent.expected_version:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
            )
        if not self._agreement_matches_preview(agreement, intent.preview):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        return agreement

    def _activate_core(
        self,
        *,
        operator_user_id: int,
        environment: Literal["dev", "staging", "prod"],
        command: ManualAgreementActivationCommand,
    ) -> ManualAgreementCommandResult:
        payload_sha256 = canonical_sha256(
            {"command_kind": "activate", **command.model_dump(mode="python")}
        )
        preview = command.preview
        self._lock_idempotency(preview.commercial_account_id, command.idempotency_key)
        replay = self._load_result(
            commercial_account_id=preview.commercial_account_id,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
        )
        if replay is not None:
            return replay
        mutation_at = self._clock()
        activation_window_start = preview.service_start_at - timedelta(minutes=5)
        if mutation_at < activation_window_start:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_ACTIVATION_NOT_DUE,
                retryable=True,
                retry_at=activation_window_start.isoformat(),
            )
        self._assert_preview_resolves(preview, checked_at=mutation_at)
        agreement = self._repository.get_by_id_for_update(
            commercial_account_id=preview.commercial_account_id,
            agreement_id=command.agreement_id,
        )
        if agreement is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_AGREEMENT_REQUIRED)
        if agreement.version != command.expected_version:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_VERSION_CONFLICT
            )
        if not self._agreement_matches_preview(agreement, preview):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        operator = self._authorize_activation(
            operator_user_id=operator_user_id,
            environment=environment,
            agreement_public_id=agreement.public_id,
            command=command,
            checked_at=mutation_at,
        )
        terms = self._repository.add_terms_revision(
            CommercialAgreementTermsCreate(
                agreement_id=agreement.id,
                commercial_account_id=agreement.commercial_account_id,
                revision=1,
                offer_code=preview.offer_code,
                price_code=preview.primary_price_code,
                catalog_policy_id=preview.catalog_policy_id,
                entitlement_policy_id=preview.entitlement_policy_id,
                payer_policy_id=preview.payer_policy_id,
                budget_policy_id=preview.budget_policy_id,
                contracted_service_period_cents=(
                    preview.contracted_service_period_cents
                ),
                effective_from=preview.service_start_at,
                source_event_id=preview.source_event_id,
            ),
            preview.items,
        )
        # Contract terms retain the negotiated service start.  The lifecycle
        # effective time describes this mutation, so already-started contracts
        # activate now while future contracts activate at their boundary.
        lifecycle_effective_at = max(preview.service_start_at, mutation_at)
        lifecycle_result = CommercialAgreementLifecycleService(
            self._connection,
            projection_hook=self._projection_hook,
            clock=lambda: mutation_at,
        ).transition_as_operator(
            operator_user_id=operator_user_id,
            runtime_environment=environment,
            command=AgreementTransitionCommand(
                commercial_account_id=agreement.commercial_account_id,
                agreement_id=agreement.id,
                expected_version=agreement.version,
                target_state=AgreementState.ACTIVE,
                idempotency_key=(
                    "manual-activate-" + payload_sha256.removeprefix("sha256:")
                ),
                reason_code=command.reason_code,
                effective_at=lifecycle_effective_at,
            ),
        )
        record_change_execution(
            command.change_request_id,
            store=PostgresChangeRequestStore(self._connection),
            operator=operator,
            succeeded=True,
            result_code="activated",
            audit_event_id=lifecycle_result.audit_event_id,
            now=mutation_at,
        )
        result = ManualAgreementCommandResult(
            command_id=uuid4(),
            commercial_account_id=agreement.commercial_account_id,
            agreement_id=agreement.id,
            public_id=agreement.public_id,
            state="active",
            version=lifecycle_result.version,
            result_terms_id=terms.terms.id,
            audit_event_id=lifecycle_result.audit_event_id,
        )
        self._insert_result(
            result=result,
            environment=environment,
            idempotency_key=command.idempotency_key,
            payload_sha256=payload_sha256,
            actor_user_id=operator_user_id,
            command_kind="activate",
            activation_change_request_id=command.change_request_id,
            authority_sha256=manual_agreement_activation_digest(command),
        )
        return result

    def _authorize_activation(
        self,
        *,
        operator_user_id: int,
        environment: Literal["dev", "staging", "prod"],
        agreement_public_id: UUID,
        command: ManualAgreementActivationCommand,
        checked_at: datetime,
    ) -> NamedOperator:
        store = PostgresChangeRequestStore(self._connection)
        request = store.get(command.change_request_id)
        operator = load_named_operator(
            self._connection,
            user_id=operator_user_id,
            environment=environment,
            step_up_event_id=command.step_up_event_id,
        )
        authority = ACTION_AUTHORITY[CommercialAction.MANUAL_AGREEMENT_ACTIVATION]
        if authority.required_role not in operator.roles:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        if (
            operator.step_up_verified_at is None
            or operator.step_up_event_id is None
            or operator.step_up_verified_at < checked_at - timedelta(minutes=15)
            or operator.step_up_verified_at > checked_at
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_STEP_UP_REQUIRED)
        if (
            request is None
            or request.environment != environment
            or request.state != "approved"
            or request.action != CommercialAction.MANUAL_AGREEMENT_ACTIVATION
            or request.expires_at <= checked_at
            or request.target_type != "commercial_agreement"
            or request.target_id != str(agreement_public_id)
            or request.payload_sha256 != manual_agreement_activation_digest(command)
        ):
            raise CommercialError(CommercialErrorCode.COMMERCIAL_APPROVAL_REQUIRED)
        return operator

    @staticmethod
    def _agreement_matches_preview(agreement, preview: ManualAgreementPreview) -> bool:
        return bool(
            agreement.state == AgreementState.DRAFT
            and agreement.billing_provider == BillingProvider.MANUAL
            and agreement.surface_code == preview.surface_code
            and agreement.channel == preview.channel
            and agreement.currency == preview.currency
            and agreement.service_start_at == preview.service_start_at
            and agreement.service_end_at == preview.service_end_at
            and agreement.current_period_start_at == preview.current_period_start_at
            and agreement.current_period_end_at == preview.current_period_end_at
            and agreement.external_contract_id == preview.contract_reference
            and agreement.metadata.get("preview_sha256") == preview.preview_sha256
        )

    def _assert_preview_resolves(
        self,
        preview: ManualAgreementPreview,
        *,
        checked_at: datetime,
    ) -> None:
        price_codes = tuple(item.price_code for item in preview.items)
        if any(price_code is None for price_code in price_codes):
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )
        try:
            request = ManualAgreementPreviewRequest(
                commercial_account_id=preview.commercial_account_id,
                catalog_policy_id=preview.catalog_policy_id,
                offer_code=preview.offer_code,
                price_codes=price_codes,
                channel=preview.channel,
                service_start_at=preview.service_start_at,
                service_end_at=preview.service_end_at,
                contract_reference=preview.contract_reference,
                source_event_id=preview.source_event_id,
                negotiated_amount_cents_by_price_code={
                    item.price_code: item.unit_amount_cents
                    for item in preview.items
                    if item.price_code is not None
                },
            )
            resolved = ManualAgreementPreviewService(
                self._connection,
                flags=self._flags,
                clock=lambda: checked_at,
            )._resolve(request, preview_at=checked_at)
        except (TypeError, ValueError) as exc:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            ) from exc
        if resolved != preview:
            raise CommercialError(
                CommercialErrorCode.COMMERCIAL_AGREEMENT_INVALID_TRANSITION
            )

    def _require_operator(self, *, user_id: int, environment: str) -> None:
        self._require_transaction()
        if not self._flags.commercial_control_enabled:
            raise RuntimeError("commercial control is disabled")
        if environment != self._flags.environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT environment FROM commercial_deployment_context WHERE singleton"
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None or row[0] != environment:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)
        operator = load_named_operator(
            self._connection,
            user_id=user_id,
            environment=environment,
        )
        if CommercialRole.COMMERCIAL_ADMIN not in operator.roles:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ROLE_REQUIRED)

    def _require_active_account(self, commercial_account_id: int) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT status FROM commercial_accounts WHERE id = %s FOR SHARE",
                (commercial_account_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_NOT_FOUND)
        if row[0] != "active":
            raise CommercialError(CommercialErrorCode.COMMERCIAL_ACCOUNT_INACTIVE)

    def _lock_idempotency(self, account_id: int, idempotency_key: str) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext('commercial_manual_command'), hashtext(%s))",
                (f"{account_id}:{idempotency_key}",),
            )
        finally:
            cursor.close()

    def _lock_surface(self, account_id: int, surface_code: str) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                "SELECT pg_advisory_xact_lock(hashtext('commercial_manual_surface'), hashtext(%s))",
                (f"{account_id}:{surface_code}",),
            )
        finally:
            cursor.close()

    def _load_result(
        self,
        *,
        commercial_account_id: int,
        idempotency_key: str,
        payload_sha256: str,
    ) -> ManualAgreementCommandResult | None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                SELECT command.command_id, command.payload_sha256,
                       command.agreement_id, agreement.public_id,
                       command.result_state, command.result_version,
                       command.result_terms_id, command.audit_event_id
                  FROM commercial_manual_agreement_commands AS command
                  JOIN commercial_agreements AS agreement
                    ON agreement.id = command.agreement_id
                   AND agreement.commercial_account_id = command.commercial_account_id
                 WHERE command.commercial_account_id = %s
                   AND command.idempotency_key = %s
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
        return ManualAgreementCommandResult(
            command_id=UUID(str(row[0])),
            commercial_account_id=commercial_account_id,
            agreement_id=row[2],
            public_id=UUID(str(row[3])),
            state=row[4],
            version=row[5],
            result_terms_id=row[6],
            audit_event_id=UUID(str(row[7])),
            replayed=True,
        )

    def _insert_result(
        self,
        *,
        result: ManualAgreementCommandResult,
        environment: str,
        idempotency_key: str,
        payload_sha256: str,
        actor_user_id: int,
        command_kind: Literal["create_draft", "activate"],
        activation_change_request_id: UUID | None = None,
        authority_sha256: str | None = None,
    ) -> None:
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute(
                """
                INSERT INTO commercial_manual_agreement_commands (
                    command_id, commercial_account_id, agreement_id,
                    environment, idempotency_key, command_kind, payload_sha256,
                    actor_user_id, result_state, result_version, result_terms_id,
                    activation_change_request_id, authority_sha256, audit_event_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
                """,
                (
                    str(result.command_id),
                    result.commercial_account_id,
                    result.agreement_id,
                    environment,
                    idempotency_key,
                    command_kind,
                    payload_sha256,
                    actor_user_id,
                    result.state,
                    result.version,
                    result.result_terms_id,
                    str(activation_change_request_id)
                    if activation_change_request_id
                    else None,
                    authority_sha256,
                    str(result.audit_event_id),
                ),
            )
        finally:
            cursor.close()

    def _run_atomic(self, operation: Callable[[], _ResultT]) -> _ResultT:
        self._require_transaction()
        cursor = self._connection.cursor()  # type: ignore[attr-defined]
        try:
            cursor.execute("SAVEPOINT commercial_manual_agreement_command")
            try:
                result = operation()
            except BaseException:
                cursor.execute(
                    "ROLLBACK TO SAVEPOINT commercial_manual_agreement_command"
                )
                cursor.execute("RELEASE SAVEPOINT commercial_manual_agreement_command")
                raise
            cursor.execute("RELEASE SAVEPOINT commercial_manual_agreement_command")
            return result
        finally:
            cursor.close()

    def _require_transaction(self) -> None:
        if bool(getattr(self._connection, "autocommit", False)):
            raise RuntimeError("manual agreement commands require a transaction")


__all__ = [
    "ManualAgreementActivationCommand",
    "ManualAgreementActivationIntent",
    "ManualAgreementCommandResult",
    "ManualAgreementDraftCommand",
    "ManualAgreementPreview",
    "ManualAgreementPreviewRequest",
    "ManualAgreementPreviewService",
    "ManualAgreementService",
    "ManualBudgetEnvelope",
    "manual_agreement_activation_digest",
]
