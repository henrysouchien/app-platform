"""Transaction-scoped PostgreSQL repository for commercial agreements."""

from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any
from uuid import UUID

from .agreements import (
    AgreementChannel,
    AgreementItemKind,
    AgreementState,
    BillingProvider,
    CommercialAgreementCreate,
    CommercialAgreementItemCreate,
    CommercialAgreementItemRecord,
    CommercialAgreementRecord,
    CommercialAgreementTermsBundle,
    CommercialAgreementTermsCreate,
    CommercialAgreementTermsRecord,
)


_AGREEMENT_COLUMNS = (
    "id, public_id, commercial_account_id, surface_code, channel, billing_provider, "
    "billing_environment, state, version, currency, service_start_at, service_end_at, "
    "current_period_start_at, current_period_end_at, trial_end_at, grace_end_at, "
    "pending_expires_at, cancel_at_period_end, canceled_at, external_subscription_id, "
    "external_contract_id, metadata, state_effective_at, created_at, updated_at"
)
_TERMS_COLUMNS = (
    "id, agreement_id, commercial_account_id, revision, offer_code, price_code, "
    "catalog_policy_id, entitlement_policy_id, payer_policy_id, budget_policy_id, "
    "contracted_service_period_cents, effective_from, effective_until, source_event_id, "
    "created_at, sealed_at, "
    "(to_jsonb(commercial_agreement_terms)->>'terminal_closed_at')::timestamptz AS terminal_closed_at, "
    "NULLIF(to_jsonb(commercial_agreement_terms)->>'terminal_command_id', '')::uuid AS terminal_command_id, "
    "(to_jsonb(commercial_agreement_terms)->>'voided_at')::timestamptz AS voided_at, "
    "NULLIF(to_jsonb(commercial_agreement_terms)->>'void_command_id', '')::uuid AS void_command_id"
)
_TERMS_FIELD_NAMES = (
    "id",
    "agreement_id",
    "commercial_account_id",
    "revision",
    "offer_code",
    "price_code",
    "catalog_policy_id",
    "entitlement_policy_id",
    "payer_policy_id",
    "budget_policy_id",
    "contracted_service_period_cents",
    "effective_from",
    "effective_until",
    "source_event_id",
    "created_at",
    "sealed_at",
    "terminal_closed_at",
    "terminal_command_id",
    "voided_at",
    "void_command_id",
)
_ITEM_COLUMNS = (
    "id, agreement_terms_id, agreement_id, commercial_account_id, item_code, item_kind, "
    "price_code, quantity, unit_amount_cents, billing_interval, service_start_at, "
    "service_end_at, metadata, created_at"
)


@dataclass(frozen=True)
class OfferTransitionMetadata:
    commercial_tier_rank: int
    transition_family: str
    channels: frozenset[str]
    entitlement_policy_id: int
    payer_policy_id: int
    budget_policy_id: int


@dataclass(frozen=True)
class BudgetPolicyEnvelope:
    model_budget_microusd: int
    technical_by_price_code: dict[str, int]
    non_model_by_price_code: dict[str, int]
    max_period_overdraft_microusd: int


def _as_mapping(columns: str, row: tuple[Any, ...]) -> dict[str, Any]:
    names = [name.strip() for name in columns.split(",")]
    return dict(zip(names, row, strict=True))


def _agreement_from_row(row: tuple[Any, ...]) -> CommercialAgreementRecord:
    payload = _as_mapping(_AGREEMENT_COLUMNS, row)
    payload["public_id"] = UUID(str(payload["public_id"]))
    payload["channel"] = AgreementChannel(payload["channel"])
    payload["billing_provider"] = BillingProvider(payload["billing_provider"])
    payload["state"] = AgreementState(payload["state"])
    return CommercialAgreementRecord.model_validate(payload)


def _terms_from_row(row: tuple[Any, ...]) -> CommercialAgreementTermsRecord:
    return CommercialAgreementTermsRecord.model_validate(
        dict(zip(_TERMS_FIELD_NAMES, row, strict=True))
    )


def _item_from_row(row: tuple[Any, ...]) -> CommercialAgreementItemRecord:
    payload = _as_mapping(_ITEM_COLUMNS, row)
    payload["item_kind"] = AgreementItemKind(payload["item_kind"])
    return CommercialAgreementItemRecord.model_validate(payload)


class PostgresAgreementRepository:
    """Persist tenant-bound agreement facts without owning commit or rollback."""

    def __init__(self, connection: Any) -> None:
        self._connection = connection

    def create_agreement(
        self, agreement: CommercialAgreementCreate
    ) -> CommercialAgreementRecord:
        self._require_transaction()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE",
                (agreement.commercial_account_id,),
            )
            if cursor.fetchone() is None:
                raise ValueError("commercial account does not exist")
            cursor.execute(
                f"""
                INSERT INTO commercial_agreements (
                    public_id, commercial_account_id, surface_code, channel,
                    billing_provider, billing_environment, state, currency,
                    service_start_at, service_end_at, current_period_start_at,
                    current_period_end_at, trial_end_at, grace_end_at,
                    pending_expires_at, cancel_at_period_end, canceled_at,
                    external_subscription_id, external_contract_id, metadata
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s::jsonb
                ) RETURNING {_AGREEMENT_COLUMNS}
                """,
                (
                    str(agreement.public_id),
                    agreement.commercial_account_id,
                    agreement.surface_code,
                    agreement.channel.value,
                    agreement.billing_provider.value,
                    agreement.billing_environment,
                    agreement.state.value,
                    agreement.currency,
                    agreement.service_start_at,
                    agreement.service_end_at,
                    agreement.current_period_start_at,
                    agreement.current_period_end_at,
                    agreement.trial_end_at,
                    agreement.grace_end_at,
                    agreement.pending_expires_at,
                    agreement.cancel_at_period_end,
                    agreement.canceled_at,
                    agreement.external_subscription_id,
                    agreement.external_contract_id,
                    json.dumps(
                        agreement.metadata, separators=(",", ":"), sort_keys=True
                    ),
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            raise RuntimeError("commercial agreement insert returned no record")
        return _agreement_from_row(row)

    def get_by_public_id(
        self,
        *,
        commercial_account_id: int,
        public_id: UUID,
    ) -> CommercialAgreementRecord | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""
                SELECT {_AGREEMENT_COLUMNS}
                FROM commercial_agreements
                WHERE commercial_account_id = %s AND public_id = %s
                """,
                (commercial_account_id, str(public_id)),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return None if row is None else _agreement_from_row(row)

    def get_by_id_for_update(
        self,
        *,
        commercial_account_id: int,
        agreement_id: int,
    ) -> CommercialAgreementRecord | None:
        self._require_transaction()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                "SELECT id FROM commercial_accounts WHERE id = %s FOR UPDATE",
                (commercial_account_id,),
            )
            if cursor.fetchone() is None:
                return None
            cursor.execute(
                f"""
                SELECT {_AGREEMENT_COLUMNS}
                FROM commercial_agreements
                WHERE commercial_account_id = %s AND id = %s
                FOR UPDATE
                """,
                (commercial_account_id, agreement_id),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return None if row is None else _agreement_from_row(row)

    def transition_state(
        self,
        *,
        expected: CommercialAgreementRecord,
        target_state: AgreementState,
        changed_at: Any,
        effective_at: Any,
    ) -> CommercialAgreementRecord | None:
        self._require_transaction()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""
                UPDATE commercial_agreements
                SET state = %s,
                    version = version + 1,
                    state_effective_at = %s,
                    canceled_at = CASE WHEN %s = 'canceled' THEN %s ELSE canceled_at END,
                    cancel_at_period_end = CASE
                        WHEN %s IN ('canceled', 'expired') THEN FALSE
                        ELSE cancel_at_period_end
                    END,
                    updated_at = %s
                WHERE id = %s AND commercial_account_id = %s
                  AND version = %s AND state = %s
                RETURNING {_AGREEMENT_COLUMNS}
                """,
                (
                    target_state.value,
                    effective_at,
                    target_state.value,
                    effective_at,
                    target_state.value,
                    changed_at,
                    expected.id,
                    expected.commercial_account_id,
                    expected.version,
                    expected.state.value,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return None if row is None else _agreement_from_row(row)

    def schedule_cancel_at_period_end(
        self,
        *,
        expected: CommercialAgreementRecord,
        changed_at: Any,
    ) -> CommercialAgreementRecord | None:
        self._require_transaction()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""
                UPDATE commercial_agreements
                SET cancel_at_period_end = TRUE,
                    version = version + 1,
                    updated_at = %s
                WHERE id = %s AND commercial_account_id = %s
                  AND version = %s AND state = %s
                  AND cancel_at_period_end = FALSE
                RETURNING {_AGREEMENT_COLUMNS}
                """,
                (
                    changed_at,
                    expected.id,
                    expected.commercial_account_id,
                    expected.version,
                    expected.state.value,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return None if row is None else _agreement_from_row(row)

    def record_terms_change(
        self,
        *,
        expected: CommercialAgreementRecord,
        changed_at: Any,
    ) -> CommercialAgreementRecord | None:
        self._require_transaction()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""
                UPDATE commercial_agreements
                SET version = version + 1,
                    updated_at = %s
                WHERE id = %s AND commercial_account_id = %s
                  AND version = %s AND state = %s
                RETURNING {_AGREEMENT_COLUMNS}
                """,
                (
                    changed_at,
                    expected.id,
                    expected.commercial_account_id,
                    expected.version,
                    expected.state.value,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return None if row is None else _agreement_from_row(row)

    def get_effective_terms_for_update(
        self,
        *,
        commercial_account_id: int,
        agreement_id: int,
        effective_at: Any,
    ) -> CommercialAgreementTermsRecord | None:
        self._require_transaction()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""
                SELECT {_TERMS_COLUMNS}
                FROM commercial_agreement_terms
                WHERE commercial_account_id = %s
                  AND agreement_id = %s
                  AND effective_from <= %s
                  AND (effective_until IS NULL OR effective_until > %s)
                  AND (to_jsonb(commercial_agreement_terms)->>'voided_at') IS NULL
                FOR UPDATE
                """,
                (
                    commercial_account_id,
                    agreement_id,
                    effective_at,
                    effective_at,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return None if row is None else _terms_from_row(row)

    def close_terms_for_replacement(
        self,
        *,
        expected: CommercialAgreementTermsRecord,
        effective_until: Any,
    ) -> bool:
        self._require_transaction()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE commercial_agreement_terms
                SET effective_until = %s
                WHERE id = %s
                  AND commercial_account_id = %s
                  AND agreement_id = %s
                  AND effective_until IS NULL
                  AND effective_from < %s
                RETURNING id
                """,
                (
                    effective_until,
                    expected.id,
                    expected.commercial_account_id,
                    expected.agreement_id,
                    effective_until,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return row is not None

    def get_offer_transition_metadata(
        self,
        *,
        catalog_policy_id: int,
        offer_code: str,
    ) -> OfferTransitionMetadata | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT offer.value->>'commercial_tier_rank',
                       offer.value->>'transition_family',
                       offer.value->'channels',
                       entitlement.id, payer.id, budget.id
                  FROM commercial_policy_versions AS policy,
                       jsonb_array_elements(
                           COALESCE(policy.body_json->'offers', '[]'::jsonb)
                       ) AS offer(value)
                  LEFT JOIN commercial_policy_versions AS entitlement
                    ON entitlement.policy_kind = 'entitlement'
                   AND entitlement.policy_code =
                       offer.value->'entitlement_policy'->>'policy_code'
                   AND entitlement.version =
                       offer.value->'entitlement_policy'->>'version'
                  LEFT JOIN commercial_policy_versions AS payer
                    ON payer.policy_kind = 'payer'
                   AND payer.policy_code =
                       offer.value->'payer_policy'->>'policy_code'
                   AND payer.version = offer.value->'payer_policy'->>'version'
                  LEFT JOIN commercial_policy_versions AS budget
                    ON budget.policy_kind = 'budget'
                   AND budget.policy_code =
                       offer.value->'budget_policy'->>'policy_code'
                   AND budget.version = offer.value->'budget_policy'->>'version'
                 WHERE policy.id = %s
                   AND policy.policy_kind = 'catalog'
                   AND offer.value->>'offer_code' = %s
                """,
                (catalog_policy_id, offer_code),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if (
            row is None
            or row[0] is None
            or not str(row[0]).isdigit()
            or not isinstance(row[1], str)
            or not isinstance(row[2], list)
            or not all(isinstance(channel, str) for channel in row[2])
            or any(
                isinstance(policy_id, bool) or not isinstance(policy_id, int)
                for policy_id in row[3:6]
            )
        ):
            return None
        return OfferTransitionMetadata(
            commercial_tier_rank=int(row[0]),
            transition_family=row[1],
            channels=frozenset(row[2]),
            entitlement_policy_id=row[3],
            payer_policy_id=row[4],
            budget_policy_id=row[5],
        )

    def get_active_catalog_body(
        self,
        *,
        catalog_policy_id: int,
        effective_at: Any,
    ) -> dict[str, Any] | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT body_json
                  FROM commercial_policy_versions
                 WHERE id = %s
                   AND policy_kind = 'catalog'
                   AND state = 'active'
                   AND activated_at <= %s
                   AND (retired_at IS NULL OR retired_at > %s)
                 FOR SHARE
                """,
                (catalog_policy_id, effective_at, effective_at),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None:
            return None
        body = row[0]
        if isinstance(body, str):
            body = json.loads(body)
        return body if isinstance(body, dict) else None

    def policies_are_effective(
        self,
        *,
        policy_ids: tuple[int, ...],
        effective_at: Any,
    ) -> bool:
        if not policy_ids or len(set(policy_ids)) != len(policy_ids):
            return False
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT COUNT(*) = %s
                  FROM commercial_policy_versions
                 WHERE id = ANY(%s)
                   AND state IN ('active', 'retired')
                   AND activated_at <= %s
                   AND (retired_at IS NULL OR retired_at > %s)
                """,
                (len(policy_ids), list(policy_ids), effective_at, effective_at),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return bool(row and row[0])

    def get_budget_policy_envelope(
        self,
        *,
        budget_policy_id: int,
    ) -> BudgetPolicyEnvelope | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT body_json
                  FROM commercial_policy_versions
                 WHERE id = %s AND policy_kind = 'budget'
                """,
                (budget_policy_id,),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        if row is None or not isinstance(row[0], dict):
            return None
        body = row[0]
        technical = body.get("technical_ceiling_microusd_by_price_code")
        non_model = body.get("non_model_ceiling_microusd_by_price_code")
        model_budget = body.get("model_budget_microusd")
        overdraft = body.get("max_period_overdraft_microusd")
        if overdraft is None:
            overdraft = 0
        if (
            isinstance(model_budget, bool)
            or not isinstance(model_budget, int)
            or model_budget < 0
            or isinstance(overdraft, bool)
            or not isinstance(overdraft, int)
            or overdraft < 0
            or not self._valid_budget_ceiling_map(technical)
            or not self._valid_budget_ceiling_map(non_model)
        ):
            return None
        assert isinstance(technical, dict)
        assert isinstance(non_model, dict)
        return BudgetPolicyEnvelope(
            model_budget_microusd=model_budget,
            technical_by_price_code=dict(technical),
            non_model_by_price_code=dict(non_model),
            max_period_overdraft_microusd=overdraft,
        )

    @staticmethod
    def _valid_budget_ceiling_map(value: object) -> bool:
        return isinstance(value, dict) and all(
            isinstance(key, str)
            and bool(key.strip())
            and not isinstance(ceiling, bool)
            and isinstance(ceiling, int)
            and ceiling >= 0
            for key, ceiling in value.items()
        )

    def close_terms_at_terminal_boundary(
        self,
        *,
        commercial_account_id: int,
        agreement_id: int,
        effective_until: Any,
        terminal_closed_at: Any,
        terminal_command_id: UUID,
    ) -> int | None:
        self._require_transaction()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE commercial_agreement_terms
                SET effective_until = %s,
                    terminal_closed_at = %s,
                    terminal_command_id = %s
                WHERE commercial_account_id = %s AND agreement_id = %s
                  AND effective_from < %s
                  AND (effective_until IS NULL OR effective_until > %s)
                RETURNING id
                """,
                (
                    effective_until,
                    terminal_closed_at,
                    str(terminal_command_id),
                    commercial_account_id,
                    agreement_id,
                    effective_until,
                    effective_until,
                ),
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return None if row is None else int(row[0])

    def supports_scheduled_terms_voiding(self) -> bool:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                SELECT COUNT(*) = 2
                  FROM information_schema.columns
                 WHERE table_schema = current_schema()
                   AND table_name = 'commercial_agreement_terms'
                   AND column_name IN ('voided_at', 'void_command_id')
                """
            )
            row = cursor.fetchone()
        finally:
            cursor.close()
        return bool(row and row[0])

    def void_future_terms_for_terminal(
        self,
        *,
        commercial_account_id: int,
        agreement_id: int,
        effective_at: Any,
        voided_at: Any,
        void_command_id: UUID,
    ) -> tuple[int, ...]:
        self._require_transaction()
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                UPDATE commercial_agreement_terms
                   SET voided_at = %s,
                       void_command_id = %s
                 WHERE commercial_account_id = %s
                   AND agreement_id = %s
                   AND effective_from >= %s
                   AND voided_at IS NULL
                RETURNING id
                """,
                (
                    voided_at,
                    str(void_command_id),
                    commercial_account_id,
                    agreement_id,
                    effective_at,
                ),
            )
            rows = cursor.fetchall()
        finally:
            cursor.close()
        return tuple(int(row[0]) for row in rows)

    def add_terms_revision(
        self,
        terms: CommercialAgreementTermsCreate,
        items: tuple[CommercialAgreementItemCreate, ...],
    ) -> CommercialAgreementTermsBundle:
        self._require_transaction()
        if not items:
            raise ValueError("agreement terms require at least one immutable item")
        item_codes = [item.item_code for item in items]
        if len(set(item_codes)) != len(item_codes):
            raise ValueError(
                "agreement item codes must be unique within a terms revision"
            )

        cursor = self._connection.cursor()
        try:
            cursor.execute(
                """
                INSERT INTO commercial_agreement_terms (
                    agreement_id, commercial_account_id, revision, offer_code,
                    price_code, catalog_policy_id, entitlement_policy_id,
                    payer_policy_id, budget_policy_id,
                    contracted_service_period_cents, effective_from,
                    effective_until, source_event_id
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s,
                    %s, %s, %s, %s, %s, %s
                ) RETURNING id
                """,
                (
                    terms.agreement_id,
                    terms.commercial_account_id,
                    terms.revision,
                    terms.offer_code,
                    terms.price_code,
                    terms.catalog_policy_id,
                    terms.entitlement_policy_id,
                    terms.payer_policy_id,
                    terms.budget_policy_id,
                    terms.contracted_service_period_cents,
                    terms.effective_from,
                    terms.effective_until,
                    terms.source_event_id,
                ),
            )
            terms_identity = cursor.fetchone()
            if terms_identity is None:
                raise RuntimeError(
                    "commercial agreement terms insert returned no record"
                )
            terms_id = terms_identity[0]
            stored_items: list[CommercialAgreementItemRecord] = []
            for item in items:
                cursor.execute(
                    f"""
                    INSERT INTO commercial_agreement_items (
                        agreement_terms_id, agreement_id, commercial_account_id,
                        item_code, item_kind, price_code, quantity,
                        unit_amount_cents, billing_interval, service_start_at,
                        service_end_at, metadata
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s, %s, %s::jsonb
                    ) RETURNING {_ITEM_COLUMNS}
                    """,
                    (
                        terms_id,
                        terms.agreement_id,
                        terms.commercial_account_id,
                        item.item_code,
                        item.item_kind.value,
                        item.price_code,
                        item.quantity,
                        item.unit_amount_cents,
                        item.billing_interval,
                        item.service_start_at,
                        item.service_end_at,
                        json.dumps(
                            item.metadata, separators=(",", ":"), sort_keys=True
                        ),
                    ),
                )
                item_row = cursor.fetchone()
                if item_row is None:
                    raise RuntimeError(
                        "commercial agreement item insert returned no record"
                    )
                stored_items.append(_item_from_row(item_row))
            cursor.execute(
                f"""
                UPDATE commercial_agreement_terms
                SET sealed_at = NOW()
                WHERE id = %s AND sealed_at IS NULL
                RETURNING {_TERMS_COLUMNS}
                """,
                (terms_id,),
            )
            sealed_terms_row = cursor.fetchone()
            if sealed_terms_row is None:
                raise RuntimeError("commercial agreement terms could not be sealed")
            stored_terms = _terms_from_row(sealed_terms_row)
        finally:
            cursor.close()
        return CommercialAgreementTermsBundle(
            terms=stored_terms,
            items=tuple(stored_items),
        )

    def get_terms_revision(
        self,
        *,
        commercial_account_id: int,
        agreement_id: int,
        revision: int,
    ) -> CommercialAgreementTermsBundle | None:
        cursor = self._connection.cursor()
        try:
            cursor.execute(
                f"""
                SELECT {_TERMS_COLUMNS}
                FROM commercial_agreement_terms
                WHERE commercial_account_id = %s
                  AND agreement_id = %s AND revision = %s
                """,
                (commercial_account_id, agreement_id, revision),
            )
            terms_row = cursor.fetchone()
            if terms_row is None:
                return None
            stored_terms = _terms_from_row(terms_row)
            cursor.execute(
                f"""
                SELECT {_ITEM_COLUMNS}
                FROM commercial_agreement_items
                WHERE agreement_terms_id = %s
                ORDER BY item_code
                """,
                (stored_terms.id,),
            )
            items = tuple(_item_from_row(row) for row in cursor.fetchall())
        finally:
            cursor.close()
        return CommercialAgreementTermsBundle(terms=stored_terms, items=items)

    def _require_transaction(self) -> None:
        if getattr(self._connection, "autocommit", False):
            raise ValueError("agreement persistence requires autocommit disabled")


__all__ = ["PostgresAgreementRepository"]
