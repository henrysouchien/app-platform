"""Typed bodies for immutable commercial policy snapshots."""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated, Literal

from pydantic import (
    AwareDatetime,
    Field,
    JsonValue,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)

from .models import NonEmptyStr, StableCode, StrictCommercialModel
from .rates import ProviderRateTable, validate_rate_decimal


NonNegativeInt = Annotated[StrictInt, Field(ge=0)]
PositiveInt = Annotated[StrictInt, Field(gt=0)]
CurrencyCode = Annotated[NonEmptyStr, Field(pattern=r"^[A-Z]{3}$")]


class PolicyRef(StrictCommercialModel):
    policy_code: StableCode
    version: NonEmptyStr


class ScopeDefinition(StrictCommercialModel):
    key: StableCode
    availability: Literal["current", "future", "internal"]


class EntitlementGrant(StrictCommercialModel):
    key: StableCode
    effect: Literal["allow", "deny", "limit"]
    subject_kind: Literal["account", "user", "token"]
    value: JsonValue

    @model_validator(mode="after")
    def _validate_value_and_execution_scope(self) -> "EntitlementGrant":
        if self.effect in {"allow", "deny"} and not isinstance(self.value, bool):
            raise ValueError("allow and deny grants require a boolean value")
        if self.effect == "limit" and (
            isinstance(self.value, bool)
            or not isinstance(self.value, int)
            or self.value < 0
        ):
            raise ValueError("limit grants require a non-negative integer value")
        if (
            self.key == "scope:trade-execute"
            and self.effect == "allow"
            and self.value is True
            and self.subject_kind == "account"
        ):
            raise ValueError("scope:trade-execute allows cannot be account-scoped")
        return self


class EntitlementRetentionRule(StrictCommercialModel):
    state: Literal["past_due", "grace", "canceled"]
    keys: tuple[StableCode, ...]
    access_seconds: PositiveInt

    @field_validator("keys")
    @classmethod
    def _safe_unique_keys(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not value or len(set(value)) != len(value):
            raise ValueError("retained entitlement keys must be non-empty and unique")
        if "scope:trade-execute" in value:
            raise ValueError("trade execution can never be retained")
        return value


class EntitlementPolicyBody(StrictCommercialModel):
    surface_code: StableCode
    grants: tuple[EntitlementGrant, ...]
    retention: tuple[EntitlementRetentionRule, ...] = ()

    @field_validator("grants")
    @classmethod
    def _validate_unique_grants(
        cls, value: tuple[EntitlementGrant, ...]
    ) -> tuple[EntitlementGrant, ...]:
        identities = [(grant.key, grant.effect, grant.subject_kind) for grant in value]
        if len(set(identities)) != len(identities):
            raise ValueError("entitlement grants must have unique key/effect/subject tuples")
        return value

    @model_validator(mode="after")
    def _validate_retention(self) -> "EntitlementPolicyBody":
        states = [rule.state for rule in self.retention]
        if len(set(states)) != len(states):
            raise ValueError("entitlement retention states must be unique")
        grant_keys = self.keys
        for rule in self.retention:
            if not set(rule.keys).issubset(grant_keys):
                raise ValueError("retained entitlement keys must come from policy grants")
        return self

    @property
    def keys(self) -> frozenset[str]:
        return frozenset(grant.key for grant in self.grants)

    def retention_for(self, state: str) -> EntitlementRetentionRule | None:
        return next((rule for rule in self.retention if rule.state == state), None)


class PayerRule(StrictCommercialModel):
    cost_class: StableCode
    providers: tuple[StableCode, ...]
    credential_route: StableCode | Literal["*"] = "*"
    credential_owner: Literal["customer", "hank", "flat_subscription"]
    payer_class: Literal["customer_paid", "hank_paid", "hank_shadow_priced"]


class PayerPolicyBody(StrictCommercialModel):
    unmatched_route_action: Literal["quarantine"]
    supports_byok: StrictBool
    rules: tuple[PayerRule, ...]
    hank_funded_cost_classes: tuple[StableCode, ...]

    @model_validator(mode="after")
    def _validate_rules(self) -> "PayerPolicyBody":
        if not self.rules:
            raise ValueError("payer policy rules must be non-empty")
        identities = [
            (
                rule.cost_class,
                rule.providers,
                rule.credential_route,
                rule.credential_owner,
            )
            for rule in self.rules
        ]
        if len(set(identities)) != len(identities):
            raise ValueError(
                "payer rules must have unique matching identities"
            )
        if any(
            not rule.providers or len(rule.providers) != len(set(rule.providers))
            for rule in self.rules
        ):
            raise ValueError("payer rule providers must be non-empty and unique")
        for index, left in enumerate(self.rules):
            for right in self.rules[index + 1 :]:
                if (
                    left.cost_class == right.cost_class
                    and left.credential_owner == right.credential_owner
                    and bool(set(left.providers).intersection(right.providers))
                    and _payer_selector_overlaps(
                        left.credential_route, right.credential_route
                    )
                    and _payer_rule_specificity(left)
                    == _payer_rule_specificity(right)
                ):
                    raise ValueError("payer rules contain an ambiguous selector overlap")
        customer_routes = {
            rule.cost_class
            for rule in self.rules
            if rule.credential_owner == "customer"
            and rule.payer_class == "customer_paid"
        }
        if self.supports_byok and not customer_routes:
            raise ValueError("BYOK payer policies require a customer-paid credential route")
        if not self.supports_byok and customer_routes:
            raise ValueError("non-BYOK payer policies cannot declare customer-paid routes")
        expected_payer_by_owner = {
            "customer": "customer_paid",
            "hank": "hank_paid",
            "flat_subscription": "hank_shadow_priced",
        }
        invalid_routes = [
            (rule.cost_class, rule.credential_owner, rule.payer_class)
            for rule in self.rules
            if rule.payer_class != expected_payer_by_owner[rule.credential_owner]
        ]
        if invalid_routes:
            raise ValueError(
                "payer class must match the observed credential owner; "
                f"invalid routes: {invalid_routes}"
            )
        declared = set(self.hank_funded_cost_classes)
        if len(declared) != len(self.hank_funded_cost_classes):
            raise ValueError("hank_funded_cost_classes must be unique")
        derived = {
            rule.cost_class
            for rule in self.rules
            if rule.payer_class in {"hank_paid", "hank_shadow_priced"}
        }
        if declared != derived:
            raise ValueError(
                "hank_funded_cost_classes must exactly match Hank-funded rules"
            )
        return self


def _payer_selector_overlaps(left: str, right: str) -> bool:
    return left == "*" or right == "*" or left == right


def _payer_rule_specificity(rule: PayerRule) -> int:
    return int(rule.credential_route != "*")


class BudgetThreshold(StrictCommercialModel):
    percent: Literal[75, 90, 100]
    action: Literal["alert", "warn_degrade", "block_hank_funded"]


class BudgetPolicyBody(StrictCommercialModel):
    currency: CurrencyCode
    period_kind: Literal["service_month", "fixed_term"]
    model_budget_microusd: NonNegativeInt
    technical_ceiling_microusd_by_price_code: dict[StableCode, PositiveInt]
    non_model_ceiling_microusd_by_price_code: dict[StableCode, NonNegativeInt]
    enforcement_basis: Literal["management_cost_basis"]
    thresholds: tuple[BudgetThreshold, ...]
    reservation_safety_state: Literal["unapproved", "approved"] = "unapproved"
    max_concurrent_reservations: PositiveInt | None = None
    max_unreserved_delta_microusd: NonNegativeInt | None = None
    late_child_allowance_microusd: NonNegativeInt | None = None
    max_period_overdraft_microusd: NonNegativeInt | None = None

    @model_validator(mode="after")
    def _validate_budget_math(self) -> "BudgetPolicyBody":
        actions = {item.percent: item.action for item in self.thresholds}
        expected_actions = {
            75: "alert",
            90: "warn_degrade",
            100: "block_hank_funded",
        }
        if len(actions) != len(self.thresholds) or actions != expected_actions:
            raise ValueError(
                "budget thresholds must define exact 75/90/100 safety actions"
            )

        technical_codes = set(self.technical_ceiling_microusd_by_price_code)
        non_model_codes = set(self.non_model_ceiling_microusd_by_price_code)
        if technical_codes != non_model_codes:
            raise ValueError("technical and non-model ceilings must cover the same price codes")
        for price_code, technical in self.technical_ceiling_microusd_by_price_code.items():
            non_model = self.non_model_ceiling_microusd_by_price_code[price_code]
            if self.model_budget_microusd + non_model != technical:
                raise ValueError(
                    f"model plus non-model ceiling must equal technical ceiling for {price_code}"
                )

        safety_values = (
            self.max_concurrent_reservations,
            self.max_unreserved_delta_microusd,
            self.late_child_allowance_microusd,
            self.max_period_overdraft_microusd,
        )
        if self.reservation_safety_state == "approved":
            if any(value is None for value in safety_values):
                raise ValueError("approved reservation safety requires every overshoot bound")
            assert self.max_concurrent_reservations is not None
            assert self.max_unreserved_delta_microusd is not None
            assert self.late_child_allowance_microusd is not None
            assert self.max_period_overdraft_microusd is not None
            maximum = (
                self.max_concurrent_reservations * self.max_unreserved_delta_microusd
                + self.late_child_allowance_microusd
            )
            if maximum > self.max_period_overdraft_microusd:
                raise ValueError("reservation safety values violate the maximum overdraft bound")
        elif any(value is not None for value in safety_values):
            raise ValueError("unapproved reservation safety must not publish partial bounds")
        return self


class RatePolicyBody(StrictCommercialModel):
    currency: Literal["USD"]
    source_currency: Annotated[str, Field(pattern=r"^[A-Z]{3}$")] = "USD"
    normalization_exchange_rate_to_usd: Decimal = Decimal("1")
    state: Literal["draft", "active"]
    effective_from: AwareDatetime | None = None
    effective_until: AwareDatetime | None = None
    providers: tuple[ProviderRateTable, ...] | dict[StableCode, JsonValue]
    unknown_hank_funded_action: Literal["block"]
    unknown_customer_paid_action: Literal["record", "block"] = "record"
    customer_paid_work_class_actions: dict[
        StableCode, Literal["record", "block"]
    ] = Field(default_factory=dict)

    @field_validator("normalization_exchange_rate_to_usd", mode="before")
    @classmethod
    def _exchange_decimal(cls, value: object) -> Decimal:
        return validate_rate_decimal(
            value, positive=True, label="normalization exchange rate"
        )

    @model_validator(mode="after")
    def _validate_rate_policy(self) -> "RatePolicyBody":
        if self.state == "draft":
            if (
                self.providers
                or self.effective_from is not None
                or self.effective_until is not None
                or self.customer_paid_work_class_actions
            ):
                raise ValueError("draft rate policy must remain empty and ineffective")
            return self
        if self.effective_from is None or not isinstance(self.providers, tuple) or not self.providers:
            raise ValueError("active rate policy requires effective provider entries")
        if self.effective_until is not None and self.effective_until <= self.effective_from:
            raise ValueError("active rate policy effective range is empty")
        provider_names = [provider.provider for provider in self.providers]
        if len(provider_names) != len(set(provider_names)):
            raise ValueError("active rate policy providers must be unique")
        for provider in self.providers:
            for entry in provider.entries:
                if entry.effective_from < self.effective_from or (
                    self.effective_until is not None
                    and (
                        entry.effective_until is None
                        or entry.effective_until > self.effective_until
                    )
                ):
                    raise ValueError(
                        "active provider rate entry must be bounded by its policy"
                    )
        if self.source_currency == "USD" and self.normalization_exchange_rate_to_usd != 1:
            raise ValueError("USD rate policy requires an exchange rate of one")
        return self


POLICY_BODY_MODELS = {
    "entitlement": EntitlementPolicyBody,
    "payer": PayerPolicyBody,
    "budget": BudgetPolicyBody,
    "rate": RatePolicyBody,
}


__all__ = [
    "BudgetPolicyBody",
    "BudgetThreshold",
    "EntitlementGrant",
    "EntitlementPolicyBody",
    "EntitlementRetentionRule",
    "POLICY_BODY_MODELS",
    "PayerPolicyBody",
    "PayerRule",
    "PolicyRef",
    "RatePolicyBody",
    "ScopeDefinition",
]
