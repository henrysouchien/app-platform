"""Load and validate the checked-in commercial catalog and policy bundle."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator
import yaml

from .models import (
    CommercialPolicySnapshotV1,
    NonEmptyStr,
    NonNegativeBigInt,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)
from .policies import (
    BudgetPolicyBody,
    EntitlementPolicyBody,
    POLICY_BODY_MODELS,
    PayerPolicyBody,
    PolicyRef,
    ScopeDefinition,
)


DEFAULT_COMMERCIAL_CONFIG_ROOT = Path(__file__).resolve().parents[2] / "config" / "commercial"
CurrencyCode = Annotated[NonEmptyStr, Field(pattern=r"^[A-Z]{3}$")]
PositiveInt = Annotated[StrictInt, Field(gt=0)]


class CatalogOffer(StrictCommercialModel):
    offer_code: StableCode
    display_name: NonEmptyStr
    surface_code: StableCode
    transition_family: StableCode
    commercial_tier_rank: Annotated[StrictInt, Field(ge=0)]
    channels: tuple[
        Literal["self_serve", "invite_trial", "pilot", "managed", "admin_test"],
        ...,
    ]
    availability: Literal["draft", "manual", "invite", "public"]
    requires_service_dates: StrictBool
    minimum_service_months: PositiveInt | None = None
    fixed_service_days: PositiveInt | None = None
    entitlement_policy: PolicyRef
    payer_policy: PolicyRef
    budget_policy: PolicyRef
    price_codes: tuple[StableCode, ...]

    @model_validator(mode="after")
    def _validate_service_shape(self) -> "CatalogOffer":
        if self.availability in {"manual", "invite"} and not self.requires_service_dates:
            raise ValueError("manual and invite offers require explicit service dates")
        if "pilot" in self.channels and self.fixed_service_days is None:
            raise ValueError("pilot offers require fixed_service_days")
        if "managed" in self.channels and not self.requires_service_dates:
            raise ValueError("managed offers require service dates")
        if not self.price_codes:
            raise ValueError("offers require at least one price code")
        if len(set(self.price_codes)) != len(self.price_codes):
            raise ValueError("offer price_codes must be unique")
        return self


class CatalogPrice(StrictCommercialModel):
    price_code: StableCode
    offer_code: StableCode
    item_kind: Literal["recurring", "onboarding", "implementation"]
    amount_cents: NonNegativeBigInt
    currency: CurrencyCode
    billing_interval: Literal["one_time", "month", "year", "fixed_term"]
    service_months: PositiveInt | None = None
    fixed_service_days: PositiveInt | None = None
    funds_service_period: StrictBool
    discount_months_vs_monthly: Annotated[StrictInt, Field(ge=0, le=11)] | None = None
    public_checkout_enabled: StrictBool
    stripe_lookup_keys: dict[Literal["test", "live"], NonEmptyStr] = Field(
        default_factory=dict
    )

    @model_validator(mode="after")
    def _validate_price_shape(self) -> "CatalogPrice":
        if self.billing_interval == "month" and self.service_months != 1:
            raise ValueError("monthly prices require service_months=1")
        if self.billing_interval == "year" and self.service_months != 12:
            raise ValueError("annual prices require service_months=12")
        if self.billing_interval == "fixed_term" and self.fixed_service_days is None:
            raise ValueError("fixed-term prices require fixed_service_days")
        if self.billing_interval == "one_time" and self.funds_service_period:
            raise ValueError("one-time implementation/onboarding prices do not fund service periods")
        if self.public_checkout_enabled and set(self.stripe_lookup_keys) != {"test", "live"}:
            raise ValueError("public checkout prices require test and live Stripe lookup keys")
        return self


class CatalogBody(StrictCommercialModel):
    currency: Literal["USD"]
    scope_registry: tuple[ScopeDefinition, ...]
    offers: tuple[CatalogOffer, ...]
    prices: tuple[CatalogPrice, ...]

    @field_validator("scope_registry")
    @classmethod
    def _unique_scopes(
        cls, value: tuple[ScopeDefinition, ...]
    ) -> tuple[ScopeDefinition, ...]:
        keys = [item.key for item in value]
        if len(set(keys)) != len(keys):
            raise ValueError("scope registry keys must be unique")
        return value

    @field_validator("offers")
    @classmethod
    def _unique_offers(cls, value: tuple[CatalogOffer, ...]) -> tuple[CatalogOffer, ...]:
        codes = [item.offer_code for item in value]
        if len(set(codes)) != len(codes):
            raise ValueError("offer codes must be unique")
        return value

    @field_validator("prices")
    @classmethod
    def _unique_prices(cls, value: tuple[CatalogPrice, ...]) -> tuple[CatalogPrice, ...]:
        codes = [item.price_code for item in value]
        if len(set(codes)) != len(codes):
            raise ValueError("price codes must be unique")
        return value


@dataclass(frozen=True)
class CommercialCatalogBundle:
    catalog_snapshot: CommercialPolicySnapshotV1
    catalog: CatalogBody
    policy_snapshots: Mapping[tuple[str, str, str], CommercialPolicySnapshotV1]
    policy_bodies: Mapping[tuple[str, str, str], StrictCommercialModel]

    def policy(self, kind: str, reference: PolicyRef) -> StrictCommercialModel:
        key = (kind, reference.policy_code, reference.version)
        try:
            return self.policy_bodies[key]
        except KeyError as exc:
            raise ValueError(
                f"missing {kind} policy {reference.policy_code}@{reference.version}"
            ) from exc

    def validate_snapshot_coherence(self) -> None:
        """Prove typed policy views are derived from the snapshots to be persisted."""

        if canonical_sha256(self.catalog_snapshot.body) != self.catalog_snapshot.content_sha256:
            raise ValueError("catalog snapshot content_sha256 does not match its body")
        snapshot_catalog = CatalogBody.model_validate(self.catalog_snapshot.body)
        if snapshot_catalog != self.catalog:
            raise ValueError("catalog snapshot and typed catalog representations differ")
        if set(self.policy_snapshots) != set(self.policy_bodies):
            raise ValueError("policy snapshot and typed body identities differ")
        for key, snapshot in self.policy_snapshots.items():
            if canonical_sha256(snapshot.body) != snapshot.content_sha256:
                raise ValueError(
                    "policy snapshot content_sha256 does not match its body: "
                    f"{snapshot.policy_kind}:{snapshot.policy_code}:{snapshot.version}"
                )
            envelope_key = (
                snapshot.policy_kind,
                snapshot.policy_code,
                snapshot.version,
            )
            if key != envelope_key:
                raise ValueError(
                    "policy mapping key and snapshot envelope identity differ: "
                    f"{key} != {envelope_key}"
                )
            body_model = POLICY_BODY_MODELS.get(snapshot.policy_kind)
            if body_model is None:
                raise ValueError(f"unsupported policy kind in bundle: {snapshot.policy_kind}")
            snapshot_body = body_model.model_validate(snapshot.body)
            if snapshot_body != self.policy_bodies[key]:
                raise ValueError(
                    "policy snapshot and typed body representations differ: "
                    f"{snapshot.policy_kind}:{snapshot.policy_code}:{snapshot.version}"
                )

    def validate(self) -> None:
        offers = {offer.offer_code: offer for offer in self.catalog.offers}
        prices = {price.price_code: price for price in self.catalog.prices}
        scope_registry = {item.key: item for item in self.catalog.scope_registry}

        for price in self.catalog.prices:
            if price.currency != self.catalog.currency:
                raise ValueError(f"price {price.price_code} currency differs from catalog")
            if price.offer_code not in offers:
                raise ValueError(
                    f"price {price.price_code} references missing offer {price.offer_code}"
                )

        lookup_owners: dict[tuple[str, str], str] = {}
        for price in self.catalog.prices:
            for environment, lookup_key in price.stripe_lookup_keys.items():
                identity = (environment, lookup_key)
                owner = lookup_owners.setdefault(identity, price.price_code)
                if owner != price.price_code:
                    raise ValueError(
                        f"Stripe lookup key {lookup_key!r} in {environment} maps to multiple prices"
                    )

        for offer in self.catalog.offers:
            offer_prices = [
                price
                for price in self.catalog.prices
                if price.offer_code == offer.offer_code
            ]
            listed_prices = {price.price_code for price in offer_prices}
            if listed_prices != set(offer.price_codes):
                raise ValueError(
                    f"offer {offer.offer_code} price_codes do not match catalog price rows"
                )

            entitlement = self.policy("entitlement", offer.entitlement_policy)
            payer = self.policy("payer", offer.payer_policy)
            budget = self.policy("budget", offer.budget_policy)
            assert isinstance(entitlement, EntitlementPolicyBody)
            assert isinstance(payer, PayerPolicyBody)
            assert isinstance(budget, BudgetPolicyBody)

            checkout_prices = [
                price for price in offer_prices if price.public_checkout_enabled
            ]
            if checkout_prices and (
                offer.availability != "public" or "self_serve" not in offer.channels
            ):
                raise ValueError(
                    f"offer {offer.offer_code} must be public self-serve before checkout"
                )

            if entitlement.surface_code != offer.surface_code:
                raise ValueError(
                    f"offer {offer.offer_code} surface does not match entitlement policy"
                )
            unknown_keys = entitlement.keys - set(scope_registry)
            if unknown_keys:
                raise ValueError(
                    f"offer {offer.offer_code} entitlement uses unknown keys: {sorted(unknown_keys)}"
                )
            if offer.availability == "public":
                unavailable = {
                    key
                    for key in entitlement.keys
                    if scope_registry[key].availability != "current"
                }
                if unavailable:
                    raise ValueError(
                        f"public offer {offer.offer_code} uses unavailable entitlements: {sorted(unavailable)}"
                    )

            if budget.currency != self.catalog.currency:
                raise ValueError(
                    f"offer {offer.offer_code} budget currency differs from catalog"
                )

            service_prices = {
                code
                for code in offer.price_codes
                if prices[code].funds_service_period
            }
            if set(budget.technical_ceiling_microusd_by_price_code) != service_prices:
                raise ValueError(
                    f"offer {offer.offer_code} budget does not cover every service-period price"
                )
            if payer.hank_funded_cost_classes and not budget.technical_ceiling_microusd_by_price_code:
                raise ValueError(f"Hank-funded offer {offer.offer_code} lacks technical ceilings")
            if "server_model" in payer.hank_funded_cost_classes and budget.model_budget_microusd <= 0:
                raise ValueError(f"Hank-funded model offer {offer.offer_code} lacks a model budget")

            fixed_term_prices = [
                price
                for price in offer_prices
                if price.funds_service_period
                and price.billing_interval == "fixed_term"
            ]
            if fixed_term_prices and (
                len(fixed_term_prices) != 1
                or offer.fixed_service_days != fixed_term_prices[0].fixed_service_days
            ):
                raise ValueError(
                    f"offer {offer.offer_code} fixed-term duration differs from its price"
                )

            self._validate_annual_economics(offer, prices)

    @staticmethod
    def _validate_annual_economics(
        offer: CatalogOffer, prices: Mapping[str, CatalogPrice]
    ) -> None:
        monthly = [prices[code] for code in offer.price_codes if prices[code].billing_interval == "month"]
        annual = [prices[code] for code in offer.price_codes if prices[code].billing_interval == "year"]
        if not monthly or not annual:
            return
        if len(monthly) != 1 or len(annual) != 1:
            raise ValueError(
                f"offer {offer.offer_code} must define exactly one monthly and one annual price"
            )
        annual_price = annual[0]
        discount_months = annual_price.discount_months_vs_monthly
        if discount_months is None:
            raise ValueError(f"annual price {annual_price.price_code} lacks declared discount")
        expected = monthly[0].amount_cents * (12 - discount_months)
        if annual_price.amount_cents != expected:
            raise ValueError(
                f"annual price {annual_price.price_code} does not match declared discount policy"
            )


def _load_document(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    payload = yaml.safe_load(text) if path.suffix in {".yaml", ".yml"} else json.loads(text)
    if not isinstance(payload, dict):
        raise ValueError(f"commercial policy document must be an object: {path}")
    return payload


def load_policy_snapshot(path: Path) -> CommercialPolicySnapshotV1:
    return CommercialPolicySnapshotV1.model_validate(_load_document(path))


def load_commercial_catalog_bundle(
    root: Path = DEFAULT_COMMERCIAL_CONFIG_ROOT,
) -> CommercialCatalogBundle:
    root = root.resolve()
    catalog_snapshot = load_policy_snapshot(root / "catalog.yaml")
    if catalog_snapshot.policy_kind != "catalog":
        raise ValueError("catalog.yaml must contain a catalog policy snapshot")
    catalog = CatalogBody.model_validate(catalog_snapshot.body)

    snapshots: dict[tuple[str, str, str], CommercialPolicySnapshotV1] = {}
    bodies: dict[tuple[str, str, str], StrictCommercialModel] = {}
    for path in sorted(root.glob("*_policies/*.json")) + sorted(root.glob("rate_cards/*.json")):
        snapshot = load_policy_snapshot(path)
        if snapshot.policy_kind not in POLICY_BODY_MODELS:
            raise ValueError(f"unsupported checked-in policy kind in {path}: {snapshot.policy_kind}")
        key = (snapshot.policy_kind, snapshot.policy_code, snapshot.version)
        if key in snapshots:
            raise ValueError(f"duplicate commercial policy identity: {key}")
        body_model = POLICY_BODY_MODELS[snapshot.policy_kind]
        snapshots[key] = snapshot
        bodies[key] = body_model.model_validate(snapshot.body)

    bundle = CommercialCatalogBundle(
        catalog_snapshot=catalog_snapshot,
        catalog=catalog,
        policy_snapshots=snapshots,
        policy_bodies=bodies,
    )
    bundle.validate_snapshot_coherence()
    bundle.validate()
    return bundle


def validate_activated_policy_baseline(
    bundle: CommercialCatalogBundle,
    baseline: Mapping[str, str],
) -> None:
    current = {
        f"{snapshot.policy_kind}:{snapshot.policy_code}:{snapshot.version}": snapshot.content_sha256
        for snapshot in [bundle.catalog_snapshot, *bundle.policy_snapshots.values()]
    }
    for identity, expected_digest in baseline.items():
        actual = current.get(identity)
        if actual is None:
            raise ValueError(f"activated policy is missing from current bundle: {identity}")
        if actual != expected_digest:
            raise ValueError(f"activated policy content changed in place: {identity}")


def refresh_policy_hashes(
    root: Path = DEFAULT_COMMERCIAL_CONFIG_ROOT,
    activated_baseline: Mapping[str, str] | None = None,
) -> list[Path]:
    """Refresh draft hashes without permitting an activated identity to change."""

    changed: list[Path] = []
    pending: list[tuple[Path, dict[str, Any], str]] = []
    seen_identities: set[str] = set()
    paths = [
        root / "catalog.yaml",
        *sorted(root.glob("*_policies/*.json")),
        *sorted(root.glob("rate_cards/*.json")),
    ]
    for path in paths:
        payload = _load_document(path)
        body = payload.get("body")
        if not isinstance(body, dict):
            raise ValueError(f"commercial policy body must be an object: {path}")
        digest = canonical_sha256(body)
        identity = ":".join(
            str(payload.get(field, ""))
            for field in ("policy_kind", "policy_code", "version")
        )
        seen_identities.add(identity)
        activated_digest = (activated_baseline or {}).get(identity)
        if activated_digest is not None and (
            digest != activated_digest
            or payload.get("content_sha256") != activated_digest
        ):
            raise ValueError(f"activated policy content changed in place: {identity}")
        if payload.get("content_sha256") == digest:
            continue
        payload["content_sha256"] = digest
        pending.append((path, payload, digest))

    missing_activated = set(activated_baseline or {}) - seen_identities
    if missing_activated:
        raise ValueError(
            "activated policies are missing from current bundle: "
            f"{sorted(missing_activated)}"
        )

    for path, payload, _digest in pending:
        if path.suffix in {".yaml", ".yml"}:
            rendered = yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)
        else:
            rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
        path.write_text(rendered, encoding="utf-8")
        changed.append(path)
    return changed


__all__ = [
    "CatalogBody",
    "CatalogOffer",
    "CatalogPrice",
    "CommercialCatalogBundle",
    "DEFAULT_COMMERCIAL_CONFIG_ROOT",
    "load_commercial_catalog_bundle",
    "load_policy_snapshot",
    "refresh_policy_hashes",
    "validate_activated_policy_baseline",
]
