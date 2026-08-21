"""Named-operator discovery of active manual commercial offers."""

from __future__ import annotations

from typing import Any, Literal, Mapping

from pydantic import AwareDatetime, StrictBool, StrictInt

from .catalog import CatalogBody
from .errors import CommercialError
from .flags import CommercialFlags
from .models import NonEmptyStr, Sha256Digest, StableCode, StrictCommercialModel


class ManualCatalogPrice(StrictCommercialModel):
    price_code: StableCode
    item_kind: Literal["recurring", "onboarding", "implementation"]
    amount_cents: StrictInt
    currency: Literal["USD"]
    billing_interval: Literal["one_time", "month", "year", "fixed_term"]
    service_months: StrictInt | None
    fixed_service_days: StrictInt | None
    funds_service_period: StrictBool


class ManualCatalogOffer(StrictCommercialModel):
    offer_code: StableCode
    display_name: NonEmptyStr
    surface_code: StableCode
    channels: tuple[Literal["pilot", "managed", "admin_test"], ...]
    requires_service_dates: StrictBool
    minimum_service_months: StrictInt | None
    fixed_service_days: StrictInt | None
    prices: tuple[ManualCatalogPrice, ...]


class ManualCatalogVersion(StrictCommercialModel):
    catalog_policy_id: StrictInt
    policy_code: StableCode
    version: NonEmptyStr
    content_sha256: Sha256Digest
    activated_at: AwareDatetime
    offers: tuple[ManualCatalogOffer, ...]


class ManualCatalogDiscovery(StrictCommercialModel):
    schema_version: Literal["commercial.manual-catalog.v1"]
    environment: Literal["dev", "staging", "prod"]
    evaluated_at: AwareDatetime
    catalogs: tuple[ManualCatalogVersion, ...]
    catalog_policy_id_by_offer_price: dict[StableCode, StrictInt]


_DISCOVERY_SQL = r"""
WITH clock AS MATERIALIZED (
    SELECT statement_timestamp() AS evaluated_at
), authorized AS MATERIALIZED (
    SELECT EXISTS (
               SELECT 1 FROM commercial_deployment_context
                WHERE singleton AND environment = %(environment)s
           ) AND EXISTS (
               SELECT 1 FROM commercial_operator_role_grants grant_row, clock
                WHERE grant_row.user_id = %(operator_user_id)s
                  AND grant_row.environment = %(environment)s
                  AND grant_row.role = 'commercial_admin'
                  AND grant_row.state = 'active'
                  AND grant_row.granted_at <= clock.evaluated_at
                  AND (grant_row.expires_at IS NULL
                       OR grant_row.expires_at > clock.evaluated_at)
           ) AS allowed
)
SELECT clock.evaluated_at, authorized.allowed,
       COALESCE(jsonb_agg(
           jsonb_build_object(
               'id', policy.id,
               'policy_code', policy.policy_code,
               'version', policy.version,
               'content_sha256', policy.content_sha256,
               'activated_at', policy.activated_at,
               'body_json', policy.body_json
           ) ORDER BY policy.activated_at DESC, policy.id DESC
       ) FILTER (WHERE policy.id IS NOT NULL), '[]'::jsonb) AS catalogs
  FROM clock CROSS JOIN authorized
  LEFT JOIN commercial_policy_versions policy
    ON authorized.allowed
   AND policy.policy_kind = 'catalog'
   AND policy.state = 'active'
   AND policy.activated_at <= clock.evaluated_at
 GROUP BY clock.evaluated_at, authorized.allowed
"""


class ManualCatalogDiscoveryService:
    def __init__(self, connection: object, *, flags: CommercialFlags) -> None:
        flags.validate()
        self._connection = connection
        self._flags = flags

    def discover_as_operator(
        self,
        *,
        operator_user_id: int,
        runtime_environment: Literal["dev", "staging", "prod"],
    ) -> ManualCatalogDiscovery:
        if not self._flags.commercial_control_enabled:
            raise ValueError("commercial control is disabled")
        if runtime_environment != self._flags.environment:
            raise CommercialError("commercial_role_required")
        with self._connection.cursor() as cursor:  # type: ignore[attr-defined]
            cursor.execute(
                _DISCOVERY_SQL,
                {
                    "operator_user_id": operator_user_id,
                    "environment": runtime_environment,
                },
            )
            row = cursor.fetchone()
        if row is None:
            raise RuntimeError("manual catalog discovery returned no result")
        if isinstance(row, Mapping):
            evaluated_at = row["evaluated_at"]
            allowed = row["allowed"]
            raw_catalogs = row["catalogs"]
        else:
            evaluated_at, allowed, raw_catalogs = row
        if not allowed:
            raise CommercialError("commercial_role_required")
        catalogs = tuple(
            catalog
            for value in raw_catalogs
            if (catalog := self._catalog(value)).offers
        )
        selectors: dict[str, int] = {}
        for catalog in catalogs:
            for offer in catalog.offers:
                for price in offer.prices:
                    selectors.setdefault(
                        f"{offer.offer_code}:{price.price_code}",
                        catalog.catalog_policy_id,
                    )
        return ManualCatalogDiscovery(
            schema_version="commercial.manual-catalog.v1",
            environment=runtime_environment,
            evaluated_at=evaluated_at,
            catalogs=catalogs,
            catalog_policy_id_by_offer_price=selectors,
        )

    @staticmethod
    def _catalog(value: dict[str, Any]) -> ManualCatalogVersion:
        body = CatalogBody.model_validate(value["body_json"])
        prices = {price.price_code: price for price in body.prices}
        offers = []
        for offer in body.offers:
            if offer.availability != "manual":
                continue
            manual_channels = tuple(
                channel
                for channel in offer.channels
                if channel in {"pilot", "managed", "admin_test"}
            )
            offer_prices = tuple(
                ManualCatalogPrice(
                    price_code=price.price_code,
                    item_kind=price.item_kind,
                    amount_cents=price.amount_cents,
                    currency=price.currency,
                    billing_interval=price.billing_interval,
                    service_months=price.service_months,
                    fixed_service_days=price.fixed_service_days,
                    funds_service_period=price.funds_service_period,
                )
                for code in offer.price_codes
                if (price := prices.get(code)) is not None
            )
            offers.append(
                ManualCatalogOffer(
                    offer_code=offer.offer_code,
                    display_name=offer.display_name,
                    surface_code=offer.surface_code,
                    channels=manual_channels,
                    requires_service_dates=offer.requires_service_dates,
                    minimum_service_months=offer.minimum_service_months,
                    fixed_service_days=offer.fixed_service_days,
                    prices=offer_prices,
                )
            )
        return ManualCatalogVersion(
            catalog_policy_id=value["id"],
            policy_code=value["policy_code"],
            version=value["version"],
            content_sha256=value["content_sha256"],
            activated_at=value["activated_at"],
            offers=tuple(offers),
        )


__all__ = ["ManualCatalogDiscovery", "ManualCatalogDiscoveryService"]
