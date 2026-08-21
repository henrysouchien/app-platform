"""Secret-safe remote attestation for a Stripe test deployment."""

from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
import re
from typing import Any, Literal

from pydantic import AwareDatetime, Field, model_validator

from ..catalog import CatalogBody, load_commercial_catalog_bundle
from ..models import (
    NonEmptyStr,
    NonNegativeBigInt,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)
from .stripe_config import (
    StripeDeploymentManifest,
    validate_stripe_catalog_mapping,
)


_PRODUCT_ID = re.compile(r"^prod_[A-Za-z0-9]{6,250}$")


class StripeDeploymentPreflightError(RuntimeError):
    """Remote Stripe deployment facts do not match reviewed local authority."""


class StripePricePreflightEvidence(StrictCommercialModel):
    price_code: StableCode
    offer_code: StableCode
    price_id: str = Field(pattern=r"^price_[A-Za-z0-9]{6,249}$")
    lookup_key: NonEmptyStr
    product_id: str = Field(pattern=r"^prod_[A-Za-z0-9]{6,250}$")
    amount_cents: NonNegativeBigInt
    currency: Literal["USD"]
    billing_interval: Literal["month", "year"]
    billing_scheme: Literal["per_unit"]
    usage_type: Literal["licensed"]
    active: Literal[True]
    livemode: Literal[False]
    product_active: Literal[True]
    product_livemode: Literal[False]


class StripeTestDeploymentPreflightEvidence(StrictCommercialModel):
    schema_version: Literal[1]
    runtime_environment: Literal["dev", "staging", "prod"]
    billing_environment: Literal["test"]
    manifest_version: StableCode
    manifest_sha256: Sha256Digest
    stripe_sdk_version: Literal["15.3.0"]
    stripe_api_version: Literal["2026-06-24.dahlia"]
    stripe_account_id: str = Field(pattern=r"^acct_[A-Za-z0-9]+$")
    observed_at: AwareDatetime
    prices: tuple[StripePricePreflightEvidence, ...] = Field(min_length=1)
    content_sha256: Sha256Digest

    @model_validator(mode="after")
    def _content_digest_matches(self) -> "StripeTestDeploymentPreflightEvidence":
        content = self.model_dump(mode="json", exclude={"content_sha256"})
        if canonical_sha256(content) != self.content_sha256:
            raise ValueError("Stripe preflight evidence digest does not match")
        return self


def verify_stripe_test_deployment(
    client: Any,
    *,
    deployment: StripeDeploymentManifest,
    catalog: CatalogBody | None = None,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> StripeTestDeploymentPreflightEvidence:
    """Retrieve and exact-validate the configured Stripe account and every Price."""

    if not isinstance(deployment, StripeDeploymentManifest):
        raise StripeDeploymentPreflightError("Stripe deployment authority is invalid")
    if deployment.billing_environment != "test":
        raise StripeDeploymentPreflightError(
            "Stripe deployment preflight is test-mode only"
        )
    if deployment.content_sha256 != canonical_sha256(deployment.content_body()):
        raise StripeDeploymentPreflightError(
            "Stripe deployment authority digest is invalid"
        )
    resolved_catalog = catalog or load_commercial_catalog_bundle().catalog
    try:
        validate_stripe_catalog_mapping(deployment, resolved_catalog)
    except Exception:
        raise StripeDeploymentPreflightError(
            "Stripe deployment catalog authority is invalid"
        ) from None
    catalog_prices = {price.price_code: price for price in resolved_catalog.prices}
    account = _safe_call(
        lambda: client.v1.accounts.retrieve_current(),
        "Stripe account attestation failed",
    )
    if _field(account, "id") != deployment.stripe_account_id:
        raise StripeDeploymentPreflightError("Stripe account attestation mismatch")

    price_evidence: list[StripePricePreflightEvidence] = []
    product_by_offer: dict[str, str] = {}
    offer_by_product: dict[str, str] = {}
    for price_code, binding in deployment.prices.items():
        expected = catalog_prices.get(price_code)
        if expected is None or expected.billing_interval not in {"month", "year"}:
            raise StripeDeploymentPreflightError(
                "Stripe deployment Price is outside recurring catalog authority"
            )
        remote = _safe_call(
            lambda price_id=binding.price_id: client.v1.prices.retrieve(
                price_id, params={"expand": ["product"]}
            ),
            "Stripe Price attestation failed",
        )
        product = _field(remote, "product")
        product_metadata = _field(product, "metadata")
        recurring = _field(remote, "recurring")
        product_id = _field(product, "id")
        if not isinstance(product_id, str) or _PRODUCT_ID.fullmatch(product_id) is None:
            raise StripeDeploymentPreflightError("Stripe Product expansion is invalid")
        if (
            _field(remote, "id") != binding.price_id
            or _field(remote, "livemode") is not False
            or _field(remote, "active") is not True
            or _field(remote, "lookup_key") != binding.lookup_key
            or _field(remote, "currency") != "usd"
            or type(_field(remote, "unit_amount")) is not int
            or _field(remote, "unit_amount") != expected.amount_cents
            or _field(remote, "type") != "recurring"
            or _field(remote, "billing_scheme") != "per_unit"
            or _field(remote, "tiers_mode") is not None
            or _field(remote, "transform_quantity") is not None
            or _field(recurring, "interval") != expected.billing_interval
            or _field(recurring, "interval_count") != 1
            or _field(recurring, "usage_type") != "licensed"
            or _field(product, "livemode") is not False
            or _field(product, "active") is not True
            or _field(product_metadata, "hank_offer_code") != expected.offer_code
        ):
            raise StripeDeploymentPreflightError("Stripe Price authority mismatch")
        prior_product = product_by_offer.setdefault(expected.offer_code, product_id)
        prior_offer = offer_by_product.setdefault(product_id, expected.offer_code)
        if prior_product != product_id or prior_offer != expected.offer_code:
            raise StripeDeploymentPreflightError(
                "Stripe Product catalog relationship mismatch"
            )
        price_evidence.append(
            StripePricePreflightEvidence(
                price_code=price_code,
                offer_code=expected.offer_code,
                price_id=binding.price_id,
                lookup_key=binding.lookup_key,
                product_id=product_id,
                amount_cents=expected.amount_cents,
                currency="USD",
                billing_interval=expected.billing_interval,
                billing_scheme="per_unit",
                usage_type="licensed",
                active=True,
                livemode=False,
                product_active=True,
                product_livemode=False,
            )
        )

    observed_at = clock()
    if (
        not isinstance(observed_at, datetime)
        or observed_at.tzinfo is None
        or observed_at.utcoffset() is None
    ):
        raise StripeDeploymentPreflightError("Stripe preflight clock is invalid")
    normalized_observed_at = observed_at.astimezone(timezone.utc)
    body = {
        "schema_version": 1,
        "runtime_environment": deployment.runtime_environment,
        "billing_environment": "test",
        "manifest_version": deployment.manifest_version,
        "manifest_sha256": deployment.content_sha256,
        "stripe_sdk_version": deployment.stripe_sdk_version,
        "stripe_api_version": deployment.stripe_api_version,
        "stripe_account_id": deployment.stripe_account_id,
        "prices": tuple(price_evidence),
    }
    return StripeTestDeploymentPreflightEvidence(
        **body,
        observed_at=normalized_observed_at,
        content_sha256=canonical_sha256(
            {
                **body,
                "observed_at": normalized_observed_at.isoformat().replace(
                    "+00:00", "Z"
                ),
                "prices": [item.model_dump(mode="json") for item in price_evidence],
            }
        ),
    )


def _safe_call(operation: Callable[[], Any], message: str) -> Any:
    try:
        return operation()
    except StripeDeploymentPreflightError:
        raise
    except Exception:
        raise StripeDeploymentPreflightError(message) from None


def _field(value: Any, name: str) -> Any:
    if isinstance(value, dict):
        return value.get(name)
    return getattr(value, name, None)


__all__ = [
    "StripeDeploymentPreflightError",
    "StripePricePreflightEvidence",
    "StripeTestDeploymentPreflightEvidence",
    "verify_stripe_test_deployment",
]
