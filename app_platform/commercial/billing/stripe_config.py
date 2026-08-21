"""Fail-closed Stripe dependency, secret, and Price mapping configuration."""

from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping

from pydantic import (
    Field,
    SecretStr,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)

from ..catalog import CatalogBody, load_commercial_catalog_bundle
from ..flags import CommercialFlags
from ..models import (
    Environment,
    NonEmptyStr,
    Sha256Digest,
    StableCode,
    StrictCommercialModel,
    canonical_sha256,
)


STRIPE_SDK_VERSION = "15.3.0"
STRIPE_API_VERSION = "2026-06-24.dahlia"
CURRENT_STRIPE_DEPLOYMENT_MANIFEST_VERSION = "stripe-deployment-2026-07-12-v1"
STRIPE_DEPLOYMENT_MANIFEST_ENV = "STRIPE_DEPLOYMENT_MANIFEST_PATH"
STRIPE_SECRET_KEY_ENV = "STRIPE_SECRET_KEY"
STRIPE_WEBHOOK_SECRET_ENV = "STRIPE_WEBHOOK_SECRET"
_MAX_MANIFEST_BYTES = 1_000_000
StripeAccountId = Annotated[
    StrictStr,
    StringConstraints(pattern=r"^acct_[A-Za-z0-9]+$", min_length=10, max_length=255),
]
StripePriceId = Annotated[
    StrictStr,
    StringConstraints(pattern=r"^price_[A-Za-z0-9]+$", min_length=12, max_length=255),
]


class StripeConfigurationError(RuntimeError):
    """Stripe is disabled or its environment-bound configuration is invalid."""


class StripePriceBinding(StrictCommercialModel):
    lookup_key: NonEmptyStr
    price_id: StripePriceId


class StripeDeploymentManifest(StrictCommercialModel):
    schema_version: Literal[1]
    manifest_version: StableCode
    runtime_environment: Environment
    billing_environment: Literal["test", "live"]
    stripe_account_id: StripeAccountId
    stripe_sdk_version: Literal["15.3.0"]
    stripe_api_version: Literal["2026-06-24.dahlia"]
    content_sha256: Sha256Digest
    prices: dict[StableCode, StripePriceBinding] = Field(min_length=1)

    @field_validator("prices")
    @classmethod
    def _canonical_prices(
        cls, value: dict[str, StripePriceBinding]
    ) -> dict[str, StripePriceBinding]:
        if tuple(value) != tuple(sorted(value)):
            raise ValueError("Stripe deployment price codes must be sorted")
        price_ids = [binding.price_id for binding in value.values()]
        if len(price_ids) != len(set(price_ids)):
            raise ValueError("Stripe deployment Price IDs must be unique")
        lookup_keys = [binding.lookup_key for binding in value.values()]
        if len(lookup_keys) != len(set(lookup_keys)):
            raise ValueError("Stripe deployment lookup keys must be unique")
        return value

    @model_validator(mode="after")
    def _live_requires_production(self) -> "StripeDeploymentManifest":
        if self.billing_environment == "live" and self.runtime_environment != "prod":
            raise ValueError("live Stripe manifests require runtime_environment=prod")
        return self

    def content_body(self) -> dict[str, object]:
        return self.model_dump(mode="python", exclude={"content_sha256"})

    def resolve_price(self, price_code: str) -> StripePriceBinding:
        try:
            return self.prices[price_code]
        except KeyError as exc:
            raise StripeConfigurationError(
                f"local price code is not mapped for Stripe: {price_code}"
            ) from exc


@dataclass(frozen=True, slots=True)
class StripeRuntimeConfiguration:
    deployment: StripeDeploymentManifest
    secret_key: SecretStr = field(repr=False)
    webhook_signing_secret: SecretStr = field(repr=False)


def _validate_runtime_secret_values(
    deployment: StripeDeploymentManifest,
    secret_key: object,
    webhook_signing_secret: object,
) -> tuple[str, str]:
    if not isinstance(secret_key, str) or not isinstance(webhook_signing_secret, str):
        raise StripeConfigurationError("Stripe runtime secrets are invalid")
    expected_prefix = (
        "sk_live_" if deployment.billing_environment == "live" else "sk_test_"
    )
    if (
        not secret_key
        or secret_key != secret_key.strip()
        or not secret_key.startswith(expected_prefix)
        or len(secret_key) <= len(expected_prefix)
    ):
        raise StripeConfigurationError("Stripe runtime secrets are invalid")
    if (
        not webhook_signing_secret
        or webhook_signing_secret != webhook_signing_secret.strip()
        or not webhook_signing_secret.startswith("whsec_")
        or len(webhook_signing_secret) <= len("whsec_")
    ):
        raise StripeConfigurationError("Stripe runtime secrets are invalid")
    return secret_key, webhook_signing_secret


def _reject_duplicate_object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise StripeConfigurationError(
                "Stripe deployment manifest contains duplicate JSON keys"
            )
        value[key] = item
    return value


def _read_manifest_payload(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise StripeConfigurationError(
            "Stripe deployment manifest is unavailable"
        ) from exc
    if not raw or len(raw) > _MAX_MANIFEST_BYTES:
        raise StripeConfigurationError("Stripe deployment manifest size is invalid")
    try:
        payload = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_object_pairs
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise StripeConfigurationError("Stripe deployment manifest is invalid") from exc
    if not isinstance(payload, dict):
        raise StripeConfigurationError(
            "Stripe deployment manifest root must be an object"
        )
    return payload


def expected_catalog_price_bindings(
    catalog: CatalogBody, *, billing_environment: Literal["test", "live"]
) -> dict[str, str]:
    return dict(
        sorted(
            (
                price.price_code,
                price.stripe_lookup_keys[billing_environment],
            )
            for price in catalog.prices
            if billing_environment in price.stripe_lookup_keys
        )
    )


def validate_stripe_catalog_mapping(
    manifest: StripeDeploymentManifest,
    catalog: CatalogBody,
) -> None:
    expected = expected_catalog_price_bindings(
        catalog, billing_environment=manifest.billing_environment
    )
    observed = {
        price_code: binding.lookup_key
        for price_code, binding in manifest.prices.items()
    }
    missing = sorted(set(expected) - set(observed))
    extra = sorted(set(observed) - set(expected))
    mismatched = sorted(
        price_code
        for price_code in set(expected) & set(observed)
        if expected[price_code] != observed[price_code]
    )
    if missing or extra or mismatched:
        raise StripeConfigurationError(
            "Stripe catalog mapping mismatch "
            f"missing={missing} extra={extra} lookup_mismatch={mismatched}"
        )


def load_stripe_deployment_manifest(
    path: str | Path,
    *,
    runtime_environment: Environment,
    billing_environment: Literal["test", "live"],
    catalog: CatalogBody | None = None,
    expected_manifest_version: str = CURRENT_STRIPE_DEPLOYMENT_MANIFEST_VERSION,
) -> StripeDeploymentManifest:
    payload = _read_manifest_payload(Path(path))
    try:
        manifest = StripeDeploymentManifest.model_validate(payload)
    except ValueError as exc:
        raise StripeConfigurationError(
            "Stripe deployment manifest contract is invalid"
        ) from exc
    if manifest.content_sha256 != canonical_sha256(manifest.content_body()):
        raise StripeConfigurationError(
            "Stripe deployment manifest digest does not match"
        )
    if manifest.manifest_version != expected_manifest_version:
        raise StripeConfigurationError(
            "Stripe deployment manifest version does not match"
        )
    if manifest.runtime_environment != runtime_environment:
        raise StripeConfigurationError(
            "Stripe runtime environment does not match manifest"
        )
    if manifest.billing_environment != billing_environment:
        raise StripeConfigurationError(
            "Stripe billing environment does not match manifest"
        )
    validate_stripe_catalog_mapping(
        manifest,
        catalog or load_commercial_catalog_bundle().catalog,
    )
    return manifest


def load_stripe_runtime_configuration(
    flags: CommercialFlags,
    *,
    env: Mapping[str, str] = os.environ,
    catalog: CatalogBody | None = None,
) -> StripeRuntimeConfiguration:
    try:
        flags.validate()
    except ValueError as exc:
        raise StripeConfigurationError("commercial feature flags are invalid") from exc
    if not flags.stripe_billing_enabled:
        raise StripeConfigurationError("Stripe billing is disabled")
    billing_environment: Literal["test", "live"] = (
        "live" if flags.stripe_live_mode_enabled else "test"
    )
    required = (
        STRIPE_DEPLOYMENT_MANIFEST_ENV,
        STRIPE_SECRET_KEY_ENV,
        STRIPE_WEBHOOK_SECRET_ENV,
    )
    missing = [name for name in required if not (env.get(name) or "").strip()]
    if missing:
        raise StripeConfigurationError(
            "Stripe configuration is incomplete; missing " + ", ".join(missing)
        )
    manifest_path = Path(env[STRIPE_DEPLOYMENT_MANIFEST_ENV])
    if not manifest_path.is_absolute():
        raise StripeConfigurationError(
            "Stripe deployment manifest path must be absolute"
        )
    manifest = load_stripe_deployment_manifest(
        manifest_path,
        runtime_environment=flags.environment,  # type: ignore[arg-type]
        billing_environment=billing_environment,
        catalog=catalog,
    )
    secret_key, webhook_signing_secret = _validate_runtime_secret_values(
        manifest,
        env[STRIPE_SECRET_KEY_ENV],
        env[STRIPE_WEBHOOK_SECRET_ENV],
    )
    return StripeRuntimeConfiguration(
        deployment=manifest,
        secret_key=SecretStr(secret_key),
        webhook_signing_secret=SecretStr(webhook_signing_secret),
    )


def build_stripe_client(configuration: StripeRuntimeConfiguration) -> Any:
    """Import the optional SDK lazily and bind every request to the reviewed API version."""

    validate_stripe_runtime_configuration(configuration)
    secret_key = configuration.secret_key

    import stripe

    if stripe.VERSION != STRIPE_SDK_VERSION:
        raise StripeConfigurationError(
            "installed Stripe SDK version does not match pin"
        )
    return stripe.StripeClient(
        secret_key.get_secret_value(),
        stripe_version=STRIPE_API_VERSION,
        max_network_retries=2,
    )


def validate_stripe_runtime_configuration(
    configuration: StripeRuntimeConfiguration,
) -> None:
    """Revalidate an immutable runtime snapshot without revealing either secret."""

    if not isinstance(configuration, StripeRuntimeConfiguration):
        raise StripeConfigurationError("Stripe runtime configuration is invalid")
    secret_key = configuration.secret_key
    webhook_signing_secret = configuration.webhook_signing_secret
    if not isinstance(secret_key, SecretStr) or not isinstance(
        webhook_signing_secret, SecretStr
    ):
        raise StripeConfigurationError("Stripe runtime configuration is invalid")
    _validate_runtime_secret_values(
        configuration.deployment,
        secret_key.get_secret_value(),
        webhook_signing_secret.get_secret_value(),
    )


def build_stripe_deployment_manifest_payload(
    *,
    runtime_environment: Environment,
    billing_environment: Literal["test", "live"],
    stripe_account_id: str,
    prices: Mapping[str, Mapping[str, str] | StripePriceBinding],
    manifest_version: str = CURRENT_STRIPE_DEPLOYMENT_MANIFEST_VERSION,
) -> dict[str, object]:
    normalized_prices = {
        price_code: (
            binding.model_dump(mode="python")
            if isinstance(binding, StripePriceBinding)
            else StripePriceBinding.model_validate(binding).model_dump(mode="python")
        )
        for price_code, binding in sorted(prices.items())
    }
    body: dict[str, object] = {
        "schema_version": 1,
        "manifest_version": manifest_version,
        "runtime_environment": runtime_environment,
        "billing_environment": billing_environment,
        "stripe_account_id": stripe_account_id,
        "stripe_sdk_version": STRIPE_SDK_VERSION,
        "stripe_api_version": STRIPE_API_VERSION,
        "prices": normalized_prices,
    }
    payload = {**body, "content_sha256": canonical_sha256(body)}
    StripeDeploymentManifest.model_validate(payload)
    return payload


__all__ = [
    "CURRENT_STRIPE_DEPLOYMENT_MANIFEST_VERSION",
    "STRIPE_API_VERSION",
    "STRIPE_DEPLOYMENT_MANIFEST_ENV",
    "STRIPE_SDK_VERSION",
    "STRIPE_SECRET_KEY_ENV",
    "STRIPE_WEBHOOK_SECRET_ENV",
    "StripeConfigurationError",
    "StripeDeploymentManifest",
    "StripePriceBinding",
    "StripeRuntimeConfiguration",
    "build_stripe_client",
    "build_stripe_deployment_manifest_payload",
    "expected_catalog_price_bindings",
    "load_stripe_deployment_manifest",
    "load_stripe_runtime_configuration",
    "validate_stripe_runtime_configuration",
    "validate_stripe_catalog_mapping",
]
