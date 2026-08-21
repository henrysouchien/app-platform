"""Narrow, validated Stripe customer and hosted Checkout provider boundary."""

from __future__ import annotations

from datetime import datetime, timezone
import re
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

from pydantic import AwareDatetime, Field, model_validator

from ..models import StrictCommercialModel, canonical_sha256
from .checkout import BillingEnvironment, PreparedCheckout


_CUSTOMER_ID = re.compile(r"^cus_[A-Za-z0-9]{6,250}$")
_SESSION_ID = re.compile(r"^cs_(test|live)_[A-Za-z0-9]{1,247}$")


class StripeCheckoutProviderError(RuntimeError):
    """A safe provider failure; raw Stripe objects and messages never cross this boundary."""


class CheckoutRedirects(StrictCommercialModel):
    environment: BillingEnvironment
    public_origin: str = Field(min_length=1, max_length=2048)
    allowed_origins: dict[BillingEnvironment, tuple[str, ...]]

    @model_validator(mode="after")
    def _strict_environment_allowlist(self) -> "CheckoutRedirects":
        if set(self.allowed_origins) != {"test", "live"}:
            raise ValueError("Checkout redirect allowlist must bind test and live environments")
        for environment, origins in self.allowed_origins.items():
            if not origins or len(set(origins)) != len(origins):
                raise ValueError(f"Checkout {environment} origins must be non-empty and unique")
            for origin in origins:
                self._validate_origin(origin)
        self._validate_origin(self.public_origin)
        if self.public_origin not in self.allowed_origins[self.environment]:
            raise ValueError("Checkout redirect origin is not allowlisted for this environment")
        if self.public_origin in self.allowed_origins["live" if self.environment == "test" else "test"]:
            raise ValueError("Checkout redirect origins cannot cross billing environments")
        return self

    @staticmethod
    def _validate_origin(value: str) -> None:
        try:
            parts = urlsplit(value)
            port = parts.port
        except ValueError:
            raise ValueError("Checkout redirect origin is invalid") from None
        if (
            parts.scheme != "https"
            or not parts.hostname
            or port is not None
            or parts.username is not None
            or parts.password is not None
            or parts.path
            or parts.query
            or parts.fragment
            or value != f"https://{parts.hostname}"
        ):
            raise ValueError("Checkout redirect origin must be canonical HTTPS without a port")

    @property
    def success_url(self) -> str:
        return f"{self.public_origin}/settings/billing?checkout=success"

    @property
    def cancel_url(self) -> str:
        return f"{self.public_origin}/settings/billing?checkout=cancel"


class StripeCustomerResult(StrictCommercialModel):
    customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")


class StripeCheckoutSessionResult(StrictCommercialModel):
    session_id: str = Field(pattern=r"^cs_(test|live)_[A-Za-z0-9]{1,247}$")
    customer_id: str = Field(pattern=r"^cus_[A-Za-z0-9]{6,250}$")
    checkout_url: str | None = Field(default=None, max_length=4096)
    expires_at: AwareDatetime
    status: Literal["open", "complete", "expired"]


class CheckoutProvider(Protocol):
    def create_customer(self, prepared: PreparedCheckout) -> StripeCustomerResult: ...

    def create_session(
        self,
        prepared: PreparedCheckout,
        *,
        customer_id: str,
        redirects: CheckoutRedirects,
    ) -> StripeCheckoutSessionResult: ...

    def retrieve_session(
        self,
        prepared: PreparedCheckout,
        *,
        session_id: str,
        customer_id: str,
    ) -> StripeCheckoutSessionResult: ...


def customer_idempotency_key(prepared: PreparedCheckout) -> str:
    return "hank_customer_" + canonical_sha256(
        {
            "commercial_account_public_id": str(prepared.account_public_id),
            "environment": prepared.environment,
        }
    ).removeprefix("sha256:")


class StripeSdkCheckoutProvider:
    """Call only the pinned StripeClient surface and validate every returned identity."""

    def __init__(self, client: Any, *, environment: BillingEnvironment) -> None:
        self._client = client
        self._environment = environment

    def create_customer(self, prepared: PreparedCheckout) -> StripeCustomerResult:
        self._require_prepared(prepared)
        customer = self._safe_provider_call(
            lambda: self._client.v1.customers.create(
                params={
                    "metadata": {
                        "hank_commercial_account_id": str(prepared.account_public_id),
                        "hank_environment": prepared.environment,
                    }
                },
                options={"idempotency_key": customer_idempotency_key(prepared)},
            ),
            "Stripe customer operation failed",
        )
        customer_id = self._field(customer, "id")
        if not isinstance(customer_id, str) or not _CUSTOMER_ID.fullmatch(customer_id):
            raise StripeCheckoutProviderError("Stripe customer identity is invalid")
        self._validate_livemode(customer)
        metadata = self._mapping(self._field(customer, "metadata"))
        if metadata.get("hank_commercial_account_id") != str(prepared.account_public_id):
            raise StripeCheckoutProviderError("Stripe customer account identity mismatch")
        if metadata.get("hank_environment") != prepared.environment:
            raise StripeCheckoutProviderError("Stripe customer environment mismatch")
        return StripeCustomerResult(customer_id=customer_id)

    def create_session(
        self,
        prepared: PreparedCheckout,
        *,
        customer_id: str,
        redirects: CheckoutRedirects,
    ) -> StripeCheckoutSessionResult:
        self._require_prepared(prepared)
        self._require_customer_id(customer_id)
        if redirects.environment != self._environment:
            raise StripeCheckoutProviderError("Checkout redirect environment mismatch")
        metadata = self._metadata(prepared)
        session = self._safe_provider_call(
            lambda: self._client.v1.checkout.sessions.create(
                params={
                    "mode": "subscription",
                    "customer": customer_id,
                    "client_reference_id": str(prepared.agreement_public_id),
                    "line_items": [{"price": prepared.stripe_price_id, "quantity": 1}],
                    "success_url": redirects.success_url,
                    "cancel_url": redirects.cancel_url,
                    "expires_at": int(prepared.pending_expires_at.timestamp()),
                    "metadata": metadata,
                    "subscription_data": {"metadata": metadata},
                    "automatic_tax": {"enabled": True},
                    "billing_address_collection": "auto",
                },
                options={"idempotency_key": prepared.provider_idempotency_key},
            ),
            "Stripe Checkout operation failed",
        )
        result = self._validate_session(
            session,
            prepared=prepared,
            expected_customer_id=customer_id,
            require_url=True,
        )
        if result.expires_at > prepared.pending_expires_at:
            raise StripeCheckoutProviderError("Stripe Checkout expiry exceeds local authority")
        return result

    def retrieve_session(
        self,
        prepared: PreparedCheckout,
        *,
        session_id: str,
        customer_id: str,
    ) -> StripeCheckoutSessionResult:
        self._require_environment(prepared)
        self._require_customer_id(customer_id)
        self._require_session_id(session_id)
        session = self._safe_provider_call(
            lambda: self._client.v1.checkout.sessions.retrieve(session_id),
            "Stripe Checkout retrieval failed",
        )
        return self._validate_session(
            session,
            prepared=prepared,
            expected_customer_id=customer_id,
            require_url=False,
        )

    def _validate_session(
        self,
        session: Any,
        *,
        prepared: PreparedCheckout,
        expected_customer_id: str,
        require_url: bool,
    ) -> StripeCheckoutSessionResult:
        session_id = self._field(session, "id")
        self._require_session_id(session_id)
        self._validate_livemode(session)
        if self._field(session, "mode") != "subscription":
            raise StripeCheckoutProviderError("Stripe Checkout mode mismatch")
        if self._field(session, "customer") != expected_customer_id:
            raise StripeCheckoutProviderError("Stripe Checkout customer mismatch")
        if self._field(session, "client_reference_id") != str(prepared.agreement_public_id):
            raise StripeCheckoutProviderError("Stripe Checkout agreement mismatch")
        if self._mapping(self._field(session, "metadata")) != self._metadata(prepared):
            raise StripeCheckoutProviderError("Stripe Checkout metadata mismatch")
        raw_status = self._field(session, "status")
        if raw_status not in {"open", "complete", "expired"}:
            raise StripeCheckoutProviderError("Stripe Checkout status is invalid")
        raw_expiry = self._field(session, "expires_at")
        if isinstance(raw_expiry, bool) or not isinstance(raw_expiry, int):
            raise StripeCheckoutProviderError("Stripe Checkout expiry is invalid")
        try:
            expires_at = datetime.fromtimestamp(raw_expiry, timezone.utc)
        except (OverflowError, OSError, ValueError):
            raise StripeCheckoutProviderError("Stripe Checkout expiry is invalid") from None
        raw_url = self._field(session, "url")
        checkout_url = self._validated_checkout_url(raw_url)
        if require_url and (raw_status != "open" or checkout_url is None):
            raise StripeCheckoutProviderError("Stripe Checkout did not return an open hosted URL")
        return StripeCheckoutSessionResult(
            session_id=session_id,
            customer_id=expected_customer_id,
            checkout_url=checkout_url,
            expires_at=expires_at,
            status=raw_status,
        )

    def _require_prepared(self, prepared: PreparedCheckout) -> None:
        if (
            prepared.state != "provider_pending"
            or not prepared.provider_call_authorized
        ):
            raise StripeCheckoutProviderError("Checkout provider authority is invalid")
        self._require_environment(prepared)

    def _require_environment(self, prepared: PreparedCheckout) -> None:
        if prepared.environment != self._environment:
            raise StripeCheckoutProviderError("Checkout provider environment is invalid")

    def _validate_livemode(self, value: Any) -> None:
        livemode = self._field(value, "livemode")
        if not isinstance(livemode, bool) or livemode != (self._environment == "live"):
            raise StripeCheckoutProviderError("Stripe object environment mismatch")

    def _require_customer_id(self, value: Any) -> None:
        if not isinstance(value, str) or not _CUSTOMER_ID.fullmatch(value):
            raise StripeCheckoutProviderError("Stripe customer identity is invalid")

    def _require_session_id(self, value: Any) -> None:
        if not isinstance(value, str) or not _SESSION_ID.fullmatch(value):
            raise StripeCheckoutProviderError("Stripe Checkout identity is invalid")
        match = _SESSION_ID.fullmatch(value)
        assert match is not None
        if match.group(1) != self._environment:
            raise StripeCheckoutProviderError("Stripe Checkout environment mismatch")

    @staticmethod
    def _metadata(prepared: PreparedCheckout) -> dict[str, str]:
        return {
            "hank_commercial_account_id": str(prepared.account_public_id),
            "hank_agreement_id": str(prepared.agreement_public_id),
            "hank_price_code": prepared.price_code,
            "hank_environment": prepared.environment,
        }

    @staticmethod
    def _validated_checkout_url(value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or len(value) > 4096:
            raise StripeCheckoutProviderError("Stripe Checkout URL is invalid")
        try:
            parts = urlsplit(value)
            port = parts.port
        except ValueError:
            raise StripeCheckoutProviderError("Stripe Checkout URL is invalid") from None
        if (
            parts.scheme != "https"
            or parts.hostname != "checkout.stripe.com"
            or port is not None
            or parts.username is not None
            or parts.password is not None
            or parts.fragment
        ):
            raise StripeCheckoutProviderError("Stripe Checkout URL is invalid")
        return value

    @staticmethod
    def _safe_provider_call(operation, message: str) -> Any:
        failed = False
        try:
            result = operation()
        except Exception:
            failed = True
            result = None
        if failed:
            raise StripeCheckoutProviderError(message)
        return result

    @staticmethod
    def _field(value: Any, name: str) -> Any:
        if isinstance(value, dict):
            return value.get(name)
        return getattr(value, name, None)

    @staticmethod
    def _mapping(value: Any) -> dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        try:
            return dict(value)
        except (TypeError, ValueError):
            return {}


__all__ = [
    "CheckoutProvider",
    "CheckoutRedirects",
    "StripeCheckoutProviderError",
    "StripeCheckoutSessionResult",
    "StripeCustomerResult",
    "StripeSdkCheckoutProvider",
    "customer_idempotency_key",
]
