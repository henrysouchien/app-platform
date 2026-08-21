"""Default-off composition for the customer billing and Stripe Portal API."""

from __future__ import annotations

import os
from typing import Mapping

from database import get_db_session

from ..flags import CommercialFlags
from .checkout_runtime import load_checkout_redirects
from .customer_portal import (
    StripeSdkPortalProvider,
    StripeSdkReceiptProvider,
    StripeSdkSubscriptionMutationProvider,
)
from .stripe_config import build_stripe_client, load_stripe_runtime_configuration


def build_customer_portal_runtime(env: Mapping[str, str] = os.environ):
    flags = CommercialFlags.from_env(env)
    if not flags.customer_billing_portal_enabled:
        return None
    configuration = load_stripe_runtime_configuration(flags, env=env)
    redirects = load_checkout_redirects(
        env, billing_environment=configuration.deployment.billing_environment
    )
    client = build_stripe_client(configuration)
    return {
        "connection_context_factory": get_db_session,
        "portal_provider": StripeSdkPortalProvider(
            client, livemode=configuration.deployment.billing_environment == "live"
        ),
        "subscription_provider": StripeSdkSubscriptionMutationProvider(
            client, deployment=configuration.deployment
        ),
        "receipt_provider": StripeSdkReceiptProvider(
            client, livemode=configuration.deployment.billing_environment == "live"
        ),
        "billing_environment": configuration.deployment.billing_environment,
        "available_price_codes": tuple(configuration.deployment.prices),
        "return_url": redirects.public_origin + "/settings/billing",
    }


__all__ = ["build_customer_portal_runtime"]
