"""Fail-closed production composition for self-serve Stripe Checkout."""

from __future__ import annotations

import json
import os
from typing import Any, Mapping

from database import get_db_session

from ..flags import CommercialFlags
from .checkout import PostgresCheckoutPreparationService
from .checkout_orchestration import CheckoutOrchestrationRuntime, CheckoutOrchestrator
from .checkout_provider import CheckoutRedirects, StripeSdkCheckoutProvider
from .stripe_config import build_stripe_client, load_stripe_runtime_configuration


CHECKOUT_PUBLIC_ORIGIN_ENV = "CHECKOUT_PUBLIC_ORIGIN"
CHECKOUT_REDIRECT_ORIGINS_ENV = "CHECKOUT_REDIRECT_ORIGINS_JSON"


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Checkout redirect configuration contains duplicate keys")
        result[key] = value
    return result


def load_checkout_redirects(
    env: Mapping[str, str], *, billing_environment: str
) -> CheckoutRedirects:
    raw = (env.get(CHECKOUT_REDIRECT_ORIGINS_ENV) or "").strip()
    public_origin = (env.get(CHECKOUT_PUBLIC_ORIGIN_ENV) or "").strip()
    if not raw or not public_origin:
        raise ValueError("Checkout redirect configuration is incomplete")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_pairs)
    except json.JSONDecodeError as exc:
        raise ValueError("Checkout redirect configuration is invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("Checkout redirect configuration must be an object")
    try:
        allowed = {
            key: tuple(value) if isinstance(value, list) else value
            for key, value in payload.items()
        }
        return CheckoutRedirects.model_validate(
            {
                "environment": billing_environment,
                "public_origin": public_origin,
                "allowed_origins": allowed,
            }
        )
    except ValueError as exc:
        raise ValueError("Checkout redirect configuration is invalid") from exc


def build_checkout_orchestrator(
    env: Mapping[str, str] = os.environ,
    *,
    connection_context_factory=get_db_session,
) -> CheckoutOrchestrator | None:
    flags = CommercialFlags.from_env(env)
    if not flags.self_serve_checkout_enabled:
        return None
    configuration = load_stripe_runtime_configuration(flags, env=env)
    redirects = load_checkout_redirects(
        env,
        billing_environment=configuration.deployment.billing_environment,
    )
    client = build_stripe_client(configuration)
    provider = StripeSdkCheckoutProvider(
        client,
        environment=configuration.deployment.billing_environment,
    )
    runtime = CheckoutOrchestrationRuntime(
        connection_context_factory=connection_context_factory,
        preparation_service_factory=lambda connection: PostgresCheckoutPreparationService(
            connection,
            flags=flags,
            deployment=configuration.deployment,
        ),
        provider=provider,
        redirects=redirects,
    )
    return CheckoutOrchestrator(runtime)


__all__ = [
    "CHECKOUT_PUBLIC_ORIGIN_ENV",
    "CHECKOUT_REDIRECT_ORIGINS_ENV",
    "build_checkout_orchestrator",
    "load_checkout_redirects",
]
