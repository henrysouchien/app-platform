"""Crash-recoverable transaction/provider orchestration for Stripe Checkout."""

from __future__ import annotations

from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from pydantic import AwareDatetime

from ..errors import CommercialError
from ..models import StrictCommercialModel
from .checkout import (
    CheckoutPreparationError,
    CheckoutPreparationRequest,
    PostgresCheckoutPreparationService,
    PreparedCheckout,
)
from .checkout_provider import (
    CheckoutProvider,
    CheckoutRedirects,
    StripeCheckoutProviderError,
    StripeCheckoutSessionResult,
)


class CheckoutOrchestrationUnavailable(RuntimeError):
    """Retryable safe failure across database or provider ambiguity."""


class CheckoutOrchestrationRejected(RuntimeError):
    """Non-retryable safe request or current-authority rejection."""


class CheckoutLaunchResult(StrictCommercialModel):
    commercial_account_public_id: UUID
    agreement_public_id: UUID
    checkout_session_id: str
    checkout_url: str | None
    checkout_expires_at: AwareDatetime
    status: str
    replayed: bool


@dataclass(frozen=True, slots=True)
class CheckoutOrchestrationRuntime:
    connection_context_factory: Callable[[], AbstractContextManager[object]]
    preparation_service_factory: Callable[[object], PostgresCheckoutPreparationService]
    provider: CheckoutProvider
    redirects: CheckoutRedirects


class CheckoutOrchestrator:
    def __init__(self, runtime: CheckoutOrchestrationRuntime) -> None:
        self._runtime = runtime

    def launch(
        self,
        *,
        actor_user_id: int,
        request: CheckoutPreparationRequest,
    ) -> CheckoutLaunchResult:
        try:
            return self._launch(actor_user_id=actor_user_id, request=request)
        except (CheckoutOrchestrationRejected, CheckoutOrchestrationUnavailable):
            raise
        except CommercialError:
            raise
        except CheckoutPreparationError:
            return self._converge_or_reject(
                actor_user_id=actor_user_id,
                request=request,
            )
        except Exception:
            raise CheckoutOrchestrationUnavailable(
                "Checkout is temporarily unavailable"
            ) from None

    def _launch(
        self,
        *,
        actor_user_id: int,
        request: CheckoutPreparationRequest,
    ) -> CheckoutLaunchResult:
        prepared = self._prepare(actor_user_id=actor_user_id, request=request)
        entry_replayed = prepared.replayed
        try:
            if prepared.state == "session_created":
                return self._retrieve_completed_preparation(prepared)

            authorized = self._prepare(actor_user_id=actor_user_id, request=request)
            if not authorized.provider_call_authorized:
                raise CheckoutOrchestrationUnavailable("Checkout authority could not be refreshed")
            customer_id = self._load_customer(authorized)
            if customer_id is None:
                customer = self._provider_call(
                    lambda: self._runtime.provider.create_customer(authorized)
                )
                customer_id = self._record_customer(
                    actor_user_id=actor_user_id,
                    request=request,
                    customer_id=customer.customer_id,
                )

            authorized = self._prepare(actor_user_id=actor_user_id, request=request)
            if not authorized.provider_call_authorized:
                raise CheckoutOrchestrationUnavailable("Checkout authority could not be refreshed")
            session = self._provider_call(
                lambda: self._runtime.provider.create_session(
                    authorized,
                    customer_id=customer_id,
                    redirects=self._runtime.redirects,
                )
            )
            self._finalize_session(
                actor_user_id=actor_user_id,
                request=request,
                session=session,
            )
            return self._result(authorized, session, replayed=entry_replayed)
        except CheckoutPreparationError:
            return self._converge_or_reject(
                actor_user_id=actor_user_id,
                request=request,
                replayed=entry_replayed,
            )

    def _converge_or_reject(
        self,
        *,
        actor_user_id: int,
        request: CheckoutPreparationRequest,
        replayed: bool = True,
    ) -> CheckoutLaunchResult:
        try:
            current = self._prepare(actor_user_id=actor_user_id, request=request)
        except CommercialError:
            raise
        except (CheckoutOrchestrationRejected, CheckoutOrchestrationUnavailable):
            raise
        except Exception:
            raise CheckoutOrchestrationUnavailable(
                "Checkout persistence is temporarily unavailable"
            ) from None
        if current.state == "session_created":
            return self._retrieve_completed_preparation(current, replayed=replayed)
        raise CheckoutOrchestrationRejected(
            "Checkout is not available for the current account"
        )

    def _prepare(
        self, *, actor_user_id: int, request: CheckoutPreparationRequest
    ) -> PreparedCheckout:
        try:
            return self._transaction(
                lambda service: service.prepare(
                    actor_user_id=actor_user_id,
                    request=request,
                )
            )
        except CommercialError:
            raise
        except CheckoutPreparationError:
            self._raise_rejected("Checkout is not available for the current account")

    def _load_customer(self, prepared: PreparedCheckout) -> str | None:
        return self._transaction(lambda service: service.load_customer_binding(prepared))

    def _record_customer(
        self,
        *,
        actor_user_id: int,
        request: CheckoutPreparationRequest,
        customer_id: str,
    ) -> str:
        def operation(service: PostgresCheckoutPreparationService) -> str:
            authorized = service.prepare(actor_user_id=actor_user_id, request=request)
            return service.record_customer_binding(authorized, customer_id=customer_id)

        return self._transaction(operation)

    def _finalize_session(
        self,
        *,
        actor_user_id: int,
        request: CheckoutPreparationRequest,
        session: StripeCheckoutSessionResult,
    ) -> None:
        def operation(service: PostgresCheckoutPreparationService) -> None:
            authorized = service.prepare(actor_user_id=actor_user_id, request=request)
            service.finalize_session(
                authorized,
                customer_id=session.customer_id,
                session_id=session.session_id,
                expires_at=session.expires_at,
            )

        self._transaction(operation)

    def _retrieve_completed_preparation(
        self, prepared: PreparedCheckout, *, replayed: bool = True
    ) -> CheckoutLaunchResult:
        if not prepared.external_checkout_session_id or not prepared.external_customer_id:
            raise CheckoutOrchestrationUnavailable("Checkout completion identity is incomplete")
        session = self._provider_call(
            lambda: self._runtime.provider.retrieve_session(
                prepared,
                session_id=prepared.external_checkout_session_id or "",
                customer_id=prepared.external_customer_id or "",
            )
        )
        return self._result(prepared, session, replayed=replayed)

    def _transaction(self, operation: Callable[[PostgresCheckoutPreparationService], Any]):
        failed = False
        result: Any = None
        try:
            with self._runtime.connection_context_factory() as connection:
                if bool(getattr(connection, "autocommit", False)):
                    setattr(connection, "autocommit", False)
                try:
                    service = self._runtime.preparation_service_factory(connection)
                    result = operation(service)
                    getattr(connection, "commit")()
                except (CommercialError, CheckoutPreparationError):
                    self._safe_rollback(connection)
                    raise
                except Exception:
                    self._safe_rollback(connection)
                    failed = True
        except (CommercialError, CheckoutPreparationError):
            raise
        except Exception:
            failed = True
        if failed:
            raise CheckoutOrchestrationUnavailable("Checkout persistence is temporarily unavailable")
        return result

    @staticmethod
    def _provider_call(operation):
        failed = False
        result = None
        try:
            result = operation()
        except StripeCheckoutProviderError:
            failed = True
        if failed:
            raise CheckoutOrchestrationUnavailable("Checkout provider is temporarily unavailable")
        return result

    @staticmethod
    def _safe_rollback(connection: object) -> None:
        try:
            getattr(connection, "rollback")()
        except Exception:
            pass

    @staticmethod
    def _raise_rejected(message: str) -> None:
        raise CheckoutOrchestrationRejected(message)

    @staticmethod
    def _result(
        prepared: PreparedCheckout,
        session: StripeCheckoutSessionResult,
        *,
        replayed: bool,
    ) -> CheckoutLaunchResult:
        return CheckoutLaunchResult(
            commercial_account_public_id=prepared.account_public_id,
            agreement_public_id=prepared.agreement_public_id,
            checkout_session_id=session.session_id,
            checkout_url=session.checkout_url,
            checkout_expires_at=session.expires_at,
            status=session.status,
            replayed=replayed,
        )


__all__ = [
    "CheckoutLaunchResult",
    "CheckoutOrchestrationRejected",
    "CheckoutOrchestrationRuntime",
    "CheckoutOrchestrationUnavailable",
    "CheckoutOrchestrator",
]
