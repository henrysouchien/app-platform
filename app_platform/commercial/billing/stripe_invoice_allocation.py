"""Deterministic operational-revenue policy for normalized Stripe invoice lines."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from ..revenue_allocation import (
    DailyCentsPeriod,
    RevenueAllocationError,
    allocate_daily_cents,
)
from .stripe_projection_provider import StripeInvoiceLineSnapshot


STRIPE_INVOICE_ALLOCATION_POLICY_VERSION = "stripe-invoice-allocation.v1"
_POINT_INTERVAL = timedelta(microseconds=1)


@dataclass(frozen=True, slots=True)
class StripeInvoiceLineAllocation:
    external_line_id: str
    service_period_start_at: datetime
    service_period_end_at: datetime
    provider_period_was_instant: bool
    periods: tuple[DailyCentsPeriod, ...]


def allocate_stripe_invoice_line(
    line: StripeInvoiceLineSnapshot,
) -> StripeInvoiceLineAllocation:
    """Map one exact provider period to a complete operational revenue schedule.

    Dahlia permits an invoice-item period whose inclusive endpoints are equal,
    while the commercial ledger represents non-empty half-open intervals. Such
    a point fact is mapped to the smallest PostgreSQL timestamp interval at the
    same instant. All other lines retain their exact provider boundaries.
    """

    provider_period_was_instant = (
        line.service_period_end_at == line.service_period_start_at
    )
    try:
        service_end = (
            line.service_period_end_at + _POINT_INTERVAL
            if provider_period_was_instant
            else line.service_period_end_at
        )
    except OverflowError:
        raise RevenueAllocationError(
            "Stripe point period exceeds the operational timestamp domain"
        ) from None
    periods = allocate_daily_cents(
        line.net_consideration_ex_tax_cents,
        line.service_period_start_at,
        service_end,
    )
    return StripeInvoiceLineAllocation(
        external_line_id=line.external_line_id,
        service_period_start_at=line.service_period_start_at,
        service_period_end_at=service_end,
        provider_period_was_instant=provider_period_was_instant,
        periods=periods,
    )


__all__ = [
    "STRIPE_INVOICE_ALLOCATION_POLICY_VERSION",
    "StripeInvoiceLineAllocation",
    "allocate_stripe_invoice_line",
]
