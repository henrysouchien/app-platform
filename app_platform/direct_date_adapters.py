"""App-owned direct-route date adapter helpers."""

from __future__ import annotations

from datetime import date
from typing import Any, Callable

from dateutil.relativedelta import relativedelta


def resolve_direct_dates(
    top_start: str | None,
    top_end: str | None,
    portfolio_dict: dict[str, Any] | None,
    *,
    today_fn: Callable[[], date] = date.today,
) -> tuple[str, str]:
    """Resolve direct-route start/end dates with dynamic ten-year defaults."""

    portfolio_dict = portfolio_dict or {}
    today = today_fn()
    default_end = today.isoformat()
    default_start = (today - relativedelta(years=10)).isoformat()
    start = top_start or portfolio_dict.get("start_date") or default_start
    end = top_end or portfolio_dict.get("end_date") or default_end
    return start, end


__all__ = ["resolve_direct_dates"]
