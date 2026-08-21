from __future__ import annotations

from datetime import date

import app_platform.direct_date_adapters as adapters


def test_resolve_direct_dates_uses_dynamic_ten_year_defaults() -> None:
    assert adapters.resolve_direct_dates(
        None,
        None,
        {},
        today_fn=lambda: date(2026, 6, 19),
    ) == ("2016-06-19", "2026-06-19")


def test_resolve_direct_dates_prefers_top_level_over_portfolio_dates() -> None:
    portfolio_dates = {
        "start_date": "2020-01-01",
        "end_date": "2020-12-31",
    }

    assert adapters.resolve_direct_dates(
        "2021-01-01",
        "2021-12-31",
        portfolio_dates,
        today_fn=lambda: date(2026, 6, 19),
    ) == ("2021-01-01", "2021-12-31")


def test_resolve_direct_dates_uses_portfolio_dates_before_defaults() -> None:
    portfolio_dates = {
        "start_date": "2020-01-01",
        "end_date": "2020-12-31",
    }

    assert adapters.resolve_direct_dates(
        None,
        None,
        portfolio_dates,
        today_fn=lambda: date(2026, 6, 19),
    ) == ("2020-01-01", "2020-12-31")
