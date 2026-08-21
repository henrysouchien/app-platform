from __future__ import annotations

from types import SimpleNamespace

import app_platform.allocation_adapters as adapters


def test_build_dependencies_reads_source_mapping() -> None:
    source = {
        "_preview_rebalance_trades": "preview",
        "get_portfolio_snapshot": "portfolio-snapshot",
        "_prime_virtual_portfolio_from_cached_positions": "prime-virtual",
        "TIER_ORDER": {"paid": 2},
        "get_factor_proxies_snapshot": "factor-proxies",
        "get_risk_limits_snapshot": "risk-limits",
        "peek_analysis_result_snapshot": "analysis-snapshot",
    }

    dependencies = adapters.build_dependencies(source)

    assert dependencies == {
        "preview_rebalance_trades_fn": "preview",
        "get_portfolio_snapshot_fn": "portfolio-snapshot",
        "prime_virtual_portfolio_fn": "prime-virtual",
        "tier_order": {"paid": 2},
        "get_factor_proxies_snapshot_fn": "factor-proxies",
        "get_risk_limits_snapshot_fn": "risk-limits",
        "peek_analysis_result_snapshot_fn": "analysis-snapshot",
    }


def test_preview_rebalance_trades_delegates_to_late_bound_action() -> None:
    captured: dict[str, object] = {}

    def _preview(**kwargs):
        captured.update(kwargs)
        return {"status": "success"}

    result = adapters.preview_rebalance_trades(
        get_dependencies_fn=lambda: {"preview_rebalance_trades_fn": _preview},
        target_weights={"AAPL": 1.0},
        user_email="user@example.com",
    )

    assert result == {"status": "success"}
    assert captured == {
        "target_weights": {"AAPL": 1.0},
        "user_email": "user@example.com",
    }


def test_preview_rebalance_trades_returns_tool_style_error_payload() -> None:
    def _preview(**kwargs):
        raise ValueError("position provider unavailable")

    result = adapters.preview_rebalance_trades(
        get_dependencies_fn=lambda: {"preview_rebalance_trades_fn": _preview},
        target_weights={"AAPL": 1.0},
    )

    assert result == {
        "status": "error",
        "error": "position provider unavailable",
    }


def test_build_cached_rebalance_risk_snapshot_assembles_cached_analysis() -> None:
    portfolio_data = SimpleNamespace(
        stock_factor_proxies=None,
        refresh_cache_key=lambda: None,
    )
    cached_analysis = SimpleNamespace(
        get_asset_class_risk_contributions=lambda: [{"asset_class": "equity"}],
        get_asset_class_factor_betas=lambda: {"equity": {"market": 1.2}},
        get_compliance_summary=lambda: {"violation_count": 1},
    )
    captured: dict[str, object] = {}

    def _get_factor_proxies(user_id, portfolio_name, portfolio, *, allow_gpt):
        captured["factor_call"] = (user_id, portfolio_name, portfolio, allow_gpt)
        return {"AAPL": "SPY"}

    def _peek_analysis(**kwargs):
        captured["analysis_call"] = kwargs
        return cached_analysis

    result = adapters.build_cached_rebalance_risk_snapshot(
        {"user_id": "7", "tier": "paid"},
        "Core",
        get_dependencies_fn=lambda: {
            "get_portfolio_snapshot_fn": lambda user_id, portfolio_name: portfolio_data,
            "prime_virtual_portfolio_fn": lambda *args, **kwargs: captured.update(
                {"prime_call": (args, kwargs)}
            ),
            "tier_order": {"registered": 1, "paid": 2},
            "get_factor_proxies_snapshot_fn": _get_factor_proxies,
            "get_risk_limits_snapshot_fn": lambda user_id, portfolio_name: (
                "risk-limits",
                "Default",
            ),
            "peek_analysis_result_snapshot_fn": _peek_analysis,
        },
    )

    assert result == {
        "risk_contributions": [{"asset_class": "equity"}],
        "factor_betas": {"equity": {"market": 1.2}},
        "compliance_summary": {"violation_count": 1},
    }
    assert portfolio_data.stock_factor_proxies == {"AAPL": "SPY"}
    assert captured["factor_call"] == (7, "Core", portfolio_data, True)
    assert captured["analysis_call"]["performance_period"] == "1M"
    assert captured["analysis_call"]["risk_limits_data"] == "risk-limits"


def test_build_cached_rebalance_risk_snapshot_returns_none_on_failure() -> None:
    result = adapters.build_cached_rebalance_risk_snapshot(
        {"user_id": "bad"},
        get_dependencies_fn=lambda: {
            "get_portfolio_snapshot_fn": lambda *args, **kwargs: object(),
        },
    )

    assert result is None
