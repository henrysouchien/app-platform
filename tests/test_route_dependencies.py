from __future__ import annotations

from types import SimpleNamespace

import pytest

from app_platform.route_dependencies import build_route_setup_dependencies


def _marker(name: str):
    def _fn(*args, **kwargs):
        return name, args, kwargs

    return _fn


def _source() -> dict:
    registry = SimpleNamespace(
        user_services_lock="lock",
        user_portfolio_services={"portfolio": object()},
        user_scenario_services={"scenario": object()},
        user_optimization_services={"optimization": object()},
    )
    admin_helpers = SimpleNamespace(
        clear_portfolio_cache=lambda **kwargs: kwargs,
        get_cache_status=lambda **kwargs: kwargs,
        send_key_to_kartra_thread=_marker("kartra"),
    )
    source = {
        "VALID_KEYS": {"paid_key_789"},
        "TIER_MAP": {"paid_key_789": "paid"},
        "LOG_DIR": "logs",
        "get_current_user": _marker("current_user"),
        "_require_paid_user": _marker("paid_user"),
        "get_api_key": _marker("api_key"),
        "limiter": object(),
        "PortfolioManager": type("PortfolioManager", (), {}),
        "PortfolioRepository": type("PortfolioRepository", (), {}),
        "TIER_ORDER": {"public": 0, "registered": 1, "paid": 2},
        "LOG_SENTINEL": object(),
        "admin_app_helpers": admin_helpers,
        "_service_registry": registry,
        "factor_proxy_service_module": SimpleNamespace(
            ensure_factor_proxies=_marker("ensure_factor_proxies")
        ),
        "asyncio": SimpleNamespace(
            to_thread=lambda func, *args, **kwargs: ("to_thread", func, args, kwargs)
        ),
        "os": SimpleNamespace(getenv=lambda key, default=None: f"{key}:{default}"),
    }
    for name in (
        "get_user_portfolio_service",
        "get_user_scenario_service",
        "get_user_optimization_service",
        "_current_portfolio_has_bootstrap_rows",
        "get_portfolio_snapshot",
        "_prime_virtual_portfolio_from_cached_positions",
        "prewarm_factor_proxies_snapshot",
        "_build_portfolio_display_data",
        "_schedule_dashboard_prewarm",
        "_schedule_holdings_metadata_prewarm",
        "enrich_holdings_with_metadata",
        "log_request",
        "log_error",
        "api_logger",
        "_resolve_direct_dates",
        "stock_service",
        "_direct_optimization_service",
        "_direct_portfolio_service",
        "_resolve_user_id",
        "get_allocation_presets",
        "_validate_and_normalize_allocations",
        "_build_cached_rebalance_risk_snapshot",
        "preview_rebalance_trades",
        "_load_strategy_templates",
        "run_in_threadpool",
        "get_factor_proxies_snapshot",
        "get_risk_limits_snapshot",
        "get_analysis_result_snapshot",
        "get_performance_result_snapshot",
        "get_risk_score_result_snapshot",
        "_performance_cache_scope",
        "_run_analyze_workflow",
        "_run_risk_score_workflow",
        "_run_performance_workflow",
        "_run_interpret_workflow",
        "_run_portfolio_analysis_workflow",
        "_run_what_if_workflow",
        "_run_stress_test_workflow",
        "_run_stress_test_run_all_workflow",
        "_run_monte_carlo_workflow",
        "_run_backtest_workflow",
        "_run_min_variance_workflow",
        "_run_max_return_workflow",
        "_run_max_sharpe_workflow",
        "_run_target_volatility_workflow",
        "_run_efficient_frontier_workflow",
        "clear_result_snapshot_caches",
        "clear_workflow_snapshot_caches",
        "clear_position_snapshot_cache",
        "clear_resolved_portfolio_config_cache",
        "_direct_scenario_service",
    ):
        source[name] = _marker(name)
    return source


def test_route_dependencies_resolve_route_seams_at_call_time() -> None:
    source = _source()
    dependencies = build_route_setup_dependencies(source)

    source["get_user_scenario_service"] = lambda user: ("scenario-service", user)
    source["_run_min_variance_workflow"] = "min-variance-workflow"
    source["run_in_threadpool"] = lambda func, *args, **kwargs: (
        "threadpool",
        func,
        args,
        kwargs,
    )

    assert dependencies.get_user_scenario_service_fn({"user_id": 7}) == (
        "scenario-service",
        {"user_id": 7},
    )
    assert dependencies.get_run_min_variance_workflow_fn() == "min-variance-workflow"
    assert dependencies.run_optimization_in_threadpool_fn("work", 1, flag=True) == (
        "threadpool",
        "work",
        (1,),
        {"flag": True},
    )


def test_route_dependencies_resolve_admin_cache_inputs_at_call_time() -> None:
    source = _source()
    dependencies = build_route_setup_dependencies(source)

    source["_direct_portfolio_service"] = "new-portfolio-service"
    source["_service_registry"].user_portfolio_services = {"user": "portfolio"}

    result = dependencies.clear_portfolio_cache_func()

    assert result["service_registry"] is source["_service_registry"]

    status_result = dependencies.cache_status_func()
    assert status_result["service_registry"] is source["_service_registry"]


@pytest.mark.parametrize(
    ("field_name", "source_key", "replacement"),
    [
        ("get_stock_service_fn", "stock_service", "new-stock-service"),
        (
            "get_direct_optimization_service_fn",
            "_direct_optimization_service",
            "new-direct-optimization",
        ),
        (
            "get_direct_portfolio_service_fn",
            "_direct_portfolio_service",
            "new-direct-portfolio",
        ),
        (
            "get_build_portfolio_display_data_fn",
            "_build_portfolio_display_data",
            "new-display-builder",
        ),
        (
            "get_schedule_dashboard_prewarm_fn",
            "_schedule_dashboard_prewarm",
            "new-dashboard-prewarm",
        ),
        (
            "get_schedule_holdings_metadata_prewarm_fn",
            "_schedule_holdings_metadata_prewarm",
            "new-metadata-prewarm",
        ),
        (
            "get_enrich_holdings_with_metadata_fn",
            "enrich_holdings_with_metadata",
            "new-enrichment",
        ),
        (
            "get_allocation_presets_fn",
            "get_allocation_presets",
            "new-allocation-presets",
        ),
        (
            "get_validate_allocations_fn",
            "_validate_and_normalize_allocations",
            "new-allocation-validator",
        ),
        (
            "get_build_cached_rebalance_risk_snapshot_fn",
            "_build_cached_rebalance_risk_snapshot",
            "new-rebalance-snapshot",
        ),
        (
            "get_preview_rebalance_trades_fn",
            "preview_rebalance_trades",
            "new-rebalance-preview",
        ),
        (
            "get_load_strategy_templates_fn",
            "_load_strategy_templates",
            "new-template-loader",
        ),
        ("get_log_request_fn", "log_request", "new-log-request"),
        ("get_direct_log_error_fn", "log_error", "new-log-error"),
        ("get_log_error_fn", "log_error", "new-log-error"),
        ("get_api_logger_fn", "api_logger", "new-api-logger"),
    ],
)
def test_route_dependencies_resolve_important_getters_at_call_time(
    field_name: str,
    source_key: str,
    replacement: str,
) -> None:
    source = _source()
    dependencies = build_route_setup_dependencies(source)

    source[source_key] = replacement

    assert getattr(dependencies, field_name)() == replacement


def test_route_dependencies_resolve_utility_wrappers() -> None:
    source = _source()
    dependencies = build_route_setup_dependencies(source)

    assert dependencies.get_ensure_factor_proxies_fn()("AAPL") == (
        "ensure_factor_proxies",
        ("AAPL",),
        {},
    )
    assert dependencies.to_thread_fn("work", 1, flag=True) == (
        "to_thread",
        "work",
        (1,),
        {"flag": True},
    )
    assert dependencies.get_environment_fn() == "ENVIRONMENT:development"


def test_route_dependencies_resolve_kartra_sender_at_call_time() -> None:
    source = _source()
    dependencies = build_route_setup_dependencies(source)

    source["admin_app_helpers"].send_key_to_kartra_thread = lambda key: (
        "kartra",
        key,
    )

    assert dependencies.send_key_to_kartra_thread_func("paid_key") == (
        "kartra",
        "paid_key",
    )
