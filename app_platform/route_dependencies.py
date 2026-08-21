"""Build app-owned dependencies for route registration."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from app_platform.route_setup import RouteSetupDependencies


def _call(source: Mapping[str, Any], name: str):
    def _adapter(*args, **kwargs):
        return source[name](*args, **kwargs)

    return _adapter


def _get(source: Mapping[str, Any], name: str):
    return lambda: source[name]


def _call_threadpool(source: Mapping[str, Any]):
    def _adapter(func, /, *args, **kwargs):
        return source["run_in_threadpool"](func, *args, **kwargs)

    return _adapter


def _call_to_thread(source: Mapping[str, Any]):
    def _adapter(func, /, *args, **kwargs):
        return source["asyncio"].to_thread(func, *args, **kwargs)

    return _adapter


def _workflow_timer(*args, **kwargs):
    from app_platform.logging.workflow_timing import workflow_timer

    return workflow_timer(*args, **kwargs)


def _clear_portfolio_cache(source: Mapping[str, Any]):
    registry = source["_service_registry"]
    return source["admin_app_helpers"].clear_portfolio_cache(
        service_registry=registry,
        clear_result_snapshot_caches_fn=source["clear_result_snapshot_caches"],
        clear_workflow_snapshot_caches_fn=source["clear_workflow_snapshot_caches"],
        clear_position_snapshot_cache_fn=source["clear_position_snapshot_cache"],
        clear_resolved_portfolio_config_cache_fn=source[
            "clear_resolved_portfolio_config_cache"
        ],
    )


def _get_cache_status(source: Mapping[str, Any]):
    return source["admin_app_helpers"].get_cache_status(
        service_registry=source["_service_registry"],
    )


def _send_key_to_kartra_thread(source: Mapping[str, Any]):
    def _adapter(*args, **kwargs):
        return source["admin_app_helpers"].send_key_to_kartra_thread(*args, **kwargs)

    return _adapter


def build_route_setup_dependencies(source: Mapping[str, Any]) -> RouteSetupDependencies:
    """Build route setup dependencies from app globals with late-bound seams."""

    return RouteSetupDependencies(
        valid_keys=source["VALID_KEYS"],
        tier_map=source["TIER_MAP"],
        log_dir=source["LOG_DIR"],
        get_current_user_dependency=source["get_current_user"],
        require_paid_user_dependency=source["_require_paid_user"],
        get_api_key_dependency=source["get_api_key"],
        limiter=source["limiter"],
        get_user_portfolio_service_fn=_call(source, "get_user_portfolio_service"),
        get_user_scenario_service_fn=_call(source, "get_user_scenario_service"),
        get_user_optimization_service_fn=_call(
            source,
            "get_user_optimization_service",
        ),
        get_portfolio_manager_cls_fn=_get(source, "PortfolioManager"),
        get_current_portfolio_has_bootstrap_rows_fn=_get(
            source,
            "_current_portfolio_has_bootstrap_rows",
        ),
        get_portfolio_snapshot_fn=_get(source, "get_portfolio_snapshot"),
        prime_virtual_portfolio_fn=_call(
            source,
            "_prime_virtual_portfolio_from_cached_positions",
        ),
        get_prewarm_factor_proxies_snapshot_fn=_get(
            source,
            "prewarm_factor_proxies_snapshot",
        ),
        get_build_portfolio_display_data_fn=_get(
            source,
            "_build_portfolio_display_data",
        ),
        get_schedule_dashboard_prewarm_fn=_get(source, "_schedule_dashboard_prewarm"),
        get_schedule_holdings_metadata_prewarm_fn=_get(
            source,
            "_schedule_holdings_metadata_prewarm",
        ),
        get_enrich_holdings_with_metadata_fn=_get(
            source,
            "enrich_holdings_with_metadata",
        ),
        get_ensure_factor_proxies_fn=(
            lambda: source["factor_proxy_service_module"].ensure_factor_proxies
        ),
        get_tier_order_fn=_get(source, "TIER_ORDER"),
        get_log_request_fn=_get(source, "log_request"),
        get_direct_log_error_fn=_get(source, "log_error"),
        get_log_error_fn=_get(source, "log_error"),
        get_api_logger_fn=_get(source, "api_logger"),
        workflow_timer_fn=_workflow_timer,
        resolve_direct_dates_fn=_call(source, "_resolve_direct_dates"),
        get_stock_service_fn=_get(source, "stock_service"),
        get_direct_optimization_service_fn=_get(
            source,
            "_direct_optimization_service",
        ),
        get_direct_portfolio_service_fn=_get(source, "_direct_portfolio_service"),
        get_resolve_user_id_fn=_get(source, "_resolve_user_id"),
        get_portfolio_repository_cls_fn=_get(source, "PortfolioRepository"),
        get_allocation_presets_fn=_get(source, "get_allocation_presets"),
        get_validate_allocations_fn=_get(source, "_validate_and_normalize_allocations"),
        get_build_cached_rebalance_risk_snapshot_fn=_get(
            source,
            "_build_cached_rebalance_risk_snapshot",
        ),
        get_preview_rebalance_trades_fn=_get(source, "preview_rebalance_trades"),
        get_load_strategy_templates_fn=_get(source, "_load_strategy_templates"),
        run_allocation_in_threadpool_fn=_call_threadpool(source),
        to_thread_fn=_call_to_thread(source),
        get_factor_proxies_snapshot_fn=_call(source, "get_factor_proxies_snapshot"),
        get_risk_limits_snapshot_fn=_call(source, "get_risk_limits_snapshot"),
        get_analysis_result_snapshot_fn=_call(source, "get_analysis_result_snapshot"),
        get_performance_result_snapshot_fn=_call(
            source,
            "get_performance_result_snapshot",
        ),
        get_risk_score_result_snapshot_fn=_call(
            source,
            "get_risk_score_result_snapshot",
        ),
        performance_cache_scope_fn=_call(source, "_performance_cache_scope"),
        tier_order=source["TIER_ORDER"],
        run_analyze_workflow_fn=_call(source, "_run_analyze_workflow"),
        run_risk_score_workflow_fn=_call(source, "_run_risk_score_workflow"),
        run_performance_workflow_fn=_call(source, "_run_performance_workflow"),
        run_interpret_workflow_fn=_call(source, "_run_interpret_workflow"),
        run_portfolio_analysis_workflow_fn=_call(
            source,
            "_run_portfolio_analysis_workflow",
        ),
        get_run_what_if_workflow_fn=_get(source, "_run_what_if_workflow"),
        get_run_stress_test_workflow_fn=_get(source, "_run_stress_test_workflow"),
        get_run_stress_test_run_all_workflow_fn=_get(
            source,
            "_run_stress_test_run_all_workflow",
        ),
        get_run_monte_carlo_workflow_fn=_get(source, "_run_monte_carlo_workflow"),
        get_run_backtest_workflow_fn=_get(source, "_run_backtest_workflow"),
        run_scenario_in_threadpool_fn=_call_threadpool(source),
        get_run_min_variance_workflow_fn=_get(source, "_run_min_variance_workflow"),
        get_run_max_return_workflow_fn=_get(source, "_run_max_return_workflow"),
        get_run_max_sharpe_workflow_fn=_get(source, "_run_max_sharpe_workflow"),
        get_run_target_volatility_workflow_fn=_get(
            source,
            "_run_target_volatility_workflow",
        ),
        get_run_efficient_frontier_workflow_fn=_get(
            source,
            "_run_efficient_frontier_workflow",
        ),
        run_optimization_in_threadpool_fn=_call_threadpool(source),
        clear_portfolio_cache_func=lambda: _clear_portfolio_cache(source),
        cache_status_func=lambda: _get_cache_status(source),
        send_key_to_kartra_thread_func=_send_key_to_kartra_thread(source),
        get_environment_fn=lambda: source["os"].getenv("ENVIRONMENT", "development"),
    )


__all__ = ["build_route_setup_dependencies"]
