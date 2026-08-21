"""App-owned dependency adapters for extracted route workflows."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import HTTPException

from actions.optimization import (
    OptimizationConstraintRequestError,
    OptimizationExpectedReturnsError,
    OptimizationRunError,
)
from services.optimization_public_contract import optimization_run_failure_detail
from utils.errors import ErrorCodes


def build_analysis_route_dependencies(source: dict[str, Any]) -> dict[str, Any]:
    """Build analysis workflow adapter dependencies from app globals at call time."""

    from app_platform.logging.workflow_timing import workflow_timer

    return {
        "get_portfolio_snapshot_fn": source["get_portfolio_snapshot"],
        "prime_virtual_portfolio_fn": source[
            "_prime_virtual_portfolio_from_cached_positions"
        ],
        "get_factor_proxies_snapshot_fn": source["get_factor_proxies_snapshot"],
        "get_risk_limits_snapshot_fn": source["get_risk_limits_snapshot"],
        "get_analysis_result_snapshot_fn": source["get_analysis_result_snapshot"],
        "get_risk_score_result_snapshot_fn": source["get_risk_score_result_snapshot"],
        "get_performance_result_snapshot_fn": source["get_performance_result_snapshot"],
        "performance_cache_scope_fn": source["_performance_cache_scope"],
        "tier_order": source["TIER_ORDER"],
        "workflow_timer_fn": workflow_timer,
    }


def build_optimization_action_dependencies(source: dict[str, Any]) -> dict[str, Any]:
    """Build optimization action dependencies from app globals at call time."""

    return {
        "portfolio_manager_cls": source["PortfolioManager"],
        "risk_limits_manager_cls": source[
            "risk_limits_manager_module"
        ].RiskLimitsManager,
        "returns_service_cls": source["returns_service_module"].ReturnsService,
        "ensure_factor_proxies_fn": source[
            "factor_proxy_service_module"
        ].ensure_factor_proxies,
        "warning_logger": source["portfolio_logger"],
    }


def build_optimization_route_dependencies(source: dict[str, Any]) -> dict[str, Any]:
    """Build optimization route adapter dependencies from app globals at call time."""

    return {
        "run_min_variance_optimization_fn": source["run_min_variance_optimization"],
        "run_max_return_optimization_fn": source["run_max_return_optimization"],
        "run_max_sharpe_optimization_fn": source["run_max_sharpe_optimization"],
        "run_target_volatility_optimization_fn": source[
            "run_target_volatility_optimization"
        ],
        "run_efficient_frontier_optimization_fn": source[
            "run_efficient_frontier_optimization"
        ],
        "action_dependencies_fn": source["_optimization_action_dependencies"],
        "raise_expected_returns_http_fn": raise_optimization_expected_returns_http,
        "raise_run_http_fn": raise_optimization_run_http,
        "raise_constraint_http_fn": raise_optimization_constraint_http,
    }


def raise_optimization_expected_returns_http(
    exc: OptimizationExpectedReturnsError,
) -> None:
    raise HTTPException(
        status_code=422,
        detail={
            "message": exc.message,
            "error_code": ErrorCodes.INVALID_PARAMETER,
            "details": {
                "coverage_analysis": exc.coverage_result.get("final_coverage", {}),
                "missing_returns": True,
                "optimization_type": exc.optimization_type,
            },
            "endpoint": exc.endpoint,
        },
    )


def raise_optimization_run_http(exc: OptimizationRunError) -> None:
    raise HTTPException(
        status_code=500,
        detail=optimization_run_failure_detail(
            endpoint=exc.endpoint,
            optimization_type=exc.optimization_type,
        ),
    ) from exc


def raise_optimization_constraint_http(exc: OptimizationConstraintRequestError) -> None:
    details: dict[str, Any] = {
        "constraint": exc.constraint,
        "reason": exc.reason,
        "optimization_type": exc.optimization_type,
    }
    if exc.mode:
        details["mode"] = exc.mode
    raise HTTPException(
        status_code=422,
        detail={
            "message": exc.message,
            "error_code": ErrorCodes.INVALID_PARAMETER,
            "details": details,
            "endpoint": exc.endpoint,
        },
    )


def run_analyze_workflow(
    *,
    analysis_routes_module: Any,
    portfolio_name: str,
    period: str,
    user: dict,
    portfolio_service: Any,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    dependencies = get_dependencies_fn()
    return analysis_routes_module.run_analyze_workflow(
        portfolio_name,
        period,
        user,
        portfolio_service,
        get_portfolio_snapshot_fn=dependencies["get_portfolio_snapshot_fn"],
        prime_virtual_portfolio_fn=dependencies["prime_virtual_portfolio_fn"],
        get_factor_proxies_snapshot_fn=dependencies["get_factor_proxies_snapshot_fn"],
        get_risk_limits_snapshot_fn=dependencies["get_risk_limits_snapshot_fn"],
        get_analysis_result_snapshot_fn=dependencies["get_analysis_result_snapshot_fn"],
        tier_order=dependencies["tier_order"],
        workflow_timer_fn=dependencies["workflow_timer_fn"],
    )


def run_risk_score_workflow(
    *,
    analysis_routes_module: Any,
    portfolio_name: str,
    user: dict,
    portfolio_service: Any,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    dependencies = get_dependencies_fn()
    return analysis_routes_module.run_risk_score_workflow(
        portfolio_name,
        user,
        portfolio_service,
        get_portfolio_snapshot_fn=dependencies["get_portfolio_snapshot_fn"],
        prime_virtual_portfolio_fn=dependencies["prime_virtual_portfolio_fn"],
        get_factor_proxies_snapshot_fn=dependencies["get_factor_proxies_snapshot_fn"],
        get_risk_limits_snapshot_fn=dependencies["get_risk_limits_snapshot_fn"],
        get_analysis_result_snapshot_fn=dependencies["get_analysis_result_snapshot_fn"],
        get_risk_score_result_snapshot_fn=dependencies[
            "get_risk_score_result_snapshot_fn"
        ],
        workflow_timer_fn=dependencies["workflow_timer_fn"],
    )


def run_performance_workflow(
    *,
    analysis_routes_module: Any,
    benchmark_ticker: str,
    portfolio_name: str,
    user: dict,
    portfolio_service: Any,
    start_date: str | None = None,
    end_date: str | None = None,
    include_attribution: bool = True,
    include_optional_metrics: bool = False,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    dependencies = get_dependencies_fn()
    return analysis_routes_module.run_performance_workflow(
        benchmark_ticker,
        portfolio_name,
        user,
        portfolio_service,
        start_date,
        end_date,
        include_attribution,
        include_optional_metrics,
        get_portfolio_snapshot_fn=dependencies["get_portfolio_snapshot_fn"],
        prime_virtual_portfolio_fn=dependencies["prime_virtual_portfolio_fn"],
        get_performance_result_snapshot_fn=dependencies[
            "get_performance_result_snapshot_fn"
        ],
        performance_cache_scope_fn=dependencies["performance_cache_scope_fn"],
        workflow_timer_fn=dependencies["workflow_timer_fn"],
    )


def run_what_if_workflow(
    *,
    scenario_routes_module: Any,
    portfolio_name: str,
    new_weights: dict,
    delta: dict,
    scenario_name: str,
    user: dict,
    scenario_service: Any,
    run_what_if_analysis_fn: Callable[..., dict[str, Any]],
    portfolio_manager_cls: type,
    risk_limits_manager_cls: type,
    ensure_factor_proxies_fn: Callable[..., Any],
    warning_logger: Any,
) -> dict[str, Any]:
    return scenario_routes_module.run_what_if_workflow(
        portfolio_name,
        new_weights,
        delta,
        scenario_name,
        user,
        scenario_service,
        run_what_if_analysis_fn=run_what_if_analysis_fn,
        portfolio_manager_cls=portfolio_manager_cls,
        risk_limits_manager_cls=risk_limits_manager_cls,
        ensure_factor_proxies_fn=ensure_factor_proxies_fn,
        warning_logger=warning_logger,
    )


def run_stress_test_workflow(
    *,
    scenario_routes_module: Any,
    portfolio_name: str,
    scenario: str | None,
    custom_shocks: dict | None,
    user: dict,
    scenario_service: Any,
    run_stress_test_analysis_fn: Callable[..., dict[str, Any]],
    portfolio_manager_cls: type,
) -> dict[str, Any]:
    return scenario_routes_module.run_stress_test_workflow(
        portfolio_name,
        scenario,
        custom_shocks,
        user,
        scenario_service,
        run_stress_test_analysis_fn=run_stress_test_analysis_fn,
        portfolio_manager_cls=portfolio_manager_cls,
    )


def run_stress_test_run_all_workflow(
    *,
    scenario_routes_module: Any,
    portfolio_name: str,
    user: dict,
    scenario_service: Any,
    run_all_stress_tests_analysis_fn: Callable[..., dict[str, Any]],
    portfolio_manager_cls: type,
    run_all_stress_tests_fn: Callable[..., Any],
) -> dict[str, Any]:
    return scenario_routes_module.run_stress_test_run_all_workflow(
        portfolio_name,
        user,
        scenario_service,
        run_all_stress_tests_analysis_fn=run_all_stress_tests_analysis_fn,
        portfolio_manager_cls=portfolio_manager_cls,
        run_all_stress_tests_fn=run_all_stress_tests_fn,
    )


def run_monte_carlo_workflow(
    *,
    scenario_routes_module: Any,
    portfolio_name: str,
    num_simulations: int,
    time_horizon_months: int,
    distribution: str,
    df: int,
    drift_model: str,
    drift_overrides: dict[str, float] | None,
    scenario_shocks: dict[str, float] | None,
    resolved_weights: dict[str, float] | None,
    portfolio_value: float | None,
    vol_scale: float,
    user: dict,
    scenario_service: Any,
    run_monte_carlo_analysis_fn: Callable[..., dict[str, Any]],
    portfolio_manager_cls: type,
    resolve_drift_inputs_fn: Callable[..., Any],
    returns_service_factory: Callable[..., Any] | None = None,
    is_db_available_fn: Callable[[], bool] | None = None,
) -> dict[str, Any]:
    if returns_service_factory is None:
        from services.returns_service import ReturnsService

        returns_service_factory = ReturnsService
    if is_db_available_fn is None:
        from database import is_db_available

        is_db_available_fn = is_db_available

    return scenario_routes_module.run_monte_carlo_workflow(
        portfolio_name,
        num_simulations,
        time_horizon_months,
        distribution,
        df,
        drift_model=drift_model,
        drift_overrides=drift_overrides,
        scenario_shocks=scenario_shocks,
        resolved_weights=resolved_weights,
        portfolio_value=portfolio_value,
        vol_scale=vol_scale,
        user=user,
        scenario_service=scenario_service,
        run_monte_carlo_analysis_fn=run_monte_carlo_analysis_fn,
        portfolio_manager_cls=portfolio_manager_cls,
        resolve_drift_inputs_fn=resolve_drift_inputs_fn,
        returns_service_factory=returns_service_factory,
        is_db_available_fn=is_db_available_fn,
    )


def run_backtest_workflow(
    *,
    scenario_routes_module: Any,
    backtest_request: Any,
    user: dict,
    run_backtest_analysis_fn: Callable[..., dict[str, Any]],
    portfolio_manager_cls: type,
    run_backtest_engine_fn: Callable[..., Any] | None = None,
    backtest_result_cls: type | None = None,
) -> dict[str, Any]:
    if run_backtest_engine_fn is None:
        from portfolio_risk_engine.backtest_engine import (
            run_backtest as run_backtest_engine,
        )

        run_backtest_engine_fn = run_backtest_engine
    if backtest_result_cls is None:
        from core.result_objects import BacktestResult

        backtest_result_cls = BacktestResult

    return scenario_routes_module.run_backtest_workflow(
        backtest_request,
        user,
        run_backtest_analysis_fn=run_backtest_analysis_fn,
        portfolio_manager_cls=portfolio_manager_cls,
        run_backtest_engine_fn=run_backtest_engine_fn,
        backtest_result_cls=backtest_result_cls,
    )


def _run_optimization_workflow(
    *,
    optimization_routes_module: Any,
    workflow_name: str,
    request: Any,
    user: dict,
    optimization_service: Any,
    action_fn_name: str,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    dependencies = get_dependencies_fn()
    workflow_fn = getattr(optimization_routes_module, workflow_name)
    return workflow_fn(
        request,
        user,
        optimization_service,
        **{
            action_fn_name: dependencies[action_fn_name],
            "action_dependencies_fn": dependencies["action_dependencies_fn"],
            "raise_expected_returns_http_fn": dependencies[
                "raise_expected_returns_http_fn"
            ],
            "raise_run_http_fn": dependencies["raise_run_http_fn"],
            "raise_constraint_http_fn": dependencies["raise_constraint_http_fn"],
        },
    )


def run_min_variance_workflow(
    *,
    optimization_routes_module: Any,
    optimization_request: Any,
    user: dict,
    optimization_service: Any,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    return _run_optimization_workflow(
        optimization_routes_module=optimization_routes_module,
        workflow_name="run_min_variance_workflow",
        request=optimization_request,
        user=user,
        optimization_service=optimization_service,
        action_fn_name="run_min_variance_optimization_fn",
        get_dependencies_fn=get_dependencies_fn,
    )


def run_max_return_workflow(
    *,
    optimization_routes_module: Any,
    optimization_request: Any,
    user: dict,
    optimization_service: Any,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    return _run_optimization_workflow(
        optimization_routes_module=optimization_routes_module,
        workflow_name="run_max_return_workflow",
        request=optimization_request,
        user=user,
        optimization_service=optimization_service,
        action_fn_name="run_max_return_optimization_fn",
        get_dependencies_fn=get_dependencies_fn,
    )


def run_max_sharpe_workflow(
    *,
    optimization_routes_module: Any,
    optimization_request: Any,
    user: dict,
    optimization_service: Any,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    return _run_optimization_workflow(
        optimization_routes_module=optimization_routes_module,
        workflow_name="run_max_sharpe_workflow",
        request=optimization_request,
        user=user,
        optimization_service=optimization_service,
        action_fn_name="run_max_sharpe_optimization_fn",
        get_dependencies_fn=get_dependencies_fn,
    )


def run_target_volatility_workflow(
    *,
    optimization_routes_module: Any,
    optimization_request: Any,
    user: dict,
    optimization_service: Any,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    return _run_optimization_workflow(
        optimization_routes_module=optimization_routes_module,
        workflow_name="run_target_volatility_workflow",
        request=optimization_request,
        user=user,
        optimization_service=optimization_service,
        action_fn_name="run_target_volatility_optimization_fn",
        get_dependencies_fn=get_dependencies_fn,
    )


def run_efficient_frontier_workflow(
    *,
    optimization_routes_module: Any,
    frontier_request: Any,
    user: dict,
    optimization_service: Any,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    return _run_optimization_workflow(
        optimization_routes_module=optimization_routes_module,
        workflow_name="run_efficient_frontier_workflow",
        request=frontier_request,
        user=user,
        optimization_service=optimization_service,
        action_fn_name="run_efficient_frontier_optimization_fn",
        get_dependencies_fn=get_dependencies_fn,
    )


__all__ = [
    "build_analysis_route_dependencies",
    "build_optimization_action_dependencies",
    "build_optimization_route_dependencies",
    "raise_optimization_expected_returns_http",
    "raise_optimization_constraint_http",
    "raise_optimization_run_http",
    "run_analyze_workflow",
    "run_backtest_workflow",
    "run_efficient_frontier_workflow",
    "run_max_return_workflow",
    "run_max_sharpe_workflow",
    "run_min_variance_workflow",
    "run_monte_carlo_workflow",
    "run_performance_workflow",
    "run_risk_score_workflow",
    "run_stress_test_run_all_workflow",
    "run_stress_test_workflow",
    "run_target_volatility_workflow",
    "run_what_if_workflow",
]
