"""Install app-module compatibility wrappers for extracted route dependencies."""

from __future__ import annotations

import os
from collections.abc import MutableMapping
from concurrent.futures import ThreadPoolExecutor
from typing import Any


def install_compatibility_wrappers(source: MutableMapping[str, Any]) -> None:
    """Populate legacy app-level names with late-bound compatibility wrappers."""

    from routes import analysis as analysis_routes
    from routes import optimization as optimization_routes
    from routes import scenarios as scenario_routes

    source["analysis_routes"] = analysis_routes
    source["optimization_routes"] = optimization_routes
    source["scenario_routes"] = scenario_routes

    def get_user_portfolio_service(user: dict):
        return source["_service_registry"].get_user_portfolio_service(user)

    def get_user_scenario_service(user: dict):
        return source["_service_registry"].get_user_scenario_service(user)

    def get_user_optimization_service(user: dict):
        return source["_service_registry"].get_user_optimization_service(user)

    def _performance_cache_scope(
        *,
        include_attribution: bool,
        include_optional_metrics: bool,
    ) -> str:
        if not include_attribution:
            if include_optional_metrics:
                return "summary_with_extras"
            return "summary_only"
        if include_optional_metrics:
            return "attr_with_extras"
        return "attr_core"

    def _allocation_adapter_dependencies() -> dict[str, Any]:
        return source["allocation_adapters"].build_dependencies(source)

    def preview_rebalance_trades(**kwargs) -> dict:
        return source["allocation_adapters"].preview_rebalance_trades(
            get_dependencies_fn=source["_allocation_adapter_dependencies"],
            **kwargs,
        )

    def _optimization_action_dependencies() -> dict[str, Any]:
        return source["route_workflow_adapters"].build_optimization_action_dependencies(
            source
        )

    def _optimization_route_adapter_dependencies() -> dict[str, Any]:
        return source["route_workflow_adapters"].build_optimization_route_dependencies(
            source
        )

    def _resolve_direct_dates(top_start, top_end, portfolio_dict):
        return source["direct_date_adapters"].resolve_direct_dates(
            top_start,
            top_end,
            portfolio_dict,
        )

    def _build_analyze_result(portfolio_service, portfolio_data, limits_data, period):
        return portfolio_service.analyze_portfolio(
            portfolio_data,
            limits_data,
            performance_period=period,
        )

    def _run_what_if_workflow(
        portfolio_name: str,
        new_weights: dict,
        delta: dict,
        scenario_name: str,
        user: dict,
        scenario_service,
    ) -> dict[str, Any]:
        return source["route_workflow_adapters"].run_what_if_workflow(
            scenario_routes_module=source["scenario_routes"],
            portfolio_name=portfolio_name,
            new_weights=new_weights,
            delta=delta,
            scenario_name=scenario_name,
            user=user,
            scenario_service=scenario_service,
            run_what_if_analysis_fn=source["run_rest_what_if_analysis"],
            portfolio_manager_cls=source["PortfolioManager"],
            risk_limits_manager_cls=source[
                "risk_limits_manager_module"
            ].RiskLimitsManager,
            ensure_factor_proxies_fn=source[
                "factor_proxy_service_module"
            ].ensure_factor_proxies,
            warning_logger=source["portfolio_logger"],
        )

    def _build_cached_rebalance_risk_snapshot(
        user: dict,
        portfolio_name: str = "CURRENT_PORTFOLIO",
    ):
        return source["allocation_adapters"].build_cached_rebalance_risk_snapshot(
            user,
            portfolio_name,
            get_dependencies_fn=source["_allocation_adapter_dependencies"],
        )

    def _run_stress_test_workflow(
        portfolio_name: str,
        scenario: str | None,
        custom_shocks: dict | None,
        user: dict,
        scenario_service,
    ) -> dict[str, Any]:
        return source["route_workflow_adapters"].run_stress_test_workflow(
            scenario_routes_module=source["scenario_routes"],
            portfolio_name=portfolio_name,
            scenario=scenario,
            custom_shocks=custom_shocks,
            user=user,
            scenario_service=scenario_service,
            run_stress_test_analysis_fn=source["run_rest_stress_test_analysis"],
            portfolio_manager_cls=source["PortfolioManager"],
        )

    def _run_stress_test_run_all_workflow(
        portfolio_name: str,
        user: dict,
        scenario_service,
    ) -> dict[str, Any]:
        return source["route_workflow_adapters"].run_stress_test_run_all_workflow(
            scenario_routes_module=source["scenario_routes"],
            portfolio_name=portfolio_name,
            user=user,
            scenario_service=scenario_service,
            run_all_stress_tests_analysis_fn=source["run_rest_all_stress_tests"],
            portfolio_manager_cls=source["PortfolioManager"],
            run_all_stress_tests_fn=source["run_all_stress_tests"],
        )

    def _run_monte_carlo_workflow(
        portfolio_name: str,
        num_simulations: int,
        time_horizon_months: int,
        distribution: str,
        df: int,
        *,
        drift_model: str = "industry_etf",
        drift_overrides: dict[str, float] | None = None,
        scenario_shocks: dict[str, float] | None = None,
        resolved_weights: dict[str, float] | None = None,
        portfolio_value: float | None = None,
        vol_scale: float = 1.0,
        user: dict,
        scenario_service,
    ) -> dict[str, Any]:
        return source["route_workflow_adapters"].run_monte_carlo_workflow(
            scenario_routes_module=source["scenario_routes"],
            portfolio_name=portfolio_name,
            num_simulations=num_simulations,
            time_horizon_months=time_horizon_months,
            distribution=distribution,
            df=df,
            drift_model=drift_model,
            drift_overrides=drift_overrides,
            scenario_shocks=scenario_shocks,
            resolved_weights=resolved_weights,
            portfolio_value=portfolio_value,
            vol_scale=vol_scale,
            user=user,
            scenario_service=scenario_service,
            run_monte_carlo_analysis_fn=source["run_rest_monte_carlo_analysis"],
            portfolio_manager_cls=source["PortfolioManager"],
            resolve_drift_inputs_fn=source["resolve_monte_carlo_drift_inputs"],
        )

    def _run_backtest_workflow(backtest_request, user: dict) -> dict[str, Any]:
        return source["route_workflow_adapters"].run_backtest_workflow(
            scenario_routes_module=source["scenario_routes"],
            backtest_request=backtest_request,
            user=user,
            run_backtest_analysis_fn=source["run_rest_backtest_analysis"],
            portfolio_manager_cls=source["PortfolioManager"],
        )

    def _run_min_variance_workflow(
        optimization_request, user: dict, optimization_service
    ):
        return source["route_workflow_adapters"].run_min_variance_workflow(
            optimization_routes_module=source["optimization_routes"],
            optimization_request=optimization_request,
            user=user,
            optimization_service=optimization_service,
            get_dependencies_fn=source["_optimization_route_adapter_dependencies"],
        )

    def _run_max_return_workflow(
        optimization_request, user: dict, optimization_service
    ):
        return source["route_workflow_adapters"].run_max_return_workflow(
            optimization_routes_module=source["optimization_routes"],
            optimization_request=optimization_request,
            user=user,
            optimization_service=optimization_service,
            get_dependencies_fn=source["_optimization_route_adapter_dependencies"],
        )

    def _run_max_sharpe_workflow(
        optimization_request, user: dict, optimization_service
    ):
        return source["route_workflow_adapters"].run_max_sharpe_workflow(
            optimization_routes_module=source["optimization_routes"],
            optimization_request=optimization_request,
            user=user,
            optimization_service=optimization_service,
            get_dependencies_fn=source["_optimization_route_adapter_dependencies"],
        )

    def _run_target_volatility_workflow(
        optimization_request,
        user: dict,
        optimization_service,
    ):
        return source["route_workflow_adapters"].run_target_volatility_workflow(
            optimization_routes_module=source["optimization_routes"],
            optimization_request=optimization_request,
            user=user,
            optimization_service=optimization_service,
            get_dependencies_fn=source["_optimization_route_adapter_dependencies"],
        )

    def _run_efficient_frontier_workflow(
        frontier_request,
        user: dict,
        optimization_service,
    ):
        return source["route_workflow_adapters"].run_efficient_frontier_workflow(
            optimization_routes_module=source["optimization_routes"],
            frontier_request=frontier_request,
            user=user,
            optimization_service=optimization_service,
            get_dependencies_fn=source["_optimization_route_adapter_dependencies"],
        )

    def enrich_holdings_with_metadata(holdings_list):
        return source["portfolio_display_service"].enrich_holdings_with_metadata(
            holdings_list
        )

    def transform_portfolio_for_display(portfolio_data, portfolio_service=None):
        return source["portfolio_display_service"].transform_portfolio_for_display(
            portfolio_data,
            portfolio_service,
            enrich_holdings_with_metadata_fn=source["enrich_holdings_with_metadata"],
            warning_logger=source["api_logger"],
        )

    def _transform_positions_payload_for_display(payload, *, statement_date=None):
        return source[
            "portfolio_display_service"
        ].transform_positions_payload_for_display(
            payload,
            statement_date=statement_date,
        )

    def _transform_position_result_for_display(result, *, statement_date=None):
        return source[
            "portfolio_display_service"
        ].transform_position_result_for_display(
            result,
            statement_date=statement_date,
        )

    def _copy_portfolio_standardization_snapshot(target_portfolio, source_portfolio):
        return source[
            "portfolio_display_service"
        ].copy_portfolio_standardization_snapshot(
            target_portfolio,
            source_portfolio,
        )

    def _prime_virtual_portfolio_from_position_result(portfolio_data, position_result):
        return source[
            "portfolio_display_service"
        ].prime_virtual_portfolio_from_position_result(
            portfolio_data,
            position_result,
            copy_portfolio_standardization_snapshot_fn=source[
                "_copy_portfolio_standardization_snapshot"
            ],
        )

    def _prime_virtual_portfolio_from_cached_positions(
        portfolio_data,
        *,
        user: dict,
        portfolio_name: str,
        position_result=None,
        scope=None,
    ):
        return source[
            "portfolio_display_service"
        ].prime_virtual_portfolio_from_cached_positions(
            portfolio_data,
            user=user,
            portfolio_name=portfolio_name,
            position_result=position_result,
            scope=scope,
            resolve_portfolio_scope_fn=source["resolve_portfolio_scope"],
            peek_position_result_snapshot_fn=source["peek_position_result_snapshot"],
            filter_position_result_fn=source["filter_position_result"],
            load_strategy_cls=source["LoadStrategy"],
            prime_virtual_portfolio_from_position_result_fn=source[
                "_prime_virtual_portfolio_from_position_result"
            ],
        )

    def _rebuild_position_result_for_display(
        *,
        user: dict,
        result,
        consolidate: bool,
    ):
        from services.position_service import PositionService, rebuild_position_result

        service = PositionService(
            user_email=user["email"], user_id=int(user["user_id"])
        )
        return rebuild_position_result(service, result, consolidate=consolidate)

    def _portfolio_display_adapter_dependencies() -> dict[str, Any]:
        return source["portfolio_display_adapters"].build_dependencies(source)

    def _build_virtual_portfolio_display(
        user: dict,
        portfolio_name: str,
        *,
        statement_date: str | None = None,
        portfolio_data=None,
        portfolio_service=None,
    ):
        return source["portfolio_display_adapters"].build_virtual_portfolio_display(
            user,
            portfolio_name,
            statement_date=statement_date,
            portfolio_data=portfolio_data,
            portfolio_service=portfolio_service,
            get_dependencies_fn=source["_portfolio_display_adapter_dependencies"],
        )

    def _build_portfolio_display_data(
        portfolio_data,
        portfolio_name: str,
        user: dict,
        portfolio_service,
    ):
        return source["portfolio_display_adapters"].build_portfolio_display_data(
            portfolio_data,
            portfolio_name,
            user,
            portfolio_service,
            get_dependencies_fn=source["_portfolio_display_adapter_dependencies"],
        )

    def _current_portfolio_has_bootstrap_rows(user_id: int):
        from database import get_db_session, is_db_available

        return source[
            "portfolio_display_adapters"
        ].current_portfolio_has_bootstrap_rows(
            user_id,
            is_db_available_fn=is_db_available,
            get_db_session_fn=get_db_session,
            logger=source["api_logger"],
        )

    def _schedule_dashboard_prewarm(
        *,
        user_id: int,
        portfolio_name: str,
        user_email: str | None = None,
        portfolio_data=None,
        user_tier: str | None = None,
    ) -> None:
        return source["portfolio_display_adapters"].schedule_dashboard_prewarm(
            user_id=user_id,
            portfolio_name=portfolio_name,
            user_email=user_email,
            portfolio_data=portfolio_data,
            user_tier=user_tier,
            get_dependencies_fn=source["_portfolio_display_adapter_dependencies"],
        )

    def _build_full_income_projection_for_prewarm(**kwargs):
        action = source["income_projection_action"]
        return action.format_full_income_projection(
            action.get_income_projection_data(**kwargs)
        )

    def _run_dashboard_prewarm(
        *,
        user_id: int,
        portfolio_name: str,
        user_email: str | None = None,
        portfolio_data=None,
        user_tier: str | None = None,
    ) -> None:
        return source["portfolio_display_adapters"].run_dashboard_prewarm(
            user_id=user_id,
            portfolio_name=portfolio_name,
            user_email=user_email,
            portfolio_data=portfolio_data,
            user_tier=user_tier,
            get_dependencies_fn=source["_portfolio_display_adapter_dependencies"],
        )

    def _schedule_holdings_metadata_prewarm(
        holdings: list[dict[str, Any]] | None,
    ) -> None:
        return source["portfolio_display_adapters"].schedule_holdings_metadata_prewarm(
            holdings,
            get_dependencies_fn=source["_portfolio_display_adapter_dependencies"],
        )

    def _analysis_route_adapter_dependencies() -> dict[str, Any]:
        return source["route_workflow_adapters"].build_analysis_route_dependencies(
            source
        )

    def _run_analyze_workflow(
        portfolio_name: str,
        period: str,
        user: dict,
        portfolio_service,
    ) -> dict[str, Any]:
        return source["route_workflow_adapters"].run_analyze_workflow(
            analysis_routes_module=source["analysis_routes"],
            portfolio_name=portfolio_name,
            period=period,
            user=user,
            portfolio_service=portfolio_service,
            get_dependencies_fn=source["_analysis_route_adapter_dependencies"],
        )

    def _run_risk_score_workflow(
        portfolio_name: str,
        user: dict,
        portfolio_service,
    ) -> dict[str, Any]:
        return source["route_workflow_adapters"].run_risk_score_workflow(
            analysis_routes_module=source["analysis_routes"],
            portfolio_name=portfolio_name,
            user=user,
            portfolio_service=portfolio_service,
            get_dependencies_fn=source["_analysis_route_adapter_dependencies"],
        )

    def _run_performance_workflow(
        benchmark_ticker: str,
        portfolio_name: str,
        user: dict,
        portfolio_service,
        start_date: str | None = None,
        end_date: str | None = None,
        include_attribution: bool = True,
        include_optional_metrics: bool = False,
    ) -> dict[str, Any]:
        return source["route_workflow_adapters"].run_performance_workflow(
            analysis_routes_module=source["analysis_routes"],
            benchmark_ticker=benchmark_ticker,
            portfolio_name=portfolio_name,
            user=user,
            portfolio_service=portfolio_service,
            start_date=start_date,
            end_date=end_date,
            include_attribution=include_attribution,
            include_optional_metrics=include_optional_metrics,
            get_dependencies_fn=source["_analysis_route_adapter_dependencies"],
        )

    source.update(
        {
            "get_user_portfolio_service": get_user_portfolio_service,
            "get_user_scenario_service": get_user_scenario_service,
            "get_user_optimization_service": get_user_optimization_service,
            "_performance_cache_scope": _performance_cache_scope,
            "_allocation_adapter_dependencies": _allocation_adapter_dependencies,
            "preview_rebalance_trades": preview_rebalance_trades,
            "_optimization_action_dependencies": _optimization_action_dependencies,
            "_optimization_route_adapter_dependencies": (
                _optimization_route_adapter_dependencies
            ),
            "_resolve_direct_dates": _resolve_direct_dates,
            "_build_analyze_result": _build_analyze_result,
            "_run_what_if_workflow": _run_what_if_workflow,
            "_build_cached_rebalance_risk_snapshot": (
                _build_cached_rebalance_risk_snapshot
            ),
            "_run_stress_test_workflow": _run_stress_test_workflow,
            "_run_stress_test_run_all_workflow": _run_stress_test_run_all_workflow,
            "_run_monte_carlo_workflow": _run_monte_carlo_workflow,
            "_run_backtest_workflow": _run_backtest_workflow,
            "_run_min_variance_workflow": _run_min_variance_workflow,
            "_run_max_return_workflow": _run_max_return_workflow,
            "_run_max_sharpe_workflow": _run_max_sharpe_workflow,
            "_run_target_volatility_workflow": _run_target_volatility_workflow,
            "_run_efficient_frontier_workflow": _run_efficient_frontier_workflow,
            "enrich_holdings_with_metadata": enrich_holdings_with_metadata,
            "transform_portfolio_for_display": transform_portfolio_for_display,
            "_transform_positions_payload_for_display": (
                _transform_positions_payload_for_display
            ),
            "_transform_position_result_for_display": (
                _transform_position_result_for_display
            ),
            "_copy_portfolio_standardization_snapshot": (
                _copy_portfolio_standardization_snapshot
            ),
            "_prime_virtual_portfolio_from_position_result": (
                _prime_virtual_portfolio_from_position_result
            ),
            "_prime_virtual_portfolio_from_cached_positions": (
                _prime_virtual_portfolio_from_cached_positions
            ),
            "_rebuild_position_result_for_display": (
                _rebuild_position_result_for_display
            ),
            "_portfolio_display_adapter_dependencies": (
                _portfolio_display_adapter_dependencies
            ),
            "_build_virtual_portfolio_display": _build_virtual_portfolio_display,
            "_build_portfolio_display_data": _build_portfolio_display_data,
            "_current_portfolio_has_bootstrap_rows": (
                _current_portfolio_has_bootstrap_rows
            ),
            "_BOOTSTRAP_PREWARM_EXECUTOR": ThreadPoolExecutor(
                max_workers=max(
                    2,
                    int(os.getenv("BOOTSTRAP_PREWARM_WORKERS", "4")),
                )
            ),
            "_schedule_dashboard_prewarm": _schedule_dashboard_prewarm,
            "_build_full_income_projection_for_prewarm": (
                _build_full_income_projection_for_prewarm
            ),
            "_run_dashboard_prewarm": _run_dashboard_prewarm,
            "_schedule_holdings_metadata_prewarm": (
                _schedule_holdings_metadata_prewarm
            ),
            "_analysis_route_adapter_dependencies": (
                _analysis_route_adapter_dependencies
            ),
            "_run_analyze_workflow": _run_analyze_workflow,
            "_run_risk_score_workflow": _run_risk_score_workflow,
            "_run_performance_workflow": _run_performance_workflow,
            "_run_interpret_workflow": analysis_routes.run_interpret_workflow,
            "_run_portfolio_analysis_workflow": (
                analysis_routes.run_portfolio_analysis_workflow
            ),
        }
    )


__all__ = ["install_compatibility_wrappers"]
