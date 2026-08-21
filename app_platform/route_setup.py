"""FastAPI router registration for the main application."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Callable

from fastapi import FastAPI


@dataclass(frozen=True)
class RouteSetupDependencies:
    valid_keys: Any
    tier_map: dict[str, Any]
    log_dir: str
    get_current_user_dependency: Any
    require_paid_user_dependency: Any
    get_api_key_dependency: Any
    limiter: Any
    get_user_portfolio_service_fn: Callable[..., Any]
    get_user_scenario_service_fn: Callable[..., Any]
    get_user_optimization_service_fn: Callable[..., Any]
    get_portfolio_manager_cls_fn: Callable[[], Any]
    get_current_portfolio_has_bootstrap_rows_fn: Callable[[], Callable[..., Any]]
    get_portfolio_snapshot_fn: Callable[[], Callable[..., Any]]
    prime_virtual_portfolio_fn: Callable[..., Any]
    get_prewarm_factor_proxies_snapshot_fn: Callable[[], Callable[..., Any]]
    get_build_portfolio_display_data_fn: Callable[[], Callable[..., Any]]
    get_schedule_dashboard_prewarm_fn: Callable[[], Callable[..., Any]]
    get_schedule_holdings_metadata_prewarm_fn: Callable[[], Callable[..., Any]]
    get_enrich_holdings_with_metadata_fn: Callable[[], Callable[..., Any]]
    get_ensure_factor_proxies_fn: Callable[[], Callable[..., Any]]
    get_tier_order_fn: Callable[[], dict[str, Any]]
    get_log_request_fn: Callable[[], Callable[..., Any]]
    get_direct_log_error_fn: Callable[[], Callable[..., Any]]
    get_log_error_fn: Callable[[], Callable[..., Any]]
    get_api_logger_fn: Callable[[], Any]
    workflow_timer_fn: Callable[..., Any]
    resolve_direct_dates_fn: Callable[..., Any]
    get_stock_service_fn: Callable[[], Any]
    get_direct_optimization_service_fn: Callable[[], Any]
    get_direct_portfolio_service_fn: Callable[[], Any]
    get_resolve_user_id_fn: Callable[[], Callable[..., Any]]
    get_portfolio_repository_cls_fn: Callable[[], Any]
    get_allocation_presets_fn: Callable[[], Callable[..., Any]]
    get_validate_allocations_fn: Callable[[], Callable[..., Any]]
    get_build_cached_rebalance_risk_snapshot_fn: Callable[[], Callable[..., Any]]
    get_preview_rebalance_trades_fn: Callable[[], Callable[..., Any]]
    get_load_strategy_templates_fn: Callable[[], Callable[..., Any]]
    run_allocation_in_threadpool_fn: Callable[..., Any]
    to_thread_fn: Callable[..., Any]
    get_factor_proxies_snapshot_fn: Callable[..., Any]
    get_risk_limits_snapshot_fn: Callable[..., Any]
    get_analysis_result_snapshot_fn: Callable[..., Any]
    get_performance_result_snapshot_fn: Callable[..., Any]
    get_risk_score_result_snapshot_fn: Callable[..., Any]
    performance_cache_scope_fn: Callable[..., Any]
    tier_order: dict[str, Any]
    run_analyze_workflow_fn: Callable[..., Any]
    run_risk_score_workflow_fn: Callable[..., Any]
    run_performance_workflow_fn: Callable[..., Any]
    run_interpret_workflow_fn: Callable[..., Any]
    run_portfolio_analysis_workflow_fn: Callable[..., Any]
    get_run_what_if_workflow_fn: Callable[[], Callable[..., Any]]
    get_run_stress_test_workflow_fn: Callable[[], Callable[..., Any]]
    get_run_stress_test_run_all_workflow_fn: Callable[[], Callable[..., Any]]
    get_run_monte_carlo_workflow_fn: Callable[[], Callable[..., Any]]
    get_run_backtest_workflow_fn: Callable[[], Callable[..., Any]]
    run_scenario_in_threadpool_fn: Callable[..., Any]
    get_run_min_variance_workflow_fn: Callable[[], Callable[..., Any]]
    get_run_max_return_workflow_fn: Callable[[], Callable[..., Any]]
    get_run_max_sharpe_workflow_fn: Callable[[], Callable[..., Any]]
    get_run_target_volatility_workflow_fn: Callable[[], Callable[..., Any]]
    get_run_efficient_frontier_workflow_fn: Callable[[], Callable[..., Any]]
    run_optimization_in_threadpool_fn: Callable[..., Any]
    clear_portfolio_cache_func: Callable[..., Any]
    cache_status_func: Callable[..., Any]
    send_key_to_kartra_thread_func: Callable[..., Any]
    get_environment_fn: Callable[[], str] = lambda: os.getenv(
        "ENVIRONMENT", "development"
    )


def configure_routes(app: FastAPI, dependencies: RouteSetupDependencies) -> None:
    """Register all application routers with injected app-level dependencies."""

    from routes import allocations as allocation_routes
    from routes import analysis as analysis_routes
    from routes import direct_analysis as direct_analysis_routes
    from routes import optimization as optimization_routes
    from routes import scenarios as scenario_routes
    from routes.admin import admin_router, create_admin_routes
    from routes.admin_api_budget import admin_api_budget_router
    from routes.agent_api import router as agent_api_router
    from routes.ai_providers import ai_providers_router
    from routes.anthropic_credential import anthropic_credential_router
    from routes.user_data_export import user_data_export_router
    from routes.user_consents import user_consents_router
    from routes.artifacts_proxy import router as artifacts_proxy_router
    from routes.auth import auth_router
    from routes.baskets_api import baskets_router
    from routes.billing import billing_router
    from app_platform.commercial.flags import CommercialFlags
    from routes.connector_tokens import connector_tokens_router
    from routes.commercial_usage_ingest import commercial_usage_ingest_router
    from routes.commercial_authority import commercial_authority_router
    from routes.commercial_usage_reconciliation_ingest import (
        commercial_usage_reconciliation_ingest_router,
    )
    from routes.dashboard_artifacts_proxy import (
        router as dashboard_artifacts_proxy_router,
    )
    from routes.data_providers import data_providers_router
    from routes.debug import debug_router
    from routes.dev_monitor import dev_monitor_router
    from routes.factor_intelligence import (
        factor_groups_router,
        factor_intelligence_router,
    )
    from routes.frontend_logging import frontend_logging_router
    from routes.gateway_proxy import gateway_proxy_router
    from routes.google_sheets_broker import google_sheets_broker_router
    from routes.google_sheets_oauth import google_sheets_oauth_router
    from routes.health import health_router
    from routes.hedge_monitor_api import hedge_monitor_router
    from routes.hedging import hedging_router
    from routes.canvas_artifacts_proxy import router as canvas_artifacts_proxy_router
    from routes.html_artifacts_proxy import router as html_artifacts_proxy_router
    from routes.ui_blocks_proxy import router as ui_blocks_proxy_router
    from routes.income import income_router
    from routes.invite_trials import create_invite_trial_router
    from app_platform.commercial.invite_trial_runtime import (
        build_invite_trial_runtime,
    )
    from routes.mcp_token_portal import create_mcp_token_portal_router
    from app_platform.commercial.mcp_token_portal_runtime import (
        build_mcp_token_portal_runtime,
    )
    from routes.internal_resolver import internal_resolver_router
    from routes.onboarding import onboarding_router
    from routes.overview import overview_router
    from routes.plaid import plaid_router
    from routes.positions import positions_router
    from routes.portfolios import create_legacy_portfolio_router, portfolios_router
    from routes.presentation_packs import presentation_packs_router
    from routes.provider_routing_api import router as provider_routing_router
    from routes.realized_performance import realized_performance_router
    from routes.research_content import research_content_router
    from routes.risk_settings import create_risk_settings_router
    from routes.schwab import schwab_router
    from routes.snaptrade import snaptrade_router
    from routes.sync_jobs import sync_jobs_router
    from routes.tax_harvest import tax_harvest_router
    from routes.trading import trading_router

    app.include_router(auth_router)
    app.include_router(google_sheets_oauth_router)
    app.include_router(dev_monitor_router)
    app.include_router(frontend_logging_router)
    app.include_router(health_router)
    app.include_router(plaid_router)
    app.include_router(schwab_router)
    app.include_router(snaptrade_router)
    app.include_router(onboarding_router)
    app.include_router(sync_jobs_router)
    app.include_router(provider_routing_router)
    app.include_router(ai_providers_router)
    app.include_router(data_providers_router)
    app.include_router(factor_intelligence_router)
    app.include_router(factor_groups_router)
    app.include_router(positions_router)
    app.include_router(overview_router)
    app.include_router(gateway_proxy_router, prefix="/api/gateway")
    app.include_router(anthropic_credential_router)
    app.include_router(user_data_export_router)
    app.include_router(user_consents_router)
    app.include_router(connector_tokens_router)
    mcp_token_portal_runtime = build_mcp_token_portal_runtime()
    if mcp_token_portal_runtime is not None:
        app.include_router(create_mcp_token_portal_router(
            runtime=mcp_token_portal_runtime,
            get_current_user_dependency=dependencies.get_current_user_dependency,
        ))
    invite_trial_runtime = build_invite_trial_runtime()
    if invite_trial_runtime is not None:
        app.include_router(create_invite_trial_router(
            runtime=invite_trial_runtime,
            get_current_user_dependency=dependencies.get_current_user_dependency,
        ))
    app.include_router(commercial_usage_ingest_router)
    app.include_router(commercial_authority_router)
    app.include_router(commercial_usage_reconciliation_ingest_router)
    app.include_router(internal_resolver_router)
    app.include_router(google_sheets_broker_router)
    app.include_router(artifacts_proxy_router)
    app.include_router(canvas_artifacts_proxy_router)
    app.include_router(html_artifacts_proxy_router)
    app.include_router(ui_blocks_proxy_router)
    app.include_router(dashboard_artifacts_proxy_router)
    app.include_router(research_content_router)
    app.include_router(presentation_packs_router)
    app.include_router(agent_api_router, prefix="/api/agent", tags=["agent"])
    app.include_router(hedging_router)
    app.include_router(baskets_router)
    app.include_router(billing_router)
    commercial_flags = CommercialFlags.from_env()
    if commercial_flags.customer_billing_portal_enabled:
        from app_platform.commercial.billing.customer_portal_runtime import (
            build_customer_portal_runtime,
        )
        from routes.customer_billing import create_customer_billing_router

        customer_portal_runtime = build_customer_portal_runtime()
        if customer_portal_runtime is not None:
            app.include_router(create_customer_billing_router(
                **customer_portal_runtime,
                get_current_user_dependency=dependencies.get_current_user_dependency,
            ))
    if commercial_flags.self_serve_checkout_enabled:
        from app_platform.commercial.billing.checkout_runtime import (
            build_checkout_orchestrator,
        )
        from routes.checkout import create_checkout_router

        checkout_orchestrator = build_checkout_orchestrator()
        if checkout_orchestrator is not None:
            app.include_router(create_checkout_router(
                orchestrator=checkout_orchestrator,
                get_current_user_dependency=dependencies.get_current_user_dependency,
            ))
    app.include_router(hedge_monitor_router)
    app.include_router(realized_performance_router)
    app.include_router(portfolios_router)
    app.include_router(
        create_legacy_portfolio_router(
            get_current_user_dependency=dependencies.get_current_user_dependency,
            require_paid_user_dependency=dependencies.require_paid_user_dependency,
            get_user_portfolio_service_fn=dependencies.get_user_portfolio_service_fn,
            get_portfolio_manager_cls_fn=dependencies.get_portfolio_manager_cls_fn,
            get_current_portfolio_has_bootstrap_rows_fn=(
                dependencies.get_current_portfolio_has_bootstrap_rows_fn
            ),
            get_portfolio_snapshot_fn=dependencies.get_portfolio_snapshot_fn,
            get_prewarm_factor_proxies_snapshot_fn=(
                dependencies.get_prewarm_factor_proxies_snapshot_fn
            ),
            get_build_portfolio_display_data_fn=(
                dependencies.get_build_portfolio_display_data_fn
            ),
            get_schedule_dashboard_prewarm_fn=(
                dependencies.get_schedule_dashboard_prewarm_fn
            ),
            get_schedule_holdings_metadata_prewarm_fn=(
                dependencies.get_schedule_holdings_metadata_prewarm_fn
            ),
            get_enrich_holdings_with_metadata_fn=(
                dependencies.get_enrich_holdings_with_metadata_fn
            ),
            get_ensure_factor_proxies_fn=dependencies.get_ensure_factor_proxies_fn,
            get_tier_order_fn=dependencies.get_tier_order_fn,
            get_log_error_fn=dependencies.get_log_error_fn,
            workflow_timer_fn=dependencies.workflow_timer_fn,
        )
    )
    app.include_router(trading_router)
    app.include_router(income_router)
    app.include_router(
        direct_analysis_routes.create_direct_analysis_router(
            get_api_key_dependency=dependencies.get_api_key_dependency,
            limiter=dependencies.limiter,
            get_stock_service_fn=dependencies.get_stock_service_fn,
            get_direct_optimization_service_fn=(
                dependencies.get_direct_optimization_service_fn
            ),
            get_direct_portfolio_service_fn=(
                dependencies.get_direct_portfolio_service_fn
            ),
            get_log_request_fn=dependencies.get_log_request_fn,
            get_log_error_fn=dependencies.get_direct_log_error_fn,
            get_api_logger_fn=dependencies.get_api_logger_fn,
            resolve_direct_dates_fn=dependencies.resolve_direct_dates_fn,
        )
    )
    app.include_router(
        allocation_routes.create_allocations_router(
            get_current_user_dependency=dependencies.get_current_user_dependency,
            get_api_key_dependency=dependencies.get_api_key_dependency,
            limiter=dependencies.limiter,
            get_resolve_user_id_fn=dependencies.get_resolve_user_id_fn,
            get_portfolio_repository_cls_fn=dependencies.get_portfolio_repository_cls_fn,
            get_allocation_presets_fn=dependencies.get_allocation_presets_fn,
            get_validate_allocations_fn=dependencies.get_validate_allocations_fn,
            get_build_cached_rebalance_risk_snapshot_fn=(
                dependencies.get_build_cached_rebalance_risk_snapshot_fn
            ),
            get_preview_rebalance_trades_fn=(
                dependencies.get_preview_rebalance_trades_fn
            ),
            get_load_strategy_templates_fn=dependencies.get_load_strategy_templates_fn,
            run_in_threadpool_fn=dependencies.run_allocation_in_threadpool_fn,
            to_thread_fn=dependencies.to_thread_fn,
        )
    )
    app.include_router(
        analysis_routes.create_analysis_router(
            get_current_user_dependency=dependencies.get_current_user_dependency,
            require_paid_user_dependency=dependencies.require_paid_user_dependency,
            get_api_key_dependency=dependencies.get_api_key_dependency,
            get_user_portfolio_service_fn=dependencies.get_user_portfolio_service_fn,
            limiter=dependencies.limiter,
            get_portfolio_snapshot_fn=dependencies.get_portfolio_snapshot_fn,
            prime_virtual_portfolio_fn=dependencies.prime_virtual_portfolio_fn,
            get_factor_proxies_snapshot_fn=dependencies.get_factor_proxies_snapshot_fn,
            get_risk_limits_snapshot_fn=dependencies.get_risk_limits_snapshot_fn,
            get_analysis_result_snapshot_fn=dependencies.get_analysis_result_snapshot_fn,
            get_performance_result_snapshot_fn=(
                dependencies.get_performance_result_snapshot_fn
            ),
            get_risk_score_result_snapshot_fn=dependencies.get_risk_score_result_snapshot_fn,
            performance_cache_scope_fn=dependencies.performance_cache_scope_fn,
            tier_order=dependencies.tier_order,
            workflow_timer_fn=dependencies.workflow_timer_fn,
            run_analyze_workflow_fn=dependencies.run_analyze_workflow_fn,
            run_risk_score_workflow_fn=dependencies.run_risk_score_workflow_fn,
            run_performance_workflow_fn=dependencies.run_performance_workflow_fn,
            run_interpret_workflow_fn=dependencies.run_interpret_workflow_fn,
            run_portfolio_analysis_workflow_fn=(
                dependencies.run_portfolio_analysis_workflow_fn
            ),
        )
    )
    app.include_router(
        scenario_routes.create_scenarios_router(
            get_current_user_dependency=dependencies.get_current_user_dependency,
            get_api_key_dependency=dependencies.get_api_key_dependency,
            get_user_scenario_service_fn=dependencies.get_user_scenario_service_fn,
            limiter=dependencies.limiter,
            get_run_what_if_workflow_fn=dependencies.get_run_what_if_workflow_fn,
            get_run_stress_test_workflow_fn=(
                dependencies.get_run_stress_test_workflow_fn
            ),
            get_run_stress_test_run_all_workflow_fn=(
                dependencies.get_run_stress_test_run_all_workflow_fn
            ),
            get_run_monte_carlo_workflow_fn=dependencies.get_run_monte_carlo_workflow_fn,
            get_run_backtest_workflow_fn=dependencies.get_run_backtest_workflow_fn,
            run_in_threadpool_fn=dependencies.run_scenario_in_threadpool_fn,
        )
    )
    app.include_router(
        optimization_routes.create_optimization_router(
            get_current_user_dependency=dependencies.get_current_user_dependency,
            get_api_key_dependency=dependencies.get_api_key_dependency,
            get_user_optimization_service_fn=(
                dependencies.get_user_optimization_service_fn
            ),
            limiter=dependencies.limiter,
            get_run_min_variance_workflow_fn=(
                dependencies.get_run_min_variance_workflow_fn
            ),
            get_run_max_return_workflow_fn=dependencies.get_run_max_return_workflow_fn,
            get_run_max_sharpe_workflow_fn=dependencies.get_run_max_sharpe_workflow_fn,
            get_run_target_volatility_workflow_fn=(
                dependencies.get_run_target_volatility_workflow_fn
            ),
            get_run_efficient_frontier_workflow_fn=(
                dependencies.get_run_efficient_frontier_workflow_fn
            ),
            run_in_threadpool_fn=dependencies.run_optimization_in_threadpool_fn,
        )
    )
    app.include_router(
        create_risk_settings_router(dependencies.get_current_user_dependency)
    )
    app.include_router(tax_harvest_router)
    if dependencies.get_environment_fn() != "production":
        app.include_router(debug_router)

    create_admin_routes(
        valid_keys=dependencies.valid_keys,
        tier_map=dependencies.tier_map,
        log_dir=dependencies.log_dir,
        clear_portfolio_cache_func=dependencies.clear_portfolio_cache_func,
        cache_status_func=dependencies.cache_status_func,
        send_key_to_kartra_thread_func=(dependencies.send_key_to_kartra_thread_func),
    )
    app.include_router(admin_router)
    app.include_router(admin_api_budget_router)


__all__ = ["RouteSetupDependencies", "configure_routes"]
