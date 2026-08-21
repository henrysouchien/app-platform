from __future__ import annotations

from types import SimpleNamespace

import app_platform.route_workflow_adapters as adapters


def test_build_analysis_route_dependencies_reads_source_mapping() -> None:
    source = {
        "get_portfolio_snapshot": "portfolio-snapshot",
        "_prime_virtual_portfolio_from_cached_positions": "prime-virtual",
        "get_factor_proxies_snapshot": "factor-proxies",
        "get_risk_limits_snapshot": "risk-limits",
        "get_analysis_result_snapshot": "analysis-snapshot",
        "get_risk_score_result_snapshot": "risk-score-snapshot",
        "get_performance_result_snapshot": "performance-snapshot",
        "_performance_cache_scope": "cache-scope",
        "TIER_ORDER": {"paid": 2},
    }

    dependencies = adapters.build_analysis_route_dependencies(source)

    assert dependencies["get_portfolio_snapshot_fn"] == "portfolio-snapshot"
    assert dependencies["prime_virtual_portfolio_fn"] == "prime-virtual"
    assert dependencies["get_factor_proxies_snapshot_fn"] == "factor-proxies"
    assert dependencies["get_risk_limits_snapshot_fn"] == "risk-limits"
    assert dependencies["get_analysis_result_snapshot_fn"] == "analysis-snapshot"
    assert dependencies["get_risk_score_result_snapshot_fn"] == "risk-score-snapshot"
    assert dependencies["get_performance_result_snapshot_fn"] == "performance-snapshot"
    assert dependencies["performance_cache_scope_fn"] == "cache-scope"
    assert dependencies["tier_order"] == {"paid": 2}
    assert callable(dependencies["workflow_timer_fn"])


def test_build_optimization_dependencies_read_source_mapping() -> None:
    risk_limits_module = SimpleNamespace(RiskLimitsManager="risk-limits-manager")
    returns_module = SimpleNamespace(ReturnsService="returns-service")
    factor_proxy_module = SimpleNamespace(ensure_factor_proxies="ensure-proxies")
    source = {
        "PortfolioManager": "portfolio-manager",
        "risk_limits_manager_module": risk_limits_module,
        "returns_service_module": returns_module,
        "factor_proxy_service_module": factor_proxy_module,
        "portfolio_logger": "logger",
        "run_min_variance_optimization": "min-var",
        "run_max_return_optimization": "max-return",
        "run_max_sharpe_optimization": "max-sharpe",
        "run_target_volatility_optimization": "target-vol",
        "run_efficient_frontier_optimization": "frontier",
        "_optimization_action_dependencies": "action-deps",
    }

    action_dependencies = adapters.build_optimization_action_dependencies(source)
    route_dependencies = adapters.build_optimization_route_dependencies(source)

    assert action_dependencies == {
        "portfolio_manager_cls": "portfolio-manager",
        "risk_limits_manager_cls": "risk-limits-manager",
        "returns_service_cls": "returns-service",
        "ensure_factor_proxies_fn": "ensure-proxies",
        "warning_logger": "logger",
    }
    assert route_dependencies["run_min_variance_optimization_fn"] == "min-var"
    assert route_dependencies["run_max_return_optimization_fn"] == "max-return"
    assert route_dependencies["run_max_sharpe_optimization_fn"] == "max-sharpe"
    assert route_dependencies["run_target_volatility_optimization_fn"] == "target-vol"
    assert route_dependencies["run_efficient_frontier_optimization_fn"] == "frontier"
    assert route_dependencies["action_dependencies_fn"] == "action-deps"
    assert route_dependencies["raise_expected_returns_http_fn"] is (
        adapters.raise_optimization_expected_returns_http
    )
    assert (
        route_dependencies["raise_run_http_fn"] is adapters.raise_optimization_run_http
    )
    assert route_dependencies["raise_constraint_http_fn"] is (
        adapters.raise_optimization_constraint_http
    )


def test_run_analyze_workflow_forwards_late_bound_dependencies() -> None:
    captured: dict[str, object] = {}
    dependencies = {
        "get_portfolio_snapshot_fn": "portfolio-snapshot",
        "prime_virtual_portfolio_fn": "prime-virtual",
        "get_factor_proxies_snapshot_fn": "factor-proxies",
        "get_risk_limits_snapshot_fn": "risk-limits",
        "get_analysis_result_snapshot_fn": "analysis-snapshot",
        "tier_order": {"paid": 2},
        "workflow_timer_fn": "workflow-timer",
    }

    def _run_analyze_workflow(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"source": "analyze"}

    result = adapters.run_analyze_workflow(
        analysis_routes_module=SimpleNamespace(
            run_analyze_workflow=_run_analyze_workflow,
        ),
        portfolio_name="Core",
        period="3M",
        user={"user_id": 7},
        portfolio_service="portfolio-service",
        get_dependencies_fn=lambda: dependencies,
    )

    assert result == {"source": "analyze"}
    assert captured["args"] == ("Core", "3M", {"user_id": 7}, "portfolio-service")
    assert captured["kwargs"] == {
        "get_portfolio_snapshot_fn": "portfolio-snapshot",
        "prime_virtual_portfolio_fn": "prime-virtual",
        "get_factor_proxies_snapshot_fn": "factor-proxies",
        "get_risk_limits_snapshot_fn": "risk-limits",
        "get_analysis_result_snapshot_fn": "analysis-snapshot",
        "tier_order": {"paid": 2},
        "workflow_timer_fn": "workflow-timer",
    }


def test_run_risk_score_workflow_forwards_late_bound_dependencies() -> None:
    captured: dict[str, object] = {}
    dependencies = {
        "get_portfolio_snapshot_fn": "portfolio-snapshot",
        "prime_virtual_portfolio_fn": "prime-virtual",
        "get_factor_proxies_snapshot_fn": "factor-proxies",
        "get_risk_limits_snapshot_fn": "risk-limits",
        "get_analysis_result_snapshot_fn": "analysis-snapshot",
        "get_risk_score_result_snapshot_fn": "risk-score-snapshot",
        "workflow_timer_fn": "workflow-timer",
    }

    def _run_risk_score_workflow(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"source": "risk-score"}

    result = adapters.run_risk_score_workflow(
        analysis_routes_module=SimpleNamespace(
            run_risk_score_workflow=_run_risk_score_workflow,
        ),
        portfolio_name="Core",
        user={"user_id": 7},
        portfolio_service="portfolio-service",
        get_dependencies_fn=lambda: dependencies,
    )

    assert result == {"source": "risk-score"}
    assert captured["args"] == ("Core", {"user_id": 7}, "portfolio-service")
    assert captured["kwargs"] == {
        "get_portfolio_snapshot_fn": "portfolio-snapshot",
        "prime_virtual_portfolio_fn": "prime-virtual",
        "get_factor_proxies_snapshot_fn": "factor-proxies",
        "get_risk_limits_snapshot_fn": "risk-limits",
        "get_analysis_result_snapshot_fn": "analysis-snapshot",
        "get_risk_score_result_snapshot_fn": "risk-score-snapshot",
        "workflow_timer_fn": "workflow-timer",
    }


def test_run_performance_workflow_forwards_late_bound_dependencies() -> None:
    captured: dict[str, object] = {}
    dependencies = {
        "get_portfolio_snapshot_fn": "portfolio-snapshot",
        "prime_virtual_portfolio_fn": "prime-virtual",
        "get_performance_result_snapshot_fn": "performance-snapshot",
        "performance_cache_scope_fn": "cache-scope",
        "workflow_timer_fn": "workflow-timer",
    }

    def _run_performance_workflow(*args, **kwargs):
        captured["args"] = args
        captured["kwargs"] = kwargs
        return {"source": "performance"}

    result = adapters.run_performance_workflow(
        analysis_routes_module=SimpleNamespace(
            run_performance_workflow=_run_performance_workflow,
        ),
        benchmark_ticker="SPY",
        portfolio_name="Core",
        user={"user_id": 7},
        portfolio_service="portfolio-service",
        start_date="2024-01-01",
        end_date="2024-12-31",
        include_attribution=False,
        include_optional_metrics=True,
        get_dependencies_fn=lambda: dependencies,
    )

    assert result == {"source": "performance"}
    assert captured["args"] == (
        "SPY",
        "Core",
        {"user_id": 7},
        "portfolio-service",
        "2024-01-01",
        "2024-12-31",
        False,
        True,
    )
    assert captured["kwargs"] == {
        "get_portfolio_snapshot_fn": "portfolio-snapshot",
        "prime_virtual_portfolio_fn": "prime-virtual",
        "get_performance_result_snapshot_fn": "performance-snapshot",
        "performance_cache_scope_fn": "cache-scope",
        "workflow_timer_fn": "workflow-timer",
    }
