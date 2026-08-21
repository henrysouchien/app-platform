from __future__ import annotations

from contextlib import contextmanager
from types import SimpleNamespace

import pandas as pd

import app_platform.portfolio_display_adapters as adapters
from core.result_objects import PositionResult
from services.position_service import rebuild_position_result


def test_build_dependencies_reads_source_mapping() -> None:
    names = [
        "resolve_portfolio_scope",
        "LoadStrategy",
        "peek_position_result_snapshot",
        "wait_for_position_result_snapshot",
        "get_position_result_snapshot",
        "filter_position_result",
        "_rebuild_position_result_for_display",
        "_transform_position_result_for_display",
        "transform_portfolio_for_display",
        "_build_virtual_portfolio_display",
        "portfolio_prewarm_service",
        "_BOOTSTRAP_PREWARM_EXECUTOR",
        "_run_dashboard_prewarm",
        "api_logger",
        "prewarm_position_result_snapshot",
        "prewarm_realized_performance_payload",
        "prewarm_realized_performance_returns_dataframe",
        "prewarm_realized_performance_attribution",
        "prewarm_income_projection_result_snapshot",
        "_build_full_income_projection_for_prewarm",
        "get_portfolio_snapshot",
        "get_factor_proxies_snapshot",
        "get_risk_limits_snapshot",
        "PortfolioService",
        "TIER_ORDER",
        "_prime_virtual_portfolio_from_cached_positions",
        "prewarm_analysis_result_snapshot",
        "_build_analyze_result",
        "get_analysis_result_snapshot",
        "prewarm_risk_score_result_snapshot",
        "prewarm_performance_result_snapshot",
        "_performance_cache_scope",
    ]
    source = {name: name for name in names}

    dependencies = adapters.build_dependencies(source)

    assert dependencies["resolve_portfolio_scope_fn"] == "resolve_portfolio_scope"
    assert dependencies["load_strategy_cls"] == "LoadStrategy"
    assert dependencies["bootstrap_prewarm_executor"] == "_BOOTSTRAP_PREWARM_EXECUTOR"
    assert dependencies["portfolio_service_factory"] == "PortfolioService"
    assert dependencies["performance_cache_scope_fn"] == "_performance_cache_scope"


class _Cursor:
    def __init__(self, rows):
        self._rows = list(rows)
        self.statements = []

    def execute(self, statement, params):
        self.statements.append((statement, params))

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None


class _Connection:
    def __init__(self, rows):
        self.cursor_obj = _Cursor(rows)

    def cursor(self):
        return self.cursor_obj


def test_current_portfolio_bootstrap_rows_detects_positions() -> None:
    connection = _Connection([{"id": 10}, {"exists": 1}])

    @contextmanager
    def _session():
        yield connection

    result = adapters.current_portfolio_has_bootstrap_rows(
        7,
        is_db_available_fn=lambda: True,
        get_db_session_fn=_session,
        logger=SimpleNamespace(debug=lambda *args, **kwargs: None),
    )

    assert result is True
    assert connection.cursor_obj.statements[0][1] == (7, "CURRENT_PORTFOLIO")
    assert connection.cursor_obj.statements[1][1] == (10,)


def test_build_virtual_portfolio_display_uses_stale_snapshot_before_fallback() -> None:
    scope = SimpleNamespace(strategy="PHYSICAL", account_filters=[])
    snapshot = SimpleNamespace(data=SimpleNamespace(positions=[{"ticker": "AAPL"}]))
    calls = []
    dependencies = {
        "load_strategy_cls": SimpleNamespace(VIRTUAL_FILTERED="VIRTUAL_FILTERED"),
        "resolve_portfolio_scope_fn": lambda user_id, portfolio: scope,
        "peek_position_result_snapshot_fn": lambda **kwargs: (
            calls.append(kwargs) or snapshot
        ),
        "wait_for_position_result_snapshot_fn": lambda **kwargs: None,
        "get_position_result_snapshot_fn": lambda **kwargs: (_ for _ in ()).throw(
            AssertionError("cold snapshot should not be loaded")
        ),
        "filter_position_result_fn": lambda result, filters: result,
        "rebuild_position_result_fn": lambda **kwargs: kwargs["result"],
        "transform_position_result_for_display_fn": (
            lambda result, **kwargs: {"source": "snapshot", "result": result}
        ),
        "transform_portfolio_for_display_fn": lambda *args, **kwargs: (
            _ for _ in ()
        ).throw(AssertionError("fallback should not run")),
    }

    result = adapters.build_virtual_portfolio_display(
        {"user_id": 7, "email": "user@example.com"},
        "CURRENT_PORTFOLIO",
        get_dependencies_fn=lambda: dependencies,
    )

    assert result == {"source": "snapshot", "result": snapshot}
    assert calls[0]["allow_stale_cache"] is True
    assert calls[0]["reprice_cached_positions"] is True


def test_virtual_display_rebuild_preserves_provider_freshness() -> None:
    scope = SimpleNamespace(strategy="VIRTUAL_FILTERED", account_filters=["acct-1"])
    snapshot = PositionResult.from_dataframe(
        pd.DataFrame(
            [
                {
                    "ticker": "AAPL",
                    "quantity": 1.0,
                    "value": 100.0,
                    "currency": "USD",
                    "type": "equity",
                    "instrument_type": "equity",
                    "position_source": "ibkr",
                }
            ]
        ),
        user_email="user@example.com",
        consolidated=False,
    )
    snapshot._provider_freshness = {
        "ibkr": {"status": "degraded", "last_error": "delayed sync"}
    }
    snapshot.provider_freshness = snapshot._provider_freshness

    class _PositionService:
        def _consolidate_cross_provider(self, frame):
            return frame

    dependencies = {
        "load_strategy_cls": SimpleNamespace(VIRTUAL_FILTERED="VIRTUAL_FILTERED"),
        "resolve_portfolio_scope_fn": lambda user_id, portfolio: scope,
        "peek_position_result_snapshot_fn": lambda **kwargs: snapshot,
        "wait_for_position_result_snapshot_fn": lambda **kwargs: None,
        "get_position_result_snapshot_fn": lambda **kwargs: snapshot,
        "filter_position_result_fn": lambda result, filters: result,
        "rebuild_position_result_fn": lambda **kwargs: rebuild_position_result(
            _PositionService(),
            kwargs["result"],
            consolidate=kwargs["consolidate"],
        ),
        "transform_position_result_for_display_fn": lambda result, **kwargs: result,
        "transform_portfolio_for_display_fn": lambda *args, **kwargs: None,
    }

    rebuilt = adapters.build_virtual_portfolio_display(
        {"user_id": 7, "email": "user@example.com"},
        "Filtered",
        get_dependencies_fn=lambda: dependencies,
    )

    assert rebuilt._provider_freshness == snapshot._provider_freshness
    assert rebuilt.provider_freshness == snapshot._provider_freshness


def test_build_portfolio_display_data_uses_late_bound_virtual_builder() -> None:
    scope = SimpleNamespace(strategy="VIRTUAL_FILTERED", account_filters=[])
    dependencies = {
        "load_strategy_cls": SimpleNamespace(PHYSICAL="PHYSICAL"),
        "resolve_portfolio_scope_fn": lambda user_id, portfolio: scope,
        "build_virtual_portfolio_display_fn": lambda *args, **kwargs: {
            "source": "virtual",
            "portfolio": args[1],
        },
        "transform_portfolio_for_display_fn": lambda *args, **kwargs: {
            "source": "physical"
        },
    }
    portfolio_data = SimpleNamespace(_last_updated=None)

    result = adapters.build_portfolio_display_data(
        portfolio_data,
        "Virtual",
        {"user_id": 7},
        object(),
        get_dependencies_fn=lambda: dependencies,
    )

    assert result == {"source": "virtual", "portfolio": "Virtual"}


def test_prewarm_adapters_forward_late_bound_dependencies() -> None:
    calls = []
    service = SimpleNamespace(
        schedule_dashboard_prewarm=lambda **kwargs: calls.append(("dashboard", kwargs)),
        run_dashboard_prewarm=lambda **kwargs: calls.append(("run", kwargs)),
        schedule_holdings_metadata_prewarm=lambda holdings, **kwargs: calls.append(
            ("holdings", holdings, kwargs)
        ),
    )
    dependencies = {
        "portfolio_prewarm_service": service,
        "bootstrap_prewarm_executor": "executor",
        "run_dashboard_prewarm_fn": "run-dashboard",
        "logger": "logger",
        "resolve_portfolio_scope_fn": "resolve-scope",
        "load_strategy_cls": "load-strategy",
        "prewarm_position_result_snapshot_fn": "position",
        "prewarm_realized_performance_payload_fn": "realized-payload",
        "prewarm_realized_performance_returns_dataframe_fn": "realized-returns",
        "prewarm_realized_performance_attribution_fn": "realized-attribution",
        "prewarm_income_projection_result_snapshot_fn": "income",
        "build_full_income_projection_fn": "income-builder",
        "get_portfolio_snapshot_fn": "portfolio-snapshot",
        "get_factor_proxies_snapshot_fn": "factor-proxies",
        "get_risk_limits_snapshot_fn": "risk-limits",
        "portfolio_service_factory": "portfolio-service",
        "tier_order": {"paid": 2},
        "prime_virtual_portfolio_from_cached_positions_fn": "prime-virtual",
        "prewarm_analysis_result_snapshot_fn": "analysis",
        "build_analyze_result_fn": "build-analysis",
        "get_analysis_result_snapshot_fn": "get-analysis",
        "prewarm_risk_score_result_snapshot_fn": "risk-score",
        "prewarm_performance_result_snapshot_fn": "performance",
        "performance_cache_scope_fn": "cache-scope",
    }

    adapters.schedule_dashboard_prewarm(
        user_id=7,
        portfolio_name="Core",
        get_dependencies_fn=lambda: dependencies,
    )
    adapters.run_dashboard_prewarm(
        user_id=7,
        portfolio_name="Core",
        get_dependencies_fn=lambda: dependencies,
    )
    adapters.schedule_holdings_metadata_prewarm(
        [{"ticker": "AAPL"}],
        get_dependencies_fn=lambda: dependencies,
    )

    assert calls[0][0] == "dashboard"
    assert calls[0][1]["executor"] == "executor"
    assert calls[0][1]["run_dashboard_prewarm_fn"] == "run-dashboard"
    assert calls[1][0] == "run"
    assert calls[1][1]["resolve_portfolio_scope_fn"] == "resolve-scope"
    assert calls[1][1]["portfolio_service_factory"] == "portfolio-service"
    assert calls[2] == (
        "holdings",
        [{"ticker": "AAPL"}],
        {
            "executor": "executor",
            "portfolio_service_factory": "portfolio-service",
            "logger": "logger",
        },
    )
