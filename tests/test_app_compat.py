from __future__ import annotations

from types import SimpleNamespace

from app_platform.app_compat import install_compatibility_wrappers


def test_installer_adds_late_bound_service_registry_wrappers() -> None:
    source: dict = {
        "_service_registry": SimpleNamespace(
            get_user_portfolio_service=lambda user: ("portfolio", user),
            get_user_scenario_service=lambda user: ("scenario", user),
            get_user_optimization_service=lambda user: ("optimization", user),
        )
    }

    install_compatibility_wrappers(source)

    source["_service_registry"].get_user_portfolio_service = lambda user: (
        "updated",
        user,
    )

    assert source["get_user_portfolio_service"]({"user_id": 7}) == (
        "updated",
        {"user_id": 7},
    )
    assert source["get_user_scenario_service"]({"user_id": 8}) == (
        "scenario",
        {"user_id": 8},
    )
    assert source["get_user_optimization_service"]({"user_id": 9}) == (
        "optimization",
        {"user_id": 9},
    )


def test_rebalance_wrapper_reads_live_source_dependencies() -> None:
    class _AllocationAdapters:
        @staticmethod
        def build_dependencies(source):
            return {"preview_rebalance_trades_fn": source["_preview_rebalance_trades"]}

        @staticmethod
        def preview_rebalance_trades(*, get_dependencies_fn, **kwargs):
            return get_dependencies_fn()["preview_rebalance_trades_fn"](**kwargs)

    source = {
        "allocation_adapters": _AllocationAdapters,
        "_preview_rebalance_trades": lambda **kwargs: {"before": kwargs},
    }

    install_compatibility_wrappers(source)
    source["_preview_rebalance_trades"] = lambda **kwargs: {"after": kwargs}

    assert source["preview_rebalance_trades"](target_weights={"AAPL": 1.0}) == {
        "after": {"target_weights": {"AAPL": 1.0}}
    }


def test_position_display_rebuild_uses_canonical_service(monkeypatch) -> None:
    import services.position_service as position_service_module

    calls = {}
    result = SimpleNamespace(
        _provider_freshness={"ibkr": {"status": "degraded"}}
    )

    class _PositionService:
        def __init__(self, *, user_email, user_id):
            calls["service"] = (user_email, user_id)

    def _rebuild(service, candidate, *, consolidate):
        calls["rebuild"] = (service, candidate, consolidate)
        candidate.provider_freshness = dict(candidate._provider_freshness)
        return candidate

    monkeypatch.setattr(position_service_module, "PositionService", _PositionService)
    monkeypatch.setattr(position_service_module, "rebuild_position_result", _rebuild)
    source = {}
    install_compatibility_wrappers(source)

    rebuilt = source["_rebuild_position_result_for_display"](
        user={"email": "user@example.com", "user_id": 7},
        result=result,
        consolidate=True,
    )

    assert calls["service"] == ("user@example.com", 7)
    assert calls["rebuild"][1:] == (result, True)
    assert rebuilt.provider_freshness == result._provider_freshness


def test_workflow_wrappers_read_live_source_dependencies() -> None:
    captured: dict = {}

    class _RouteWorkflowAdapters:
        @staticmethod
        def run_monte_carlo_workflow(**kwargs):
            captured.update(kwargs)
            return {"ok": True}

    source = {
        "route_workflow_adapters": _RouteWorkflowAdapters,
        "PortfolioManager": object,
        "resolve_monte_carlo_drift_inputs": lambda *args, **kwargs: "drift-before",
        "run_rest_monte_carlo_analysis": lambda *args, **kwargs: "action-before",
    }

    install_compatibility_wrappers(source)
    source["run_rest_monte_carlo_analysis"] = lambda *args, **kwargs: "action-after"
    source["resolve_monte_carlo_drift_inputs"] = lambda *args, **kwargs: "drift-after"

    assert source["_run_monte_carlo_workflow"](
        "CURRENT_PORTFOLIO",
        100,
        12,
        "normal",
        5,
        user={"user_id": 1},
        scenario_service=object(),
    ) == {"ok": True}
    assert captured["run_monte_carlo_analysis_fn"]() == "action-after"
    assert captured["resolve_drift_inputs_fn"]() == "drift-after"
