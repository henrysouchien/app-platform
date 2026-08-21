"""App-owned adapters for allocation/rebalance compatibility paths."""

from __future__ import annotations

from typing import Any, Callable


def build_dependencies(source: dict[str, Any]) -> dict[str, Any]:
    """Build allocation adapter dependencies from app globals at call time."""

    return {
        "preview_rebalance_trades_fn": source["_preview_rebalance_trades"],
        "get_portfolio_snapshot_fn": source["get_portfolio_snapshot"],
        "prime_virtual_portfolio_fn": source[
            "_prime_virtual_portfolio_from_cached_positions"
        ],
        "tier_order": source["TIER_ORDER"],
        "get_factor_proxies_snapshot_fn": source["get_factor_proxies_snapshot"],
        "get_risk_limits_snapshot_fn": source["get_risk_limits_snapshot"],
        "peek_analysis_result_snapshot_fn": source["peek_analysis_result_snapshot"],
    }


def preview_rebalance_trades(
    *,
    get_dependencies_fn: Callable[[], dict[str, Any]],
    **kwargs: Any,
) -> dict[str, Any]:
    """Run rebalance preview with the prior REST-facing tool error contract."""

    dependencies = get_dependencies_fn()
    try:
        return dependencies["preview_rebalance_trades_fn"](**kwargs)
    except Exception as exc:  # noqa: BLE001 - preserve tool-style validation payloads for REST
        return {"status": "error", "error": str(exc)}


def build_cached_rebalance_risk_snapshot(
    user: dict,
    portfolio_name: str = "CURRENT_PORTFOLIO",
    *,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any] | None:
    """Best-effort cached risk snapshot for rebalance diagnostics."""

    dependencies = get_dependencies_fn()
    try:
        user_id = int(user["user_id"])
        portfolio_data = dependencies["get_portfolio_snapshot_fn"](
            user_id,
            portfolio_name,
        )
        dependencies["prime_virtual_portfolio_fn"](
            portfolio_data,
            user=user,
            portfolio_name=portfolio_name,
        )
        normalized_tier = (
            str(user.get("tier") or "registered").strip().lower() or "registered"
        )
        allow_gpt = (
            dependencies["tier_order"].get(normalized_tier, 0)
            >= dependencies["tier_order"]["paid"]
        )
        portfolio_data.stock_factor_proxies = dependencies[
            "get_factor_proxies_snapshot_fn"
        ](
            user_id,
            portfolio_name,
            portfolio_data,
            allow_gpt=allow_gpt,
        )
        portfolio_data.refresh_cache_key()
        risk_limits_data, _ = dependencies["get_risk_limits_snapshot_fn"](
            user_id,
            portfolio_name,
        )
        cached_analysis = dependencies["peek_analysis_result_snapshot_fn"](
            user_id=user_id,
            portfolio_name=portfolio_name,
            portfolio_data=portfolio_data,
            risk_limits_data=risk_limits_data,
            performance_period="1M",
        )
        if cached_analysis is None:
            return None

        return {
            "risk_contributions": cached_analysis.get_asset_class_risk_contributions(),
            "factor_betas": cached_analysis.get_asset_class_factor_betas(),
            "compliance_summary": cached_analysis.get_compliance_summary(),
        }
    except Exception:
        return None


__all__ = [
    "build_dependencies",
    "build_cached_rebalance_risk_snapshot",
    "preview_rebalance_trades",
]
