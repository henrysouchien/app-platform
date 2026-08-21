"""App-owned adapters for portfolio display and prewarm compatibility."""

from __future__ import annotations

from typing import Any, Callable, Optional


def build_dependencies(source: dict[str, Any]) -> dict[str, Any]:
    """Build portfolio display/prewarm dependencies from app globals at call time."""

    return {
        "resolve_portfolio_scope_fn": source["resolve_portfolio_scope"],
        "load_strategy_cls": source["LoadStrategy"],
        "peek_position_result_snapshot_fn": source["peek_position_result_snapshot"],
        "wait_for_position_result_snapshot_fn": source[
            "wait_for_position_result_snapshot"
        ],
        "get_position_result_snapshot_fn": source["get_position_result_snapshot"],
        "filter_position_result_fn": source["filter_position_result"],
        "rebuild_position_result_fn": source["_rebuild_position_result_for_display"],
        "transform_position_result_for_display_fn": source[
            "_transform_position_result_for_display"
        ],
        "transform_portfolio_for_display_fn": source["transform_portfolio_for_display"],
        "build_virtual_portfolio_display_fn": source[
            "_build_virtual_portfolio_display"
        ],
        "portfolio_prewarm_service": source["portfolio_prewarm_service"],
        "bootstrap_prewarm_executor": source["_BOOTSTRAP_PREWARM_EXECUTOR"],
        "run_dashboard_prewarm_fn": source["_run_dashboard_prewarm"],
        "logger": source["api_logger"],
        "prewarm_position_result_snapshot_fn": source[
            "prewarm_position_result_snapshot"
        ],
        "prewarm_realized_performance_payload_fn": source[
            "prewarm_realized_performance_payload"
        ],
        "prewarm_realized_performance_returns_dataframe_fn": source[
            "prewarm_realized_performance_returns_dataframe"
        ],
        "prewarm_realized_performance_attribution_fn": source[
            "prewarm_realized_performance_attribution"
        ],
        "prewarm_income_projection_result_snapshot_fn": source[
            "prewarm_income_projection_result_snapshot"
        ],
        "build_full_income_projection_fn": source[
            "_build_full_income_projection_for_prewarm"
        ],
        "get_portfolio_snapshot_fn": source["get_portfolio_snapshot"],
        "get_factor_proxies_snapshot_fn": source["get_factor_proxies_snapshot"],
        "get_risk_limits_snapshot_fn": source["get_risk_limits_snapshot"],
        "portfolio_service_factory": source["PortfolioService"],
        "tier_order": source["TIER_ORDER"],
        "prime_virtual_portfolio_from_cached_positions_fn": source[
            "_prime_virtual_portfolio_from_cached_positions"
        ],
        "prewarm_analysis_result_snapshot_fn": source[
            "prewarm_analysis_result_snapshot"
        ],
        "build_analyze_result_fn": source["_build_analyze_result"],
        "get_analysis_result_snapshot_fn": source["get_analysis_result_snapshot"],
        "prewarm_risk_score_result_snapshot_fn": source[
            "prewarm_risk_score_result_snapshot"
        ],
        "prewarm_performance_result_snapshot_fn": source[
            "prewarm_performance_result_snapshot"
        ],
        "performance_cache_scope_fn": source["_performance_cache_scope"],
    }


def current_portfolio_has_bootstrap_rows(
    user_id: int,
    *,
    is_db_available_fn: Callable[[], bool],
    get_db_session_fn: Callable[[], Any],
    logger: Any,
) -> Optional[bool]:
    """Return whether CURRENT_PORTFOLIO has rows worth bootstrapping."""

    try:
        if not is_db_available_fn():
            return None

        with get_db_session_fn() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id FROM portfolios WHERE user_id = %s AND name = %s LIMIT 1",
                (int(user_id), "CURRENT_PORTFOLIO"),
            )
            row = cursor.fetchone()
            if not row:
                return False

            portfolio_id = row["id"] if isinstance(row, dict) else row[0]
            cursor.execute(
                "SELECT 1 FROM positions WHERE portfolio_id = %s LIMIT 1",
                (portfolio_id,),
            )
            return cursor.fetchone() is not None
    except Exception as exc:
        logger.debug(
            "CURRENT_PORTFOLIO bootstrap preflight skipped for user=%s: %s",
            user_id,
            exc,
        )
        return None


def build_virtual_portfolio_display(
    user: dict,
    portfolio_name: str,
    *,
    statement_date: str | None = None,
    portfolio_data: Any = None,
    portfolio_service: Any = None,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Build display payload from a warm live snapshot or fallback portfolio data."""

    dependencies = get_dependencies_fn()
    load_strategy_cls = dependencies["load_strategy_cls"]
    normalized_portfolio_name = str(portfolio_name or "").strip() or "CURRENT_PORTFOLIO"
    scope = dependencies["resolve_portfolio_scope_fn"](
        int(user["user_id"]),
        normalized_portfolio_name,
    )

    def _peek_bootstrap_snapshot(*, consolidate: bool):
        base_kwargs = {
            "user_email": user["email"],
            "user_id": int(user["user_id"]),
            "consolidate": consolidate,
        }
        for peek_kwargs in (
            {"allow_stale_cache": True, "reprice_cached_positions": True},
            {"allow_stale_cache": True, "reprice_cached_positions": False},
            {},
        ):
            candidate = dependencies["peek_position_result_snapshot_fn"](
                **base_kwargs,
                **peek_kwargs,
            )
            if candidate is not None:
                return candidate
        for wait_kwargs in (
            {
                "allow_stale_cache": True,
                "reprice_cached_positions": True,
                "timeout_seconds": 0.2,
            },
            {
                "allow_stale_cache": True,
                "reprice_cached_positions": False,
                "timeout_seconds": 0.2,
            },
        ):
            candidate = dependencies["wait_for_position_result_snapshot_fn"](
                **base_kwargs,
                **wait_kwargs,
            )
            if candidate is not None:
                return candidate
        return None

    if scope.strategy == load_strategy_cls.VIRTUAL_FILTERED:
        snapshot = _peek_bootstrap_snapshot(consolidate=False)
        if snapshot is not None:
            snapshot = dependencies["filter_position_result_fn"](
                snapshot,
                scope.account_filters or [],
            )
            if snapshot.data.positions:
                snapshot = dependencies["rebuild_position_result_fn"](
                    user=user,
                    result=snapshot,
                    consolidate=True,
                )
    else:
        snapshot = _peek_bootstrap_snapshot(consolidate=True)

    if snapshot is not None:
        return dependencies["transform_position_result_for_display_fn"](
            snapshot,
            statement_date=statement_date,
        )

    if portfolio_data is not None and portfolio_service is not None:
        return dependencies["transform_portfolio_for_display_fn"](
            portfolio_data,
            portfolio_service,
        )

    if scope.strategy == load_strategy_cls.VIRTUAL_FILTERED:
        result = dependencies["get_position_result_snapshot_fn"](
            user_email=user["email"],
            user_id=int(user["user_id"]),
            consolidate=False,
        )
        result = dependencies["filter_position_result_fn"](
            result,
            scope.account_filters or [],
        )
        if result.data.positions:
            result = dependencies["rebuild_position_result_fn"](
                user=user,
                result=result,
                consolidate=True,
            )
    else:
        result = dependencies["get_position_result_snapshot_fn"](
            user_email=user["email"],
            user_id=int(user["user_id"]),
            consolidate=True,
        )

    return dependencies["transform_position_result_for_display_fn"](
        result,
        statement_date=statement_date,
    )


def build_portfolio_display_data(
    portfolio_data: Any,
    portfolio_name: str,
    user: dict,
    portfolio_service: Any,
    *,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> dict[str, Any]:
    """Choose the correct display source for one portfolio bootstrap response."""

    dependencies = get_dependencies_fn()
    normalized_portfolio_name = str(portfolio_name or "").strip() or "CURRENT_PORTFOLIO"
    scope = dependencies["resolve_portfolio_scope_fn"](
        int(user["user_id"]),
        normalized_portfolio_name,
    )
    if scope.strategy != dependencies["load_strategy_cls"].PHYSICAL:
        return dependencies["build_virtual_portfolio_display_fn"](
            user,
            normalized_portfolio_name,
            statement_date=(
                portfolio_data._last_updated.isoformat()
                if getattr(portfolio_data, "_last_updated", None)
                else None
            ),
            portfolio_data=portfolio_data,
            portfolio_service=portfolio_service,
        )
    display_payload = dependencies["transform_portfolio_for_display_fn"](
        portfolio_data,
        portfolio_service,
    )
    data_quality = getattr(portfolio_data, "data_quality", None)
    if data_quality is not None:
        display_payload["data_quality"] = data_quality
    return display_payload


def schedule_dashboard_prewarm(
    *,
    user_id: int,
    portfolio_name: str,
    user_email: str | None = None,
    portfolio_data: Any = None,
    user_tier: str | None = None,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> None:
    """Register shared dashboard snapshot futures without blocking bootstrap."""

    dependencies = get_dependencies_fn()
    return dependencies["portfolio_prewarm_service"].schedule_dashboard_prewarm(
        user_id=user_id,
        portfolio_name=portfolio_name,
        user_email=user_email,
        portfolio_data=portfolio_data,
        user_tier=user_tier,
        executor=dependencies["bootstrap_prewarm_executor"],
        run_dashboard_prewarm_fn=dependencies["run_dashboard_prewarm_fn"],
        logger=dependencies["logger"],
    )


def run_dashboard_prewarm(
    *,
    user_id: int,
    portfolio_name: str,
    user_email: str | None = None,
    portfolio_data: Any = None,
    user_tier: str | None = None,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> None:
    """Register shared dashboard snapshot futures before bootstrap returns."""

    dependencies = get_dependencies_fn()
    return dependencies["portfolio_prewarm_service"].run_dashboard_prewarm(
        user_id=user_id,
        portfolio_name=portfolio_name,
        user_email=user_email,
        portfolio_data=portfolio_data,
        user_tier=user_tier,
        resolve_portfolio_scope_fn=dependencies["resolve_portfolio_scope_fn"],
        load_strategy_cls=dependencies["load_strategy_cls"],
        prewarm_position_result_snapshot_fn=dependencies[
            "prewarm_position_result_snapshot_fn"
        ],
        prewarm_realized_performance_payload_fn=dependencies[
            "prewarm_realized_performance_payload_fn"
        ],
        prewarm_realized_performance_returns_dataframe_fn=dependencies[
            "prewarm_realized_performance_returns_dataframe_fn"
        ],
        prewarm_realized_performance_attribution_fn=dependencies[
            "prewarm_realized_performance_attribution_fn"
        ],
        prewarm_income_projection_result_snapshot_fn=dependencies[
            "prewarm_income_projection_result_snapshot_fn"
        ],
        build_full_income_projection_fn=dependencies["build_full_income_projection_fn"],
        get_portfolio_snapshot_fn=dependencies["get_portfolio_snapshot_fn"],
        get_factor_proxies_snapshot_fn=dependencies["get_factor_proxies_snapshot_fn"],
        get_risk_limits_snapshot_fn=dependencies["get_risk_limits_snapshot_fn"],
        portfolio_service_factory=dependencies["portfolio_service_factory"],
        tier_order=dependencies["tier_order"],
        prime_virtual_portfolio_from_cached_positions_fn=dependencies[
            "prime_virtual_portfolio_from_cached_positions_fn"
        ],
        prewarm_analysis_result_snapshot_fn=dependencies[
            "prewarm_analysis_result_snapshot_fn"
        ],
        build_analyze_result_fn=dependencies["build_analyze_result_fn"],
        get_analysis_result_snapshot_fn=dependencies["get_analysis_result_snapshot_fn"],
        prewarm_risk_score_result_snapshot_fn=dependencies[
            "prewarm_risk_score_result_snapshot_fn"
        ],
        prewarm_performance_result_snapshot_fn=dependencies[
            "prewarm_performance_result_snapshot_fn"
        ],
        performance_cache_scope_fn=dependencies["performance_cache_scope_fn"],
        logger=dependencies["logger"],
    )


def schedule_holdings_metadata_prewarm(
    holdings: list[dict[str, Any]] | None,
    *,
    get_dependencies_fn: Callable[[], dict[str, Any]],
) -> None:
    """Warm shared holdings metadata needed by first holdings/performance views."""

    dependencies = get_dependencies_fn()
    return dependencies["portfolio_prewarm_service"].schedule_holdings_metadata_prewarm(
        holdings,
        executor=dependencies["bootstrap_prewarm_executor"],
        portfolio_service_factory=dependencies["portfolio_service_factory"],
        logger=dependencies["logger"],
    )


__all__ = [
    "build_dependencies",
    "build_portfolio_display_data",
    "build_virtual_portfolio_display",
    "current_portfolio_has_bootstrap_rows",
    "run_dashboard_prewarm",
    "schedule_dashboard_prewarm",
    "schedule_holdings_metadata_prewarm",
]
