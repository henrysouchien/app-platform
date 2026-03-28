def test_database_module_still_exports_legacy_entrypoints():
    import database

    assert hasattr(database, "get_db_session")
    assert hasattr(database, "get_pool")


def test_database_client_import_chain_still_loads():
    from app_platform.db.client_base import DatabaseClientBase
    from inputs.database_client import DatabaseClient

    assert issubclass(DatabaseClient, DatabaseClientBase)
    assert callable(DatabaseClient.get_or_create_user_id)


def test_app_platform_root_reexports_logging_entrypoints():
    from app_platform import LoggingManager, get_logger
    from app_platform.logging import LoggingManager as PlatformLoggingManager
    from app_platform.logging import get_logger as platform_get_logger

    assert LoggingManager is PlatformLoggingManager
    assert get_logger is platform_get_logger


def test_rate_limiter_and_factor_route_import_chains_still_load():
    from slowapi import Limiter
    from utils.rate_limiter import (
        DEFAULT_KEYS,
        IS_DEV,
        PUBLIC_KEY,
        TIER_MAP,
        VALID_KEYS,
        limiter,
    )
    from routes.factor_intelligence import factor_intelligence_router

    assert isinstance(limiter, Limiter)
    assert isinstance(VALID_KEYS, set)
    assert isinstance(TIER_MAP, dict)
    assert isinstance(PUBLIC_KEY, str)
    assert isinstance(DEFAULT_KEYS, dict)
    assert isinstance(IS_DEV, bool)
    assert factor_intelligence_router.prefix == "/api/factor-intelligence"
