import importlib
import logging

import pytest


def test_exception_hierarchy_preserves_domain_catchability():
    platform_exceptions = importlib.import_module("app_platform.db.exceptions")
    input_exceptions = importlib.import_module("inputs.exceptions")

    assert issubclass(platform_exceptions.NotFoundError, platform_exceptions.DatabaseError)
    assert issubclass(input_exceptions.UserNotFoundError, platform_exceptions.NotFoundError)
    assert issubclass(input_exceptions.PortfolioNotFoundError, platform_exceptions.DatabaseError)

    with pytest.raises(platform_exceptions.DatabaseError):
        raise input_exceptions.UserNotFoundError("user-123")


def test_handle_database_error_passes_through_known_errors():
    platform_exceptions = importlib.import_module("app_platform.db.exceptions")

    @platform_exceptions.handle_database_error
    def raise_known():
        raise platform_exceptions.ValidationError("bad field")

    with pytest.raises(platform_exceptions.ValidationError):
        raise_known()


def test_handle_database_error_wraps_unknown_exceptions():
    platform_exceptions = importlib.import_module("app_platform.db.exceptions")

    @platform_exceptions.handle_database_error
    def explode():
        raise ValueError("boom")

    with pytest.raises(platform_exceptions.DatabaseError) as exc_info:
        explode()

    assert exc_info.value.operation == "explode"
    assert isinstance(exc_info.value.original_error, ValueError)


def test_recoverable_error_detection_and_logging(caplog):
    platform_exceptions = importlib.import_module("app_platform.db.exceptions")
    logger = logging.getLogger("tests.app_platform.db_exceptions")

    recoverable = platform_exceptions.ConnectionError("cannot connect")
    non_recoverable = platform_exceptions.ValidationError("invalid")

    assert platform_exceptions.is_recoverable_error(recoverable) is True
    assert platform_exceptions.is_recoverable_error(non_recoverable) is False

    with caplog.at_level(logging.WARNING, logger=logger.name):
        platform_exceptions.log_database_error(recoverable, logger)
        platform_exceptions.log_database_error(non_recoverable, logger)

    assert "Recoverable database error" in caplog.text
    assert "Database error" in caplog.text
