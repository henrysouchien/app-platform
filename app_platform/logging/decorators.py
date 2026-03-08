"""Structured logging decorators."""

from __future__ import annotations

import asyncio
import functools
import time
from typing import Callable

from .core import get_logging_manager, log_error, log_event, log_slow_operation


def log_errors(severity: str = "medium"):
    """Decorator: catch/log exceptions, then re-raise."""

    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                try:
                    return await func(*args, **kwargs)
                except Exception as exc:  # pragma: no cover - exercised by tests
                    log_error(
                        source=f"{func.__module__}:{func.__name__}",
                        message=f"Function {func.__name__} failed",
                        exc=exc,
                        severity=severity,
                    )
                    raise

            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as exc:
                log_error(
                    source=f"{func.__module__}:{func.__name__}",
                    message=f"Function {func.__name__} failed",
                    exc=exc,
                    severity=severity,
                )
                raise

        return wrapper

    return decorator


def log_timing(threshold_s: float | None = None):
    """Decorator: measure function duration and log only above threshold."""

    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                start = time.perf_counter()
                try:
                    return await func(*args, **kwargs)
                finally:
                    duration_s = time.perf_counter() - start
                    manager = get_logging_manager()
                    assert manager is not None
                    threshold = (
                        manager.slow_operation_threshold_s
                        if threshold_s is None
                        else threshold_s
                    )
                    if duration_s >= threshold:
                        log_slow_operation(
                            f"{func.__module__}.{func.__name__}",
                            duration_s,
                        )

            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                duration_s = time.perf_counter() - start
                manager = get_logging_manager()
                assert manager is not None
                threshold = (
                    manager.slow_operation_threshold_s
                    if threshold_s is None
                    else threshold_s
                )
                if duration_s >= threshold:
                    log_slow_operation(
                        f"{func.__module__}.{func.__name__}",
                        duration_s,
                    )

        return wrapper

    return decorator


def log_operation(name: str):
    """Decorator: log operation start/end around a function call."""

    def decorator(func: Callable) -> Callable:
        if asyncio.iscoroutinefunction(func):

            @functools.wraps(func)
            async def async_wrapper(*args, **kwargs):
                log_event(
                    "operation_start",
                    f"{name} started",
                    operation=name,
                    function=func.__name__,
                )
                start = time.perf_counter()
                try:
                    result = await func(*args, **kwargs)
                except Exception as exc:
                    duration_s = time.perf_counter() - start
                    log_error(
                        source=f"{func.__module__}:{func.__name__}",
                        message=f"{name} failed",
                        exc=exc,
                        operation=name,
                        duration_s=duration_s,
                    )
                    raise
                duration_s = time.perf_counter() - start
                log_event(
                    "operation_end",
                    f"{name} finished",
                    operation=name,
                    function=func.__name__,
                    duration_s=duration_s,
                )
                return result

            return async_wrapper

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            log_event(
                "operation_start",
                f"{name} started",
                operation=name,
                function=func.__name__,
            )
            start = time.perf_counter()
            try:
                result = func(*args, **kwargs)
            except Exception as exc:
                duration_s = time.perf_counter() - start
                log_error(
                    source=f"{func.__module__}:{func.__name__}",
                    message=f"{name} failed",
                    exc=exc,
                    operation=name,
                    duration_s=duration_s,
                )
                raise
            duration_s = time.perf_counter() - start
            log_event(
                "operation_end",
                f"{name} finished",
                operation=name,
                function=func.__name__,
                duration_s=duration_s,
            )
            return result

        return wrapper

    return decorator


__all__ = ["log_errors", "log_operation", "log_timing"]
