"""Exceptions raised by the API budget guard."""

from __future__ import annotations


class BudgetExceededError(RuntimeError):
    """Raised when a hard budget limit blocks a vendor call."""

    def __init__(
        self,
        *,
        provider: str,
        operation: str,
        blocked_scope: str | None,
        blocked_key_kind: str | None,
        blocked_window_kind: str | None,
        blocked_threshold: int | None,
        blocked_count: int | None,
    ) -> None:
        self.provider = str(provider)
        self.operation = str(operation)
        self.blocked_scope = blocked_scope
        self.blocked_key_kind = blocked_key_kind
        self.blocked_window_kind = blocked_window_kind
        self.blocked_threshold = blocked_threshold
        self.blocked_count = blocked_count
        super().__init__(
            "API budget exceeded for "
            f"{self.provider}/{self.operation}: "
            f"scope={blocked_scope}, key_kind={blocked_key_kind}, "
            f"window={blocked_window_kind}, threshold={blocked_threshold}, "
            f"count={blocked_count}"
        )


class BudgetGuardUnavailable(RuntimeError):
    """Raised when the guard infrastructure is unavailable and fail-open is disabled."""
