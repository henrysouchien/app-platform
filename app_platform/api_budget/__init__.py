"""Public API for the API budget guard mechanism."""

from .exceptions import BudgetExceededError, BudgetGuardUnavailable
from .guard import guard_call, is_provider_over_budget
from .llm_cost import LLMUsage
from .store import reset_counter

try:
    from providers.completion import CompletionResult
except Exception:  # pragma: no cover - optional fallback for narrower installs
    CompletionResult = None  # type: ignore[assignment]

__all__ = [
    "BudgetExceededError",
    "BudgetGuardUnavailable",
    "CompletionResult",
    "LLMUsage",
    "guard_call",
    "is_provider_over_budget",
    "reset_counter",
]
