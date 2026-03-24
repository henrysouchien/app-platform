"""Helpers for recording named workflow step timings."""

from __future__ import annotations

from contextlib import contextmanager
import time
from typing import Any, Iterator

from .core import log_timing_event


class WorkflowTimer:
    """Collect named step timings and emit a single structured timing event."""

    def __init__(self, name: str, **details: Any) -> None:
        self.name = name
        self.details = {key: value for key, value in details.items() if value is not None}
        self.steps: dict[str, float] = {}
        self._start = time.perf_counter()

    @contextmanager
    def step(self, name: str) -> Iterator[None]:
        """Record elapsed time for a named workflow step."""
        start = time.perf_counter()
        try:
            yield
        finally:
            self.steps[name] = round((time.perf_counter() - start) * 1000, 2)

    def add_details(self, **details: Any) -> None:
        """Attach extra structured details before the workflow is emitted."""
        self.details.update({key: value for key, value in details.items() if value is not None})

    def finish(self, **details: Any) -> None:
        """Emit the workflow timing event with all collected step timings."""
        self.add_details(**details)
        total_ms = round((time.perf_counter() - self._start) * 1000, 2)
        steps = dict(self.steps)
        steps["total"] = total_ms
        log_timing_event(
            kind="step",
            name=self.name,
            duration_ms=total_ms,
            steps=steps,
            **self.details,
        )


@contextmanager
def workflow_timer(name: str, **details: Any) -> Iterator[WorkflowTimer]:
    """Yield a ``WorkflowTimer`` and emit it on successful completion."""
    timer = WorkflowTimer(name, **details)
    try:
        yield timer
    except Exception:
        raise
    else:
        timer.finish()


__all__ = ["WorkflowTimer", "workflow_timer"]
