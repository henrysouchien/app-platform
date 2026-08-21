from __future__ import annotations

import pytest

from app_platform.gateway.control_run_lifecycle import (
    CONTROL_ACTIVE_RUN_STATES,
    CONTROL_CANCELLABLE_RUN_STATES,
    CONTROL_CHAT_MESSAGEABLE_RUN_STATES,
    CONTROL_CHAT_TOKEN_FORGET_STATES,
    CONTROL_RESUMABLE_RUN_STATES,
    CONTROL_TERMINAL_RUN_STATES,
    is_control_chat_messageable_state,
    is_control_run_cancellable_state,
    is_control_run_resumable_state,
    should_forget_control_chat_token,
)


def test_control_run_lifecycle_matches_chassis_classification_shape() -> None:
    assert CONTROL_ACTIVE_RUN_STATES == {
        "starting",
        "queued",
        "waiting",
        "running",
        "approval_pending",
    }
    assert CONTROL_TERMINAL_RUN_STATES == {
        "completed",
        "budget_limited",
        "failed",
        "interrupted",
        "cancelled",
    }
    assert CONTROL_RESUMABLE_RUN_STATES == {"failed", "interrupted", "cancelled"}
    assert CONTROL_CANCELLABLE_RUN_STATES == CONTROL_ACTIVE_RUN_STATES


def test_chat_messageability_is_explicitly_not_the_active_state_set() -> None:
    assert CONTROL_CHAT_MESSAGEABLE_RUN_STATES == CONTROL_ACTIVE_RUN_STATES | {"completed"}
    assert CONTROL_CHAT_TOKEN_FORGET_STATES == {"budget_limited", "failed", "interrupted", "cancelled"}


@pytest.mark.parametrize("state", sorted(CONTROL_ACTIVE_RUN_STATES | {"completed"}))
def test_chat_messageable_states(state: str) -> None:
    assert is_control_chat_messageable_state(state) is True
    assert should_forget_control_chat_token(state) is False


@pytest.mark.parametrize("state", ["budget_limited", "failed", "interrupted", "cancelled", "", "unknown"])
def test_chat_non_messageable_states(state: str) -> None:
    assert is_control_chat_messageable_state(state) is False


@pytest.mark.parametrize("state", ["budget_limited", "failed", "interrupted", "cancelled"])
def test_chat_token_forget_states(state: str) -> None:
    assert should_forget_control_chat_token(state) is True


def test_unknown_run_states_are_not_cancellable_or_resumable() -> None:
    assert is_control_run_cancellable_state("unknown") is False
    assert is_control_run_resumable_state("unknown") is False
