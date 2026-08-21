from __future__ import annotations

import hashlib

import pytest
from pydantic import ValidationError

from app_platform.gateway.control_contracts import (
    CONTROL_CONTRACT_SCHEMA_BUNDLE_VERSION,
    CONTROL_EVENT_CONTRACT_ROUTES,
    CONTROL_EVENT_CONTRACT_VERSION,
    CONTROL_EVENT_ROUTE_SCHEMA_MODELS,
    CONTROL_REQUEST_CONTRACT_ROUTES,
    CONTROL_REQUEST_CONTRACT_VERSION,
    CONTROL_REQUEST_ROUTE_SCHEMA_MODELS,
    CONTROL_RESPONSE_CONTRACT_ROUTES,
    CONTROL_RESPONSE_CONTRACT_VERSION,
    CONTROL_RESPONSE_ROUTE_SCHEMA_MODELS,
    CONTROL_RUN_CONTRACT_VERSION,
    CONTROL_RUN_PAYLOAD_CONTRACT_ROUTES,
    CONTROL_RUN_ROUTE_SCHEMA_MODELS,
    ControlContractValidationError,
    ControlEventEnvelopeContract,
    ControlEventPayloadContract,
    EventsDroppedControlEventContract,
    FutureControlEventContract,
    ReplayTruncatedControlEventContract,
    RunResumedControlEventContract,
    RunResumedFromControlEventContract,
    RunStateChangedControlEventContract,
    TextDeltaControlEventContract,
    control_contract_schema_bundle,
    control_request_contract_applies,
    control_response_contract_applies,
    normalize_control_request_contract_payload,
    normalize_control_response_contract_payload,
    normalize_control_run_contract_payload,
)


def _agent_run_schedule_create_payload() -> dict:
    return {
        "kind": "agent_run_schedule",
        "name": "weekday-nvda-earnings-watch",
        "enabled": True,
        "timezone": "America/New_York",
        "cadence": {
            "type": "weekly",
            "days_of_week": [1, 2, 3, 4, 5],
            "time_of_day": "08:30",
        },
        "dispatch": {
            "kind": "autonomous",
            "profile": "analyst",
            "mode": "skill",
            "skill": "earnings-review",
            "ticker": "NVDA",
            "task": None,
            "context": "Review new earnings/news and report material changes.",
        },
        "request_id": "schedule-create-1",
    }


def _readable_resource_payload(**overrides) -> dict:
    payload = {
        "resource_id": "note:bg-1:daily:2026-06-12",
        "control_run_id": "bg-1",
        "skill_run_id": "skill-run-1",
        "contract_name": "MarkdownNote",
        "content_type": "text/markdown",
        "content_class": "human_readable",
        "content_snapshot_id": "sha256:" + "a" * 64,
        "content_sha256": "a" * 64,
        "content_bytes": 42,
        "truncated": False,
        "title": "Daily note",
        "source_path": "daily/2026-06-12.md",
        "byte_start": 10,
        "byte_end": 52,
        "tool_name": "memory_write",
        "created_at": "2026-06-12T15:46:49Z",
    }
    content = overrides.get("content")
    if isinstance(content, str):
        content_bytes = content.encode("utf-8")
        overrides.setdefault("content_bytes", len(content_bytes))
        overrides.setdefault("content_sha256", hashlib.sha256(content_bytes).hexdigest())
    payload.update(overrides)
    return payload


def test_control_run_contract_normalizes_run_lists_and_preserves_extensions() -> None:
    payload = {
        "runs": [
            {
                "kind": "chat",
                "run_id": "sess-1",
                "state": "completed",
                "title": "Analyst answer",
                "messageable": True,
            }
        ],
        "next_cursor": "cursor-1",
    }

    assert normalize_control_run_contract_payload(payload) == payload


def test_control_contract_schema_bundle_publishes_versions_and_lifecycle() -> None:
    bundle = control_contract_schema_bundle()

    assert bundle["schema_version"] == CONTROL_CONTRACT_SCHEMA_BUNDLE_VERSION
    assert bundle["contract_versions"] == {
        "run": CONTROL_RUN_CONTRACT_VERSION,
        "request": CONTROL_REQUEST_CONTRACT_VERSION,
        "response": CONTROL_RESPONSE_CONTRACT_VERSION,
        "event": CONTROL_EVENT_CONTRACT_VERSION,
    }
    assert bundle["run_lifecycle"]["states"] == [
        "starting",
        "queued",
        "waiting",
        "running",
        "approval_pending",
        "completed",
        "budget_limited",
        "failed",
        "interrupted",
        "cancelled",
    ]
    assert bundle["run_lifecycle"]["resumable_states"] == ["failed", "interrupted", "cancelled"]
    assert "ControlRunContract" in bundle["models"]
    assert "ControlRunEnvelopeContract" in bundle["models"]
    assert "ControlRunListContract" in bundle["models"]
    assert "ControlEventEnvelopeContract" in bundle["models"]
    assert "RunStateChangedControlEventContract" in bundle["models"]
    assert "RunResumedControlEventContract" in bundle["models"]
    assert "RunResumedFromControlEventContract" in bundle["models"]
    assert "EventsDroppedControlEventContract" in bundle["models"]
    assert "ReplayTruncatedControlEventContract" in bundle["models"]
    assert "DispatchScopeContract" in bundle["models"]
    assert "ChatRunDispatchRequestContract" in bundle["models"]
    assert "AutonomousRunDispatchRequestContract" in bundle["models"]
    assert "ApprovalNotificationContract" in bundle["models"]
    assert "ApprovalNotificationRetryRequestContract" in bundle["models"]
    assert "ApprovalNotificationRetryResponseContract" in bundle["models"]
    assert "ReadableResourceContract" in bundle["models"]
    assert "ReadableResourceDetailContract" in bundle["models"]
    assert "ReadableResourceListContract" in bundle["models"]
    assert "ResumeRunRequestContract" in bundle["models"]
    assert bundle["route_schemas"]["run_payloads"]["GET /control/runs"] == [
        "ControlRunListContract",
        "ControlRunEnvelopeContract",
        "ControlRunContract",
    ]
    assert bundle["route_schemas"]["run_payloads"]["POST /control/runs"] == [
        "ControlRunListContract",
        "ControlRunEnvelopeContract",
        "ControlRunContract",
    ]
    assert bundle["route_schemas"]["browser_requests"]["POST /control/runs"] == [
        "ChatRunDispatchRequestContract",
        "AutonomousRunDispatchRequestContract",
    ]
    assert "channel" not in bundle["models"]["ChatRunDispatchRequestContract"]["properties"]
    assert "channel" not in bundle["models"]["AutonomousRunDispatchRequestContract"]["properties"]
    assert "POST /control/runs/{run_id}/resume" in bundle["route_contracts"]["browser_requests"]
    assert (
        "POST /control/runs/{run_id}/approvals/{approval_id}/notifications/retry"
        in bundle["route_contracts"]["browser_requests"]
    )
    assert bundle["route_schemas"]["browser_requests"][
        "POST /control/runs/{run_id}/approvals/{approval_id}/notifications/retry"
    ] == "ApprovalNotificationRetryRequestContract"
    assert bundle["route_schemas"]["response_envelopes"][
        "POST /control/runs/{run_id}/approvals/{approval_id}/notifications/retry"
    ] == "ApprovalNotificationRetryResponseContract"
    assert bundle["route_contracts"]["control_events"] == list(CONTROL_EVENT_CONTRACT_ROUTES)
    assert bundle["route_schemas"]["control_events"] == dict(CONTROL_EVENT_ROUTE_SCHEMA_MODELS)
    assert bundle["route_schemas"]["response_envelopes"]["GET /control/artifacts"] == "ArtifactListContract"
    assert bundle["route_schemas"]["response_envelopes"]["GET /control/readable-resources"] == (
        "ReadableResourceListContract"
    )
    assert bundle["route_schemas"]["response_envelopes"]["GET /control/readable-resources/{resource_id}"] == (
        "ReadableResourceDetailContract"
    )
    assert bundle["route_schemas"]["browser_requests"]["POST /control/schedules"] == (
        "AgentRunScheduleCreateRequestContract"
    )
    assert bundle["route_schemas"]["browser_requests"]["PATCH /control/schedules/{schedule_id}"] == (
        "AgentRunScheduleUpdateRequestContract"
    )
    assert bundle["route_schemas"]["browser_requests"]["PUT /control/schedules/{schedule_id}/enabled"] == (
        "ScheduleEnabledRequestContract"
    )
    assert bundle["route_schemas"]["response_envelopes"]["GET /control/schedules/{schedule_id}"] == [
        "ControlScheduleContract",
        "ScheduleEnvelopeContract",
    ]
    assert bundle["route_schemas"]["response_envelopes"]["POST /control/schedules"] == [
        "ControlScheduleContract",
        "ScheduleEnvelopeContract",
    ]
    assert bundle["route_schemas"]["response_envelopes"]["PATCH /control/schedules/{schedule_id}"] == [
        "ControlScheduleContract",
        "ScheduleEnvelopeContract",
    ]
    assert bundle["route_schemas"]["response_envelopes"]["PUT /control/schedules/{schedule_id}/enabled"] == [
        "ControlScheduleContract",
        "ScheduleEnvelopeContract",
    ]
    assert bundle["route_schemas"]["response_envelopes"]["DELETE /control/schedules/{schedule_id}"] == [
        "ControlScheduleContract",
        "ScheduleEnvelopeContract",
        "ScheduleDeleteResponseContract",
    ]


def test_control_event_contracts_cover_projected_sse_resume_and_drop_shapes() -> None:
    envelope = ControlEventEnvelopeContract.model_validate({
        "run_id": "bg_1",
        "seq": 4,
        "event": {
            "type": "run_state_changed",
            "run_id": "bg_1",
            "control_run_id": "bg_1",
            "state": "running",
            "ts": 1710000000,
        },
    })
    assert envelope.model_dump(mode="json", exclude_unset=True) == {
        "run_id": "bg_1",
        "seq": 4,
        "event": {
            "type": "run_state_changed",
            "control_run_id": "bg_1",
            "run_id": "bg_1",
            "state": "running",
            "ts": 1710000000,
        },
    }

    assert RunStateChangedControlEventContract.model_validate({
        "type": "run_state_changed",
        "run_id": "bg_1",
        "state": "budget_limited",
    }).state == "budget_limited"
    assert ControlEventPayloadContract.model_validate({
        "type": "run_state_changed",
        "run_id": "bg_1",
        "state": "failed",
    }).root.state == "failed"
    assert TextDeltaControlEventContract.model_validate({
        "type": "text_delta",
        "control_run_id": "bg_1",
        "content": "",
    }).content == ""
    assert RunResumedControlEventContract.model_validate({
        "type": "run_resumed",
        "run_id": "bg_parent",
        "resumed_run_id": "bg_child",
        "resumed_task_id": "task_child",
        "request_id": "resume-1",
    }).resumed_run_id == "bg_child"
    assert RunResumedFromControlEventContract.model_validate({
        "type": "run_resumed_from",
        "run_id": "bg_child",
        "resumed_from": "bg_parent",
        "resumed_from_task_id": "task_parent",
        "request_id": "resume-1",
    }).resumed_from == "bg_parent"
    assert EventsDroppedControlEventContract.model_validate({
        "type": "events_dropped",
        "run_id": "bg_1",
        "count": 2,
        "dropped_through_seq": 3,
        "oldest_ts": 1710000000.25,
    }).count == 2
    assert ReplayTruncatedControlEventContract.model_validate({
        "type": "replay_truncated",
        "run_id": "bg_1",
        "control_run_id": "bg_1",
        "dropped_before_seq": 2,
    }).dropped_before_seq == 2
    assert FutureControlEventContract.model_validate({
        "type": "future_control_event",
        "custom_payload": {"ok": True},
    }).type == "future_control_event"
    assert ControlEventPayloadContract.model_validate({
        "type": "future_control_event",
        "custom_payload": {"ok": True},
    }).root.type == "future_control_event"


def test_control_event_contracts_reject_noncanonical_or_unowned_known_events() -> None:
    with pytest.raises(ValidationError, match="unknown control run state"):
        RunStateChangedControlEventContract.model_validate({
            "type": "run_state_changed",
            "run_id": "bg_1",
            "state": "complete",
        })

    with pytest.raises(ValidationError, match="text_delta must include a run owner id"):
        TextDeltaControlEventContract.model_validate({
            "type": "text_delta",
            "text": "hello",
        })
    with pytest.raises(ValidationError, match="text_delta must include a run owner id"):
        ControlEventPayloadContract.model_validate({
            "type": "text_delta",
            "text": "hello",
        })

    with pytest.raises(ValidationError, match="run_resumed must include resumed_run_id or resumed_as"):
        RunResumedControlEventContract.model_validate({
            "type": "run_resumed",
            "run_id": "bg_parent",
        })

    with pytest.raises(ValidationError, match="run_resumed_from must include resumed_from"):
        RunResumedFromControlEventContract.model_validate({
            "type": "run_resumed_from",
            "run_id": "bg_child",
        })

    with pytest.raises(ValidationError, match="count must be non-negative"):
        EventsDroppedControlEventContract.model_validate({
            "type": "events_dropped",
            "run_id": "bg_1",
            "count": -1,
        })

    with pytest.raises(ValidationError, match="run_state_changed must use its specific control event contract"):
        FutureControlEventContract.model_validate({
            "type": "run_state_changed",
            "run_id": "bg_1",
            "state": "running",
        })


def test_control_contract_schema_route_registry_matches_runtime_predicates() -> None:
    assert set(CONTROL_RUN_ROUTE_SCHEMA_MODELS) == set(CONTROL_RUN_PAYLOAD_CONTRACT_ROUTES)
    assert set(CONTROL_RESPONSE_ROUTE_SCHEMA_MODELS) == set(CONTROL_RESPONSE_CONTRACT_ROUTES)
    assert set(CONTROL_REQUEST_ROUTE_SCHEMA_MODELS) == set(CONTROL_REQUEST_CONTRACT_ROUTES)
    assert set(CONTROL_EVENT_ROUTE_SCHEMA_MODELS) == set(CONTROL_EVENT_CONTRACT_ROUTES)

    for segments in CONTROL_RESPONSE_CONTRACT_ROUTES.values():
        assert control_response_contract_applies(segments), segments
    for segments in CONTROL_REQUEST_CONTRACT_ROUTES.values():
        assert control_request_contract_applies(segments), segments


def test_control_run_contract_normalizes_autonomous_run_envelopes() -> None:
    payload = {
        "run": {
            "kind": "autonomous",
            "run_id": "bg-1",
            "task_id": "task-1",
            "state": "running",
            "profile": "analyst",
            "mode": "task",
        },
        "run_id": "bg-1",
    }

    assert normalize_control_run_contract_payload(payload) == payload


def test_control_run_contract_validates_direct_run_payloads() -> None:
    payload = {"kind": "chat", "run_id": "sess-1", "state": "approval_pending"}

    assert normalize_control_run_contract_payload(payload) == payload


def test_control_run_contract_can_require_direct_run_payloads() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_run_contract_payload(
            {"run_id": "sess-1", "state": "running"},
            direct_run_required=True,
        )

    assert exc_info.value.issues == [
        {"path": "kind", "message": "Field required", "type": "missing"}
    ]


def test_control_run_contract_rejects_missing_state() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_run_contract_payload({"run": {"kind": "chat", "run_id": "sess-1"}})

    assert exc_info.value.issues == [
        {"path": "run.state", "message": "Field required", "type": "missing"}
    ]


def test_control_run_contract_rejects_unknown_state() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_run_contract_payload(
            {"runs": [{"kind": "chat", "run_id": "sess-1", "state": "unknown"}]}
        )

    assert exc_info.value.issues == [
        {
            "path": "runs[0].state",
            "message": "Value error, unknown control run state: unknown",
            "type": "value_error",
        }
    ]


def test_control_run_contract_validates_redacted_dispatch_scope_metadata() -> None:
    payload = {
        "run": {
            "kind": "autonomous",
            "run_id": "bg-1",
            "state": "running",
            "dispatch_scope": {
                "kind": "portfolio",
                "source": "user_selected",
                "portfolio_name": "taxable_combined",
                "portfolio_id": None,
                "display_name": "Taxable Combined",
            },
        }
    }

    assert normalize_control_run_contract_payload(payload) == payload


def test_control_run_contract_rejects_unredacted_dispatch_scope_metadata() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_run_contract_payload(
            {
                "run": {
                    "kind": "chat",
                    "run_id": "sess-1",
                    "state": "running",
                    "dispatch_scope": {
                        "kind": "portfolio",
                        "source": "user_selected",
                        "portfolio_name": "taxable_combined",
                        "account_id": "acc-1",
                    },
                }
            }
        )

    assert exc_info.value.issues == [
        {"path": "run.dispatch_scope.account_id", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}
    ]


def test_control_response_contract_accepts_approval_lists_and_preserves_extensions() -> None:
    payload = {
        "approvals": [
            {
                "approval_id": "approval-1",
                "state": "pending_user",
                "run_id": "bg-1",
                "tool_name": "write_artifact",
                "notification": {
                    "state": "sent",
                    "channels": ["telegram"],
                    "last_sent_at": "2026-07-03T15:00:50Z",
                },
            }
        ],
        "next_cursor": "cursor-1",
    }

    assert normalize_control_response_contract_payload(payload, ("approvals",)) == payload


def test_control_response_contract_rejects_missing_approval_identity() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {"approvals": [{"state": "pending_user"}]},
            ("approvals",),
        )

    assert exc_info.value.issues == [
        {
            "path": "approvals[0]",
            "message": "Value error, approval_id, pending_id, tool_call_id, or id must be a non-empty string",
            "type": "value_error",
        }
    ]


def test_control_response_contract_rejects_unsafe_approval_notification_metadata() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {
                "approvals": [
                    {
                        "approval_id": "approval-1",
                        "state": "pending_user",
                        "notification": {
                            "state": "sent",
                            "channels": ["telegram"],
                            "last_sent_at": "2026-07-03T15:00:50Z",
                            "message": "Raw notification copy must not cross this contract.",
                        },
                    }
                ]
            },
            ("approvals",),
        )

    assert exc_info.value.issues == [
        {
            "path": "approvals[0].notification.message",
            "message": "Extra inputs are not permitted",
            "type": "extra_forbidden",
        }
    ]


def test_control_response_contract_rejects_top_level_raw_approval_notification_fields() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {
                "approvals": [
                    {
                        "approval_id": "approval-1",
                        "state": "pending_user",
                        "notification_message": "Raw notification copy must not cross this contract.",
                        "notificationSubject": "Approval needed",
                        "notification_recipient": "@private_user",
                    }
                ]
            },
            ("approvals",),
        )

    assert exc_info.value.issues == [
        {
            "path": "approvals[0]",
            "message": (
                "Value error, raw notification fields are not permitted: "
                "notificationSubject, notification_message, notification_recipient"
            ),
            "type": "value_error",
        }
    ]


def test_control_response_contract_rejects_malformed_approval_notification_state() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {
                "approvals": [
                    {
                        "approval_id": "approval-1",
                        "state": "pending_user",
                        "notification": {
                            "state": "sent",
                            "channels": [],
                        },
                    }
                ]
            },
            ("approvals",),
        )

    assert exc_info.value.issues == [
        {
            "path": "approvals[0].notification",
            "message": "Value error, sent notification state requires at least one channel",
            "type": "value_error",
        }
    ]


def test_control_request_contract_accepts_empty_approval_notification_retry_body() -> None:
    assert normalize_control_request_contract_payload(
        {},
        ("runs", "bg-1", "approvals", "approval-1", "notifications", "retry"),
    ) == {}


def test_control_request_contract_rejects_approval_notification_retry_body_fields() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"notification_destination": "@private_user"},
            ("runs", "bg-1", "approvals", "approval-1", "notifications", "retry"),
        )

    assert exc_info.value.issues == [
        {
            "path": "notification_destination",
            "message": "Extra inputs are not permitted",
            "type": "extra_forbidden",
        }
    ]


def test_control_response_contract_accepts_redacted_approval_notification_retry_response() -> None:
    payload = {
        "status": "queued",
        "approval_id": "approval-1",
        "requeued": 1,
        "delivery_scheduled": False,
        "notification": {
            "state": "pending",
            "channels": ["telegram"],
        },
    }

    assert normalize_control_response_contract_payload(
        payload,
        ("runs", "bg-1", "approvals", "approval-1", "notifications", "retry"),
    ) == payload


def test_control_response_contract_rejects_unsafe_approval_notification_retry_response() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {
                "status": "queued",
                "approval_id": "approval-1",
                "requeued": 1,
                "delivery_scheduled": False,
                "notification": {
                    "state": "pending",
                    "channels": ["telegram"],
                    "message": "Raw notification copy must not cross this contract.",
                },
            },
            ("runs", "bg-1", "approvals", "approval-1", "notifications", "retry"),
        )

    assert exc_info.value.issues == [
        {
            "path": "notification.message",
            "message": "Extra inputs are not permitted",
            "type": "extra_forbidden",
        }
    ]

    with pytest.raises(ControlContractValidationError) as destination_exc_info:
        normalize_control_response_contract_payload(
            {
                "approvals": [
                    {
                        "approval_id": "approval-1",
                        "state": "pending_user",
                        "notification": {
                            "state": "sent",
                            "channels": ["telegram:@private_user"],
                        },
                    }
                ]
            },
            ("approvals",),
        )

    assert destination_exc_info.value.issues == [
        {
            "path": "approvals[0].notification.channels",
            "message": "Value error, channels must be one of: telegram, email, push",
            "type": "value_error",
        }
    ]


def test_control_response_contract_accepts_supported_approval_identity_aliases() -> None:
    payload = {
        "approvals": [
            {"approval_id": "approval-1", "state": "pending_user"},
            {"pending_id": "pending-1", "state": "pending_user"},
            {"tool_call_id": "tool-1", "state": "pending_user"},
            {"id": "id-1", "state": "pending_user"},
        ]
    }

    assert normalize_control_response_contract_payload(payload, ("approvals",)) == payload


def test_control_request_contract_accepts_approval_decisions() -> None:
    payload = {"approved": True, "allow_tool_type": False, "reason": "Reviewed from analyst control deck"}

    assert normalize_control_request_contract_payload(payload, ("runs", "bg-1", "approvals", "approval-1")) == payload


def test_control_request_contract_accepts_minimal_approval_decisions() -> None:
    payload = {"approved": False}

    assert normalize_control_request_contract_payload(payload, ("runs", "bg-1", "approvals", "approval-1")) == payload


def test_control_request_contract_accepts_nullable_approval_decision_reason() -> None:
    payload = {"approved": True, "allow_tool_type": False, "reason": None}

    assert normalize_control_request_contract_payload(payload, ("runs", "bg-1", "approvals", "approval-1")) == payload


def test_control_request_contract_rejects_string_approval_decision_bool() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"approved": "false", "allow_tool_type": False},
            ("runs", "bg-1", "approvals", "approval-1"),
        )

    assert exc_info.value.issues == [
        {"path": "approved", "message": "Input should be a valid boolean", "type": "bool_type"}
    ]


def test_control_request_contract_rejects_nullable_approval_decision_allow_tool_type() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"approved": True, "allow_tool_type": None},
            ("runs", "bg-1", "approvals", "approval-1"),
        )

    assert exc_info.value.issues == [
        {
            "path": "allow_tool_type",
            "message": "Value error, allow_tool_type must be omitted or a boolean",
            "type": "value_error",
        }
    ]


def test_control_request_contract_rejects_extra_approval_decision_fields() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"approved": True, "allow_tool_type": False, "run_id": "bg-1"},
            ("runs", "bg-1", "approvals", "approval-1"),
        )

    assert exc_info.value.issues == [
        {"path": "run_id", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}
    ]


def test_control_request_contract_accepts_chat_run_messages() -> None:
    payload = {
        "messages": [{"role": "user", "content": "Continue the run."}],
        "request_id": "web_chat_1",
        "context": {"purpose": "agent-control"},
        "model": None,
        "deadline_sec": 30,
    }

    assert normalize_control_request_contract_payload(payload, ("runs", "sess-1", "messages")) == payload


def test_control_request_contract_accepts_autonomous_run_messages() -> None:
    payload = {"message": "Check AWS exposure.", "message_id": "web_1"}

    assert normalize_control_request_contract_payload(payload, ("runs", "bg-1", "messages")) == payload


def test_control_request_contract_rejects_non_finite_chat_run_message_deadlines() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {
                "messages": [{"role": "user", "content": "Continue the run."}],
                "deadline_sec": float("nan"),
            },
            ("runs", "sess-1", "messages"),
        )

    assert exc_info.value.issues == [
        {"path": "deadline_sec", "message": "Value error, deadline_sec must be finite", "type": "value_error"}
    ]


def test_control_request_contract_rejects_ambiguous_run_messages() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {
                "messages": [{"role": "user", "content": "Continue the run."}],
                "message": "Check AWS exposure.",
            },
            ("runs", "bg-1", "messages"),
        )

    assert exc_info.value.issues == [
        {
            "path": "$",
            "message": "run message request must include either messages or message, not both",
            "type": "value_error",
        }
    ]


def test_control_request_contract_rejects_extra_run_message_fields() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {
                "messages": [{"role": "user", "content": "Continue the run."}],
                "run_id": "sess-1",
            },
            ("runs", "sess-1", "messages"),
        )

    assert exc_info.value.issues == [
        {"path": "run_id", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}
    ]


def test_control_request_contract_rejects_unknown_chat_run_message_roles() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"messages": [{"role": "tool", "content": "internal tool output"}]},
            ("runs", "sess-1", "messages"),
        )

    assert exc_info.value.issues == [
        {
            "path": "messages[0].role",
            "message": "Input should be 'user' or 'assistant'",
            "type": "literal_error",
        }
    ]


def test_control_request_contract_rejects_empty_autonomous_run_messages() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"message": "   ", "message_id": "web_1"},
            ("runs", "bg-1", "messages"),
        )

    assert exc_info.value.issues == [
        {"path": "message", "message": "Value error, message must be a non-empty string", "type": "value_error"}
    ]


def test_control_request_contract_rejects_nullable_autonomous_message_id() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"message": "Check AWS exposure.", "message_id": None},
            ("runs", "bg-1", "messages"),
        )

    assert exc_info.value.issues == [
        {
            "path": "message_id",
            "message": "Value error, message_id must be omitted or a non-empty string",
            "type": "value_error",
        }
    ]


def test_control_request_contract_rejects_extra_autonomous_run_message_kind() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"kind": "autonomous", "message": "Check AWS exposure.", "message_id": "web_1"},
            ("runs", "bg-1", "messages"),
        )

    assert exc_info.value.issues == [
        {"path": "kind", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}
    ]


def test_control_request_contract_accepts_resume_requests() -> None:
    payload = {"message": "Resume from latest safe point.", "request_id": "web_resume_1", "context": "Keep prior context."}

    assert normalize_control_request_contract_payload(payload, ("runs", "bg-1", "resume")) == payload


def test_control_request_contract_accepts_empty_resume_requests() -> None:
    assert normalize_control_request_contract_payload({}, ("runs", "bg-1", "resume")) == {}


def test_control_request_contract_accepts_agent_run_schedule_create() -> None:
    payload = _agent_run_schedule_create_payload()

    assert normalize_control_request_contract_payload(payload, ("schedules",)) == payload


def test_control_request_contract_accepts_agent_run_schedule_update() -> None:
    payload = {
        "kind": "agent_run_schedule",
        "timezone": "UTC",
        "cadence": {"type": "daily", "time_of_day": "16:00"},
        "request_id": "schedule-update-1",
    }

    assert normalize_control_request_contract_payload(payload, ("schedules", "schedule-1")) == payload


def test_control_request_contract_accepts_schedule_enabled_write() -> None:
    payload = {"enabled": False}

    assert normalize_control_request_contract_payload(
        payload,
        ("schedules", "schedule-1", "enabled"),
    ) == payload


def test_control_request_contract_accepts_schedule_run_now_empty_body() -> None:
    assert normalize_control_request_contract_payload(
        {},
        ("schedules", "schedule-1", "run-now"),
    ) == {}


def test_control_request_contract_rejects_schedule_run_now_extra_fields() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"command": ["python", "scripts/run_agent.py"]},
            ("schedules", "schedule-1", "run-now"),
        )

    assert exc_info.value.issues == [
        {"path": "command", "message": "Extra inputs are not permitted", "type": "extra_forbidden"},
    ]


def test_control_response_contract_accepts_schedule_run_now_envelope() -> None:
    payload = {
        "run": {"kind": "autonomous", "run_id": "bg_1", "state": "running"},
        "run_id": "bg_1",
        "task_id": "bg_1",
    }

    assert normalize_control_response_contract_payload(
        payload,
        ("schedules", "schedule-1", "run-now"),
    ) == payload


def test_control_response_contract_rejects_schedule_run_now_unknown_state() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {"run": {"kind": "autonomous", "run_id": "bg_1", "state": "mystery"}},
            ("schedules", "schedule-1", "run-now"),
        )

    assert exc_info.value.issues == [
        {"path": "run.state", "message": "Value error, unknown control run state: mystery", "type": "value_error"},
    ]


def test_control_request_contract_rejects_raw_schedule_create_fields() -> None:
    payload = {
        **_agent_run_schedule_create_payload(),
        "command": ["python", "scripts/run_agent.py"],
        "working_directory": "/tmp",
    }

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(payload, ("schedules",))

    assert exc_info.value.issues == [
        {"path": "command", "message": "Extra inputs are not permitted", "type": "extra_forbidden"},
        {
            "path": "working_directory",
            "message": "Extra inputs are not permitted",
            "type": "extra_forbidden",
        },
    ]


def test_control_request_contract_rejects_raw_schedule_dispatch_fields() -> None:
    payload = _agent_run_schedule_create_payload()
    payload["dispatch"] = {
        **payload["dispatch"],
        "command": ["python", "scripts/run_agent.py"],
    }

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(payload, ("schedules",))

    assert exc_info.value.issues == [
        {
            "path": "dispatch.command",
            "message": "Extra inputs are not permitted",
            "type": "extra_forbidden",
        }
    ]


def test_control_request_contract_accepts_schedule_dispatch_scope() -> None:
    payload = _agent_run_schedule_create_payload()
    payload["dispatch"] = {
        **payload["dispatch"],
        "dispatch_scope": {
            "kind": "portfolio",
            "source": "user_selected",
            "portfolio_name": "taxable_combined",
            "portfolio_id": None,
            "display_name": "Taxable Combined",
        },
    }

    assert normalize_control_request_contract_payload(payload, ("schedules",)) == payload


def test_control_request_contract_rejects_schedule_dispatch_scope_authority_fields() -> None:
    payload = _agent_run_schedule_create_payload()
    payload["dispatch"] = {
        **payload["dispatch"],
        "dispatch_scope": {
            "kind": "portfolio",
            "source": "user_selected",
            "portfolio_name": "taxable_combined",
            "account_id": "acc-1",
        },
    }

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(payload, ("schedules",))

    assert exc_info.value.issues == [
        {
            "path": "dispatch.dispatch_scope.account_id",
            "message": "Extra inputs are not permitted",
            "type": "extra_forbidden",
        }
    ]


def test_control_request_contract_rejects_invalid_schedule_kind() -> None:
    payload = {**_agent_run_schedule_create_payload(), "kind": "launchd"}

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(payload, ("schedules",))

    assert exc_info.value.issues == [
        {
            "path": "kind",
            "message": "Input should be 'agent_run_schedule'",
            "type": "literal_error",
        }
    ]


def test_control_request_contract_rejects_nullable_schedule_create_enabled() -> None:
    payload = {**_agent_run_schedule_create_payload(), "enabled": None}

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(payload, ("schedules",))

    assert exc_info.value.issues == [
        {
            "path": "enabled",
            "message": "Value error, enabled must be omitted or a boolean",
            "type": "value_error",
        }
    ]


def test_control_request_contract_rejects_nullable_schedule_update_fields() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"kind": "agent_run_schedule", "name": None, "enabled": True},
            ("schedules", "schedule-1"),
        )

    assert exc_info.value.issues == [
        {
            "path": "name",
            "message": "Value error, name must be omitted or a concrete value",
            "type": "value_error",
        }
    ]


def test_control_request_contract_rejects_empty_schedule_update() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"kind": "agent_run_schedule", "request_id": "schedule-update-1"},
            ("schedules", "schedule-1"),
        )

    assert exc_info.value.issues == [
        {
            "path": "$",
            "message": "Value error, schedule update must include at least one mutable field",
            "type": "value_error",
        }
    ]


def test_control_request_contract_rejects_string_schedule_enabled_flag() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"enabled": "false"},
            ("schedules", "schedule-1", "enabled"),
        )

    assert exc_info.value.issues == [
        {
            "path": "enabled",
            "message": "Input should be a valid boolean",
            "type": "bool_type",
        }
    ]


def test_control_request_contract_rejects_extra_resume_fields() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"message": "Resume from latest safe point.", "request_id": "web_resume_1", "run_id": "bg-1"},
            ("runs", "bg-1", "resume"),
        )

    assert exc_info.value.issues == [
        {"path": "run_id", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}
    ]


def test_control_request_contract_rejects_resume_context_objects() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {"message": "Resume from latest safe point.", "context": {"note": "ok"}},
            ("runs", "bg-1", "resume"),
        )

    assert exc_info.value.issues == [
        {"path": "context", "message": "Input should be a valid string", "type": "string_type"}
    ]


def test_control_request_contract_leaves_unscoped_payloads_unchanged() -> None:
    payload = {"approved": "false", "run_id": "bg-1"}

    assert normalize_control_request_contract_payload(payload, ("runs", "bg-1")) == payload


def test_control_request_contract_accepts_autonomous_dispatch_scope() -> None:
    payload = {
        "kind": "autonomous",
        "profile": "analyst",
        "mode": "task",
        "task": "Check AWS exposure.",
        "dispatch_scope": {
            "kind": "portfolio",
            "source": "user_selected",
            "portfolio_name": "taxable_combined",
            "portfolio_id": None,
            "display_name": "Taxable Combined",
        },
    }

    assert normalize_control_request_contract_payload(payload, ("runs",)) == payload


def test_control_request_contract_accepts_chat_dispatch_scope() -> None:
    payload = {
        "kind": "chat",
        "message": "Start a read-only portfolio chat.",
        "ticker": "MSFT",
        "context": {"keep": True},
        "dispatch_scope": {
            "kind": "portfolio",
            "source": "active_default",
            "portfolio_name": "core",
            "display_name": "Core Portfolio",
        },
    }

    assert normalize_control_request_contract_payload(payload, ("runs",)) == payload


def test_control_request_contract_rejects_dispatch_scope_authority_fields() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "task",
                "task": "Check AWS exposure.",
                "dispatch_scope": {
                    "kind": "portfolio",
                    "source": "user_selected",
                    "portfolio_name": "taxable_combined",
                    "account_id": "acc-1",
                },
            },
            ("runs",),
        )

    assert exc_info.value.issues == [
        {"path": "dispatch_scope.account_id", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}
    ]


def test_control_request_contract_rejects_chat_context_authority_fields() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {
                "kind": "chat",
                "message": "Start a read-only portfolio chat.",
                "context": {
                    "keep": True,
                    "portfolio_name": "taxable_combined",
                },
            },
            ("runs",),
        )

    assert exc_info.value.issues == [
        {
            "path": "context.portfolio_name",
            "message": (
                "context must not include portfolio, account, owner, credential, token, "
                "route, or channel authority fields"
            ),
            "type": "value_error",
        }
    ]


def test_control_request_contract_rejects_dispatch_channel_claims() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "task",
                "task": "Check AWS exposure.",
                "channel": "web",
            },
            ("runs",),
        )

    assert exc_info.value.issues == [
        {"path": "channel", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}
    ]


def test_control_request_contract_rejects_display_only_dispatch_scope() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {
                "kind": "chat",
                "message": "Start a read-only portfolio chat.",
                "dispatch_scope": {
                    "kind": "portfolio",
                    "source": "user_selected",
                    "display_name": "Taxable Combined",
                },
            },
            ("runs",),
        )

    assert exc_info.value.issues == [
        {"path": "dispatch_scope.portfolio_name", "message": "Field required", "type": "missing"}
    ]


def test_control_request_contract_rejects_unknown_dispatch_kind() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload({"kind": "scheduled", "task": "Check AWS exposure."}, ("runs",))

    assert exc_info.value.issues == [
        {"path": "kind", "message": "dispatch request kind must be chat or autonomous", "type": "value_error"}
    ]


def test_control_request_contract_rejects_raw_dispatch_authority_fields() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_request_contract_payload(
            {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "task",
                "task": "Check AWS exposure.",
                "owner_user_id": "999",
            },
            ("runs",),
        )

    assert exc_info.value.issues == [
        {"path": "owner_user_id", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}
    ]


def test_control_response_contract_accepts_artifact_lists_with_either_identity_field() -> None:
    payload = {
        "artifacts": [
            {
                "artifact_id": "artifact-1",
                "contract_name": "HtmlArtifact",
                "control_run_id": "bg-1",
                "skill_run_id": "skill-run-1",
            },
            {
                "id": "artifact-2",
                "contract_name": "DashboardArtifact",
                "control_run_id": "bg-1",
                "skill_run_id": "skill-run-2",
            },
        ]
    }

    assert normalize_control_response_contract_payload(payload, ("artifacts",)) == payload


def test_control_response_contract_rejects_artifacts_without_identity() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {"artifacts": [{"contract_name": "HtmlArtifact"}]},
            ("artifacts",),
        )

    assert exc_info.value.issues == [
        {
            "path": "artifacts[0]",
            "message": "Value error, artifact_id or id must be a non-empty string",
            "type": "value_error",
        }
    ]


def test_control_response_contract_accepts_readable_resource_lists_and_detail() -> None:
    resource = _readable_resource_payload()
    detail = _readable_resource_payload(content="## Daily note\n\nCaptured markdown.")

    assert normalize_control_response_contract_payload(
        {"readable_resources": [resource], "next_cursor": "cursor-1"},
        ("readable-resources",),
    ) == {"readable_resources": [resource], "next_cursor": "cursor-1"}
    assert normalize_control_response_contract_payload(
        detail,
        ("readable-resources", detail["resource_id"]),
    ) == detail


def test_control_response_contract_rejects_readable_resources_without_provenance() -> None:
    resource = _readable_resource_payload()
    resource.pop("control_run_id")

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload({"readable_resources": [resource]}, ("readable-resources",))

    assert exc_info.value.issues == [
        {
            "path": "readable_resources[0]",
            "message": (
                "Value error, control_run_id, run_id, session_id, or task_id must identify "
                "the owning control run"
            ),
            "type": "value_error",
        }
    ]


def test_control_response_contract_rejects_readable_resource_id_mismatch() -> None:
    resource = _readable_resource_payload(content="## Daily note")

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(resource, ("readable-resources", "note:bg-2:daily"))

    assert exc_info.value.issues == [
        {"path": "resource_id", "message": "resource_id must match requested readable resource id", "type": "value_error"}
    ]


def test_control_response_contract_rejects_readable_resource_content_in_list() -> None:
    resource = {**_readable_resource_payload(), "content": "## Daily note"}

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload({"readable_resources": [resource]}, ("readable-resources",))

    assert exc_info.value.issues == [
        {"path": "readable_resources[0].content", "message": "Extra inputs are not permitted", "type": "extra_forbidden"}
    ]


def test_control_response_contract_rejects_readable_resource_bad_snapshot_metadata() -> None:
    resource = _readable_resource_payload(content_sha256="not-a-sha", content="## Daily note")

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(resource, ("readable-resources", resource["resource_id"]))

    assert exc_info.value.issues == [
        {
            "path": "content_sha256",
            "message": "Value error, content_sha256 must be a 64-character hex digest",
            "type": "value_error",
        }
    ]


def test_control_response_contract_rejects_readable_resource_snapshot_mismatch() -> None:
    resource = _readable_resource_payload(content="## Daily note", content_sha256="b" * 64, content_bytes=999)

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(resource, ("readable-resources", resource["resource_id"]))

    assert exc_info.value.issues == [
        {
            "path": "content",
            "message": "Value error, content byte length must match content_bytes",
            "type": "value_error",
        }
    ]

    sha_resource = _readable_resource_payload(content="## Daily note", content_sha256="b" * 64)

    with pytest.raises(ControlContractValidationError) as sha_exc_info:
        normalize_control_response_contract_payload(sha_resource, ("readable-resources", sha_resource["resource_id"]))

    assert sha_exc_info.value.issues == [
        {
            "path": "content",
            "message": "Value error, content sha256 digest must match content_sha256",
            "type": "value_error",
        }
    ]


def test_control_response_contract_rejects_readable_resource_unsafe_resource_id() -> None:
    resource = _readable_resource_payload(resource_id="note/bg-1/daily", content="## Daily note")

    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(resource, ("readable-resources", resource["resource_id"]))

    assert exc_info.value.issues == [
        {
            "path": "resource_id",
            "message": "Value error, resource_id must be an opaque route-safe path segment",
            "type": "value_error",
        }
    ]


def test_control_response_contract_accepts_run_logs() -> None:
    payload = {"run_id": "bg-1", "log_lines": ["line 1", "line 2"], "more_available": False}

    assert normalize_control_response_contract_payload(payload, ("runs", "bg-1", "logs")) == payload


def test_control_response_contract_accepts_schedule_lists_with_identity_aliases() -> None:
    payload = {
        "schedules": [
            {"schedule_id": "schedule-1", "enabled": True},
            {"id": "schedule-2", "enabled": False},
            {"name": "Nightly review"},
            {"label": "Manual QA fixture"},
            {"id": 123, "name": "Daily close"},
        ],
        "next_cursor": "cursor-1",
    }

    assert normalize_control_response_contract_payload(payload, ("schedules",)) == payload


def test_control_response_contract_projects_schedule_rows_to_browser_safe_fields() -> None:
    payload = {
        "schedules": [
            {
                "schedule_id": "schedule-1",
                "name": "Daily model refresh",
                "source": "launchd",
                "enabled": True,
                "profile": "analyst",
                "ticker": "MSFT",
                "schedule_description": "Weekdays at 6:30 PM",
                "next_run_at": "2026-06-02T18:30:00Z",
                "owned_by_current_user": True,
                "can_edit": False,
                "command": ["python", "scripts/run_agent.py"],
                "working_directory": "/Users/example/project",
                "log_file": "/tmp/agent.log",
                "launchd_label": "com.example.agent",
                "plist": {"ProgramArguments": ["python", "scripts/run_agent.py"]},
                "environment": {"SECRET_TOKEN": "do-not-forward"},
                "job_params": {"raw": True},
                "params": {"command": "python scripts/run_agent.py"},
            },
        ],
        "next_cursor": "cursor-1",
    }

    assert normalize_control_response_contract_payload(payload, ("schedules",)) == {
        "schedules": [
            {
                "schedule_id": "schedule-1",
                "name": "Daily model refresh",
                "source": "launchd",
                "enabled": True,
                "profile": "analyst",
                "ticker": "MSFT",
                "schedule_description": "Weekdays at 6:30 PM",
                "next_run_at": "2026-06-02T18:30:00Z",
                "owned_by_current_user": True,
                "can_edit": False,
            },
        ],
        "next_cursor": "cursor-1",
    }


def test_control_response_contract_projects_agent_run_schedule_detail() -> None:
    payload = {
        "schedule": {
            "schedule_id": "schedule-1",
            "name": "weekday-nvda-earnings-watch",
            "kind": "agent_run_schedule",
            "enabled": True,
            "timezone": "America/New_York",
            "cadence": {
                "type": "weekly",
                "days_of_week": [1, 2, 3, 4, 5],
                "time_of_day": "08:30",
            },
            "dispatch": {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "earnings-review",
                "ticker": "NVDA",
                "context": "Review new earnings/news and report material changes.",
            },
            "command": ["python", "scripts/run_agent.py"],
            "working_directory": "/tmp",
        },
        "audit": {"created_by": "server"},
    }

    assert normalize_control_response_contract_payload(payload, ("schedules", "schedule-1")) == {
        "schedule": {
            "schedule_id": "schedule-1",
            "name": "weekday-nvda-earnings-watch",
            "kind": "agent_run_schedule",
            "enabled": True,
            "timezone": "America/New_York",
            "cadence": {
                "type": "weekly",
                "days_of_week": [1, 2, 3, 4, 5],
                "time_of_day": "08:30",
            },
            "dispatch": {
                "kind": "autonomous",
                "profile": "analyst",
                "mode": "skill",
                "skill": "earnings-review",
                "ticker": "NVDA",
                "context": "Review new earnings/news and report material changes.",
            },
        }
    }


def test_control_response_contract_projects_schedule_delete_raw_schedule_response() -> None:
    payload = {
        "schedule_id": "schedule-1",
        "name": "weekday-nvda-earnings-watch",
        "kind": "agent_run_schedule",
        "enabled": False,
        "timezone": "UTC",
        "command": ["python", "scripts/run_agent.py"],
        "environment": {"SECRET_TOKEN": "do-not-forward"},
    }

    assert normalize_control_response_contract_payload(
        payload,
        ("schedules", "schedule-1", "delete"),
    ) == {
        "schedule_id": "schedule-1",
        "name": "weekday-nvda-earnings-watch",
        "kind": "agent_run_schedule",
        "enabled": False,
        "timezone": "UTC",
    }


def test_control_response_contract_projects_schedule_delete_ack_response() -> None:
    payload = {
        "deleted": True,
        "schedule_id": "schedule-1",
        "command": ["python", "scripts/run_agent.py"],
        "working_directory": "/tmp",
        "environment": {"SECRET_TOKEN": "do-not-forward"},
    }

    assert normalize_control_response_contract_payload(
        payload,
        ("schedules", "schedule-1", "delete"),
    ) == {
        "deleted": True,
        "schedule_id": "schedule-1",
    }


def test_control_response_contract_rejects_schedules_without_identity() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {"schedules": [{"enabled": True}]},
            ("schedules",),
        )

    assert exc_info.value.issues == [
        {
            "path": "schedules[0]",
            "message": "Value error, schedule_id, id, name, or label must be a non-empty string",
            "type": "value_error",
        }
    ]


def test_control_response_contract_rejects_invalid_run_logs() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {"run_id": "bg-1", "log_lines": "line 1", "more_available": False},
            ("runs", "bg-1", "logs"),
        )

    assert exc_info.value.issues == [
        {"path": "log_lines", "message": "Input should be a valid list", "type": "list_type"}
    ]


def test_control_response_contract_requires_strict_run_logs_more_available_bool() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {"run_id": "bg-1", "log_lines": ["line 1"], "more_available": "false"},
            ("runs", "bg-1", "logs"),
        )

    assert exc_info.value.issues == [
        {"path": "more_available", "message": "Input should be a valid boolean", "type": "bool_type"}
    ]


def test_control_response_contract_rejects_mismatched_run_logs_identity() -> None:
    with pytest.raises(ControlContractValidationError) as exc_info:
        normalize_control_response_contract_payload(
            {"run_id": "bg-2", "log_lines": ["line 1"], "more_available": False},
            ("runs", "bg-1", "logs"),
        )

    assert exc_info.value.issues == [
        {"path": "run_id", "message": "run_id must match requested control run id", "type": "value_error"}
    ]


def test_control_response_contract_leaves_unscoped_payloads_unchanged() -> None:
    payload = {"profiles": [{"name": "analyst"}]}

    assert normalize_control_response_contract_payload(payload, ("profiles",)) == payload
