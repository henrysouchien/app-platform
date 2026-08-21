"""Typed contracts for Agent Control payloads proxied by the gateway."""

from __future__ import annotations

import copy
import hashlib
import math
import re
from typing import Any, Literal, TypeAlias
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    BaseModel,
    ConfigDict,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    ValidationError,
    ValidationInfo,
    field_validator,
    model_validator,
    RootModel,
)
from pydantic.json_schema import SkipJsonSchema

from .control_run_lifecycle import (
    CONTROL_ACTIVE_RUN_STATES,
    CONTROL_CANCELLABLE_RUN_STATES,
    CONTROL_CHAT_MESSAGEABLE_RUN_STATES,
    CONTROL_RESUMABLE_RUN_STATES,
    CONTROL_RUN_CONTRACT_VERSION,
    CONTROL_RUN_STATE_CLASSIFICATION,
    CONTROL_TERMINAL_RUN_STATES,
    is_control_run_state,
)

SkillTextListValue: TypeAlias = StrictStr | list[StrictStr]
SkillNumericValue: TypeAlias = StrictInt | StrictFloat

CONTROL_REQUEST_CONTRACT_VERSION = "control-request-v1"
CONTROL_RESPONSE_CONTRACT_VERSION = "control-response-v1"
CONTROL_EVENT_CONTRACT_VERSION = "control-event-v1"
CONTROL_CONTRACT_SCHEMA_BUNDLE_VERSION = "agent-control-contracts-v1"
_CONTROL_CONTEXT_AUTHORITY_FIELDS = frozenset(
    {
        "account_id",
        "account_ids",
        "api_key",
        "auth",
        "authorization",
        "channel",
        "credential",
        "credential_id",
        "credential_ids",
        "credentials",
        "email",
        "owner_id",
        "owner_user_id",
        "portfolio",
        "portfolio_id",
        "portfolio_name",
        "refresh_token",
        "risk_user_id",
        "route",
        "route_id",
        "token",
        "user_email",
        "user_id",
    }
)
_APPROVAL_NOTIFICATION_FORBIDDEN_EXTRA_FIELDS = frozenset(
    {
        "notification_body",
        "notification_copy",
        "notification_decision_url",
        "notification_destination",
        "notification_destinations",
        "notification_message",
        "notification_payload",
        "notification_text",
        "notification_url",
    }
)
_APPROVAL_NOTIFICATION_CHANNELS = ("telegram", "email", "push")

CONTROL_RUN_PAYLOAD_CONTRACT_ROUTES = (
    "GET /control/runs",
    "GET /control/runs/{run_id}",
    "POST /control/runs",
    "DELETE /control/runs/{run_id}",
    "POST /control/runs/{run_id}/messages",
    "POST /control/runs/{run_id}/resume",
)
CONTROL_NON_DIRECT_RUN_ROUTE_SCHEMA_MODELS = [
    "ControlRunListContract",
    "ControlRunEnvelopeContract",
    "ControlRunContract",
]
CONTROL_DIRECT_RUN_ROUTE_SCHEMA_MODELS = [
    "ControlRunContract",
    "ControlRunEnvelopeContract",
]
CONTROL_RUN_ROUTE_SCHEMA_MODELS: dict[str, str | list[str]] = {
    "GET /control/runs": CONTROL_NON_DIRECT_RUN_ROUTE_SCHEMA_MODELS,
    "GET /control/runs/{run_id}": [
        *CONTROL_DIRECT_RUN_ROUTE_SCHEMA_MODELS,
    ],
    "POST /control/runs": CONTROL_NON_DIRECT_RUN_ROUTE_SCHEMA_MODELS,
    "DELETE /control/runs/{run_id}": [
        *CONTROL_DIRECT_RUN_ROUTE_SCHEMA_MODELS,
    ],
    "POST /control/runs/{run_id}/messages": CONTROL_NON_DIRECT_RUN_ROUTE_SCHEMA_MODELS,
    "POST /control/runs/{run_id}/resume": CONTROL_NON_DIRECT_RUN_ROUTE_SCHEMA_MODELS,
}
CONTROL_RESPONSE_CONTRACT_ROUTES: dict[str, tuple[str, ...]] = {
    "GET /control/approvals": ("approvals",),
    "POST /control/runs/{run_id}/approvals/{approval_id}/notifications/retry": (
        "runs",
        "{run_id}",
        "approvals",
        "{approval_id}",
        "notifications",
        "retry",
    ),
    "GET /control/artifacts": ("artifacts",),
    "GET /control/readable-resources": ("readable-resources",),
    "GET /control/readable-resources/{resource_id}": ("readable-resources", "{resource_id}"),
    "GET /control/skills": ("skills",),
    "GET /control/schedules": ("schedules",),
    "GET /control/schedules/{schedule_id}": ("schedules", "{schedule_id}"),
    "POST /control/schedules": ("schedules", "{schedule_id}"),
    "PATCH /control/schedules/{schedule_id}": ("schedules", "{schedule_id}"),
    "PUT /control/schedules/{schedule_id}/enabled": ("schedules", "{schedule_id}"),
    "POST /control/schedules/{schedule_id}/run-now": (
        "schedules",
        "{schedule_id}",
        "run-now",
    ),
    "DELETE /control/schedules/{schedule_id}": ("schedules", "{schedule_id}", "delete"),
    "GET /control/runs/{run_id}/logs": ("runs", "{run_id}", "logs"),
}
CONTROL_REQUEST_CONTRACT_ROUTES: dict[str, tuple[str, ...]] = {
    "POST /control/runs": ("runs",),
    "POST /control/schedules": ("schedules",),
    "PATCH /control/schedules/{schedule_id}": ("schedules", "{schedule_id}"),
    "PUT /control/schedules/{schedule_id}/enabled": (
        "schedules",
        "{schedule_id}",
        "enabled",
    ),
    "POST /control/schedules/{schedule_id}/run-now": (
        "schedules",
        "{schedule_id}",
        "run-now",
    ),
    "POST /control/runs/{run_id}/approvals/{approval_id}": (
        "runs",
        "{run_id}",
        "approvals",
        "{approval_id}",
    ),
    "POST /control/runs/{run_id}/approvals/{approval_id}/notifications/retry": (
        "runs",
        "{run_id}",
        "approvals",
        "{approval_id}",
        "notifications",
        "retry",
    ),
    "POST /control/runs/{run_id}/messages": ("runs", "{run_id}", "messages"),
    "POST /control/runs/{run_id}/resume": ("runs", "{run_id}", "resume"),
}
CONTROL_RESPONSE_ROUTE_SCHEMA_MODELS: dict[str, str | list[str]] = {
    "GET /control/approvals": "ApprovalListContract",
    "POST /control/runs/{run_id}/approvals/{approval_id}/notifications/retry": (
        "ApprovalNotificationRetryResponseContract"
    ),
    "GET /control/artifacts": "ArtifactListContract",
    "GET /control/readable-resources": "ReadableResourceListContract",
    "GET /control/readable-resources/{resource_id}": "ReadableResourceDetailContract",
    "GET /control/skills": "SkillListContract",
    "GET /control/schedules": "ScheduleListContract",
    "GET /control/schedules/{schedule_id}": [
        "ControlScheduleContract",
        "ScheduleEnvelopeContract",
    ],
    "POST /control/schedules": [
        "ControlScheduleContract",
        "ScheduleEnvelopeContract",
    ],
    "PATCH /control/schedules/{schedule_id}": [
        "ControlScheduleContract",
        "ScheduleEnvelopeContract",
    ],
    "PUT /control/schedules/{schedule_id}/enabled": [
        "ControlScheduleContract",
        "ScheduleEnvelopeContract",
    ],
    "POST /control/schedules/{schedule_id}/run-now": "ControlRunEnvelopeContract",
    "DELETE /control/schedules/{schedule_id}": [
        "ControlScheduleContract",
        "ScheduleEnvelopeContract",
        "ScheduleDeleteResponseContract",
    ],
    "GET /control/runs/{run_id}/logs": "RunLogsContract",
}
CONTROL_REQUEST_ROUTE_SCHEMA_MODELS: dict[str, str | list[str]] = {
    "POST /control/runs": [
        "ChatRunDispatchRequestContract",
        "AutonomousRunDispatchRequestContract",
    ],
    "POST /control/schedules": "AgentRunScheduleCreateRequestContract",
    "PATCH /control/schedules/{schedule_id}": "AgentRunScheduleUpdateRequestContract",
    "PUT /control/schedules/{schedule_id}/enabled": "ScheduleEnabledRequestContract",
    "POST /control/schedules/{schedule_id}/run-now": "ScheduleRunNowRequestContract",
    "POST /control/runs/{run_id}/approvals/{approval_id}": "ApprovalDecisionRequestContract",
    "POST /control/runs/{run_id}/approvals/{approval_id}/notifications/retry": (
        "ApprovalNotificationRetryRequestContract"
    ),
    "POST /control/runs/{run_id}/messages": [
        "ChatRunMessageRequestContract",
        "AutonomousRunMessageRequestContract",
    ],
    "POST /control/runs/{run_id}/resume": "ResumeRunRequestContract",
}
CONTROL_EVENT_CONTRACT_ROUTES = (
    "GET /control/events",
)
CONTROL_KNOWN_EVENT_TYPES = frozenset({
    "events_dropped",
    "parent_message_sent",
    "replay_truncated",
    "run_resumed",
    "run_resumed_from",
    "run_state_changed",
    "state_changed",
    "text_delta",
})
CONTROL_EVENT_ROUTE_SCHEMA_MODELS: dict[str, dict[str, str | list[str]]] = {
    "GET /control/events": {
        "projected_envelope": "ControlEventEnvelopeContract",
        "event_payload": "ControlEventPayloadContract",
        "known_event_payloads": [
            "RunStateChangedControlEventContract",
            "TextDeltaControlEventContract",
            "ParentMessageSentControlEventContract",
            "RunResumedControlEventContract",
            "RunResumedFromControlEventContract",
            "EventsDroppedControlEventContract",
            "ReplayTruncatedControlEventContract",
        ],
        "future_event_payload": "FutureControlEventContract",
    },
}
CONTROL_EVENT_PAYLOAD_SCHEMA_MODELS = [
    "RunStateChangedControlEventContract",
    "TextDeltaControlEventContract",
    "ParentMessageSentControlEventContract",
    "RunResumedControlEventContract",
    "RunResumedFromControlEventContract",
    "EventsDroppedControlEventContract",
    "ReplayTruncatedControlEventContract",
    "FutureControlEventContract",
]
CONTROL_EVENT_PAYLOAD_ROUTE_SCHEMA_MODELS = [
    "ControlEventPayloadContract",
    *CONTROL_EVENT_PAYLOAD_SCHEMA_MODELS,
]
CONTROL_EVENT_ROUTE_SCHEMA_MODEL_NAMES = [
    "ControlEventEnvelopeContract",
    "ControlEventPayloadContract",
    "FutureControlEventContract",
    *[
        model_name
        for model_name in CONTROL_EVENT_PAYLOAD_SCHEMA_MODELS
        if model_name != "FutureControlEventContract"
    ],
]
CONTROL_EVENT_OWNER_FIELDS = (
    "control_run_id",
    "run_id",
    "session_id",
    "task_id",
    "skill_run_id",
)
CONTROL_SCHEDULE_BROWSER_SAFE_FIELDS = frozenset({
    "schedule_id",
    "id",
    "name",
    "label",
    "kind",
    "enabled",
    "state",
    "source",
    "profile",
    "skill",
    "task",
    "ticker",
    "run_id",
    "last_run_id",
    "schedule_description",
    "description",
    "cadence_summary",
    "timezone",
    "last_exit_status",
    "last_run_at",
    "next_run_at",
    "created_at",
    "updated_at",
    "owned_by_current_user",
    "editable",
    "can_edit",
    "can_delete",
    "can_enable",
    "can_disable",
    "can_run_now",
})
CONTROL_SKILL_BROWSER_SAFE_FIELDS = frozenset({
    "name",
    "label",
    "display_label",
    "displayLabel",
    "title",
    "description",
    "agent_description",
    "summary",
    "version",
    "scope",
    "catalog",
    "product_visible",
    "productVisible",
    "catalog_visible",
    "catalogVisible",
    "visible_in_catalog",
    "visibleInCatalog",
    "visible",
    "agent_callable",
    "agentCallable",
    "can_launch",
    "canLaunch",
    "can_schedule",
    "canSchedule",
    "schedule_eligible",
    "scheduleEligible",
    "blocked_reason",
    "blockedReason",
    "disabled_reason",
    "disabledReason",
    "resumable",
    "requires_portfolio",
    "requiresPortfolio",
    "requires_portfolio_context",
    "requiresPortfolioContext",
    "portfolio_required",
    "portfolioRequired",
    "required_context",
    "requiredContext",
    "required_inputs",
    "requiredInputs",
    "context_requirements",
    "contextRequirements",
    "input_requirements",
    "inputRequirements",
    "requirements",
    "inputs",
    "profile",
    "profiles",
    "compatible_profiles",
    "compatibleProfiles",
    "mode",
    "modes",
    "compatible_modes",
    "compatibleModes",
    "outputs",
    "output_types",
    "outputTypes",
    "action_class",
    "actionClass",
    "approval_policy",
    "approvalPolicy",
    "tier",
    "tier_availability",
    "tierAvailability",
    "credential_requirements",
    "credentialRequirements",
    "max_turns",
    "max_budget_usd",
    "persist_state",
    "typed_contract",
})
_SCHEDULE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_TIME_OF_DAY_RE = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")
_TICKER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.\-]{0,31}$")


class ControlContractValidationError(Exception):
    """Raised when an upstream Agent Control payload breaks the proxy contract."""

    def __init__(self, issues: list[dict[str, str]]) -> None:
        self.issues = issues
        super().__init__("Agent Control payload did not match the typed control-plane contract.")


class DispatchScopeContract(BaseModel):
    """Browser-safe structured scope for a control-plane dispatch."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["portfolio"]
    source: Literal["active_default", "user_selected"]
    portfolio_name: StrictStr
    portfolio_id: StrictStr | None = None
    display_name: StrictStr | None = None

    @field_validator("portfolio_name")
    @classmethod
    def _validate_portfolio_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("portfolio_name must be a non-empty string")
        if len(value) > 256:
            raise ValueError("portfolio_name must be 256 characters or fewer")
        return value

    @field_validator("portfolio_id", "display_name")
    @classmethod
    def _validate_optional_scope_string(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError(f"{info.field_name} must be omitted, null, or a non-empty string")
        if len(value) > 256:
            raise ValueError(f"{info.field_name} must be 256 characters or fewer")
        return value


class ControlRunContract(BaseModel):
    """Shared minimum contract for control runs crossing the gateway boundary."""

    model_config = ConfigDict(extra="allow")

    kind: Literal["chat", "autonomous"]
    run_id: str
    state: str
    dispatch_scope: DispatchScopeContract | None = None

    @field_validator("run_id", "state", mode="before")
    @classmethod
    def _require_non_empty_string(cls, value: Any, info: ValidationInfo) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        return value

    @field_validator("state")
    @classmethod
    def _require_known_state(cls, value: str) -> str:
        if not is_control_run_state(value):
            raise ValueError(f"unknown control run state: {value}")
        return value


class ControlRunListContract(BaseModel):
    """Shared minimum contract for control run list responses."""

    model_config = ConfigDict(extra="allow")

    runs: list[ControlRunContract]


class ControlRunEnvelopeContract(BaseModel):
    """Shared minimum contract for control run response envelopes."""

    model_config = ConfigDict(extra="allow")

    run: ControlRunContract


def _control_event_string_value(model: BaseModel, field_name: str) -> str | None:
    value = getattr(model, field_name, None)
    if not isinstance(value, str):
        extra = getattr(model, "__pydantic_extra__", None) or {}
        value = extra.get(field_name)
    return value.strip() if isinstance(value, str) and value.strip() else None


def _control_event_has_string(model: BaseModel, fields: tuple[str, ...]) -> bool:
    return any(_control_event_string_value(model, field_name) is not None for field_name in fields)


def _control_event_require_owner(model: BaseModel, event_type: str) -> None:
    if not _control_event_has_string(model, CONTROL_EVENT_OWNER_FIELDS):
        raise ValueError(f"{event_type} must include a run owner id")


def _require_non_empty_event_string(value: str | None, info: ValidationInfo) -> str | None:
    if value is not None and not value.strip():
        raise ValueError(f"{info.field_name} must be omitted, null, or a non-empty string")
    return value


class ControlEventContract(BaseModel):
    """Shared minimum contract for raw Agent Control events."""

    model_config = ConfigDict(extra="allow")

    type: StrictStr
    control_run_id: StrictStr | None = None
    run_id: StrictStr | None = None
    session_id: StrictStr | None = None
    task_id: StrictStr | None = None
    skill_run_id: StrictStr | None = None
    state: StrictStr | None = None
    ts: StrictInt | StrictFloat | None = None

    @field_validator("type")
    @classmethod
    def _require_event_type(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("type must be a non-empty string")
        return value.strip()

    @field_validator("control_run_id", "run_id", "session_id", "task_id", "skill_run_id", "state")
    @classmethod
    def _validate_optional_event_string(cls, value: str | None, info: ValidationInfo) -> str | None:
        return _require_non_empty_event_string(value, info)


class RunStateChangedControlEventContract(ControlEventContract):
    """Run state transition event contract."""

    type: Literal["run_state_changed", "state_changed"]
    state: StrictStr

    @field_validator("state")
    @classmethod
    def _require_canonical_state(cls, value: str) -> str:
        if not is_control_run_state(value):
            raise ValueError(f"unknown control run state: {value}")
        return value

    @model_validator(mode="after")
    def _require_owner(self) -> "RunStateChangedControlEventContract":
        _control_event_require_owner(self, str(self.type))
        return self


class TextDeltaControlEventContract(ControlEventContract):
    """Text delta event contract, accepting both raw text and content aliases."""

    type: Literal["text_delta"]
    text: StrictStr | None = None
    content: StrictStr | None = None

    @model_validator(mode="after")
    def _require_owner_and_text(self) -> "TextDeltaControlEventContract":
        _control_event_require_owner(self, "text_delta")
        if self.text is None and self.content is None:
            raise ValueError("text_delta must include text content")
        return self


class ParentMessageSentControlEventContract(ControlEventContract):
    """Operator/parent message event contract."""

    type: Literal["parent_message_sent"]
    message: StrictStr | None = None
    content: StrictStr | None = None
    text: StrictStr | None = None

    @field_validator("message", "content", "text")
    @classmethod
    def _validate_optional_message_text(cls, value: str | None, info: ValidationInfo) -> str | None:
        return _require_non_empty_event_string(value, info)

    @model_validator(mode="after")
    def _require_owner_and_message(self) -> "ParentMessageSentControlEventContract":
        _control_event_require_owner(self, "parent_message_sent")
        if not _control_event_has_string(self, ("message", "content", "text")):
            raise ValueError("parent_message_sent must include message content")
        return self


class RunResumedControlEventContract(ControlEventContract):
    """Resume event recorded on the original run."""

    type: Literal["run_resumed"]
    resumed_run_id: StrictStr | None = None
    resumed_as: StrictStr | None = None
    resumed_task_id: StrictStr | None = None
    request_id: StrictStr | None = None

    @field_validator("resumed_run_id", "resumed_as", "resumed_task_id", "request_id")
    @classmethod
    def _validate_resume_string(cls, value: str | None, info: ValidationInfo) -> str | None:
        return _require_non_empty_event_string(value, info)

    @model_validator(mode="after")
    def _require_owner_and_resume_target(self) -> "RunResumedControlEventContract":
        _control_event_require_owner(self, "run_resumed")
        if not _control_event_has_string(self, ("resumed_run_id", "resumed_as", "resumed_task_id")):
            raise ValueError("run_resumed must include resumed_run_id or resumed_as")
        return self


class RunResumedFromControlEventContract(ControlEventContract):
    """Resume event recorded on the continuation run."""

    type: Literal["run_resumed_from"]
    resumed_from: StrictStr | None = None
    resumed_from_run_id: StrictStr | None = None
    resumed_from_task_id: StrictStr | None = None
    request_id: StrictStr | None = None

    @field_validator("resumed_from", "resumed_from_run_id", "resumed_from_task_id", "request_id")
    @classmethod
    def _validate_resumed_from_string(cls, value: str | None, info: ValidationInfo) -> str | None:
        return _require_non_empty_event_string(value, info)

    @model_validator(mode="after")
    def _require_owner_and_resume_source(self) -> "RunResumedFromControlEventContract":
        _control_event_require_owner(self, "run_resumed_from")
        if not _control_event_has_string(self, ("resumed_from", "resumed_from_run_id", "resumed_from_task_id")):
            raise ValueError("run_resumed_from must include resumed_from")
        return self


class EventsDroppedControlEventContract(ControlEventContract):
    """Visible sentinel for malformed or queue-dropped Agent Control events."""

    type: Literal["events_dropped"]
    count: StrictInt | StrictFloat | None = None
    dropped_through_seq: StrictInt | None = None
    oldest_ts: StrictInt | StrictFloat | None = None
    reason: StrictStr | None = None
    message: StrictStr | None = None
    source_type: StrictStr | None = None
    issues: list[StrictStr] | None = None

    @field_validator("count", "oldest_ts")
    @classmethod
    def _require_finite_number(cls, value: int | float | None, info: ValidationInfo) -> int | float | None:
        if value is not None and not math.isfinite(float(value)):
            raise ValueError(f"{info.field_name} must be finite")
        if info.field_name == "count" and value is not None and value < 0:
            raise ValueError("count must be non-negative")
        return value

    @field_validator("dropped_through_seq")
    @classmethod
    def _require_positive_dropped_seq(cls, value: int | None) -> int | None:
        if value is not None and value < 1:
            raise ValueError("dropped_through_seq must be a positive integer")
        return value

    @field_validator("reason", "message", "source_type")
    @classmethod
    def _validate_optional_drop_string(cls, value: str | None, info: ValidationInfo) -> str | None:
        return _require_non_empty_event_string(value, info)


class ReplayTruncatedControlEventContract(ControlEventContract):
    """Projected replay-gap sentinel for the upstream v1 event stream."""

    type: Literal["replay_truncated"]
    dropped_before_seq: StrictInt

    @field_validator("dropped_before_seq")
    @classmethod
    def _require_positive_drop_boundary(cls, value: int) -> int:
        if value < 1:
            raise ValueError("dropped_before_seq must be a positive integer")
        return value

    @model_validator(mode="after")
    def _require_owner(self) -> "ReplayTruncatedControlEventContract":
        _control_event_require_owner(self, "replay_truncated")
        return self


class FutureControlEventContract(ControlEventContract):
    """Forward-compatible event contract for unknown future event types."""

    @field_validator("type")
    @classmethod
    def _reject_known_event_type(cls, value: str) -> str:
        normalized = ControlEventContract._require_event_type(value)
        if normalized in CONTROL_KNOWN_EVENT_TYPES:
            raise ValueError(f"{normalized} must use its specific control event contract")
        return normalized


ControlEventPayloadUnion = (
    RunStateChangedControlEventContract
    | TextDeltaControlEventContract
    | ParentMessageSentControlEventContract
    | RunResumedControlEventContract
    | RunResumedFromControlEventContract
    | EventsDroppedControlEventContract
    | ReplayTruncatedControlEventContract
    | FutureControlEventContract
)


class ControlEventPayloadContract(RootModel[ControlEventPayloadUnion]):
    """Discriminated payload contract for a single Agent Control event."""


class ControlEventEnvelopeContract(BaseModel):
    """Projected Agent Control SSE envelope used by the upstream v1 event stream."""

    model_config = ConfigDict(extra="allow")

    run_id: StrictStr
    seq: StrictInt | None = None
    event: ControlEventPayloadUnion

    @field_validator("run_id")
    @classmethod
    def _require_run_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("run_id must be a non-empty string")
        return value

    @field_validator("seq")
    @classmethod
    def _require_positive_seq(cls, value: int | None) -> int | None:
        if value is not None and value < 1:
            raise ValueError("seq must be null or a positive integer")
        return value


class ApprovalNotificationContract(BaseModel):
    """Redacted notification delivery projection for a pending approval."""

    model_config = ConfigDict(extra="forbid")

    state: Literal[
        "pending",
        "sent",
        "skipped_no_destination",
        "skipped_policy",
        "failed_retryable",
        "failed_terminal",
    ]
    channels: list[Literal["telegram", "email", "push"]] = []
    last_sent_at: StrictStr | None = None

    @field_validator("channels", mode="before")
    @classmethod
    def _validate_channels(cls, value: Any) -> list[str]:
        if not isinstance(value, list):
            raise ValueError("channels must be a list of channel names")
        if len(value) > 8:
            raise ValueError("channels must include 8 entries or fewer")
        seen: set[str] = set()
        normalized_channels = []
        for channel in value:
            if not isinstance(channel, str):
                raise ValueError("channels must be strings")
            normalized = channel.strip().lower()
            if not normalized:
                raise ValueError("channels must be non-empty strings")
            if len(normalized) > 64:
                raise ValueError("channels must be 64 characters or fewer")
            if normalized not in _APPROVAL_NOTIFICATION_CHANNELS:
                raise ValueError("channels must be one of: telegram, email, push")
            if normalized in seen:
                raise ValueError("channels must not contain duplicates")
            seen.add(normalized)
            normalized_channels.append(normalized)
        return normalized_channels

    @field_validator("last_sent_at")
    @classmethod
    def _validate_last_sent_at(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("last_sent_at must be omitted, null, or a non-empty string")
        if len(value) > 128:
            raise ValueError("last_sent_at must be 128 characters or fewer")
        return value

    @model_validator(mode="after")
    def _require_sent_channel(self) -> "ApprovalNotificationContract":
        if self.state == "sent" and not self.channels:
            raise ValueError("sent notification state requires at least one channel")
        return self


class PendingApprovalContract(BaseModel):
    """Minimum approval shape needed by the web approval lane."""

    model_config = ConfigDict(extra="allow")

    approval_id: str | None = None
    pending_id: str | None = None
    tool_call_id: str | None = None
    id: str | None = None
    state: str
    notification: ApprovalNotificationContract | None = None

    @field_validator("state", mode="before")
    @classmethod
    def _require_non_empty_string(cls, value: Any, info: ValidationInfo) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        return value

    @model_validator(mode="after")
    def _require_approval_identity(self) -> "PendingApprovalContract":
        extra_fields = set(self.model_extra or {})
        forbidden_fields = sorted(
            field
            for field in extra_fields
            if field in _APPROVAL_NOTIFICATION_FORBIDDEN_EXTRA_FIELDS
            or re.sub(r"[^a-z0-9]+", "", field.lower()).startswith(("notification", "notify"))
        )
        if forbidden_fields:
            raise ValueError(f"raw notification fields are not permitted: {', '.join(forbidden_fields)}")
        for value in (self.approval_id, self.pending_id, self.tool_call_id, self.id):
            if isinstance(value, str) and value.strip():
                return self
        raise ValueError("approval_id, pending_id, tool_call_id, or id must be a non-empty string")


class ApprovalListContract(BaseModel):
    """Shared minimum contract for approval list responses."""

    model_config = ConfigDict(extra="allow")

    approvals: list[PendingApprovalContract]


class ApprovalNotificationRetryRequestContract(BaseModel):
    """Browser-safe empty body for retrying a pending approval notification."""

    model_config = ConfigDict(extra="forbid")


class ApprovalNotificationRetryResponseContract(BaseModel):
    """Redacted retry-control response for a pending approval notification."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["queued", "not_retryable"]
    approval_id: StrictStr
    requeued: StrictInt
    delivery_scheduled: StrictBool
    notification: ApprovalNotificationContract | None = None

    @field_validator("approval_id")
    @classmethod
    def _require_non_empty_approval_id(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("approval_id must be a non-empty string")
        return value

    @field_validator("requeued")
    @classmethod
    def _require_non_negative_requeued(cls, value: int) -> int:
        if value < 0:
            raise ValueError("requeued must be greater than or equal to 0")
        return value


class ApprovalDecisionRequestContract(BaseModel):
    """Browser-safe approval decision request body accepted by the proxy."""

    model_config = ConfigDict(extra="forbid")

    approved: StrictBool
    allow_tool_type: StrictBool | SkipJsonSchema[None] = None
    reason: StrictStr | None = None

    @field_validator("allow_tool_type", mode="before")
    @classmethod
    def _reject_null_allow_tool_type(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("allow_tool_type must be omitted or a boolean")
        return value


class ChatRunMessageEntryContract(BaseModel):
    """Single chat transcript entry sent for chat-kind run continuation."""

    model_config = ConfigDict(extra="forbid")

    role: Literal["user", "assistant"]
    content: StrictStr

    @field_validator("content")
    @classmethod
    def _require_non_empty_string(cls, value: str, info: ValidationInfo) -> str:
        if not value.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        return value


class ChatRunMessageRequestContract(BaseModel):
    """Browser-safe full-transcript continuation body for chat-kind runs."""

    model_config = ConfigDict(extra="forbid")

    messages: list[ChatRunMessageEntryContract]
    request_id: StrictStr | None = None
    context: dict[str, Any] | SkipJsonSchema[None] = None
    model: StrictStr | None = None
    deadline_sec: StrictInt | StrictFloat | None = None

    @field_validator("messages")
    @classmethod
    def _require_messages(cls, value: list[ChatRunMessageEntryContract]) -> list[ChatRunMessageEntryContract]:
        if not value:
            raise ValueError("messages must contain at least one message")
        return value

    @field_validator("context", mode="before")
    @classmethod
    def _reject_null_context(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("context must be omitted or an object")
        return value

    @field_validator("request_id", "model")
    @classmethod
    def _reject_blank_optional_string(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None and not value.strip():
            raise ValueError(f"{info.field_name} must be omitted, null, or a non-empty string")
        return value

    @field_validator("deadline_sec")
    @classmethod
    def _reject_non_finite_deadline(cls, value: int | float | None) -> int | float | None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("deadline_sec must be finite")
        return value


class AutonomousRunMessageRequestContract(BaseModel):
    """Browser-safe operator steering body for autonomous runs."""

    model_config = ConfigDict(extra="forbid")

    message: StrictStr
    message_id: StrictStr | SkipJsonSchema[None] = None

    @field_validator("message")
    @classmethod
    def _require_non_empty_message(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("message must be a non-empty string")
        return value

    @field_validator("message_id", mode="before")
    @classmethod
    def _reject_blank_message_id(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("message_id must be omitted or a non-empty string")
        if isinstance(value, str) and not value.strip():
            raise ValueError("message_id must be omitted or a non-empty string")
        return value


class ResumeRunRequestContract(BaseModel):
    """Browser-safe top-level autonomous resume body."""

    model_config = ConfigDict(extra="forbid")

    context: StrictStr | None = None
    message: StrictStr | None = None
    request_id: StrictStr | None = None

    @field_validator("message", "request_id")
    @classmethod
    def _reject_blank_resume_string(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None and not value.strip():
            raise ValueError(f"{info.field_name} must be omitted, null, or a non-empty string")
        return value

    @field_validator("context")
    @classmethod
    def _reject_blank_resume_context(cls, value: str | None) -> str | None:
        if isinstance(value, str) and not value.strip():
            raise ValueError("context must be omitted, null, or a non-empty string")
        return value


class ChatRunDispatchRequestContract(BaseModel):
    """Browser-safe chat-run dispatch request accepted by the proxy."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["chat"]
    message: StrictStr
    skill: StrictStr | None = None
    ticker: StrictStr | None = None
    deadline_sec: StrictInt | StrictFloat | None = None
    dispatch_scope: DispatchScopeContract | None = None
    context: dict[str, Any] | SkipJsonSchema[None] = None

    @field_validator("message")
    @classmethod
    def _validate_message(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("message must be a non-empty string")
        if len(value) > 20000:
            raise ValueError("message must be 20000 characters or fewer")
        return value

    @field_validator("skill", "ticker")
    @classmethod
    def _validate_optional_short_string(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError(f"{info.field_name} must be omitted, null, or a non-empty string")
        if len(value) > 256:
            raise ValueError(f"{info.field_name} must be 256 characters or fewer")
        return value

    @field_validator("context", mode="before")
    @classmethod
    def _reject_null_context(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("context must be omitted or an object")
        return value

    @field_validator("deadline_sec")
    @classmethod
    def _reject_non_finite_deadline(cls, value: int | float | None) -> int | float | None:
        if isinstance(value, float) and not math.isfinite(value):
            raise ValueError("deadline_sec must be finite")
        return value


class AutonomousRunDispatchRequestContract(BaseModel):
    """Browser-safe autonomous dispatch request accepted by the proxy."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["autonomous"]
    profile: StrictStr | None = None
    mode: Literal["task", "skill", "once"] | None = None
    skill: StrictStr | None = None
    task: StrictStr | None = None
    ticker: StrictStr | None = None
    context: StrictStr | None = None
    dispatch_scope: DispatchScopeContract | None = None

    @field_validator("profile", "skill", "ticker")
    @classmethod
    def _validate_optional_short_string(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError(f"{info.field_name} must be omitted, null, or a non-empty string")
        if len(value) > 256:
            raise ValueError(f"{info.field_name} must be 256 characters or fewer")
        return value

    @field_validator("task")
    @classmethod
    def _validate_task(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("task must be omitted, null, or a non-empty string")
        if len(value) > 20000:
            raise ValueError("task must be 20000 characters or fewer")
        return value

    @field_validator("context")
    @classmethod
    def _validate_context(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("context must be omitted, null, or a non-empty string")
        if len(value) > 20000:
            raise ValueError("context must be 20000 characters or fewer")
        return value


class AgentRunScheduleCadenceContract(BaseModel):
    """Browser-safe cadence shape for scheduled autonomous agent runs."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["daily", "weekly", "monthly"]
    time_of_day: StrictStr
    days_of_week: list[StrictInt] | None = None
    days_of_month: list[StrictInt] | None = None

    @field_validator("time_of_day")
    @classmethod
    def _require_time_of_day(cls, value: str) -> str:
        if _TIME_OF_DAY_RE.fullmatch(value) is None:
            raise ValueError("time_of_day must use 24-hour HH:MM format")
        return value

    @field_validator("days_of_week")
    @classmethod
    def _validate_days_of_week(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return value
        if not value:
            raise ValueError("days_of_week must contain at least one day")
        if len(value) > 7 or len(set(value)) != len(value):
            raise ValueError("days_of_week must contain unique ISO weekday values")
        if any(day < 1 or day > 7 for day in value):
            raise ValueError("days_of_week values must be between 1 and 7")
        return value

    @field_validator("days_of_month")
    @classmethod
    def _validate_days_of_month(cls, value: list[int] | None) -> list[int] | None:
        if value is None:
            return value
        if not value:
            raise ValueError("days_of_month must contain at least one day")
        if len(value) > 31 or len(set(value)) != len(value):
            raise ValueError("days_of_month must contain unique month-day values")
        if any(day < 1 or day > 31 for day in value):
            raise ValueError("days_of_month values must be between 1 and 31")
        return value

    @model_validator(mode="after")
    def _require_matching_day_fields(self) -> "AgentRunScheduleCadenceContract":
        if self.type == "daily":
            if self.days_of_week is not None or self.days_of_month is not None:
                raise ValueError("daily cadence must not include days_of_week or days_of_month")
        elif self.type == "weekly":
            if self.days_of_week is None:
                raise ValueError("weekly cadence requires days_of_week")
            if self.days_of_month is not None:
                raise ValueError("weekly cadence must not include days_of_month")
        elif self.type == "monthly":
            if self.days_of_month is None:
                raise ValueError("monthly cadence requires days_of_month")
            if self.days_of_week is not None:
                raise ValueError("monthly cadence must not include days_of_week")
        return self


class AgentRunScheduleDispatchContract(BaseModel):
    """Browser-safe autonomous dispatch template embedded in a schedule."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["autonomous"]
    profile: StrictStr
    mode: Literal["task", "skill"]
    skill: StrictStr | None = None
    ticker: StrictStr | None = None
    task: StrictStr | None = None
    context: StrictStr | None = None
    dispatch_scope: DispatchScopeContract | None = None

    @field_validator("profile", "skill")
    @classmethod
    def _validate_short_token(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError(f"{info.field_name} must be omitted, null, or a non-empty string")
        if len(value) > 128:
            raise ValueError(f"{info.field_name} must be 128 characters or fewer")
        return value

    @field_validator("ticker")
    @classmethod
    def _validate_ticker(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if _TICKER_RE.fullmatch(value.strip()) is None:
            raise ValueError("ticker must be a non-empty ticker token")
        return value

    @field_validator("task")
    @classmethod
    def _validate_task(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("task must be omitted, null, or a non-empty string")
        if len(value) > 2000:
            raise ValueError("task must be 2000 characters or fewer")
        return value

    @field_validator("context")
    @classmethod
    def _validate_context(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("context must be omitted, null, or a non-empty string")
        if len(value) > 8000:
            raise ValueError("context must be 8000 characters or fewer")
        return value

    @model_validator(mode="after")
    def _require_mode_payload(self) -> "AgentRunScheduleDispatchContract":
        if self.mode == "task" and not (self.task or "").strip():
            raise ValueError("task-mode schedule dispatch requires task")
        if self.mode == "skill" and not (self.skill or "").strip():
            raise ValueError("skill-mode schedule dispatch requires skill")
        return self


class AgentRunScheduleCreateRequestContract(BaseModel):
    """Browser-safe create body for scheduled autonomous agent runs."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["agent_run_schedule"]
    name: StrictStr
    enabled: StrictBool | None = None
    timezone: StrictStr
    cadence: AgentRunScheduleCadenceContract
    dispatch: AgentRunScheduleDispatchContract
    request_id: StrictStr | None = None

    @field_validator("enabled", mode="before")
    @classmethod
    def _reject_null_enabled(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("enabled must be omitted or a boolean")
        return value

    @field_validator("request_id", mode="before")
    @classmethod
    def _reject_null_request_id(cls, value: Any) -> Any:
        if value is None:
            raise ValueError("request_id must be omitted or a safe non-empty identifier")
        return value

    @field_validator("name", "request_id")
    @classmethod
    def _validate_schedule_token(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return value
        if _SCHEDULE_NAME_RE.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be a safe non-empty identifier")
        return value

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, value: str) -> str:
        if not value.strip() or len(value) > 64:
            raise ValueError("timezone must be a non-empty IANA timezone")
        try:
            ZoneInfo(value)
        except ZoneInfoNotFoundError as exc:
            raise ValueError("timezone must be a valid IANA timezone") from exc
        return value


class AgentRunScheduleUpdateRequestContract(BaseModel):
    """Browser-safe partial update body for scheduled autonomous agent runs."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["agent_run_schedule"] | None = None
    name: StrictStr | None = None
    enabled: StrictBool | None = None
    timezone: StrictStr | None = None
    cadence: AgentRunScheduleCadenceContract | None = None
    dispatch: AgentRunScheduleDispatchContract | None = None
    request_id: StrictStr | None = None

    @field_validator(
        "kind",
        "name",
        "enabled",
        "timezone",
        "cadence",
        "dispatch",
        "request_id",
        mode="before",
    )
    @classmethod
    def _reject_null_update_field(cls, value: Any, info: ValidationInfo) -> Any:
        if value is None:
            raise ValueError(f"{info.field_name} must be omitted or a concrete value")
        return value

    @field_validator("name", "request_id")
    @classmethod
    def _validate_schedule_token(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return value
        if _SCHEDULE_NAME_RE.fullmatch(value) is None:
            raise ValueError(f"{info.field_name} must be a safe non-empty identifier")
        return value

    @field_validator("timezone")
    @classmethod
    def _validate_timezone(cls, value: str | None) -> str | None:
        if value is None:
            return value
        return AgentRunScheduleCreateRequestContract._validate_timezone(value)

    @model_validator(mode="after")
    def _require_update_field(self) -> "AgentRunScheduleUpdateRequestContract":
        if not any(
            value is not None
            for value in (self.name, self.enabled, self.timezone, self.cadence, self.dispatch)
        ):
            raise ValueError("schedule update must include at least one mutable field")
        return self


class ScheduleEnabledRequestContract(BaseModel):
    """Browser-safe enable/disable body for a schedule."""

    model_config = ConfigDict(extra="forbid")

    enabled: StrictBool


class ControlArtifactContract(BaseModel):
    """Minimum artifact provenance shape needed by the artifact lane."""

    model_config = ConfigDict(extra="allow")

    artifact_id: str | None = None
    id: str | None = None
    control_run_id: str | None = None
    run_id: str | None = None
    session_id: str | None = None
    task_id: str | None = None
    skill_run_id: str | None = None
    contract_name: str | None = None

    @staticmethod
    def _non_empty(value: str | None) -> str:
        return value.strip() if isinstance(value, str) else ""

    @model_validator(mode="after")
    def _require_artifact_provenance(self) -> "ControlArtifactContract":
        artifact_id = self._non_empty(self.artifact_id)
        alternate_id = self._non_empty(self.id)
        if not artifact_id and not alternate_id:
            raise ValueError("artifact_id or id must be a non-empty string")
        owner_id = next(
            (
                value
                for value in (
                    self._non_empty(self.control_run_id),
                    self._non_empty(self.run_id),
                    self._non_empty(self.session_id),
                    self._non_empty(self.task_id),
                )
                if value
            ),
            "",
        )
        if not owner_id:
            raise ValueError("control_run_id, run_id, session_id, or task_id must identify the owning control run")
        if not self._non_empty(self.skill_run_id):
            raise ValueError("skill_run_id must be a non-empty string")
        if not self._non_empty(self.contract_name):
            raise ValueError("contract_name must be a non-empty string")
        return self


class ArtifactListContract(BaseModel):
    """Shared minimum contract for artifact list responses."""

    model_config = ConfigDict(extra="allow")

    artifacts: list[ControlArtifactContract]


class ReadableResourceContract(BaseModel):
    """Immutable human-readable text resource metadata exposed by Agent Control."""

    model_config = ConfigDict(extra="forbid")

    resource_id: StrictStr
    control_run_id: StrictStr | None = None
    run_id: StrictStr | None = None
    session_id: StrictStr | None = None
    task_id: StrictStr | None = None
    skill_run_id: StrictStr
    contract_name: StrictStr
    content_type: Literal["text/markdown", "text/plain"]
    content_class: Literal["human_readable", "dev_only"]
    content_snapshot_id: StrictStr
    content_sha256: StrictStr
    content_bytes: StrictInt
    truncated: StrictBool
    title: StrictStr | None = None
    source_path: StrictStr | None = None
    byte_start: StrictInt | None = None
    byte_end: StrictInt | None = None
    tool_name: StrictStr | None = None
    created_at: StrictStr | None = None

    @field_validator(
        "resource_id",
        "control_run_id",
        "run_id",
        "session_id",
        "task_id",
        "skill_run_id",
        "contract_name",
        "content_snapshot_id",
        "title",
        "source_path",
        "tool_name",
        "created_at",
    )
    @classmethod
    def _validate_optional_non_empty_string(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        if len(value) > 512:
            raise ValueError(f"{info.field_name} must be 512 characters or fewer")
        if info.field_name == "resource_id" and (
            re.search(r"[/\\\s]", value) is not None or value in {".", ".."}
        ):
            raise ValueError("resource_id must be an opaque route-safe path segment")
        return value

    @field_validator("content_sha256")
    @classmethod
    def _validate_content_sha256(cls, value: str) -> str:
        if re.fullmatch(r"[0-9a-fA-F]{64}", value.strip()) is None:
            raise ValueError("content_sha256 must be a 64-character hex digest")
        return value.lower()

    @field_validator("content_bytes", "byte_start", "byte_end")
    @classmethod
    def _validate_non_negative_int(cls, value: int | None, info: ValidationInfo) -> int | None:
        if value is None:
            return value
        if value < 0:
            raise ValueError(f"{info.field_name} must be non-negative")
        return value

    @model_validator(mode="after")
    def _require_resource_provenance(self) -> "ReadableResourceContract":
        owner_id = next(
            (
                value.strip()
                for value in (self.control_run_id, self.run_id, self.session_id, self.task_id)
                if isinstance(value, str) and value.strip()
            ),
            "",
        )
        if not owner_id:
            raise ValueError("control_run_id, run_id, session_id, or task_id must identify the owning control run")
        if self.byte_start is not None and self.byte_end is not None and self.byte_end < self.byte_start:
            raise ValueError("byte_end must be greater than or equal to byte_start")
        return self


class ReadableResourceDetailContract(ReadableResourceContract):
    """Immutable human-readable text resource detail including bounded content."""

    content: StrictStr

    @field_validator("content")
    @classmethod
    def _validate_content(cls, value: str, info: ValidationInfo) -> str:
        if not value.strip():
            raise ValueError("content must be a non-empty string")
        content_bytes = value.encode("utf-8")
        if len(content_bytes) > 2_000_000:
            raise ValueError("content must be 2 MB or smaller")
        expected_bytes = info.data.get("content_bytes")
        if isinstance(expected_bytes, int) and len(content_bytes) != expected_bytes:
            raise ValueError("content byte length must match content_bytes")
        expected_sha256 = info.data.get("content_sha256")
        if isinstance(expected_sha256, str) and hashlib.sha256(content_bytes).hexdigest() != expected_sha256:
            raise ValueError("content sha256 digest must match content_sha256")
        return value


class ReadableResourceListContract(BaseModel):
    """Readable-resource list envelope."""

    model_config = ConfigDict(extra="forbid")

    readable_resources: list[ReadableResourceContract]
    next_cursor: StrictStr | None = None

    @field_validator("next_cursor")
    @classmethod
    def _validate_next_cursor(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not value.strip():
            raise ValueError("next_cursor must be omitted, null, or a non-empty string")
        return value


class ControlSkillContract(BaseModel):
    """Minimum browser-safe skill identity shape exposed by Agent Control."""

    model_config = ConfigDict(extra="allow")

    name: StrictStr
    label: StrictStr | None = None
    display_label: StrictStr | None = None
    displayLabel: StrictStr | None = None
    title: StrictStr | None = None
    description: StrictStr | None = None
    agent_description: StrictStr | None = None
    summary: StrictStr | None = None
    version: StrictStr | None = None
    scope: StrictStr | None = None
    catalog: StrictBool | None = None
    product_visible: StrictBool | None = None
    productVisible: StrictBool | None = None
    catalog_visible: StrictBool | None = None
    catalogVisible: StrictBool | None = None
    visible_in_catalog: StrictBool | None = None
    visibleInCatalog: StrictBool | None = None
    visible: StrictBool | None = None
    agent_callable: StrictBool | None = None
    agentCallable: StrictBool | None = None
    can_launch: StrictBool | None = None
    canLaunch: StrictBool | None = None
    can_schedule: StrictBool | None = None
    canSchedule: StrictBool | None = None
    schedule_eligible: StrictBool | None = None
    scheduleEligible: StrictBool | None = None
    blocked_reason: StrictStr | None = None
    blockedReason: StrictStr | None = None
    disabled_reason: StrictStr | None = None
    disabledReason: StrictStr | None = None
    resumable: StrictBool | None = None
    requires_portfolio: StrictBool | None = None
    requiresPortfolio: StrictBool | None = None
    requires_portfolio_context: StrictBool | None = None
    requiresPortfolioContext: StrictBool | None = None
    portfolio_required: StrictBool | None = None
    portfolioRequired: StrictBool | None = None
    required_context: SkillTextListValue | None = None
    requiredContext: SkillTextListValue | None = None
    required_inputs: SkillTextListValue | None = None
    requiredInputs: SkillTextListValue | None = None
    context_requirements: SkillTextListValue | None = None
    contextRequirements: SkillTextListValue | None = None
    input_requirements: SkillTextListValue | None = None
    inputRequirements: SkillTextListValue | None = None
    requirements: SkillTextListValue | None = None
    inputs: SkillTextListValue | None = None
    profile: SkillTextListValue | None = None
    profiles: SkillTextListValue | None = None
    compatible_profiles: SkillTextListValue | None = None
    compatibleProfiles: SkillTextListValue | None = None
    mode: SkillTextListValue | None = None
    modes: SkillTextListValue | None = None
    compatible_modes: SkillTextListValue | None = None
    compatibleModes: SkillTextListValue | None = None
    outputs: SkillTextListValue | None = None
    output_types: SkillTextListValue | None = None
    outputTypes: SkillTextListValue | None = None
    action_class: StrictStr | None = None
    actionClass: StrictStr | None = None
    approval_policy: StrictStr | None = None
    approvalPolicy: StrictStr | None = None
    tier: SkillTextListValue | None = None
    tier_availability: SkillTextListValue | None = None
    tierAvailability: SkillTextListValue | None = None
    credential_requirements: SkillTextListValue | None = None
    credentialRequirements: SkillTextListValue | None = None
    max_turns: StrictInt | None = None
    max_budget_usd: SkillNumericValue | None = None
    persist_state: StrictBool | None = None
    typed_contract: StrictStr | None = None

    @field_validator("name")
    @classmethod
    def _require_skill_name(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("name must be a non-empty string")
        if len(value) > 256:
            raise ValueError("name must be 256 characters or fewer")
        return value.strip()

    @field_validator("max_turns")
    @classmethod
    def _validate_max_turns(cls, value: int | None) -> int | None:
        if value is not None and value < 1:
            raise ValueError("max_turns must be a positive integer")
        return value

    @field_validator("max_budget_usd")
    @classmethod
    def _validate_max_budget_usd(cls, value: int | float | None) -> int | float | None:
        if value is None:
            return value
        if not math.isfinite(float(value)):
            raise ValueError("max_budget_usd must be finite")
        if value < 0:
            raise ValueError("max_budget_usd must be non-negative")
        return value


class SkillCatalogStatusContract(BaseModel):
    """Browser-safe identity and availability state for the canonical catalog."""

    model_config = ConfigDict(extra="forbid")

    schema_version: StrictStr
    status: Literal["healthy", "degraded"]
    catalog_digest: StrictStr
    invalid_count: StrictInt

    @field_validator("schema_version")
    @classmethod
    def _require_schema_version(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("schema_version must be a non-empty string")
        return value.strip()

    @field_validator("catalog_digest")
    @classmethod
    def _validate_catalog_digest(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", normalized):
            raise ValueError("catalog_digest must be a sha256 digest")
        return normalized

    @field_validator("invalid_count")
    @classmethod
    def _validate_invalid_count(cls, value: int) -> int:
        if value < 0:
            raise ValueError("invalid_count must be non-negative")
        return value


class SkillCatalogDiagnosticContract(BaseModel):
    """Stable browser-safe diagnostic identity without internal error text."""

    model_config = ConfigDict(extra="forbid")

    skill_name: StrictStr
    code: StrictStr
    stage: StrictStr

    @field_validator("skill_name", "code", "stage")
    @classmethod
    def _require_diagnostic_text(cls, value: str, info: ValidationInfo) -> str:
        if not value.strip():
            raise ValueError(f"{info.field_name} must be a non-empty string")
        return value.strip()


class SkillListContract(BaseModel):
    """Browser-safe skill catalog list envelope."""

    model_config = ConfigDict(extra="forbid")

    skills: list[ControlSkillContract]
    catalog: SkillCatalogStatusContract | None = None
    diagnostics: list[SkillCatalogDiagnosticContract] | None = None


class RunLogsContract(BaseModel):
    """Shared minimum contract for selected-run log tail responses."""

    model_config = ConfigDict(extra="allow")

    run_id: str
    log_lines: list[str]
    more_available: StrictBool

    @field_validator("run_id", mode="before")
    @classmethod
    def _require_non_empty_run_id(cls, value: Any) -> str:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("run_id must be a non-empty string")
        return value


class ControlScheduleContract(BaseModel):
    """Minimum schedule identity shape needed by the dispatch lane."""

    model_config = ConfigDict(extra="allow")

    schedule_id: Any = None
    id: Any = None
    name: Any = None
    label: Any = None

    @model_validator(mode="after")
    def _require_schedule_identity(self) -> "ControlScheduleContract":
        for value in (self.schedule_id, self.id, self.name, self.label):
            if isinstance(value, str) and value.strip():
                return self
        raise ValueError("schedule_id, id, name, or label must be a non-empty string")


class ScheduleListContract(BaseModel):
    """Shared minimum contract for schedule list responses."""

    model_config = ConfigDict(extra="allow")

    schedules: list[ControlScheduleContract]


class ScheduleEnvelopeContract(BaseModel):
    """Shared minimum contract for a schedule detail response envelope."""

    model_config = ConfigDict(extra="ignore")

    schedule: ControlScheduleContract


class ScheduleDeleteResponseContract(BaseModel):
    """Browser-safe acknowledgement shape for schedule delete responses."""

    model_config = ConfigDict(extra="ignore")

    deleted: StrictBool | None = None
    ok: StrictBool | None = None
    schedule_id: StrictStr | None = None
    id: StrictStr | None = None
    name: StrictStr | None = None

    @field_validator("schedule_id", "id", "name")
    @classmethod
    def _reject_blank_identity(cls, value: str | None, info: ValidationInfo) -> str | None:
        if value is not None and not value.strip():
            raise ValueError(f"{info.field_name} must be omitted, null, or a non-empty string")
        return value


class ScheduleRunNowRequestContract(BaseModel):
    """Browser-safe empty body for running a user-owned schedule immediately."""

    model_config = ConfigDict(extra="forbid")


CONTROL_CONTRACT_SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "ApprovalDecisionRequestContract": ApprovalDecisionRequestContract,
    "ApprovalListContract": ApprovalListContract,
    "ApprovalNotificationContract": ApprovalNotificationContract,
    "ApprovalNotificationRetryRequestContract": ApprovalNotificationRetryRequestContract,
    "ApprovalNotificationRetryResponseContract": ApprovalNotificationRetryResponseContract,
    "AgentRunScheduleCadenceContract": AgentRunScheduleCadenceContract,
    "AgentRunScheduleCreateRequestContract": AgentRunScheduleCreateRequestContract,
    "AgentRunScheduleDispatchContract": AgentRunScheduleDispatchContract,
    "AgentRunScheduleUpdateRequestContract": AgentRunScheduleUpdateRequestContract,
    "AutonomousRunDispatchRequestContract": AutonomousRunDispatchRequestContract,
    "AutonomousRunMessageRequestContract": AutonomousRunMessageRequestContract,
    "ArtifactListContract": ArtifactListContract,
    "ChatRunDispatchRequestContract": ChatRunDispatchRequestContract,
    "ChatRunMessageEntryContract": ChatRunMessageEntryContract,
    "ChatRunMessageRequestContract": ChatRunMessageRequestContract,
    "ControlArtifactContract": ControlArtifactContract,
    "ControlEventContract": ControlEventContract,
    "ControlEventEnvelopeContract": ControlEventEnvelopeContract,
    "ControlEventPayloadContract": ControlEventPayloadContract,
    "ControlRunContract": ControlRunContract,
    "ControlRunEnvelopeContract": ControlRunEnvelopeContract,
    "ControlRunListContract": ControlRunListContract,
    "ControlScheduleContract": ControlScheduleContract,
    "SkillCatalogDiagnosticContract": SkillCatalogDiagnosticContract,
    "SkillCatalogStatusContract": SkillCatalogStatusContract,
    "ControlSkillContract": ControlSkillContract,
    "DispatchScopeContract": DispatchScopeContract,
    "EventsDroppedControlEventContract": EventsDroppedControlEventContract,
    "FutureControlEventContract": FutureControlEventContract,
    "PendingApprovalContract": PendingApprovalContract,
    "ParentMessageSentControlEventContract": ParentMessageSentControlEventContract,
    "ReadableResourceContract": ReadableResourceContract,
    "ReadableResourceDetailContract": ReadableResourceDetailContract,
    "ReadableResourceListContract": ReadableResourceListContract,
    "ReplayTruncatedControlEventContract": ReplayTruncatedControlEventContract,
    "ResumeRunRequestContract": ResumeRunRequestContract,
    "RunLogsContract": RunLogsContract,
    "RunResumedControlEventContract": RunResumedControlEventContract,
    "RunResumedFromControlEventContract": RunResumedFromControlEventContract,
    "RunStateChangedControlEventContract": RunStateChangedControlEventContract,
    "ScheduleDeleteResponseContract": ScheduleDeleteResponseContract,
    "ScheduleEnabledRequestContract": ScheduleEnabledRequestContract,
    "ScheduleEnvelopeContract": ScheduleEnvelopeContract,
    "ScheduleListContract": ScheduleListContract,
    "ScheduleRunNowRequestContract": ScheduleRunNowRequestContract,
    "SkillListContract": SkillListContract,
    "TextDeltaControlEventContract": TextDeltaControlEventContract,
}


def control_contract_schema_bundle() -> dict[str, Any]:
    """Return the generated Agent Control contract schema bundle."""

    model_schemas, defs = _contract_model_schemas()
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://hank.investments/schemas/agent-control-contracts-v1.json",
        "title": "Agent Control Gateway Contract Bundle",
        "schema_version": CONTROL_CONTRACT_SCHEMA_BUNDLE_VERSION,
        "generated_from": "app_platform.gateway.control_contracts",
        "contract_versions": {
            "run": CONTROL_RUN_CONTRACT_VERSION,
            "request": CONTROL_REQUEST_CONTRACT_VERSION,
            "response": CONTROL_RESPONSE_CONTRACT_VERSION,
            "event": CONTROL_EVENT_CONTRACT_VERSION,
        },
        "run_lifecycle": {
            "states": list(CONTROL_RUN_STATE_CLASSIFICATION.keys()),
            "classification": {
                state: dict(classification)
                for state, classification in CONTROL_RUN_STATE_CLASSIFICATION.items()
            },
            "active_states": _ordered_run_states(CONTROL_ACTIVE_RUN_STATES),
            "terminal_states": _ordered_run_states(CONTROL_TERMINAL_RUN_STATES),
            "resumable_states": _ordered_run_states(CONTROL_RESUMABLE_RUN_STATES),
            "cancellable_states": _ordered_run_states(CONTROL_CANCELLABLE_RUN_STATES),
            "chat_messageable_states": _ordered_run_states(CONTROL_CHAT_MESSAGEABLE_RUN_STATES),
        },
        "route_contracts": {
            "run_payloads": list(CONTROL_RUN_PAYLOAD_CONTRACT_ROUTES),
            "response_envelopes": list(CONTROL_RESPONSE_CONTRACT_ROUTES),
            "browser_requests": list(CONTROL_REQUEST_CONTRACT_ROUTES),
            "control_events": list(CONTROL_EVENT_CONTRACT_ROUTES),
        },
        "route_schemas": {
            "run_payloads": dict(CONTROL_RUN_ROUTE_SCHEMA_MODELS),
            "response_envelopes": dict(CONTROL_RESPONSE_ROUTE_SCHEMA_MODELS),
            "browser_requests": dict(CONTROL_REQUEST_ROUTE_SCHEMA_MODELS),
            "control_events": dict(CONTROL_EVENT_ROUTE_SCHEMA_MODELS),
        },
        "$defs": defs,
        "models": model_schemas,
    }


def _ordered_run_states(states: frozenset[str]) -> list[str]:
    return [state for state in CONTROL_RUN_STATE_CLASSIFICATION if state in states]


def _contract_model_schemas() -> tuple[dict[str, Any], dict[str, Any]]:
    models: dict[str, Any] = {}
    defs: dict[str, Any] = {}
    for name, model in CONTROL_CONTRACT_SCHEMA_MODELS.items():
        schema = model.model_json_schema(ref_template="#/$defs/{model}")
        for def_name, definition in schema.pop("$defs", {}).items():
            defs[def_name] = definition
        models[name] = schema

    for schema in [*models.values(), *defs.values()]:
        _enrich_contract_schema(schema)
    return models, defs


def _enrich_contract_schema(schema: dict[str, Any]) -> None:
    title = schema.get("title")
    if title == "ControlRunContract":
        _min_length(schema, "run_id")
        _enum(schema, "state", list(CONTROL_RUN_STATE_CLASSIFICATION))
    elif title == "ControlEventEnvelopeContract":
        _min_length(schema, "run_id")
        _minimum(schema, "seq", 1)
    elif title == "ControlEventContract":
        _min_length(schema, "type")
        for field_name in (*CONTROL_EVENT_OWNER_FIELDS, "state"):
            _min_length(schema, field_name)
    elif title == "FutureControlEventContract":
        _min_length(schema, "type")
        for field_name in (*CONTROL_EVENT_OWNER_FIELDS, "state"):
            _min_length(schema, field_name)
        _not_string_enum(schema, "type", sorted(CONTROL_KNOWN_EVENT_TYPES))
    elif title == "RunStateChangedControlEventContract":
        _require_any_string_field(schema, CONTROL_EVENT_OWNER_FIELDS)
        _enum(schema, "state", list(CONTROL_RUN_STATE_CLASSIFICATION))
    elif title == "TextDeltaControlEventContract":
        _require_any_string_field(schema, CONTROL_EVENT_OWNER_FIELDS)
        _require_any_string_field(schema, ("text", "content"), require_non_empty=False)
    elif title == "ParentMessageSentControlEventContract":
        _require_any_string_field(schema, CONTROL_EVENT_OWNER_FIELDS)
        _require_any_string_field(schema, ("message", "content", "text"))
    elif title == "RunResumedControlEventContract":
        _require_any_string_field(schema, CONTROL_EVENT_OWNER_FIELDS)
        _require_any_string_field(schema, ("resumed_run_id", "resumed_as", "resumed_task_id"))
    elif title == "RunResumedFromControlEventContract":
        _require_any_string_field(schema, CONTROL_EVENT_OWNER_FIELDS)
        _require_any_string_field(schema, ("resumed_from", "resumed_from_run_id", "resumed_from_task_id"))
    elif title == "EventsDroppedControlEventContract":
        _minimum(schema, "count", 0)
        _minimum(schema, "dropped_through_seq", 1)
        _min_length(schema, "reason")
        _min_length(schema, "message")
        _min_length(schema, "source_type")
        _array_string_min_length(schema, "issues", 1)
    elif title == "ReplayTruncatedControlEventContract":
        _require_any_string_field(schema, CONTROL_EVENT_OWNER_FIELDS)
        _minimum(schema, "dropped_before_seq", 1)
    elif title == "PendingApprovalContract":
        _min_length(schema, "state")
        _identity_any_of(schema, ("approval_id", "pending_id", "tool_call_id", "id"))
    elif title == "ApprovalNotificationContract":
        _array_string_min_length(schema, "channels", 1)
        _array_string_max_length(schema, "channels", 64)
        _array_max_items(schema, "channels", 8)
        _min_length(schema, "last_sent_at")
        _max_length(schema, "last_sent_at", 128)
        schema["allOf"] = [
            *copy.deepcopy(schema.get("allOf", [])),
            {
                "if": {"required": ["state"], "properties": {"state": {"const": "sent"}}},
                "then": {
                    "required": ["channels"],
                    "properties": {"channels": {"minItems": 1}},
                },
            },
        ]
    elif title == "ApprovalNotificationRetryResponseContract":
        _min_length(schema, "approval_id")
        _minimum(schema, "requeued", 0)
    elif title == "ChatRunMessageEntryContract":
        _min_length(schema, "content")
    elif title == "ChatRunMessageRequestContract":
        _array_min_items(schema, "messages", 1)
        _min_length(schema, "request_id")
        _min_length(schema, "model")
    elif title == "AutonomousRunMessageRequestContract":
        _min_length(schema, "message")
        _min_length(schema, "message_id")
    elif title == "ResumeRunRequestContract":
        _min_length(schema, "context")
        _min_length(schema, "message")
        _min_length(schema, "request_id")
    elif title == "DispatchScopeContract":
        _min_length(schema, "portfolio_name")
        _min_length(schema, "portfolio_id")
        _min_length(schema, "display_name")
    elif title == "ChatRunDispatchRequestContract":
        _min_length(schema, "message")
        _min_length(schema, "skill")
        _min_length(schema, "ticker")
    elif title == "AutonomousRunDispatchRequestContract":
        _min_length(schema, "profile")
        _min_length(schema, "skill")
        _min_length(schema, "ticker")
        _min_length(schema, "task")
        _min_length(schema, "context")
    elif title == "AgentRunScheduleCadenceContract":
        _min_length(schema, "time_of_day")
        _array_min_items(schema, "days_of_week", 1)
        _array_min_items(schema, "days_of_month", 1)
    elif title == "AgentRunScheduleDispatchContract":
        _min_length(schema, "profile")
        _min_length(schema, "skill")
        _min_length(schema, "ticker")
        _min_length(schema, "task")
        _min_length(schema, "context")
    elif title in {
        "AgentRunScheduleCreateRequestContract",
        "AgentRunScheduleUpdateRequestContract",
    }:
        _min_length(schema, "name")
        _min_length(schema, "timezone")
        _min_length(schema, "request_id")
    elif title == "ControlArtifactContract":
        _identity_any_of(schema, ("artifact_id", "id"))
        _identity_any_of(schema, ("control_run_id", "run_id", "session_id", "task_id"))
        schema["required"] = sorted({
            *schema.get("required", []),
            "contract_name",
            "skill_run_id",
        })
        _min_length(schema, "contract_name")
        _min_length(schema, "skill_run_id")
    elif title in {"ReadableResourceContract", "ReadableResourceDetailContract"}:
        _identity_any_of(schema, ("control_run_id", "run_id", "session_id", "task_id"))
        for field_name in (
            "resource_id",
            "skill_run_id",
            "contract_name",
            "content_snapshot_id",
            "content_sha256",
            "title",
            "source_path",
            "tool_name",
            "created_at",
        ):
            _min_length(schema, field_name)
        _pattern(schema, "resource_id", r"^(?!\.{1,2}$)[^/\\\s]+$")
        _pattern(schema, "content_sha256", r"^[0-9a-fA-F]{64}$")
        _minimum(schema, "content_bytes", 0)
        _minimum(schema, "byte_start", 0)
        _minimum(schema, "byte_end", 0)
        if title == "ReadableResourceDetailContract":
            _min_length(schema, "content")
            _max_length(schema, "content", 2_000_000)
    elif title == "ReadableResourceListContract":
        _array_min_items(schema, "readable_resources", 0)
        _min_length(schema, "next_cursor")
    elif title == "RunLogsContract":
        _min_length(schema, "run_id")
    elif title == "ControlScheduleContract":
        _identity_any_of(schema, ("schedule_id", "id", "name", "label"))
    elif title == "ScheduleEnvelopeContract":
        schema["required"] = sorted({*schema.get("required", []), "schedule"})
    elif title == "ScheduleDeleteResponseContract":
        _min_length(schema, "schedule_id")
        _min_length(schema, "id")
        _min_length(schema, "name")
    _remove_non_nullable_none_defaults(schema)


def _property_schema(schema: dict[str, Any], name: str) -> dict[str, Any] | None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return None
    prop = properties.get(name)
    return prop if isinstance(prop, dict) else None


def _min_length(schema: dict[str, Any], name: str, minimum: int = 1) -> None:
    prop = _property_schema(schema, name)
    if prop is None:
        return
    if prop.get("type") == "string":
        prop["minLength"] = minimum
        prop["pattern"] = r"\S"
    any_of = prop.get("anyOf")
    if isinstance(any_of, list):
        for option in any_of:
            if isinstance(option, dict) and option.get("type") == "string":
                option["minLength"] = minimum
                option["pattern"] = r"\S"


def _enum(schema: dict[str, Any], name: str, values: list[str]) -> None:
    prop = _property_schema(schema, name)
    if prop is None:
        return
    prop["enum"] = values


def _not_string_enum(schema: dict[str, Any], name: str, values: list[str]) -> None:
    schema["not"] = {
        "properties": {
            name: {
                "enum": values,
            },
        },
        "required": [name],
    }


def _minimum(schema: dict[str, Any], name: str, minimum: int | float) -> None:
    prop = _property_schema(schema, name)
    if prop is None:
        return
    if prop.get("type") in {"integer", "number"}:
        prop["minimum"] = minimum
    any_of = prop.get("anyOf")
    if isinstance(any_of, list):
        for option in any_of:
            if isinstance(option, dict) and option.get("type") in {"integer", "number"}:
                option["minimum"] = minimum


def _max_length(schema: dict[str, Any], name: str, maximum: int) -> None:
    prop = _property_schema(schema, name)
    if prop is None:
        return
    if prop.get("type") == "string":
        prop["maxLength"] = maximum
    any_of = prop.get("anyOf")
    if isinstance(any_of, list):
        for option in any_of:
            if isinstance(option, dict) and option.get("type") == "string":
                option["maxLength"] = maximum


def _pattern(schema: dict[str, Any], name: str, pattern: str) -> None:
    prop = _property_schema(schema, name)
    if prop is None:
        return
    if prop.get("type") == "string":
        prop["pattern"] = pattern
    any_of = prop.get("anyOf")
    if isinstance(any_of, list):
        for option in any_of:
            if isinstance(option, dict) and option.get("type") == "string":
                option["pattern"] = pattern


def _array_min_items(schema: dict[str, Any], name: str, minimum: int) -> None:
    prop = _property_schema(schema, name)
    if prop is not None and prop.get("type") == "array":
        prop["minItems"] = minimum


def _array_max_items(schema: dict[str, Any], name: str, maximum: int) -> None:
    prop = _property_schema(schema, name)
    if prop is not None and prop.get("type") == "array":
        prop["maxItems"] = maximum


def _array_string_min_length(schema: dict[str, Any], name: str, minimum: int) -> None:
    prop = _property_schema(schema, name)
    if prop is None or prop.get("type") != "array":
        return
    items = prop.get("items")
    if isinstance(items, dict) and items.get("type") == "string":
        items["minLength"] = minimum
        items["pattern"] = r"\S"


def _array_string_max_length(schema: dict[str, Any], name: str, maximum: int) -> None:
    prop = _property_schema(schema, name)
    if prop is None or prop.get("type") != "array":
        return
    items = prop.get("items")
    if isinstance(items, dict) and items.get("type") == "string":
        items["maxLength"] = maximum


def _require_any_string_field(
    schema: dict[str, Any],
    fields: tuple[str, ...],
    *,
    require_non_empty: bool = True,
) -> None:
    branches = []
    for field in fields:
        field_schema: dict[str, Any] = {"type": "string"}
        if require_non_empty:
            field_schema.update({"minLength": 1, "pattern": r"\S"})
        branches.append({
            "required": [field],
            "properties": {field: field_schema},
        })
    schema["allOf"] = [*copy.deepcopy(schema.get("allOf", [])), {"anyOf": branches}]


def _identity_any_of(schema: dict[str, Any], fields: tuple[str, ...]) -> None:
    branches = []
    for field in fields:
        branches.append({
            "required": [field],
            "properties": {
                field: {"type": "string", "minLength": 1, "pattern": r"\S"},
            },
        })
    schema["anyOf"] = [*copy.deepcopy(schema.get("anyOf", [])), *branches]


def _remove_non_nullable_none_defaults(schema: dict[str, Any]) -> None:
    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return
    for prop in properties.values():
        if not isinstance(prop, dict) or prop.get("default") is not None:
            continue
        any_of = prop.get("anyOf")
        allows_null = prop.get("type") == "null" or (
            isinstance(any_of, list)
            and any(
                isinstance(option, dict) and option.get("type") == "null"
                for option in any_of
            )
        )
        if not allows_null:
            prop.pop("default", None)


def normalize_control_run_contract_payload(payload: Any, *, direct_run_required: bool = False) -> Any:
    """Validate and normalize any control run objects embedded in a payload."""

    if not isinstance(payload, dict):
        if direct_run_required:
            raise ControlContractValidationError([_issue((), "control run must be an object")])
        return payload

    normalized = dict(payload)
    issues: list[dict[str, str]] = []

    if "runs" in payload:
        runs_payload = payload.get("runs")
        if not isinstance(runs_payload, list):
            issues.append(_issue(("runs",), "runs must be a list"))
        else:
            normalized_runs: list[dict[str, Any]] = []
            for index, run_payload in enumerate(runs_payload):
                normalized_run, run_issues = _normalize_control_run(run_payload, ("runs", index))
                issues.extend(run_issues)
                if normalized_run is not None:
                    normalized_runs.append(normalized_run)
            normalized["runs"] = normalized_runs

    if "run" in payload:
        run_payload = payload.get("run")
        normalized_run, run_issues = _normalize_control_run(run_payload, ("run",))
        issues.extend(run_issues)
        if normalized_run is not None:
            normalized["run"] = normalized_run
    elif direct_run_required or _looks_like_direct_control_run(payload):
        normalized_run, run_issues = _normalize_control_run(payload, ())
        issues.extend(run_issues)
        if normalized_run is not None:
            normalized = normalized_run

    if issues:
        raise ControlContractValidationError(issues)
    return normalized


def normalize_control_response_contract_payload(payload: Any, segments: tuple[str, ...]) -> Any:
    """Validate non-run Agent Control response envelopes consumed by the UI."""

    if not control_response_contract_applies(segments):
        return payload
    if segments == ("approvals",):
        return _normalize_contract_model(ApprovalListContract, payload, ())
    if _is_approval_notification_retry_segments(segments):
        return _normalize_contract_model(
            ApprovalNotificationRetryResponseContract,
            payload,
            (),
        )
    if segments == ("artifacts",):
        return _normalize_contract_model(ArtifactListContract, payload, ())
    if segments == ("readable-resources",):
        return _normalize_contract_model(ReadableResourceListContract, payload, ())
    if len(segments) == 2 and segments[0] == "readable-resources":
        normalized = _normalize_contract_model(ReadableResourceDetailContract, payload, ())
        requested_resource_id = segments[1].strip()
        if normalized.get("resource_id") != requested_resource_id:
            raise ControlContractValidationError([
                _issue(("resource_id",), "resource_id must match requested readable resource id")
            ])
        return normalized
    if segments == ("skills",):
        return _project_skill_list_response(
            _normalize_contract_model(SkillListContract, payload, ())
        )
    if segments == ("schedules",):
        return _project_schedule_list_response(
            _normalize_contract_model(ScheduleListContract, payload, ())
        )
    if len(segments) == 2 and segments[0] == "schedules":
        return _normalize_schedule_detail_response(payload)
    if len(segments) == 3 and segments[0] == "schedules" and segments[2] == "delete":
        return _normalize_schedule_delete_response(payload)
    if len(segments) == 3 and segments[0] == "schedules" and segments[2] == "run-now":
        return normalize_control_run_contract_payload(payload)
    if len(segments) == 3 and segments[0] == "runs" and segments[2] == "logs":
        normalized = _normalize_contract_model(RunLogsContract, payload, ())
        requested_run_id = segments[1].strip()
        if normalized.get("run_id") != requested_run_id:
            raise ControlContractValidationError([
                _issue(("run_id",), "run_id must match requested control run id")
            ])
        return normalized
    return payload


def _project_skill_list_response(payload: dict[str, Any]) -> dict[str, Any]:
    skills = payload.get("skills")
    if not isinstance(skills, list):
        return {"skills": skills}
    projected = {
        "skills": [
            _project_control_skill(skill)
            if isinstance(skill, dict)
            else skill
            for skill in skills
        ]
    }
    if "catalog" in payload:
        projected["catalog"] = payload["catalog"]
    if "diagnostics" in payload:
        projected["diagnostics"] = payload["diagnostics"]
    return projected


def _project_control_skill(skill: dict[str, Any]) -> dict[str, Any]:
    """Project skill rows to product-safe browser metadata."""

    return {
        key: value
        for key, value in skill.items()
        if key in CONTROL_SKILL_BROWSER_SAFE_FIELDS
    }


def _project_schedule_list_response(payload: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(payload)
    schedules = normalized.get("schedules")
    if isinstance(schedules, list):
        normalized["schedules"] = [
            _project_control_schedule(schedule)
            if isinstance(schedule, dict)
            else schedule
            for schedule in schedules
        ]
    return normalized


def _project_control_schedule(schedule: dict[str, Any]) -> dict[str, Any]:
    """Project schedule rows to the browser-safe read model.

    Upstream CLI/TUI schedules can carry raw launchd/jobs command bodies. The web
    deck only needs display/provenance/capability fields, so unknown row fields
    fail closed until they are intentionally added to the shared contract.
    """

    projected = {
        key: value
        for key, value in schedule.items()
        if key in CONTROL_SCHEDULE_BROWSER_SAFE_FIELDS
    }
    if schedule.get("kind") == "agent_run_schedule":
        cadence = schedule.get("cadence")
        if isinstance(cadence, dict):
            try:
                projected["cadence"] = AgentRunScheduleCadenceContract.model_validate(cadence).model_dump(
                    mode="json",
                    exclude_unset=True,
                )
            except ValidationError:
                pass
        dispatch = schedule.get("dispatch")
        if isinstance(dispatch, dict):
            try:
                projected["dispatch"] = AgentRunScheduleDispatchContract.model_validate(dispatch).model_dump(
                    mode="json",
                    exclude_unset=True,
                )
            except ValidationError:
                pass
    return projected


def _normalize_schedule_detail_response(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict) and isinstance(payload.get("schedule"), dict):
        normalized = _normalize_contract_model(ScheduleEnvelopeContract, payload, ())
        schedule = normalized.get("schedule")
        if isinstance(schedule, dict):
            return {"schedule": _project_control_schedule(schedule)}
        return normalized
    return _project_control_schedule(_normalize_contract_model(ControlScheduleContract, payload, ()))


def _normalize_schedule_delete_response(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict) and isinstance(payload.get("schedule"), dict):
        return _normalize_schedule_detail_response(payload)
    if isinstance(payload, dict):
        if "deleted" in payload or "ok" in payload:
            return _normalize_contract_model(
                ScheduleDeleteResponseContract,
                payload,
                (),
                root_message="control response must be an object",
            )
        try:
            return _project_control_schedule(_normalize_contract_model(ControlScheduleContract, payload, ()))
        except ControlContractValidationError:
            return _normalize_contract_model(
                ScheduleDeleteResponseContract,
                payload,
                (),
                root_message="control response must be an object",
            )
    return _normalize_contract_model(
        ScheduleDeleteResponseContract,
        payload,
        (),
        root_message="control response must be an object",
    )


def normalize_control_request_contract_payload(payload: Any, segments: tuple[str, ...]) -> Any:
    """Validate browser-originated Agent Control request envelopes before forwarding."""

    if not control_request_contract_applies(segments):
        return payload
    if segments == ("runs",):
        return _normalize_control_dispatch_request(payload)
    if segments == ("schedules",):
        return _normalize_contract_model(
            AgentRunScheduleCreateRequestContract,
            payload,
            (),
            root_message="control request must be an object",
        )
    if len(segments) == 2 and segments[0] == "schedules":
        return _normalize_contract_model(
            AgentRunScheduleUpdateRequestContract,
            payload,
            (),
            root_message="control request must be an object",
        )
    if len(segments) == 3 and segments[0] == "schedules" and segments[2] == "enabled":
        return _normalize_contract_model(
            ScheduleEnabledRequestContract,
            payload,
            (),
            root_message="control request must be an object",
        )
    if len(segments) == 3 and segments[0] == "schedules" and segments[2] == "run-now":
        return _normalize_contract_model(
            ScheduleRunNowRequestContract,
            payload,
            (),
            root_message="control request must be an object",
        )
    if len(segments) == 4 and segments[0] == "runs" and segments[2] == "approvals":
        return _normalize_contract_model(
            ApprovalDecisionRequestContract,
            payload,
            (),
            root_message="control request must be an object",
        )
    if _is_approval_notification_retry_segments(segments):
        return _normalize_contract_model(
            ApprovalNotificationRetryRequestContract,
            payload,
            (),
            root_message="control request must be an object",
        )
    if len(segments) == 3 and segments[0] == "runs" and segments[2] == "messages":
        return _normalize_control_run_message_request(payload)
    if len(segments) == 3 and segments[0] == "runs" and segments[2] == "resume":
        return _normalize_contract_model(
            ResumeRunRequestContract,
            payload,
            (),
            root_message="control request must be an object",
        )
    return payload


def control_response_contract_applies(segments: tuple[str, ...]) -> bool:
    return (
        segments == ("approvals",)
        or _is_approval_notification_retry_segments(segments)
        or segments == ("artifacts",)
        or segments == ("readable-resources",)
        or segments == ("skills",)
        or segments == ("schedules",)
        or (len(segments) == 2 and segments[0] == "readable-resources")
        or (len(segments) == 2 and segments[0] == "schedules")
        or (len(segments) == 3 and segments[0] == "schedules" and segments[2] == "delete")
        or (len(segments) == 3 and segments[0] == "schedules" and segments[2] == "run-now")
        or (len(segments) == 3 and segments[0] == "runs" and segments[2] == "logs")
    )


def control_request_contract_applies(segments: tuple[str, ...]) -> bool:
    return (
        segments == ("runs",)
        or segments == ("schedules",)
        or (len(segments) == 2 and segments[0] == "schedules")
        or (len(segments) == 3 and segments[0] == "schedules" and segments[2] == "enabled")
        or (len(segments) == 3 and segments[0] == "schedules" and segments[2] == "run-now")
        or (len(segments) == 4 and segments[0] == "runs" and segments[2] == "approvals")
        or _is_approval_notification_retry_segments(segments)
        or (len(segments) == 3 and segments[0] == "runs" and segments[2] == "messages")
        or (len(segments) == 3 and segments[0] == "runs" and segments[2] == "resume")
    )


def _is_approval_notification_retry_segments(segments: tuple[str, ...]) -> bool:
    return (
        len(segments) == 6
        and segments[0] == "runs"
        and segments[2] == "approvals"
        and segments[4] == "notifications"
        and segments[5] == "retry"
    )


def _looks_like_direct_control_run(payload: dict[str, Any]) -> bool:
    return payload.get("kind") in {"chat", "autonomous"} or (
        "kind" in payload and ("run_id" in payload or "state" in payload)
    )


def _normalize_control_run(payload: Any, path: tuple[str | int, ...]) -> tuple[dict[str, Any] | None, list[dict[str, str]]]:
    if not isinstance(payload, dict):
        return None, [_issue(path, "control run must be an object")]
    try:
        run = ControlRunContract.model_validate(payload)
    except ValidationError as exc:
        return None, _validation_issues(exc, path)
    return run.model_dump(mode="json", exclude_unset=True), []


def _normalize_control_run_message_request(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ControlContractValidationError([_issue((), "control request must be an object")])
    has_chat_transcript = "messages" in payload
    has_autonomous_message = "message" in payload
    if has_chat_transcript and has_autonomous_message:
        raise ControlContractValidationError([
            _issue((), "run message request must include either messages or message, not both")
        ])
    if has_chat_transcript:
        return _normalize_contract_model(ChatRunMessageRequestContract, payload, ())
    if has_autonomous_message:
        return _normalize_contract_model(AutonomousRunMessageRequestContract, payload, ())
    raise ControlContractValidationError([
        _issue((), "run message request must include messages or message")
    ])


def _normalized_control_field_key(value: str) -> str:
    snake_case = re.sub(r"(?<!^)(?=[A-Z])", "_", value)
    return re.sub(r"[^a-z0-9]+", "_", snake_case.lower()).strip("_")


def _context_authority_path(value: Any, path: tuple[str | int, ...] = ()) -> tuple[str | int, ...] | None:
    if isinstance(value, dict):
        for key, nested_value in value.items():
            normalized_key = _normalized_control_field_key(str(key))
            next_path = path + (str(key),)
            if normalized_key in _CONTROL_CONTEXT_AUTHORITY_FIELDS:
                return next_path
            nested_issue_path = _context_authority_path(nested_value, next_path)
            if nested_issue_path is not None:
                return nested_issue_path
    elif isinstance(value, list):
        for index, item in enumerate(value):
            nested_issue_path = _context_authority_path(item, path + (index,))
            if nested_issue_path is not None:
                return nested_issue_path
    return None


def _reject_context_authority_fields(payload: dict[str, Any]) -> None:
    issue_path = _context_authority_path(payload.get("context"))
    if issue_path is None:
        return
    raise ControlContractValidationError([
        _issue(
            ("context",) + issue_path,
            "context must not include portfolio, account, owner, credential, token, route, or channel authority fields",
        )
    ])


def _normalize_control_dispatch_request(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ControlContractValidationError([_issue((), "control request must be an object")])
    kind = payload.get("kind")
    if kind == "chat":
        _reject_context_authority_fields(payload)
        return _normalize_contract_model(
            ChatRunDispatchRequestContract,
            payload,
            (),
            root_message="control request must be an object",
        )
    if kind == "autonomous":
        return _normalize_contract_model(
            AutonomousRunDispatchRequestContract,
            payload,
            (),
            root_message="control request must be an object",
        )
    raise ControlContractValidationError([
        _issue(("kind",), "dispatch request kind must be chat or autonomous")
    ])


def _normalize_contract_model(
    model: type[BaseModel],
    payload: Any,
    path: tuple[str | int, ...],
    *,
    root_message: str = "control response must be an object",
) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ControlContractValidationError([_issue(path, root_message)])
    try:
        validated = model.model_validate(payload)
    except ValidationError as exc:
        raise ControlContractValidationError(_validation_issues(exc, path)) from exc
    return validated.model_dump(mode="json", exclude_unset=True)


def _validation_issues(exc: ValidationError, prefix: tuple[str | int, ...]) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    for error in exc.errors(include_url=False):
        loc = tuple(error.get("loc") or ())
        issues.append(
            _issue(
                prefix + loc,
                str(error.get("msg") or "invalid value"),
                error_type=str(error.get("type") or "validation_error"),
            )
        )
    return issues


def _issue(
    path: tuple[str | int, ...],
    message: str,
    *,
    error_type: str = "value_error",
) -> dict[str, str]:
    return {"path": _format_path(path), "message": message, "type": error_type}


def _format_path(path: tuple[str | int, ...]) -> str:
    if not path:
        return "$"
    formatted = ""
    for part in path:
        if isinstance(part, int):
            formatted += f"[{part}]"
        else:
            formatted += f".{part}" if formatted else part
    return formatted


__all__ = [
    "CONTROL_CONTRACT_SCHEMA_BUNDLE_VERSION",
    "CONTROL_EVENT_CONTRACT_ROUTES",
    "CONTROL_EVENT_CONTRACT_VERSION",
    "CONTROL_EVENT_PAYLOAD_ROUTE_SCHEMA_MODELS",
    "CONTROL_EVENT_PAYLOAD_SCHEMA_MODELS",
    "CONTROL_EVENT_ROUTE_SCHEMA_MODELS",
    "CONTROL_EVENT_ROUTE_SCHEMA_MODEL_NAMES",
    "CONTROL_KNOWN_EVENT_TYPES",
    "CONTROL_REQUEST_CONTRACT_ROUTES",
    "CONTROL_REQUEST_CONTRACT_VERSION",
    "CONTROL_REQUEST_ROUTE_SCHEMA_MODELS",
    "CONTROL_RESPONSE_CONTRACT_ROUTES",
    "CONTROL_RESPONSE_CONTRACT_VERSION",
    "CONTROL_RESPONSE_ROUTE_SCHEMA_MODELS",
    "CONTROL_DIRECT_RUN_ROUTE_SCHEMA_MODELS",
    "CONTROL_NON_DIRECT_RUN_ROUTE_SCHEMA_MODELS",
    "CONTROL_RUN_PAYLOAD_CONTRACT_ROUTES",
    "CONTROL_RUN_ROUTE_SCHEMA_MODELS",
    "CONTROL_RUN_CONTRACT_VERSION",
    "CONTROL_CONTRACT_SCHEMA_MODELS",
    "ApprovalListContract",
    "ApprovalDecisionRequestContract",
    "ApprovalNotificationContract",
    "ApprovalNotificationRetryRequestContract",
    "ApprovalNotificationRetryResponseContract",
    "AgentRunScheduleCadenceContract",
    "AgentRunScheduleCreateRequestContract",
    "AgentRunScheduleDispatchContract",
    "AgentRunScheduleUpdateRequestContract",
    "AutonomousRunDispatchRequestContract",
    "AutonomousRunMessageRequestContract",
    "ArtifactListContract",
    "ChatRunDispatchRequestContract",
    "ChatRunMessageEntryContract",
    "ChatRunMessageRequestContract",
    "ControlContractValidationError",
    "ControlArtifactContract",
    "ControlEventContract",
    "ControlEventEnvelopeContract",
    "ControlEventPayloadContract",
    "ControlRunContract",
    "ControlRunEnvelopeContract",
    "ControlRunListContract",
    "ControlSkillContract",
    "EventsDroppedControlEventContract",
    "FutureControlEventContract",
    "PendingApprovalContract",
    "ParentMessageSentControlEventContract",
    "ReadableResourceContract",
    "ReadableResourceDetailContract",
    "ReadableResourceListContract",
    "ReplayTruncatedControlEventContract",
    "DispatchScopeContract",
    "ResumeRunRequestContract",
    "RunLogsContract",
    "RunResumedControlEventContract",
    "RunResumedFromControlEventContract",
    "RunStateChangedControlEventContract",
    "ScheduleDeleteResponseContract",
    "ScheduleListContract",
    "ScheduleEnabledRequestContract",
    "ScheduleEnvelopeContract",
    "ControlScheduleContract",
    "SkillCatalogDiagnosticContract",
    "SkillCatalogStatusContract",
    "SkillListContract",
    "TextDeltaControlEventContract",
    "control_contract_schema_bundle",
    "control_request_contract_applies",
    "control_response_contract_applies",
    "normalize_control_request_contract_payload",
    "normalize_control_response_contract_payload",
    "normalize_control_run_contract_payload",
]
