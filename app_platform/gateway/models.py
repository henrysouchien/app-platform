"""Pydantic models for the gateway proxy."""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import unicodedata
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


_ALLOWED_EFFORT_LEVELS = frozenset(
  {"none", "minimal", "low", "medium", "high", "xhigh", "max"}
)
CHAT_ATTACHMENTS_CONTRACT = "chat-attachments-v1"
INVESTMENT_SELECTED_CONTENT_CONTRACT = "investment-selected-content-v1"
CHAT_ATTACHMENT_MAX_COUNT = 8
CHAT_ATTACHMENT_MAX_BYTES = 1024 * 1024
CHAT_ATTACHMENT_MAX_BASE64_BYTES = 1_398_104
CHAT_ATTACHMENT_MAX_TOTAL_BYTES = 4 * 1024 * 1024
CHAT_ATTACHMENT_MAX_TOTAL_BASE64_BYTES = 5_592_416
_CHAT_ATTACHMENT_NAME_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_CHAT_ATTACHMENT_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_CHAT_ATTACHMENT_MEDIA_TYPES_BY_SUFFIX = {
    ".txt": "text/plain",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".json": "application/json",
    ".csv": "text/csv",
    ".tsv": "text/tab-separated-values",
}


def _expected_attachment_input_name(index: int) -> str:
    return "source_document" if index == 1 else f"source_document_{index}"


class ChatAttachmentV1(BaseModel):
    """Closed, current-turn-only text attachment forwarded to the gateway."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["chat-attachment/1"]
    input_name: str
    display_name: str
    media_type: str
    encoding: Literal["utf-8"]
    content_bytes: int = Field(gt=0, le=CHAT_ATTACHMENT_MAX_BYTES)
    content_sha256: str
    content_b64: str = Field(
        min_length=4,
        max_length=CHAT_ATTACHMENT_MAX_BASE64_BYTES,
    )

    @field_validator("input_name")
    @classmethod
    def _validate_input_name(cls, value: str) -> str:
        if _CHAT_ATTACHMENT_NAME_RE.fullmatch(value) is None:
            raise ValueError("input_name is invalid")
        return value

    @field_validator("display_name")
    @classmethod
    def _validate_display_name(cls, value: str) -> str:
        normalized = unicodedata.normalize("NFC", value).strip()
        if value != normalized:
            raise ValueError(
                "display_name must be NFC-normalized without surrounding whitespace"
            )
        if not value or "/" in value or "\\" in value or value in {".", ".."}:
            raise ValueError("display_name must be a basename")
        if any(unicodedata.category(char) == "Cc" for char in value):
            raise ValueError("display_name contains control characters")
        if len(value.encode("utf-8")) > 255:
            raise ValueError("display_name exceeds 255 UTF-8 bytes")
        return value

    @field_validator("content_sha256")
    @classmethod
    def _validate_content_sha256(cls, value: str) -> str:
        if _CHAT_ATTACHMENT_SHA256_RE.fullmatch(value) is None:
            raise ValueError("content_sha256 must be 64 lowercase hex characters")
        return value

    @model_validator(mode="after")
    def _validate_content(self) -> "ChatAttachmentV1":
        suffix = next(
            (
                candidate
                for candidate in sorted(
                    _CHAT_ATTACHMENT_MEDIA_TYPES_BY_SUFFIX,
                    key=len,
                    reverse=True,
                )
                if self.display_name.lower().endswith(candidate)
            ),
            None,
        )
        expected_media_type = (
            _CHAT_ATTACHMENT_MEDIA_TYPES_BY_SUFFIX.get(suffix)
            if suffix is not None
            else None
        )
        if expected_media_type is None or self.media_type != expected_media_type:
            raise ValueError(
                "media_type does not match the allowlisted display_name suffix"
            )
        if not self.content_b64 or self.content_b64.startswith("data:"):
            raise ValueError(
                "content_b64 must be canonical base64 without a data URL prefix"
            )
        try:
            decoded = base64.b64decode(self.content_b64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("content_b64 is not valid base64") from exc
        if base64.b64encode(decoded).decode("ascii") != self.content_b64:
            raise ValueError("content_b64 is not canonical base64")
        if len(decoded) != self.content_bytes:
            raise ValueError("content_bytes does not match decoded content")
        if len(decoded) > CHAT_ATTACHMENT_MAX_BYTES:
            raise ValueError("attachment exceeds the per-file byte limit")
        try:
            decoded.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("attachment content must be valid UTF-8") from exc
        if hashlib.sha256(decoded).hexdigest() != self.content_sha256:
            raise ValueError("content_sha256 does not match decoded content")
        return self


class InvestmentArtifactSelection(BaseModel):
    """Untrusted coordinates for one explicit bounded Investment view."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    artifact_id: str = Field(min_length=1, max_length=256)
    view: Literal["summary", "excerpt"]

    @field_validator("artifact_id")
    @classmethod
    def _validate_artifact_id(cls, value: str) -> str:
        if value != value.strip() or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            raise ValueError("artifact_id is invalid")
        return value


class GatewayUiBlocksContract(BaseModel):
    """UI blocks contract declared by a rendering chat client."""

    contract_version: int


class GatewayChatRequest(BaseModel):
    """Client payload for proxied gateway chat."""

    model_config = ConfigDict(extra="forbid")

    messages: list[dict[str, Any]]
    context: dict[str, Any] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)
    model_key: Optional[str] = None
    effort: Optional[str] = None
    catalog_revision: Optional[str] = None
    ui_blocks_contract: GatewayUiBlocksContract | None = None
    attachments: tuple[ChatAttachmentV1, ...] = ()
    investment_artifact_selection: InvestmentArtifactSelection | None = None

    @model_validator(mode="after")
    def _validate_attachments(self) -> "GatewayChatRequest":
        if len(self.attachments) > CHAT_ATTACHMENT_MAX_COUNT:
            raise ValueError(
                f"attachments cannot contain more than {CHAT_ATTACHMENT_MAX_COUNT} files"
            )
        total_bytes = sum(attachment.content_bytes for attachment in self.attachments)
        if total_bytes > CHAT_ATTACHMENT_MAX_TOTAL_BYTES:
            raise ValueError("attachments exceed the aggregate decoded byte limit")
        total_base64_bytes = sum(
            len(attachment.content_b64) for attachment in self.attachments
        )
        if total_base64_bytes > CHAT_ATTACHMENT_MAX_TOTAL_BASE64_BYTES:
            raise ValueError("attachments exceed the aggregate base64 byte limit")
        for index, attachment in enumerate(self.attachments, start=1):
            expected_name = _expected_attachment_input_name(index)
            if attachment.input_name != expected_name:
                raise ValueError(
                    f"attachments[{index - 1}].input_name must be {expected_name!r}"
                )
        return self

    @field_validator("model_key", "catalog_revision", mode="before")
    @classmethod
    def _normalize_selection_text(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("selection values must be strings")
        text = value.strip()
        return text or None

    @field_validator("effort", mode="before")
    @classmethod
    def _normalize_effort(cls, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip().lower()
        if not text:
            return None
        if text not in _ALLOWED_EFFORT_LEVELS:
            allowed = ", ".join(sorted(_ALLOWED_EFFORT_LEVELS))
            raise ValueError(f"invalid effort={value!r}; expected one of: {allowed}")
        return text


class GatewayChatCancelRequest(BaseModel):
    """Client payload for cancelling the active proxied gateway chat turn."""

    conversation_id: Optional[str] = None


class GatewayToolApprovalRequest(BaseModel):
    """Client payload for proxied gateway tool approvals."""

    tool_call_id: str
    nonce: str
    approved: bool
    allow_tool_type: Optional[bool] = None
    conversation_id: Optional[str] = None


class GatewayCapabilityChoice(BaseModel):
    """One authenticated, session-eligible stable model choice."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    model_key: str
    label: str
    supported_efforts: list[str]
    default_effort: str
    lifecycle: str


class GatewayCapabilityChoiceSelection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    model_key: str
    label: str
    effort: str
    reason: str


class GatewayCapabilityChoiceNotice(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    code: str
    message: str
    model_key: str | None = None


class GatewayCapabilityChoicesResponse(BaseModel):
    """Browser-safe projection of a single session capability's choices."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: Literal["session.driver"]
    catalog_revision: str
    policy_revision: str
    selected: GatewayCapabilityChoiceSelection | None
    notices: list[GatewayCapabilityChoiceNotice]
    choices: list[GatewayCapabilityChoice]


class GatewayModelPreferenceUpdate(BaseModel):
    """Stable-key account preference forwarded to the gateway authority."""

    model_config = ConfigDict(extra="forbid")

    model_key: str
    effort: str | None = None
    catalog_revision: str | None = None

    @field_validator("model_key", "catalog_revision", mode="before")
    @classmethod
    def _normalize_preference_text(cls, value: Any) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("preference selection values must be strings")
        return value.strip() or None

    @field_validator("effort", mode="before")
    @classmethod
    def _normalize_preference_effort(cls, value: Any) -> str | None:
        return GatewayChatRequest._normalize_effort(value)


class GatewayModelPreferenceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    capability: Literal["session.driver"]
    model_key: str | None
    effort: str | None


class GatewayCapabilitiesResponse(BaseModel):
    """Browser-safe gateway capability projection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: Literal["gateway-capabilities/1"] = "gateway-capabilities/1"
    status: Literal["available"] = "available"
    contracts: tuple[str, ...] = ()


__all__ = [
    "CHAT_ATTACHMENTS_CONTRACT",
    "INVESTMENT_SELECTED_CONTENT_CONTRACT",
    "ChatAttachmentV1",
    "InvestmentArtifactSelection",
    "GatewayCapabilityChoice",
    "GatewayCapabilityChoiceNotice",
    "GatewayCapabilityChoicesResponse",
    "GatewayCapabilityChoiceSelection",
    "GatewayCapabilitiesResponse",
    "GatewayChatCancelRequest",
    "GatewayChatRequest",
    "GatewayModelPreferenceResponse",
    "GatewayModelPreferenceUpdate",
    "GatewayToolApprovalRequest",
    "GatewayUiBlocksContract",
]
