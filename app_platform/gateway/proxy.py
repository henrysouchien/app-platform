"""Gateway proxy router factory."""

from __future__ import annotations

import asyncio
import copy
import inspect
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Optional
from urllib.parse import quote

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import ValidationError
from pydantic_core import core_schema

from app_platform.auth.dependencies import TIER_ORDER, resolve_user_tier
from .control_run_lifecycle import (
    is_control_chat_messageable_state,
    is_control_run_state,
    should_forget_control_chat_token,
)
from .control_contracts import (
    CONTROL_REQUEST_CONTRACT_VERSION,
    CONTROL_RESPONSE_CONTRACT_VERSION,
    CONTROL_RUN_CONTRACT_VERSION,
    ControlContractValidationError,
    control_request_contract_applies,
    control_response_contract_applies,
    normalize_control_request_contract_payload,
    normalize_control_response_contract_payload,
    normalize_control_run_contract_payload,
)
from .models import (
    CHAT_ATTACHMENTS_CONTRACT,
    INVESTMENT_SELECTED_CONTENT_CONTRACT,
    GatewayChatCancelRequest,
    GatewayCapabilityChoicesResponse,
    GatewayCapabilitiesResponse,
    GatewayChatRequest,
    GatewayModelPreferenceResponse,
    GatewayModelPreferenceUpdate,
    GatewayToolApprovalRequest,
)
from .session import GatewaySessionManager

logger = logging.getLogger(__name__)
_RESERVED_HEADERS = frozenset({"authorization"})
_KNOWN_UPSTREAM_ERRORS = frozenset(
    {
        "auth_expired",
        "cross_user_reuse",
        "missing_user_id",
        "strict_mode_default_user",
        "credentials_unavailable",
        "credentials_timeout",
    }
)
_STREAM_HEARTBEAT_SECONDS = 15.0
_CONTROL_IDENTITY_FIELDS = frozenset({"user_id", "user_email", "email", "risk_user_id"})
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
_CONTROL_PLANE_VERSION_HEADER = "X-Control-Plane-Version"
_CONTROL_CHAT_CONTINUATION_CONTRACT = "control-chat-continuation-v1"
_EXPLICIT_CONVERSATION_ID_RE = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")
_CONTROL_SCHEDULE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SAFE_ATTACHMENT_INPUT_NAME_RE = re.compile(r"^[a-z][a-z0-9._-]{0,127}$")
_CONTROL_ARTIFACT_DIRECT_OWNER_LOOKUP_LIMIT = 64


class _GatewayChatRequestOpenAPIBody:
    """Keep the canonical chat schema while validation maps safe HTTP errors."""

    @classmethod
    def __get_pydantic_core_schema__(
        cls,
        source_type: Any,
        handler: Any,
    ) -> core_schema.CoreSchema:
        del cls, source_type
        return core_schema.no_info_plain_validator_function(
            lambda value: value,
            json_schema_input_schema=handler.generate_schema(GatewayChatRequest),
        )


@dataclass
class GatewayConfig:
    """Gateway configuration with request-time resolvers."""

    gateway_url: str | Callable[[], str] = ""
    api_key: str | Callable[[], str] = field(default="", repr=False)
    ssl_verify: bool | str | Callable[[], bool | str] = True
    channel: str = "web"
    request_headers_factory: Callable[[Any], dict[str, str]] | None = None
    context_enricher: Callable[[Any, Any, dict[str, Any]], dict[str, Any]] | None = None
    dispatch_scope_validator: Callable[[Request, dict[str, Any], dict[str, Any]], Any] | None = None
    fail_on_context_enricher_error: bool = False
    min_chat_tier: str = "paid"
    required_contracts: frozenset[str] = field(default_factory=frozenset)
    contract_check_ttl_seconds: float = 300.0
    required_control_plane_version: str | None = "1"
    control_chat_continuation_contract: str | None = None

    def __post_init__(self) -> None:
        self.min_chat_tier = str(self.min_chat_tier or "paid").strip().lower() or "paid"
        if self.min_chat_tier not in TIER_ORDER:
            raise ValueError(
                f"Invalid min_chat_tier={self.min_chat_tier!r}; must be one of {sorted(TIER_ORDER)}"
            )
        if self.required_control_plane_version is not None:
            normalized_version = str(self.required_control_plane_version).strip()
            self.required_control_plane_version = normalized_version or None
        if self.control_chat_continuation_contract is not None:
            normalized_contract = str(self.control_chat_continuation_contract).strip()
            self.control_chat_continuation_contract = normalized_contract or None

    def resolve_url(self) -> str:
        raw_url = self.gateway_url() if callable(self.gateway_url) else self.gateway_url
        gateway_url = (raw_url or "").strip().rstrip("/")
        if not gateway_url:
            raise HTTPException(status_code=500, detail="GATEWAY_URL is not configured")
        return gateway_url

    def resolve_api_key(self) -> str:
        raw_key = self.api_key() if callable(self.api_key) else self.api_key
        api_key = (raw_key or "").strip()
        if not api_key:
            raise HTTPException(status_code=500, detail="GATEWAY_API_KEY is not configured")
        return api_key

    def resolve_ssl_verify(self) -> bool | str:
        raw_verify = self.ssl_verify() if callable(self.ssl_verify) else self.ssl_verify
        if isinstance(raw_verify, str):
            return _parse_ssl_verify(raw_verify)
        return raw_verify


@dataclass(frozen=True)
class _ChatRunToken:
    token: str = field(repr=False)
    expires_at: float | None = None


def _parse_ssl_verify(raw: str) -> bool | str:
    """Parse SSL verification from an env-style string."""

    stripped = raw.strip()
    lowered = stripped.lower()
    if lowered == "false":
        return False
    if lowered in ("", "true"):
        return True
    return stripped


def default_http_client_factory(ssl_verify: bool | str) -> httpx.AsyncClient:
    """Create the upstream HTTP client with the standard timeout policy."""

    timeout = httpx.Timeout(connect=10.0, read=None, write=30.0, pool=30.0)
    return httpx.AsyncClient(timeout=timeout, verify=ssl_verify, trust_env=False)


def _get_user_key(user: dict[str, Any]) -> str:
    """Build a stable user key for per-user state."""

    user_id = user.get("user_id")
    if user_id is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid user identity (user_id missing — auth middleware bug)",
        )
    return str(user_id)


def _require_min_chat_tier(user: dict[str, Any], config: GatewayConfig) -> str:
    """Require the same paid-tier floor for every gateway-backed AI surface."""

    user_tier = resolve_user_tier(user)
    if TIER_ORDER.get(user_tier, 0) < TIER_ORDER[config.min_chat_tier]:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "upgrade_required",
                "message": f"AI chat requires a {config.min_chat_tier} subscription.",
                "tier_required": config.min_chat_tier,
                "tier_current": user_tier,
            },
        )
    return user_tier


def _explicit_conversation_id(context: Any) -> str | None:
    """Return a validated client-supplied conversation_id for proxy session scoping."""

    if not isinstance(context, dict):
        return None
    raw_conversation_id = context.get("conversation_id")
    if raw_conversation_id is None:
        return None
    if not isinstance(raw_conversation_id, str):
        logger.warning("Ignoring invalid gateway conversation_id: expected string")
        return None

    conversation_id = raw_conversation_id.strip()
    if _EXPLICIT_CONVERSATION_ID_RE.fullmatch(conversation_id) is None:
        logger.warning(
            "Ignoring invalid gateway conversation_id: unsafe charset, empty, or too long"
        )
        return None
    return conversation_id


def _query_conversation_id(request: Request) -> str | None:
    """Return a validated proxy conversation id from query parameters."""

    raw_conversation_id = request.query_params.get("conversation_id")
    if raw_conversation_id is None:
        return None
    conversation_id = raw_conversation_id.strip()
    if not conversation_id:
        return None
    if _EXPLICIT_CONVERSATION_ID_RE.fullmatch(conversation_id) is None:
        raise HTTPException(status_code=400, detail="Invalid conversation_id")
    return conversation_id


def _is_valid_control_schedule_id(value: str) -> bool:
    return _CONTROL_SCHEDULE_ID_RE.fullmatch(value) is not None


def _is_schedule_detail_segments(segments: tuple[str, ...]) -> bool:
    return len(segments) == 2 and segments[0] == "schedules"


def _is_schedule_delete_segments(segments: tuple[str, ...]) -> bool:
    return len(segments) == 3 and segments[0] == "schedules" and segments[2] == "delete"


def _build_gateway_chat_payload(
    chat_request: GatewayChatRequest,
    channel: str,
    user_key: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Build upstream chat payload with enforced channel/user_id.

    Optional stable-key intent and effort are forwarded when present.
    Channel and ``user_id`` remain proxy-enforced and cannot be spoofed from context.
    """

    upstream_context = {**(chat_request.context or {}), "channel": channel}
    if user_key is not None:
        upstream_context["user_id"] = user_key
    payload: dict[str, Any] = {
        "messages": chat_request.messages,
        "context": upstream_context,
        "metadata": chat_request.metadata or {},
    }
    if user_key is not None:
        payload["user_id"] = user_key
    if request_id is not None:
        payload["request_id"] = request_id
    if chat_request.model_key:
        payload["model_key"] = chat_request.model_key
    if chat_request.effort:
        payload["effort"] = chat_request.effort
    if chat_request.catalog_revision:
        payload["catalog_revision"] = chat_request.catalog_revision
    if chat_request.ui_blocks_contract is not None:
        payload["ui_blocks_contract"] = chat_request.ui_blocks_contract.model_dump()
    if chat_request.attachments:
        payload["attachments"] = [
            attachment.model_dump(mode="json")
            for attachment in chat_request.attachments
        ]
    if chat_request.investment_artifact_selection is not None:
        payload["investment_artifact_selection"] = (
            chat_request.investment_artifact_selection.model_dump(mode="json")
        )
    return payload


# The shared upstream client disables the read timeout for SSE bodies, so the
# wait for stream-open response headers must be bounded separately — otherwise a
# non-responding gateway parks the request forever with the user stream lock held.
_STREAM_OPEN_TIMEOUT_SECONDS = 30.0


async def _open_gateway_chat_stream(
    client: httpx.AsyncClient,
    gateway_url: str,
    session_token: str,
    payload: dict[str, Any],
    extra_headers: dict[str, str] | None = None,
) -> httpx.Response:
    headers: dict[str, str] = {}
    if extra_headers:
        headers.update(
            {key: value for key, value in extra_headers.items() if key.lower() not in _RESERVED_HEADERS}
        )
    headers["Authorization"] = f"Bearer {session_token}"
    request = client.build_request(
        "POST",
        f"{gateway_url}/api/chat",
        headers=headers,
        json=payload,
    )
    try:
        return await asyncio.wait_for(
            client.send(request, stream=True),
            timeout=_STREAM_OPEN_TIMEOUT_SECONDS,
        )
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            status_code=504,
            detail={
                "error": "gateway_stream_open_timeout",
                "message": (
                    "Gateway did not start the chat stream within "
                    f"{_STREAM_OPEN_TIMEOUT_SECONDS:.0f}s."
                ),
            },
        ) from exc


# Error bodies ride the same read=None client as SSE streams; a gateway that
# sends error headers but stalls the body would otherwise hold the request (and
# the user stream lock) indefinitely.
_ERROR_BODY_READ_TIMEOUT_SECONDS = 10.0


async def _read_error_body(response: httpx.Response) -> bytes:
    try:
        return await asyncio.wait_for(response.aread(), _ERROR_BODY_READ_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        logger.warning("gateway error-body read timed out; treating body as empty")
        return b""


async def _classify_upstream_error(
    response: httpx.Response,
) -> tuple[str, dict[str, Any] | None, bytes]:
    """Classify gateway pre-stream errors without parsing SSE streams.

    Returns the raw body bytes alongside the classification: the body is read
    exactly once here (a timed-out read leaves the stream consumed, so callers
    must not attempt a second ``aread``).
    """

    body_bytes = await _read_error_body(response)
    try:
        body = json.loads(body_bytes)
    except (ValueError, TypeError):
        body = None

    if isinstance(body, dict):
        error_code = body.get("error")
        if error_code in _KNOWN_UPSTREAM_ERRORS:
            return str(error_code), body, body_bytes

    if response.status_code == 401:
        return "session_expired", body if isinstance(body, dict) else None, body_bytes

    return "unknown", body if isinstance(body, dict) else None, body_bytes


async def _fetch_gateway_contracts(client: httpx.AsyncClient, gateway_url: str) -> set[str]:
    # Bounded explicitly: the shared client has read=None for SSE streaming, which
    # would let this plain JSON GET wait forever on an unresponsive gateway.
    response = await client.get(
        f"{gateway_url}/api/health",
        timeout=httpx.Timeout(10.0),
    )
    if response.status_code >= 400:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "gateway_health_unavailable",
                "message": "Gateway health check failed.",
                "upstream_status": response.status_code,
            },
        )
    try:
        payload = response.json()
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=502,
            detail={
                "error": "gateway_health_invalid",
                "message": "Gateway health response was not valid JSON.",
            },
        ) from exc

    raw_contracts = ((payload.get("package") or {}).get("contracts") if isinstance(payload, dict) else None)
    if not isinstance(raw_contracts, list):
        return set()
    return {str(contract) for contract in raw_contracts if str(contract).strip()}


def _gateway_heartbeat_chunk() -> bytes:
    payload = json.dumps({"type": "heartbeat", "timestamp": int(time.time())})
    return f"data: {payload}\n\n".encode("utf-8")


def create_gateway_router(
    config: GatewayConfig,
    get_current_user: Callable[..., Any],
    http_client_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
    *,
    session_manager: Optional[GatewaySessionManager] = None,
) -> APIRouter:
    """Create a gateway proxy router with injected config and auth."""

    router = APIRouter(tags=["gateway-proxy"])
    session_manager = session_manager if session_manager is not None else GatewaySessionManager()
    contract_cache: dict[str, Any] = {"gateway_url": None, "contracts": set(), "checked_at": 0.0}
    chat_run_tokens: dict[str, _ChatRunToken] = {}
    chat_run_messageable: dict[str, bool] = {}

    def _create_http_client() -> httpx.AsyncClient:
        if http_client_factory is not None:
            return http_client_factory()
        return default_http_client_factory(config.resolve_ssl_verify())

    router._session_manager = session_manager  # type: ignore[attr-defined]
    router._create_http_client = _create_http_client  # type: ignore[attr-defined]

    def _reset_contract_cache_for_tests() -> None:
        contract_cache["gateway_url"] = None
        contract_cache["contracts"] = set()
        contract_cache["checked_at"] = 0.0

    router._reset_contract_cache_for_tests = _reset_contract_cache_for_tests  # type: ignore[attr-defined]

    async def _gateway_contracts(client: httpx.AsyncClient, gateway_url: str) -> set[str]:
        now = time.monotonic()
        if (
            contract_cache["gateway_url"] == gateway_url
            and now - float(contract_cache["checked_at"]) < config.contract_check_ttl_seconds
        ):
            return set(contract_cache["contracts"])

        try:
            contracts = await _fetch_gateway_contracts(client, gateway_url)
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "gateway_health_unreachable",
                    "message": "Gateway health check could not be reached",
                },
            ) from exc

        contract_cache["gateway_url"] = gateway_url
        contract_cache["contracts"] = set(contracts)
        contract_cache["checked_at"] = now
        return set(contracts)

    async def _ensure_gateway_contracts(client: httpx.AsyncClient, gateway_url: str) -> None:
        required_contracts = set(config.required_contracts or ())
        if not required_contracts:
            return

        contracts = await _gateway_contracts(client, gateway_url)
        missing = required_contracts - contracts
        if missing:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "gateway_contract_missing",
                    "message": "Gateway runtime is missing required contracts.",
                    "missing_contracts": sorted(missing),
                    "available_contracts": sorted(contracts),
                },
            )

    async def _ensure_chat_attachments_contract(
        client: httpx.AsyncClient,
        gateway_url: str,
    ) -> None:
        try:
            contracts = await _gateway_contracts(client, gateway_url)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "capability_unavailable",
                    "message": "Gateway capabilities are temporarily unavailable.",
                },
            ) from exc
        if CHAT_ATTACHMENTS_CONTRACT not in contracts:
            raise HTTPException(
                status_code=412,
                detail={
                    "code": "attachment_contract_unavailable",
                    "message": "The active gateway does not support chat attachments.",
                },
            )

    async def _ensure_investment_selected_content_contract(
        client: httpx.AsyncClient,
        gateway_url: str,
    ) -> None:
        try:
            contracts = await _gateway_contracts(client, gateway_url)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "capability_unavailable",
                    "message": "Gateway capabilities are temporarily unavailable.",
                },
            ) from exc
        if INVESTMENT_SELECTED_CONTENT_CONTRACT not in contracts:
            raise HTTPException(
                status_code=412,
                detail={
                    "code": "investment_selection_contract_unavailable",
                    "message": "The active gateway does not support Investment selections.",
                },
            )

    async def _supports_control_chat_continuation(client: httpx.AsyncClient, gateway_url: str) -> bool:
        required_contract = config.control_chat_continuation_contract
        if not required_contract:
            return False
        try:
            contracts = await _gateway_contracts(client, gateway_url)
        except HTTPException:
            raise
        except Exception:
            return False
        return required_contract in contracts

    async def _validated_gateway_chat_request(
        payload: _GatewayChatRequestOpenAPIBody = Body(...),
    ) -> GatewayChatRequest:
        try:
            return GatewayChatRequest.model_validate(payload)
        except ValidationError as exc:
            errors = exc.errors(include_input=False, include_url=False)
            messages = tuple(str(error.get("msg") or "") for error in errors)
            attachment_errors = tuple(
                error
                for error in errors
                if tuple(error.get("loc", ())[:1]) == ("attachments",)
                or "attachment" in str(error.get("msg") or "").lower()
            )
            investment_selection_errors = tuple(
                error
                for error in errors
                if tuple(error.get("loc", ())[:1])
                == ("investment_artifact_selection",)
            )
            status_code = 422
            code = "chat_request_invalid"
            message = "The chat request did not match the gateway proxy contract."
            if attachment_errors:
                code = "attachment_invalid"
                message = "An attachment did not match the chat attachment contract."
            elif investment_selection_errors:
                code = "investment_selection_invalid"
                message = "The Investment selection did not match the gateway contract."
            if any("media_type" in error_message for error_message in messages):
                status_code = 415
                code = "attachment_media_type_unsupported"
                message = "The attachment media type is not supported."
            if any(
                marker in error_message
                for error_message in messages
                for marker in (
                    "more than 8 files",
                    "aggregate decoded byte limit",
                    "aggregate base64 byte limit",
                    "less than or equal to 1048576",
                )
            ):
                status_code = 413
                code = "attachment_limit_exceeded"
                message = "The attachment count or size limit was exceeded."

            input_name = None
            raw_attachments = payload.get("attachments") if isinstance(payload, dict) else None
            if isinstance(raw_attachments, list):
                for error in attachment_errors:
                    location = tuple(error.get("loc", ()))
                    if len(location) < 2 or not isinstance(location[1], int):
                        continue
                    index = location[1]
                    if not (0 <= index < len(raw_attachments)):
                        continue
                    raw_attachment = raw_attachments[index]
                    candidate = (
                        raw_attachment.get("input_name")
                        if isinstance(raw_attachment, dict)
                        else None
                    )
                    if (
                        isinstance(candidate, str)
                        and _SAFE_ATTACHMENT_INPUT_NAME_RE.fullmatch(candidate) is not None
                    ):
                        input_name = candidate
                        break

            detail = {"code": code, "message": message}
            if input_name is not None:
                detail["input_name"] = input_name
            raise HTTPException(
                status_code=status_code,
                detail=detail,
            ) from exc

    def _user_email(user: dict[str, Any]) -> str | None:
        raw_user_email = user.get("email")
        if raw_user_email is not None and str(raw_user_email).strip():
            return str(raw_user_email).strip()
        return None

    async def _control_token(
        user_key: str,
        user_email: str | None,
        client: httpx.AsyncClient,
        *,
        force_refresh: bool = False,
    ) -> str:
        return await session_manager.get_control_token(
            user_key=user_key,
            client=client,
            api_key_fn=config.resolve_api_key,
            gateway_url_fn=config.resolve_url,
            force_refresh=force_refresh,
            channel=config.channel,
            user_email=user_email,
        )

    def _chat_run_key(user_key: str, run_id: str) -> str:
        return f"{user_key}:chat-run:{run_id}"

    def _is_approval_notification_retry_path(segments: tuple[str, ...]) -> bool:
        return (
            len(segments) == 6
            and segments[0] == "runs"
            and segments[2] == "approvals"
            and segments[4] == "notifications"
            and segments[5] == "retry"
        )

    def _validate_control_path(path: str, method: str) -> tuple[str, tuple[str, ...]]:
        stripped = path.strip("/")
        if not stripped:
            raise HTTPException(status_code=404, detail="Control endpoint not found")
        segments = tuple(stripped.split("/"))
        if any(not segment or segment in {".", ".."} or "\\" in segment for segment in segments):
            raise HTTPException(status_code=404, detail="Control endpoint not found")

        allowed = False
        if segments == ("health",):
            allowed = method == "GET"
        elif segments == ("profiles",):
            allowed = method == "GET"
        elif segments == ("skills",):
            allowed = method == "GET"
        elif segments == ("events",):
            allowed = method == "GET"
        elif segments == ("runs",):
            allowed = method in {"GET", "POST"}
        elif segments == ("approvals",):
            allowed = method == "GET"
        elif segments == ("artifacts",):
            allowed = method == "GET"
        elif segments == ("readable-resources",):
            allowed = method == "GET"
        elif len(segments) == 2 and segments[0] == "readable-resources":
            allowed = method == "GET"
        elif segments == ("schedules",):
            allowed = method in {"GET", "POST"}
        elif len(segments) == 2 and segments[0] == "schedules":
            allowed = _is_valid_control_schedule_id(segments[1]) and method in {"GET", "PATCH", "DELETE"}
        elif len(segments) == 3 and segments[0] == "schedules" and segments[2] == "enabled":
            allowed = _is_valid_control_schedule_id(segments[1]) and method == "PUT"
        elif len(segments) == 3 and segments[0] == "schedules" and segments[2] == "run-now":
            allowed = _is_valid_control_schedule_id(segments[1]) and method == "POST"
        elif len(segments) == 2 and segments[0] == "runs":
            allowed = method in {"GET", "DELETE"}
        elif len(segments) == 3 and segments[0] == "runs" and segments[2] == "logs":
            allowed = method == "GET"
        elif len(segments) == 3 and segments[0] == "runs" and segments[2] == "messages":
            allowed = method == "POST"
        elif len(segments) == 3 and segments[0] == "runs" and segments[2] == "resume":
            allowed = method == "POST"
        elif len(segments) == 4 and segments[0] == "runs" and segments[2] == "approvals":
            allowed = method == "POST"
        elif _is_approval_notification_retry_path(segments):
            allowed = method == "POST"

        if not allowed:
            raise HTTPException(status_code=404, detail="Control endpoint not found")

        return "/".join(quote(segment, safe="") for segment in segments), segments

    def _validate_artifact_detail_path(path: str, method: str) -> tuple[str, tuple[str, ...]]:
        stripped = path.strip("/")
        if not stripped:
            raise HTTPException(status_code=404, detail="Artifact endpoint not found")
        segments = tuple(stripped.split("/"))
        if (
            method != "GET"
            or len(segments) != 3
            or any(not segment or segment in {".", ".."} or "\\" in segment for segment in segments)
        ):
            raise HTTPException(status_code=404, detail="Artifact endpoint not found")
        return "/".join(quote(segment, safe="") for segment in segments), segments

    def _strip_client_identity(payload: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in payload.items() if key not in _CONTROL_IDENTITY_FIELDS}

    def _control_field_key(value: str) -> str:
        snake_case = re.sub(r"(?<!^)(?=[A-Z])", "_", value)
        return re.sub(r"[^a-z0-9]+", "_", snake_case.lower()).strip("_")

    def _strip_context_authority(value: Any) -> Any:
        if isinstance(value, dict):
            return {
                key: _strip_context_authority(nested_value)
                for key, nested_value in value.items()
                if _control_field_key(str(key)) not in _CONTROL_CONTEXT_AUTHORITY_FIELDS
            }
        if isinstance(value, list):
            return [_strip_context_authority(item) for item in value]
        return value

    def _sanitize_context(context: Any, *, enforce_channel: bool) -> dict[str, Any] | None:
        if not isinstance(context, dict):
            return None
        sanitized = _strip_context_authority(context)
        if enforce_channel:
            sanitized["channel"] = config.channel
        else:
            sanitized.pop("channel", None)
        return sanitized

    def _autonomous_dispatch_policy_payload(segments: tuple[str, ...], payload: Any) -> dict[str, Any] | None:
        if not isinstance(payload, dict):
            return None
        if segments == ("runs",):
            return payload
        if segments == ("schedules",) or _is_schedule_detail_segments(segments):
            dispatch = payload.get("dispatch")
            return dispatch if isinstance(dispatch, dict) else None
        return None

    def _reject_web_control_dev_dispatch(segments: tuple[str, ...], payload: Any) -> None:
        policy_payload = _autonomous_dispatch_policy_payload(segments, payload)
        if config.channel != "web" or policy_payload is None or not isinstance(payload, dict):
            return
        def normalized_catalog_key(value: Any) -> str:
            return re.sub(r"[\s_-]+", "-", str(value or "").strip().lower()).strip("-")

        profile = normalized_catalog_key(policy_payload.get("profile"))
        skill = normalized_catalog_key(policy_payload.get("skill"))
        has_dev_mode = "dev_mode" in payload or "dev_mode" in policy_payload
        if not has_dev_mode and (
            policy_payload.get("kind") != "autonomous" or (profile != "fixture" and not skill.startswith("fixture-"))
        ):
            return

        raise HTTPException(
            status_code=403,
            detail={
                "error": "web_control_dev_dispatch_forbidden",
                "message": "Web Agent Control cannot launch fixture or dev-mode runs.",
            },
        )

    def _catalog_names(payload: Any, key: str) -> set[str]:
        if isinstance(payload, dict):
            raw_entries = payload.get(key)
        else:
            raw_entries = payload
        if not isinstance(raw_entries, list):
            return set()

        names: set[str] = set()
        for entry in raw_entries:
            raw_name = entry.get("name") if isinstance(entry, dict) else entry
            if raw_name is None:
                continue
            name = str(raw_name).strip()
            if name:
                names.add(name)
        return names

    async def _control_catalog_names(
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
        *,
        endpoint: str,
        key: str,
    ) -> set[str]:
        response = await client.get(
            f"{gateway_url}/api/control/{endpoint}",
            headers={"Authorization": f"Bearer {session_token}"},
        )
        if response.status_code >= 400:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "control_catalog_unavailable",
                    "message": f"Agent Control {endpoint} catalog could not be loaded.",
                    "upstream_status": response.status_code,
                },
            )
        try:
            payload = response.json()
        except (ValueError, TypeError) as exc:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "control_catalog_unavailable",
                    "message": f"Agent Control {endpoint} catalog returned invalid JSON.",
                },
            ) from exc

        return _catalog_names(payload, key)

    def _raise_dispatch_allowlist_error(field: str, value: str, allowed: set[str]) -> None:
        raise HTTPException(
            status_code=403,
            detail={
                "error": "control_dispatch_not_allowed",
                "message": f"Choose a {field} from the Agent Control {field} catalog.",
                "field": field,
                "value": value,
                "allowed_values": sorted(allowed),
            },
        )

    async def _ensure_autonomous_dispatch_catalog_allowed(
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
        *,
        user_key: str,
        user_email: str | None,
        segments: tuple[str, ...],
        payload: Any,
    ) -> str:
        policy_payload = _autonomous_dispatch_policy_payload(segments, payload)
        if policy_payload is None or policy_payload.get("kind") != "autonomous":
            return session_token

        mode = str(policy_payload.get("mode") or "task").strip() or "task"
        if mode not in {"task", "skill", "once"}:
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "control_dispatch_not_allowed",
                    "message": "Choose a supported Agent Control run mode.",
                    "field": "mode",
                    "value": mode,
                    "allowed_values": ["once", "skill", "task"],
                },
            )

        async def catalog_names(endpoint: str, key: str) -> set[str]:
            nonlocal session_token
            retried = False
            while True:
                try:
                    return await _control_catalog_names(
                        client,
                        gateway_url,
                        session_token,
                        endpoint=endpoint,
                        key=key,
                    )
                except HTTPException as exc:
                    detail = exc.detail
                    should_refresh = (
                        not retried
                        and isinstance(detail, dict)
                        and detail.get("error") == "control_catalog_unavailable"
                        and detail.get("upstream_status") == 401
                    )
                    if not should_refresh:
                        raise
                    retried = True
                    session_manager.invalidate_control_token(user_key)
                    session_token = await _control_token(
                        user_key,
                        user_email,
                        client,
                        force_refresh=True,
                    )

        profile = str(policy_payload.get("profile") or "").strip()
        profiles = await catalog_names("profiles", "profiles")
        if not profile or profile not in profiles:
            _raise_dispatch_allowlist_error("profile", profile, profiles)

        skill = str(policy_payload.get("skill") or "").strip()
        if mode != "skill":
            if skill:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "control_dispatch_not_allowed",
                        "message": "Skill is only allowed for skill-mode Agent Control runs.",
                        "field": "skill",
                        "value": skill,
                        "allowed_values": [],
                    },
                )
            return session_token

        skills = await catalog_names("skills", "skills")
        if not skill or skill not in skills:
            _raise_dispatch_allowlist_error("skill", skill, skills)
        return session_token

    async def _validate_dispatch_scope_for_browser(
        *,
        request: Request,
        user: dict[str, Any],
        segments: tuple[str, ...],
        payload: Any,
    ) -> Any:
        policy_payload = _autonomous_dispatch_policy_payload(segments, payload)
        if not isinstance(policy_payload, dict):
            return payload
        scope = policy_payload.get("dispatch_scope")
        if not isinstance(scope, dict) or config.dispatch_scope_validator is None:
            return payload

        try:
            validation_result = config.dispatch_scope_validator(request, user, copy.deepcopy(scope))
            if inspect.isawaitable(validation_result):
                validation_result = await validation_result
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "dispatch_scope_validation_failed",
                    "message": "Selected portfolio scope could not be validated.",
                },
            ) from exc

        if validation_result is None:
            return payload
        if not isinstance(validation_result, dict):
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "dispatch_scope_validation_failed",
                    "message": "Selected portfolio scope validator returned an invalid payload.",
                },
            )
        policy_payload["dispatch_scope"] = validation_result
        return payload

    def _store_chat_dispatch_tokens(user_key: str, payload: dict[str, Any]) -> dict[str, Any]:
        token = payload.get("chat_session_token")
        run_id = payload.get("run_id") or payload.get("chat_session_id")
        expires_at = payload.get("chat_session_expires_at")
        run_payload = payload.get("run")
        if isinstance(run_payload, dict):
            run_id = run_id or run_payload.get("run_id") or run_payload.get("session_id")
        if isinstance(token, str) and token.strip() and isinstance(run_id, str) and run_id.strip():
            expiry = None
            if expires_at is not None:
                try:
                    expiry = float(expires_at)
                except (TypeError, ValueError):
                    expiry = None
            chat_run_tokens[_chat_run_key(user_key, run_id.strip())] = _ChatRunToken(
                token=token.strip(),
                expires_at=expiry,
            )

        sanitized = dict(payload)
        sanitized.pop("chat_session_token", None)
        return sanitized

    def _get_chat_run_token(user_key: str, run_id: str) -> str | None:
        key = _chat_run_key(user_key, run_id)
        cached = chat_run_tokens.get(key)
        if cached is None:
            return None
        if cached.expires_at is not None and cached.expires_at <= time.time():
            chat_run_tokens.pop(key, None)
            return None
        return cached.token

    def _forget_chat_run_token(user_key: str, run_id: str) -> None:
        chat_run_tokens.pop(_chat_run_key(user_key, run_id), None)

    def _known_chat_run_messageable(user_key: str, run_id: str) -> bool | None:
        return chat_run_messageable.get(_chat_run_key(user_key, run_id))

    def _remember_chat_run_messageability(user_key: str, run_id: str, state: str) -> bool:
        messageable = is_control_chat_messageable_state(state)
        if messageable or is_control_run_state(state):
            chat_run_messageable[_chat_run_key(user_key, run_id)] = messageable
        else:
            chat_run_messageable[_chat_run_key(user_key, run_id)] = False
        return messageable

    def _forget_terminal_chat_run(user_key: str, payload: Any) -> None:
        if not isinstance(payload, dict):
            return
        runs_payload = payload.get("runs")
        if isinstance(runs_payload, list):
            for run_payload in runs_payload:
                _forget_terminal_chat_run(user_key, run_payload)
            return
        run_payload = payload.get("run") if isinstance(payload.get("run"), dict) else payload
        if not isinstance(run_payload, dict) or run_payload.get("kind") != "chat":
            return
        state = str(run_payload.get("state") or "")
        run_id = run_payload.get("run_id") or run_payload.get("session_id")
        if should_forget_control_chat_token(state) and isinstance(run_id, str) and run_id.strip():
            _forget_chat_run_token(user_key, run_id.strip())

    def _annotate_chat_messageability(
        user_key: str,
        payload: Any,
        *,
        control_chat_continuation_supported: bool,
    ) -> Any:
        if not isinstance(payload, dict):
            return payload

        def annotate_run(run_payload: Any) -> None:
            if not isinstance(run_payload, dict) or run_payload.get("kind") != "chat":
                return
            run_id = run_payload.get("run_id") or run_payload.get("session_id")
            has_token = isinstance(run_id, str) and bool(_get_chat_run_token(user_key, run_id.strip()))
            state_present = "state" in run_payload
            state = str(run_payload.get("state") or "")
            state_messageable = (
                _remember_chat_run_messageability(user_key, run_id.strip(), state)
                if state_present and isinstance(run_id, str) and bool(run_id.strip())
                else is_control_chat_messageable_state(state)
            )
            token_messageable = has_token and (
                not config.control_chat_continuation_contract or control_chat_continuation_supported
            ) and state_messageable
            # Web control sessions can continue same-user/channel chat runs upstream even
            # when this proxy process no longer has the minted chat-session token.
            run_payload["messageable"] = token_messageable or (
                control_chat_continuation_supported
                and
                isinstance(run_id, str) and bool(run_id.strip()) and state_messageable
            )

        runs_payload = payload.get("runs")
        if isinstance(runs_payload, list):
            for run_payload in runs_payload:
                annotate_run(run_payload)
        annotate_run(payload.get("run") if isinstance(payload.get("run"), dict) else payload)
        return payload

    def _control_plane_version_from_response(response: httpx.Response, payload: Any = None) -> str | None:
        header_version = response.headers.get(_CONTROL_PLANE_VERSION_HEADER)
        if header_version is not None and str(header_version).strip():
            return str(header_version).strip()
        if isinstance(payload, dict):
            raw_version = payload.get("control_plane_version") or payload.get("version")
            if raw_version is not None and str(raw_version).strip():
                return str(raw_version).strip()
        return None

    def _control_plane_version_headers(response: httpx.Response) -> dict[str, str]:
        version = response.headers.get(_CONTROL_PLANE_VERSION_HEADER)
        return {_CONTROL_PLANE_VERSION_HEADER: version} if version else {}

    def _control_plane_version_error(version: str | None, *, require_present: bool = False) -> JSONResponse | None:
        expected_version = config.required_control_plane_version
        if not expected_version or (not version and not require_present) or version == expected_version:
            return None
        actual_version = version or "missing"
        headers = {_CONTROL_PLANE_VERSION_HEADER: version} if version else {}
        return JSONResponse(
            status_code=502,
            content={
                "detail": {
                    "error": "control_plane_version_mismatch",
                    "message": "Gateway control plane version is not compatible with this client.",
                    "expected_version": expected_version,
                    "actual_version": actual_version,
                }
            },
            headers=headers,
        )

    def _control_response_contract_error(
        exc: ControlContractValidationError,
        response_headers: dict[str, str],
    ) -> JSONResponse:
        return JSONResponse(
            status_code=502,
            content={
                "detail": {
                    "error": "control_response_contract_invalid",
                    "message": "Agent Control received an unexpected control-plane response.",
                    "action": (
                        "Run Agent Control dev status and verify the upstream control-plane "
                        "response schema before retrying."
                    ),
                    "contract": CONTROL_RESPONSE_CONTRACT_VERSION,
                    "issues": exc.issues,
                }
            },
            headers=response_headers,
        )

    def _control_request_contract_error(exc: ControlContractValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content={
                "detail": {
                    "error": "control_request_contract_invalid",
                    "message": "Agent Control received an invalid browser control-plane request.",
                    "action": "Reload the page and retry the Agent Control action before continuing the run.",
                    "contract": CONTROL_REQUEST_CONTRACT_VERSION,
                    "issues": exc.issues,
                }
            },
        )

    def _string_set_from_field(record: dict[str, Any], key: str) -> set[str]:
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            return {value.strip()}
        if isinstance(value, list):
            return {
                entry.strip()
                for entry in value
                if isinstance(entry, str) and entry.strip()
            }
        return set()

    def _control_run_identity_values(run_payload: Any) -> set[str]:
        if not isinstance(run_payload, dict):
            return set()
        values: set[str] = set()
        for key in ("run_id", "task_id", "session_id", "control_run_id", "control_session_id"):
            values.update(_string_set_from_field(run_payload, key))
        values.update(_string_set_from_field(run_payload, "skill_run_ids"))
        values.update(_string_set_from_field(run_payload, "skillRunIds"))
        return values

    def _control_artifact_strong_owner_identity_values(artifact_payload: Any) -> set[str]:
        if not isinstance(artifact_payload, dict):
            return set()
        values: set[str] = set()
        for key in (
            "control_run_id",
            "control_session_id",
            "session_id",
            "task_id",
        ):
            values.update(_string_set_from_field(artifact_payload, key))
        return values

    def _control_artifact_run_id_owner_values(artifact_payload: Any) -> set[str]:
        if not isinstance(artifact_payload, dict):
            return set()
        if _control_artifact_strong_owner_identity_values(artifact_payload):
            return set()
        return _string_set_from_field(artifact_payload, "run_id")

    def _control_artifact_context_identity_values(artifact_payload: Any) -> set[str]:
        if not isinstance(artifact_payload, dict):
            return set()
        values = set[str]()
        for key in (
            "run_id",
            "skill_run_id",
            "skillRunId",
        ):
            values.update(_string_set_from_field(artifact_payload, key))
        return values

    def _control_artifact_visible_for_run_ids(artifact_payload: Any, visible_ids: set[str]) -> bool:
        strong_owner_ids = _control_artifact_strong_owner_identity_values(artifact_payload)
        if strong_owner_ids:
            return strong_owner_ids <= visible_ids
        return bool(_control_artifact_context_identity_values(artifact_payload) & visible_ids)

    async def _cached_visible_control_run_identity_values_for_owner(
        owner_id: str,
        *,
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
        direct_run_identity_cache: dict[str, set[str]],
    ) -> set[str] | None:
        if owner_id in direct_run_identity_cache:
            return direct_run_identity_cache[owner_id]
        if len(direct_run_identity_cache) >= _CONTROL_ARTIFACT_DIRECT_OWNER_LOOKUP_LIMIT:
            return None
        direct_run_identity_cache[owner_id] = await _visible_control_run_identity_values_for_run_id(
            client=client,
            gateway_url=gateway_url,
            session_token=session_token,
            run_id=owner_id,
        )
        return direct_run_identity_cache[owner_id]

    async def _visible_control_run_identity_values_for_run_id(
        *,
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
        run_id: str,
    ) -> set[str]:
        headers = {"Authorization": f"Bearer {session_token}"}
        response = await client.get(
            f"{gateway_url}/api/control/runs/{quote(run_id, safe='')}",
            headers=headers,
        )
        if response.status_code != 200:
            return set()
        try:
            payload = response.json()
        except ValueError:
            return set()
        version = _control_plane_version_from_response(response, payload)
        if _control_plane_version_error(version, require_present=True) is not None:
            return set()
        try:
            payload = normalize_control_run_contract_payload(payload, direct_run_required=True)
        except ControlContractValidationError:
            return set()
        run_payload = payload.get("run") if isinstance(payload, dict) and isinstance(payload.get("run"), dict) else payload
        return _control_run_identity_values(run_payload)

    async def _recent_visible_control_run_identity_sets(
        *,
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
    ) -> list[set[str]]:
        headers = {"Authorization": f"Bearer {session_token}"}
        response = await client.get(
            f"{gateway_url}/api/control/runs",
            headers=headers,
            params={"limit": 200},
        )
        if response.status_code != 200:
            return []
        try:
            payload = response.json()
        except ValueError:
            return []
        version = _control_plane_version_from_response(response, payload)
        if _control_plane_version_error(version, require_present=True) is not None:
            return []
        try:
            payload = normalize_control_run_contract_payload(payload)
        except ControlContractValidationError:
            return []
        runs = payload.get("runs") if isinstance(payload, dict) else None
        if not isinstance(runs, list):
            return []
        return [
            identity_values
            for run_payload in runs
            if (identity_values := _control_run_identity_values(run_payload))
        ]

    def _control_artifact_visible_for_recent_run_identity_sets(
        artifact_payload: Any,
        recent_visible_identity_sets: list[set[str]],
    ) -> bool:
        return any(
            _control_artifact_visible_for_run_ids(artifact_payload, visible_ids)
            for visible_ids in recent_visible_identity_sets
        )

    async def _control_artifact_visible_for_global_index(
        artifact_payload: Any,
        *,
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
        direct_run_identity_cache: dict[str, set[str]],
        recent_visible_identity_sets: list[set[str]] | None,
    ) -> tuple[bool, list[set[str]] | None]:
        strong_owner_ids = _control_artifact_strong_owner_identity_values(artifact_payload)
        if strong_owner_ids:
            if len(strong_owner_ids) > _CONTROL_ARTIFACT_DIRECT_OWNER_LOOKUP_LIMIT:
                return False, recent_visible_identity_sets
            for owner_id in sorted(strong_owner_ids):
                owner_visible_ids = await _cached_visible_control_run_identity_values_for_owner(
                    owner_id,
                    client=client,
                    gateway_url=gateway_url,
                    session_token=session_token,
                    direct_run_identity_cache=direct_run_identity_cache,
                )
                if owner_visible_ids is not None and _control_artifact_visible_for_run_ids(artifact_payload, owner_visible_ids):
                    return True, recent_visible_identity_sets
            if recent_visible_identity_sets is None:
                recent_visible_identity_sets = await _recent_visible_control_run_identity_sets(
                    client=client,
                    gateway_url=gateway_url,
                    session_token=session_token,
                )
            return (
                _control_artifact_visible_for_recent_run_identity_sets(artifact_payload, recent_visible_identity_sets),
                recent_visible_identity_sets,
            )

        run_id_owner_ids = _control_artifact_run_id_owner_values(artifact_payload)
        if run_id_owner_ids:
            if len(run_id_owner_ids) > _CONTROL_ARTIFACT_DIRECT_OWNER_LOOKUP_LIMIT:
                return False, recent_visible_identity_sets
            for owner_id in sorted(run_id_owner_ids):
                owner_visible_ids = await _cached_visible_control_run_identity_values_for_owner(
                    owner_id,
                    client=client,
                    gateway_url=gateway_url,
                    session_token=session_token,
                    direct_run_identity_cache=direct_run_identity_cache,
                )
                if owner_visible_ids is not None and owner_id in owner_visible_ids:
                    return True, recent_visible_identity_sets
            if recent_visible_identity_sets is None:
                recent_visible_identity_sets = await _recent_visible_control_run_identity_sets(
                    client=client,
                    gateway_url=gateway_url,
                    session_token=session_token,
                )
            return (
                _control_artifact_visible_for_recent_run_identity_sets(artifact_payload, recent_visible_identity_sets),
                recent_visible_identity_sets,
            )

        if recent_visible_identity_sets is None:
            recent_visible_identity_sets = await _recent_visible_control_run_identity_sets(
                client=client,
                gateway_url=gateway_url,
                session_token=session_token,
            )
        return (
            _control_artifact_visible_for_recent_run_identity_sets(artifact_payload, recent_visible_identity_sets),
            recent_visible_identity_sets,
        )

    async def _control_artifact_detail_visible_for_user(
        artifact_payload: Any,
        *,
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
    ) -> bool:
        if not isinstance(artifact_payload, dict):
            return True
        if (
            not _control_artifact_strong_owner_identity_values(artifact_payload)
            and not _control_artifact_run_id_owner_values(artifact_payload)
            and not _control_artifact_context_identity_values(artifact_payload)
        ):
            return True
        visible, _recent_visible_ids = await _control_artifact_visible_for_global_index(
            artifact_payload,
            client=client,
            gateway_url=gateway_url,
            session_token=session_token,
            direct_run_identity_cache={},
            recent_visible_identity_sets=None,
        )
        return visible

    def _control_readable_resource_is_human_readable(resource_payload: Any) -> bool:
        return isinstance(resource_payload, dict) and resource_payload.get("content_class") == "human_readable"

    async def _control_readable_resource_detail_visible_for_user(
        resource_payload: Any,
        *,
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
    ) -> bool:
        if not isinstance(resource_payload, dict):
            return False
        if (
            not _control_artifact_strong_owner_identity_values(resource_payload)
            and not _control_artifact_run_id_owner_values(resource_payload)
            and not _control_artifact_context_identity_values(resource_payload)
        ):
            return False
        return await _control_artifact_detail_visible_for_user(
            resource_payload,
            client=client,
            gateway_url=gateway_url,
            session_token=session_token,
        )

    def _readable_resource_not_found_response(response_headers: dict[str, str]) -> JSONResponse:
        return JSONResponse(
            status_code=404,
            content={
                "detail": {
                    "error": "readable_resource_not_found",
                    "message": "Readable resource not found.",
                }
            },
            headers=response_headers,
        )

    async def _artifact_detail_json_or_text_response(
        response: httpx.Response,
        *,
        user_key: str,
        segments: tuple[str, ...],
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
    ) -> Response:
        body = await response.aread()
        media_type = response.headers.get("content-type") or "application/octet-stream"
        response_headers = _control_plane_version_headers(response)
        if response.status_code >= 400:
            return await _json_or_text_response(
                httpx.Response(
                    response.status_code,
                    content=body,
                    headers=response.headers,
                    request=response.request,
                ),
                user_key=user_key,
                segments=segments,
            )
        if "application/json" not in media_type:
            return _control_response_contract_error(
                ControlContractValidationError([
                    {"path": "$", "message": "artifact detail response must be JSON", "type": "value_error"}
                ]),
                response_headers,
            )
        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            return _control_response_contract_error(
                ControlContractValidationError([
                    {"path": "$", "message": "artifact detail response must be valid JSON", "type": "value_error"}
                ]),
                response_headers,
            )

        version = _control_plane_version_from_response(response, payload)
        version_error = _control_plane_version_error(version, require_present=False)
        if version_error is not None:
            return version_error
        if not await _control_artifact_detail_visible_for_user(
            payload,
            client=client,
            gateway_url=gateway_url,
            session_token=session_token,
        ):
            return JSONResponse(
                status_code=404,
                content={
                    "detail": {
                        "error": "artifact_not_found",
                        "message": "Artifact not found.",
                    }
                },
                headers=response_headers,
            )
        return JSONResponse(content=payload, status_code=response.status_code, headers=response_headers)

    async def _filter_control_readable_resources_for_visible_runs(
        payload: Any,
        *,
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
        query_params: dict[str, str],
    ) -> Any:
        if not isinstance(payload, dict) or not isinstance(payload.get("readable_resources"), list):
            return payload
        resources = payload["readable_resources"]
        if not resources:
            return payload

        requested_run_id = str(query_params.get("run_id") or "").strip() or None
        if requested_run_id:
            visible_ids = await _visible_control_run_identity_values_for_run_id(
                client=client,
                gateway_url=gateway_url,
                session_token=session_token,
                run_id=requested_run_id,
            )
            filtered_resources = [
                resource
                for resource in resources
                if not isinstance(resource, dict)
                or (
                    _control_readable_resource_is_human_readable(resource)
                    and (
                        not (
                            _control_artifact_strong_owner_identity_values(resource)
                            or _control_artifact_run_id_owner_values(resource)
                            or _control_artifact_context_identity_values(resource)
                        )
                        or _control_artifact_visible_for_run_ids(resource, visible_ids)
                    )
                )
            ]
            return {**payload, "readable_resources": filtered_resources}

        filtered_resources = []
        direct_run_identity_cache: dict[str, set[str]] = {}
        recent_visible_identity_sets: list[set[str]] | None = None
        for resource in resources:
            if not isinstance(resource, dict):
                filtered_resources.append(resource)
                continue
            if not _control_readable_resource_is_human_readable(resource):
                continue
            if (
                not _control_artifact_strong_owner_identity_values(resource)
                and not _control_artifact_run_id_owner_values(resource)
                and not _control_artifact_context_identity_values(resource)
            ):
                filtered_resources.append(resource)
                continue
            visible, recent_visible_identity_sets = await _control_artifact_visible_for_global_index(
                resource,
                client=client,
                gateway_url=gateway_url,
                session_token=session_token,
                direct_run_identity_cache=direct_run_identity_cache,
                recent_visible_identity_sets=recent_visible_identity_sets,
            )
            if visible:
                filtered_resources.append(resource)
        return {**payload, "readable_resources": filtered_resources}

    async def _filter_control_artifacts_for_visible_runs(
        payload: Any,
        *,
        client: httpx.AsyncClient,
        gateway_url: str,
        session_token: str,
        query_params: dict[str, str],
    ) -> Any:
        if not isinstance(payload, dict) or not isinstance(payload.get("artifacts"), list):
            return payload
        artifacts = payload["artifacts"]
        if not artifacts:
            return payload

        requested_run_id = str(query_params.get("run_id") or "").strip() or None
        if requested_run_id:
            visible_ids = await _visible_control_run_identity_values_for_run_id(
                client=client,
                gateway_url=gateway_url,
                session_token=session_token,
                run_id=requested_run_id,
            )
            filtered_artifacts = [
                artifact
                for artifact in artifacts
                if _control_artifact_visible_for_run_ids(artifact, visible_ids)
            ]
            return {**payload, "artifacts": filtered_artifacts}

        filtered_artifacts = []
        direct_run_identity_cache: dict[str, set[str]] = {}
        recent_visible_identity_sets: list[set[str]] | None = None
        for artifact in artifacts:
            visible, recent_visible_identity_sets = await _control_artifact_visible_for_global_index(
                artifact,
                client=client,
                gateway_url=gateway_url,
                session_token=session_token,
                direct_run_identity_cache=direct_run_identity_cache,
                recent_visible_identity_sets=recent_visible_identity_sets,
            )
            if visible:
                filtered_artifacts.append(artifact)
        return {**payload, "artifacts": filtered_artifacts}

    def _sanitize_control_payload(segments: tuple[str, ...], payload: Any) -> Any:
        if not isinstance(payload, dict):
            return payload
        _reject_web_control_dev_dispatch(segments, payload)
        sanitized = _strip_client_identity(copy.deepcopy(payload))
        if segments == ("runs",) and sanitized.get("kind") in {"chat", "autonomous"}:
            sanitized.pop("channel", None)
            context = _sanitize_context(sanitized.get("context"), enforce_channel=False)
            if context is not None:
                sanitized["context"] = context
            return sanitized
        if len(segments) == 3 and segments[0] == "runs" and segments[2] == "messages":
            sanitized.pop("channel", None)
            if isinstance(sanitized.get("messages"), list):
                context = _sanitize_context(sanitized.get("context"), enforce_channel=True)
                if context is not None:
                    sanitized["context"] = context
            else:
                sanitized.pop("context", None)
            return sanitized
        if len(segments) == 3 and segments[0] == "runs" and segments[2] == "resume":
            sanitized.pop("channel", None)
            return sanitized
        if len(segments) == 4 and segments[0] == "runs" and segments[2] == "approvals":
            sanitized.pop("channel", None)
            sanitized.pop("context", None)
            return sanitized
        if _is_approval_notification_retry_path(segments):
            sanitized.pop("channel", None)
            sanitized.pop("context", None)
            return sanitized
        sanitized.pop("channel", None)
        context = _sanitize_context(sanitized.get("context"), enforce_channel=False)
        if context is not None:
            sanitized["context"] = context
        return sanitized

    def _inject_control_dispatch_channel(segments: tuple[str, ...], payload: Any) -> Any:
        if segments != ("runs",) or not isinstance(payload, dict) or payload.get("kind") not in {"chat", "autonomous"}:
            return payload
        body = {**payload, "channel": config.channel}
        if isinstance(body.get("context"), dict):
            body["context"] = {**body["context"], "channel": config.channel}
        return body

    async def _json_or_text_response(
        response: httpx.Response,
        *,
        user_key: str,
        segments: tuple[str, ...],
        response_contract_segments: tuple[str, ...] | None = None,
        direct_control_run_required: bool = False,
        chat_run_message_auth: bool = False,
        control_chat_continuation_supported: bool = False,
        client: httpx.AsyncClient | None = None,
        gateway_url: str | None = None,
        session_token: str | None = None,
        query_params: dict[str, str] | None = None,
    ) -> Response:
        body = await response.aread()
        media_type = response.headers.get("content-type") or "application/octet-stream"
        response_headers = _control_plane_version_headers(response)
        contract_segments = segments if response_contract_segments is None else response_contract_segments
        if response.status_code >= 400:
            if _is_approval_notification_retry_path(contract_segments):
                return JSONResponse(
                    status_code=response.status_code,
                    content={
                        "detail": {
                            "error": "approval_notification_retry_failed",
                            "message": "Approval notification retry could not be completed.",
                        }
                    },
                    headers=response_headers,
                )
            if response.status_code == 404 and segments == ("readable-resources",):
                return JSONResponse(
                    content={"readable_resources": []},
                    status_code=200,
                    headers=response_headers,
                )
            if response.status_code == 401 and len(segments) == 3 and segments[0] == "runs" and segments[2] == "messages":
                _forget_chat_run_token(user_key, segments[1])
                if chat_run_message_auth:
                    return JSONResponse(
                        status_code=409,
                        content={
                            "detail": {
                                "error": "chat_run_not_messageable",
                                "message": "This chat run can no longer be continued from Agent Control.",
                            }
                        },
                        headers=response_headers,
                    )
            return Response(
                content=body,
                status_code=response.status_code,
                media_type=media_type,
                headers=response_headers,
            )

        if "application/json" not in media_type:
            if response.status_code == 204 and not body and _is_schedule_delete_segments(contract_segments):
                return Response(status_code=response.status_code, headers=response_headers)
            version_error = _control_plane_version_error(
                _control_plane_version_from_response(response),
                require_present=segments == ("health",),
            )
            if version_error is not None:
                return version_error
            if control_response_contract_applies(contract_segments):
                return _control_response_contract_error(
                    ControlContractValidationError([
                        {"path": "$", "message": "control response must be JSON", "type": "value_error"}
                    ]),
                    response_headers,
                )
            return Response(
                content=body,
                status_code=response.status_code,
                media_type=media_type,
                headers=response_headers,
            )

        try:
            payload = json.loads(body)
        except (ValueError, TypeError):
            version_error = _control_plane_version_error(
                _control_plane_version_from_response(response),
                require_present=segments == ("health",),
            )
            if version_error is not None:
                return version_error
            if control_response_contract_applies(contract_segments):
                return _control_response_contract_error(
                    ControlContractValidationError([
                        {"path": "$", "message": "control response must be valid JSON", "type": "value_error"}
                    ]),
                    response_headers,
                )
            return Response(
                content=body,
                status_code=response.status_code,
                media_type=media_type,
                headers=response_headers,
            )
        version = _control_plane_version_from_response(response, payload)
        version_error = _control_plane_version_error(version, require_present=segments == ("health",))
        if version_error is not None:
            return version_error
        if isinstance(payload, dict) and version and segments == ("health",) and "control_plane_version" not in payload:
            payload["control_plane_version"] = version
        if len(contract_segments) == 2 and contract_segments[0] == "readable-resources":
            if not _control_readable_resource_is_human_readable(payload):
                return _readable_resource_not_found_response(response_headers)
            if (
                client is None
                or not gateway_url
                or not session_token
                or not await _control_readable_resource_detail_visible_for_user(
                    payload,
                    client=client,
                    gateway_url=gateway_url,
                    session_token=session_token,
                )
            ):
                return _readable_resource_not_found_response(response_headers)
            try:
                payload = normalize_control_response_contract_payload(payload, contract_segments)
            except ControlContractValidationError as exc:
                return _control_response_contract_error(exc, response_headers)
            return JSONResponse(content=payload, status_code=response.status_code, headers=response_headers)
        if segments and segments[0] == "runs" and not _is_approval_notification_retry_path(contract_segments):
            try:
                payload = normalize_control_run_contract_payload(
                    payload,
                    direct_run_required=direct_control_run_required,
                )
            except ControlContractValidationError as exc:
                return JSONResponse(
                    status_code=502,
                    content={
                        "detail": {
                            "error": "control_run_contract_invalid",
                            "message": "Gateway control run payload did not match the typed control-plane contract.",
                            "action": (
                                "Run Agent Control dev status and verify the upstream control-plane "
                                "run-state schema before retrying."
                            ),
                            "contract": CONTROL_RUN_CONTRACT_VERSION,
                            "issues": exc.issues,
                        }
                    },
                    headers=response_headers,
                )
        if segments not in {("artifacts",), ("readable-resources",)}:
            try:
                payload = normalize_control_response_contract_payload(payload, contract_segments)
            except ControlContractValidationError as exc:
                return _control_response_contract_error(exc, response_headers)
        if isinstance(payload, dict) and segments == ("runs",):
            payload = _store_chat_dispatch_tokens(user_key, payload)
        payload = _annotate_chat_messageability(
            user_key,
            payload,
            control_chat_continuation_supported=control_chat_continuation_supported,
        )
        if segments == ("artifacts",):
            if client is not None and gateway_url and session_token:
                payload = await _filter_control_artifacts_for_visible_runs(
                    payload,
                    client=client,
                    gateway_url=gateway_url,
                    session_token=session_token,
                    query_params=query_params or {},
                )
            try:
                payload = normalize_control_response_contract_payload(payload, contract_segments)
            except ControlContractValidationError as exc:
                return _control_response_contract_error(exc, response_headers)
        if segments == ("readable-resources",):
            if client is not None and gateway_url and session_token:
                payload = await _filter_control_readable_resources_for_visible_runs(
                    payload,
                    client=client,
                    gateway_url=gateway_url,
                    session_token=session_token,
                    query_params=query_params or {},
                )
            try:
                payload = normalize_control_response_contract_payload(payload, contract_segments)
            except ControlContractValidationError as exc:
                return _control_response_contract_error(exc, response_headers)
        _forget_terminal_chat_run(user_key, payload)
        return JSONResponse(content=payload, status_code=response.status_code, headers=response_headers)

    async def _proxy_control_stream(
        *,
        request: Request,
        user_key: str,
        user_email: str | None,
        path: str,
        segments: tuple[str, ...],
    ) -> Response:
        client = _create_http_client()
        upstream_response: httpx.Response | None = None

        async def _open(session_token: str) -> httpx.Response:
            req = client.build_request(
                "GET",
                f"{gateway_url}/api/control/{path}",
                headers={"Authorization": f"Bearer {session_token}"},
                params=dict(request.query_params),
            )
            return await client.send(req, stream=True)

        try:
            gateway_url = config.resolve_url()
            await _ensure_gateway_contracts(client, gateway_url)
            session_token = await _control_token(user_key, user_email, client)
            upstream_response = await _open(session_token)
            if upstream_response.status_code == 401:
                await upstream_response.aclose()
                session_manager.invalidate_control_token(user_key)
                session_token = await _control_token(user_key, user_email, client, force_refresh=True)
                upstream_response = await _open(session_token)

            if upstream_response.status_code != 200:
                response = await _json_or_text_response(
                    upstream_response,
                    user_key=user_key,
                    segments=segments,
                )
                await client.aclose()
                return response
            version = _control_plane_version_from_response(upstream_response)
            version_error = _control_plane_version_error(version, require_present=True)
            if version_error is not None:
                await upstream_response.aclose()
                await client.aclose()
                return version_error
            response_headers = {
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
                **_control_plane_version_headers(upstream_response),
            }

            async def event_stream():
                assert upstream_response is not None
                _disconnected = False
                _close_task: asyncio.Task | None = None

                def _start_close_upstream() -> asyncio.Task:
                    nonlocal _close_task

                    if _close_task is None:
                        _close_task = asyncio.create_task(upstream_response.aclose())
                        _close_task.add_done_callback(lambda t: t.exception())
                    return _close_task

                async def _watch_disconnect() -> None:
                    nonlocal _disconnected

                    while True:
                        await asyncio.sleep(2)
                        if await request.is_disconnected():
                            _disconnected = True
                            _start_close_upstream()
                            return

                disconnect_task = asyncio.create_task(_watch_disconnect())
                try:
                    async for chunk in upstream_response.aiter_raw():
                        if chunk:
                            yield chunk
                except asyncio.CancelledError:
                    raise
                except Exception:
                    if not _disconnected:
                        raise
                finally:
                    disconnect_task.cancel()
                    try:
                        await disconnect_task
                    except (asyncio.CancelledError, Exception):
                        pass
                    try:
                        await asyncio.shield(_start_close_upstream())
                    except (asyncio.CancelledError, Exception):
                        pass
                    try:
                        await asyncio.shield(client.aclose())
                    except (asyncio.CancelledError, Exception):
                        pass

            return StreamingResponse(
                event_stream(),
                media_type="text/event-stream",
                headers=response_headers,
            )
        except Exception as exc:
            if upstream_response is not None:
                await upstream_response.aclose()
            await client.aclose()
            # A transport/timeout error during stream SETUP (contracts/token/open — before any bytes are
            # sent) would otherwise re-raise as a bare 500 via Starlette ServerErrorMiddleware (outside
            # CORSMiddleware) → browser net::ERR_FAILED. Convert to a CORS-traversing 504/502; re-raise
            # everything else (incl. HTTPException, which already gets CORS) unchanged. CancelledError is a
            # BaseException, so this `except Exception` never catches it.
            if isinstance(exc, httpx.TimeoutException):
                raise HTTPException(
                    status_code=504,
                    detail={
                        "error": "control_upstream_timeout",
                        "message": "Agent control gateway timed out.",
                    },
                ) from exc
            if isinstance(exc, httpx.RequestError):
                raise HTTPException(
                    status_code=502,
                    detail={
                        "error": "control_upstream_unavailable",
                        "message": "Agent control gateway is unavailable.",
                    },
                ) from exc
            raise

    async def _proxy_control_request(
        *,
        request: Request,
        user: dict[str, Any],
        user_key: str,
        user_email: str | None,
        path: str,
        segments: tuple[str, ...],
        method: str,
        payload: Any = None,
    ) -> Response:
        _reject_web_control_dev_dispatch(segments, payload)
        body = _sanitize_control_payload(segments, payload)
        if method in {"POST", "PUT", "PATCH"}:
            try:
                body = normalize_control_request_contract_payload(body, segments)
            except ControlContractValidationError as exc:
                return _control_request_contract_error(exc)
        body = _inject_control_dispatch_channel(segments, body)
        body = await _validate_dispatch_scope_for_browser(
            request=request,
            user=user,
            segments=segments,
            payload=body,
        )
        client = _create_http_client()
        try:
            gateway_url = config.resolve_url()
            await _ensure_gateway_contracts(client, gateway_url)
            control_chat_continuation_supported = await _supports_control_chat_continuation(client, gateway_url)
            chat_run_token = None
            is_run_message = len(segments) == 3 and segments[0] == "runs" and segments[2] == "messages"
            is_chat_run_message = is_run_message and isinstance(body, dict) and isinstance(body.get("messages"), list)
            response_contract_segments: tuple[str, ...] | None = None
            if method == "POST" and segments == ("schedules",):
                response_contract_segments = ("schedules", "{schedule_id}")
            elif (
                method == "PUT"
                and len(segments) == 3
                and segments[0] == "schedules"
                and segments[2] == "enabled"
            ):
                response_contract_segments = ("schedules", segments[1])
            elif (
                method == "POST"
                and len(segments) == 3
                and segments[0] == "schedules"
                and segments[2] == "run-now"
            ):
                response_contract_segments = ("schedules", segments[1], "run-now")
            elif method == "DELETE" and len(segments) == 2 and segments[0] == "schedules":
                response_contract_segments = ("schedules", segments[1], "delete")
            elif method == "POST" and _is_approval_notification_retry_path(segments):
                response_contract_segments = segments
            if is_run_message:
                chat_run_token = _get_chat_run_token(user_key, segments[1])
                continuation_contract_required = bool(config.control_chat_continuation_contract)
                known_messageable = _known_chat_run_messageable(user_key, segments[1])
                if (
                    is_chat_run_message
                    and (
                        known_messageable is False
                        or (
                            not control_chat_continuation_supported
                            and (continuation_contract_required or chat_run_token is None)
                        )
                    )
                ):
                    return JSONResponse(
                        status_code=409,
                        content={
                            "detail": {
                                "error": "chat_run_not_messageable",
                                "message": "This chat run is not continuable from Agent Control.",
                            }
                        },
                    )
            control_session_token: str | None = None
            if chat_run_token:
                session_token = chat_run_token
            else:
                control_session_token = await _control_token(user_key, user_email, client)
                session_token = control_session_token
            if (
                method in {"POST", "PATCH"}
                and isinstance(body, dict)
                and _autonomous_dispatch_policy_payload(segments, body) is not None
            ):
                if control_session_token is None:
                    control_session_token = await _control_token(user_key, user_email, client)
                control_session_token = await _ensure_autonomous_dispatch_catalog_allowed(
                    client,
                    gateway_url,
                    control_session_token,
                    user_key=user_key,
                    user_email=user_email,
                    segments=segments,
                    payload=body,
                )
                session_token = control_session_token
            retried = False
            retried_chat_token_fallback = False
            while True:
                response = await client.request(
                    method,
                    f"{gateway_url}/api/control/{path}",
                    headers={"Authorization": f"Bearer {session_token}"},
                    params=dict(request.query_params),
                    json=body if method in {"POST", "PUT", "PATCH"} else None,
                )
                if (
                    response.status_code == 401
                    and is_chat_run_message
                    and chat_run_token
                    and control_chat_continuation_supported
                    and not retried_chat_token_fallback
                ):
                    _forget_chat_run_token(user_key, segments[1])
                    chat_run_token = None
                    retried_chat_token_fallback = True
                    session_token = await _control_token(user_key, user_email, client)
                    continue
                if response.status_code != 401 or retried:
                    return await _json_or_text_response(
                        response,
                        user_key=user_key,
                        segments=segments,
                        response_contract_segments=response_contract_segments,
                        direct_control_run_required=method in {"GET", "DELETE"}
                        and len(segments) == 2
                        and segments[0] == "runs",
                        chat_run_message_auth=bool(is_chat_run_message),
                        control_chat_continuation_supported=control_chat_continuation_supported,
                        client=client,
                        gateway_url=gateway_url,
                        session_token=session_token,
                        query_params=dict(request.query_params),
                    )
                retried = True
                session_manager.invalidate_control_token(user_key)
                session_token = await _control_token(user_key, user_email, client, force_refresh=True)
        except httpx.TimeoutException as exc:
            # Cold/slow upstream: surface a CORS-traversing 504 instead of letting the httpx error
            # propagate as a bare 500 via Starlette ServerErrorMiddleware — which sits OUTSIDE
            # CORSMiddleware, so the browser gets net::ERR_FAILED with no Access-Control-Allow-Origin
            # and the web Agent Control deck latches "unavailable".
            raise HTTPException(
                status_code=504,
                detail={
                    "error": "control_upstream_timeout",
                    "message": "Agent control gateway timed out.",
                },
            ) from exc
        except httpx.RequestError as exc:
            # Upstream unreachable (connect / transport error): same CORS-bypass hazard as the timeout.
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "control_upstream_unavailable",
                    "message": "Agent control gateway is unavailable.",
                },
            ) from exc
        finally:
            await client.aclose()

    async def _proxy_model_preference(
        *,
        method: str,
        user: dict[str, Any],
        update: GatewayModelPreferenceUpdate | None = None,
    ) -> GatewayModelPreferenceResponse:
        """Use this user's chat bearer for account preference authority."""

        _require_min_chat_tier(user, config)
        user_key = _get_user_key(user)
        raw_user_email = user.get("email")
        user_email = (
            str(raw_user_email).strip()
            if raw_user_email is not None and str(raw_user_email).strip()
            else None
        )
        client = _create_http_client()
        try:
            gateway_url = config.resolve_url()
            await _ensure_gateway_contracts(client, gateway_url)
            session_token = await session_manager.get_token(
                user_key=user_key,
                client=client,
                api_key_fn=config.resolve_api_key,
                gateway_url_fn=config.resolve_url,
                channel=config.channel,
                user_email=user_email,
            )
            retried = False
            while True:
                upstream = await client.request(
                    method,
                    f"{gateway_url}/api/model-preferences/session.driver",
                    headers={"Authorization": f"Bearer {session_token}"},
                    json=(
                        update.model_dump(exclude_none=True)
                        if update is not None
                        else None
                    ),
                    timeout=httpx.Timeout(10.0, read=20.0),
                )
                if upstream.status_code != 401 or retried:
                    break
                retried = True
                session_manager.invalidate_token(user_key)
                session_token = await session_manager.get_token(
                    user_key=user_key,
                    client=client,
                    api_key_fn=config.resolve_api_key,
                    gateway_url_fn=config.resolve_url,
                    force_refresh=True,
                    channel=config.channel,
                    user_email=user_email,
                )
            if upstream.status_code >= 400:
                await upstream.aread()
                raise HTTPException(
                    status_code=upstream.status_code,
                    detail={
                        "error": "model_preference_rejected",
                        "message": "The gateway rejected the model preference request.",
                    },
                    headers={"Cache-Control": "private, no-store"},
                )
            try:
                preference = GatewayModelPreferenceResponse.model_validate(
                    upstream.json()
                )
            except (ValueError, TypeError) as exc:
                raise HTTPException(
                    status_code=502,
                    detail={
                        "error": "model_preference_contract_invalid",
                        "message": "Gateway returned an invalid model preference response.",
                    },
                ) from exc
            session_manager.invalidate_token(user_key)
            return preference
        except httpx.TimeoutException as exc:
            raise HTTPException(
                status_code=504,
                detail={
                    "error": "model_preference_timeout",
                    "message": "Gateway model preference request timed out.",
                },
            ) from exc
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "model_preference_unavailable",
                    "message": "Gateway model preference service is unavailable.",
                },
            ) from exc
        finally:
            await client.aclose()

    @router.put(
        "/model-preferences/session.driver",
        response_model=GatewayModelPreferenceResponse,
    )
    async def gateway_put_model_preference(
        update: GatewayModelPreferenceUpdate,
        response: Response,
        user: dict[str, Any] = Depends(get_current_user),
    ) -> GatewayModelPreferenceResponse:
        response.headers["Cache-Control"] = "private, no-store"
        return await _proxy_model_preference(method="PUT", user=user, update=update)

    @router.delete(
        "/model-preferences/session.driver",
        response_model=GatewayModelPreferenceResponse,
    )
    async def gateway_delete_model_preference(
        response: Response,
        user: dict[str, Any] = Depends(get_current_user),
    ) -> GatewayModelPreferenceResponse:
        response.headers["Cache-Control"] = "private, no-store"
        return await _proxy_model_preference(method="DELETE", user=user)

    @router.get(
        "/capability-choices/session.driver",
        response_model=GatewayCapabilityChoicesResponse,
    )
    async def gateway_capability_choices(
        request: Request,
        user: dict[str, Any] = Depends(get_current_user),
    ) -> GatewayCapabilityChoicesResponse:
        """Return only this authenticated user's session-driver choices."""

        _require_min_chat_tier(user, config)
        user_key = _get_user_key(user)
        raw_user_email = user.get("email")
        user_email = None
        if raw_user_email is not None and str(raw_user_email).strip():
            user_email = str(raw_user_email).strip()

        client = _create_http_client()
        try:
            await _ensure_gateway_contracts(client, config.resolve_url())
            capability_choices = await session_manager.ensure_capability_choices(
                user_key=user_key,
                client=client,
                api_key_fn=config.resolve_api_key,
                gateway_url_fn=config.resolve_url,
                channel=config.channel,
                user_email=user_email,
            )
        finally:
            await client.aclose()

        if not isinstance(capability_choices, dict):
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "capability_choices_unavailable",
                    "message": "Session model choices are temporarily unavailable.",
                },
            )
        session_driver = capability_choices.get("session.driver")
        if not isinstance(session_driver, dict):
            raise HTTPException(
                status_code=503,
                detail={
                    "error": "capability_choices_unavailable",
                    "message": "Session-driver choices were not returned by the gateway.",
                },
            )
        return GatewayCapabilityChoicesResponse.model_validate(session_driver)

    @router.get("/capabilities")
    async def gateway_capabilities(
        user: dict[str, Any] = Depends(get_current_user),
    ) -> GatewayCapabilitiesResponse:
        """Project browser-safe optional gateway capabilities."""

        _require_min_chat_tier(user, config)
        client = _create_http_client()
        try:
            gateway_url = config.resolve_url()
            await _ensure_gateway_contracts(client, gateway_url)
            contracts = await _gateway_contracts(client, gateway_url)
        except Exception as exc:
            raise HTTPException(
                status_code=503,
                detail={
                    "code": "capability_unavailable",
                    "message": "Gateway capabilities are temporarily unavailable.",
                },
            ) from exc
        finally:
            await client.aclose()
        return GatewayCapabilitiesResponse(
            contracts=tuple(
                contract
                for contract in (
                    CHAT_ATTACHMENTS_CONTRACT,
                    INVESTMENT_SELECTED_CONTENT_CONTRACT,
                )
                if contract in contracts
            ),
        )

    @router.post("/chat")
    async def gateway_chat(
        request: Request,
        chat_request: GatewayChatRequest = Depends(_validated_gateway_chat_request),
        user: dict[str, Any] = Depends(get_current_user),
    ):
        """Proxy web-channel chat stream to the gateway."""

        context = chat_request.context or {}
        purpose = str(context.get("purpose") or "chat").strip().lower() or "chat"
        if purpose == "normalizer":
            raise HTTPException(
                status_code=400,
                detail={
                    "error": "chat_purpose_unavailable",
                    "message": "The requested chat purpose is not available.",
                },
            )
        conversation_id: str | None = None
        if purpose == "research_workspace":
            _thread_id = context.get("thread_id")
            if _thread_id is not None and str(_thread_id).strip():
                conversation_id = str(_thread_id).strip()
        if conversation_id is None:
            conversation_id = _explicit_conversation_id(context)
        _require_min_chat_tier(user, config)

        user_key = _get_user_key(user)
        raw_user_email = user.get("email")
        user_email = None
        if raw_user_email is not None and str(raw_user_email).strip():
            user_email = str(raw_user_email).strip()
        user_lock = await session_manager.get_stream_lock(user_key, conversation_id)
        if user_lock.locked():
            raise HTTPException(status_code=409, detail="A chat stream is already active")

        await user_lock.acquire()
        client = _create_http_client()
        upstream_response: Optional[httpx.Response] = None
        lock_released = False

        async def release_resources() -> None:
            nonlocal lock_released
            if upstream_response is not None:
                await upstream_response.aclose()
            await client.aclose()
            if not lock_released and user_lock.locked():
                user_lock.release()
                lock_released = True

        try:
            extra_headers: dict[str, str] = {}
            if config.request_headers_factory is not None:
                try:
                    factory_headers = config.request_headers_factory(request)
                    extra_headers.update(factory_headers or {})
                except Exception as exc:
                    logger.warning(
                        "request_headers_factory raised; skipping extra headers exception_type=%s",
                        type(exc).__name__,
                    )

            request_id = (
                extra_headers.get("X-Request-ID")
                or request.headers.get("X-Request-ID")
                or str(uuid.uuid4())
            )
            extra_headers["X-Request-ID"] = request_id

            upstream_payload = _build_gateway_chat_payload(
                chat_request,
                config.channel,
                user_key,
                request_id,
            )
            if config.context_enricher is not None:
                original_context = upstream_payload.get("context") or {}
                context_copy = copy.deepcopy(original_context)
                try:
                    returned_context = await asyncio.to_thread(
                        config.context_enricher, request, user, context_copy
                    )
                    merged = {**original_context, **(returned_context or {})}
                    merged["channel"] = config.channel
                    if user_key is not None:
                        merged["user_id"] = user_key
                    upstream_payload["context"] = merged
                except Exception as exc:
                    if config.fail_on_context_enricher_error:
                        logger.warning(
                            "context_enricher raised exception_type=%s",
                            type(exc).__name__,
                        )
                        raise RuntimeError("context_enricher_failed") from None
                    logger.warning(
                        "context_enricher raised; skipping exception_type=%s",
                        type(exc).__name__,
                    )
            gateway_url = config.resolve_url()
            if chat_request.attachments:
                await _ensure_chat_attachments_contract(client, gateway_url)
            if chat_request.investment_artifact_selection is not None:
                await _ensure_investment_selected_content_contract(client, gateway_url)
            await _ensure_gateway_contracts(client, gateway_url)
            session_token = await session_manager.get_token(
                user_key=user_key,
                client=client,
                api_key_fn=config.resolve_api_key,
                gateway_url_fn=config.resolve_url,
                conversation_id=conversation_id,
                channel=config.channel,
                user_email=user_email,
            )

            session_expired_retried = False
            auth_expired_retried = False
            while True:
                upstream_response = await _open_gateway_chat_stream(
                    client=client,
                    gateway_url=gateway_url,
                    session_token=session_token,
                    payload=upstream_payload,
                    extra_headers=extra_headers,
                )

                if upstream_response.status_code == 200:
                    break

                error_code, _error_body, error_body_bytes = await _classify_upstream_error(upstream_response)
                if error_code == "session_expired" and not session_expired_retried:
                    session_expired_retried = True
                    logger.info(
                        "gateway chat retrying after session_expired request_id=%s",
                        request_id,
                    )
                    await upstream_response.aclose()
                    upstream_response = None
                    session_token = await session_manager.get_token(
                        user_key=user_key,
                        client=client,
                        api_key_fn=config.resolve_api_key,
                        gateway_url_fn=config.resolve_url,
                        force_refresh=True,
                        conversation_id=conversation_id,
                        channel=config.channel,
                        user_email=user_email,
                    )
                    continue

                if error_code == "auth_expired" and not auth_expired_retried:
                    auth_expired_retried = True
                    logger.info(
                        "gateway chat retrying after auth_expired request_id=%s",
                        request_id,
                    )
                    await upstream_response.aclose()
                    upstream_response = None
                    session_manager.invalidate_token(user_key, conversation_id)
                    session_token = await session_manager.get_token(
                        user_key=user_key,
                        client=client,
                        api_key_fn=config.resolve_api_key,
                        gateway_url_fn=config.resolve_url,
                        force_refresh=True,
                        conversation_id=conversation_id,
                        channel=config.channel,
                        user_email=user_email,
                    )
                    continue

                # Reuse the classify read: the body was consumed exactly once
                # there, and a second aread after a timed-out read would raise
                # httpx.StreamConsumed.
                detail_bytes = error_body_bytes
                status_code = upstream_response.status_code
                media_type = upstream_response.headers.get("content-type") or "text/plain"
                await release_resources()
                return Response(
                    content=detail_bytes or f"Gateway error ({status_code})".encode("utf-8"),
                    status_code=status_code,
                    media_type=media_type,
                )

            async def event_stream():
                _disconnected = False

                async def _watch_disconnect() -> None:
                    nonlocal _disconnected

                    while True:
                        await asyncio.sleep(2)
                        if await request.is_disconnected():
                            _disconnected = True
                            try:
                                await asyncio.shield(upstream_response.aclose())
                            except Exception:
                                pass
                            return

                disconnect_task = asyncio.create_task(_watch_disconnect())
                next_chunk_task: asyncio.Task[bytes] | None = None
                try:
                    assert upstream_response is not None
                    raw_iter = upstream_response.aiter_raw()
                    next_chunk_task = asyncio.create_task(raw_iter.__anext__())
                    while True:
                        done, _pending = await asyncio.wait(
                            {next_chunk_task},
                            timeout=_STREAM_HEARTBEAT_SECONDS,
                        )
                        if not done:
                            yield _gateway_heartbeat_chunk()
                            continue

                        try:
                            chunk = next_chunk_task.result()
                        except StopAsyncIteration:
                            break

                        next_chunk_task = asyncio.create_task(raw_iter.__anext__())
                        if chunk:
                            yield chunk
                except Exception:
                    if not _disconnected:
                        raise
                finally:
                    if next_chunk_task is not None:
                        if not next_chunk_task.done():
                            next_chunk_task.cancel()
                            try:
                                await next_chunk_task
                            except (asyncio.CancelledError, Exception):
                                pass
                        else:
                            try:
                                next_chunk_task.exception()
                            except (asyncio.CancelledError, Exception):
                                pass
                    disconnect_task.cancel()
                    try:
                        await disconnect_task
                    except (asyncio.CancelledError, Exception):
                        pass
                    await release_resources()
                    if _disconnected:
                        session_manager.invalidate_token(user_key, conversation_id)

            return StreamingResponse(
                event_stream(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                    "Connection": "keep-alive",
                },
            )
        except HTTPException:
            await release_resources()
            raise
        except Exception as exc:
            await release_resources()
            raise HTTPException(status_code=502, detail="Gateway proxy error") from exc

    @router.post("/chat/cancel")
    async def gateway_chat_cancel(
        cancel_request: GatewayChatCancelRequest,
        user: dict[str, Any] = Depends(get_current_user),
    ) -> Response:
        """Cancel the active upstream gateway chat turn for the cached session."""

        _require_min_chat_tier(user, config)
        user_key = _get_user_key(user)
        raw_conversation_id = cancel_request.conversation_id
        conversation_id = None
        if raw_conversation_id is not None and str(raw_conversation_id).strip():
            conversation_id = str(raw_conversation_id).strip()
            if not _EXPLICIT_CONVERSATION_ID_RE.fullmatch(conversation_id):
                raise HTTPException(status_code=400, detail="conversation_id is invalid")

        session_token = session_manager.lookup_token(user_key, conversation_id)
        session_id = session_manager.lookup_session_id(user_key, conversation_id)
        if not session_token or not session_id:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "gateway_chat_session_not_found",
                    "message": "No cached gateway chat session exists for this conversation.",
                },
            )

        client = _create_http_client()
        try:
            gateway_url = config.resolve_url()
            response = await client.post(
                f"{gateway_url}/api/chat/cancel",
                headers={"Authorization": f"Bearer {session_token}"},
                json={"session_id": session_id},
            )
            body = await response.aread()
            if response.status_code in {401, 403}:
                session_manager.invalidate_token(user_key, conversation_id)
            return Response(
                content=body or b"",
                status_code=response.status_code,
                media_type=response.headers.get("content-type") or "application/json",
            )
        except HTTPException:
            raise
        except Exception as exc:
            raise HTTPException(status_code=502, detail="Gateway proxy error") from exc
        finally:
            await client.aclose()

    @router.get("/chat/subscribe")
    async def gateway_chat_subscribe(
        request: Request,
        user: dict[str, Any] = Depends(get_current_user),
    ):
        """Attach to an active upstream gateway chat turn for the cached conversation."""

        _require_min_chat_tier(user, config)
        user_key = _get_user_key(user)
        conversation_id = _query_conversation_id(request)
        session_token = session_manager.lookup_token(user_key, conversation_id)
        session_id = session_manager.lookup_session_id(user_key, conversation_id)
        if not session_token or not session_id:
            raise HTTPException(
                status_code=404,
                detail={
                    "error": "gateway_chat_session_not_found",
                    "message": "No cached gateway chat session exists for this conversation.",
                },
            )

        raw_after_seq = request.query_params.get("after_seq", "0")
        try:
            after_seq = max(int(raw_after_seq), 0)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="after_seq must be an integer")

        client = _create_http_client()
        upstream_response: Optional[httpx.Response] = None
        closed = False

        async def release_resources() -> None:
            nonlocal closed
            if closed:
                return
            closed = True
            if upstream_response is not None:
                await upstream_response.aclose()
            await client.aclose()

        try:
            params = {
                "session_id": session_id,
                "after_seq": str(after_seq),
                "client_label": request.query_params.get("client_label") or "risk_module_web",
            }
            for capability_param in ("ui_blocks_contract_version",):
                capability_value = request.query_params.get(capability_param)
                if capability_value is not None:
                    params[capability_param] = capability_value
            gateway_url = config.resolve_url()
            request_headers: dict[str, str] = {"Authorization": f"Bearer {session_token}"}
            upstream_request = client.build_request(
                "GET",
                f"{gateway_url}/api/chat/subscribe",
                headers=request_headers,
                params=params,
            )
            upstream_response = await client.send(upstream_request, stream=True)

            if upstream_response.status_code != 200:
                detail_bytes = await _read_error_body(upstream_response)
                status_code = upstream_response.status_code
                media_type = upstream_response.headers.get("content-type") or "text/plain"
                if status_code in {401, 403}:
                    session_manager.invalidate_token(user_key, conversation_id)
                await release_resources()
                return Response(
                    content=detail_bytes or f"Gateway subscribe error ({status_code})".encode("utf-8"),
                    status_code=status_code,
                    media_type=media_type,
                )

            async def event_stream():
                _disconnected = False

                async def _watch_disconnect() -> None:
                    nonlocal _disconnected

                    while True:
                        await asyncio.sleep(2)
                        if await request.is_disconnected():
                            _disconnected = True
                            try:
                                assert upstream_response is not None
                                await asyncio.shield(upstream_response.aclose())
                            except Exception:
                                pass
                            return

                disconnect_task = asyncio.create_task(_watch_disconnect())
                next_chunk_task: asyncio.Task[bytes] | None = None
                try:
                    assert upstream_response is not None
                    raw_iter = upstream_response.aiter_raw()
                    next_chunk_task = asyncio.create_task(raw_iter.__anext__())
                    while True:
                        done, _pending = await asyncio.wait(
                            {next_chunk_task},
                            timeout=_STREAM_HEARTBEAT_SECONDS,
                        )
                        if not done:
                            yield _gateway_heartbeat_chunk()
                            continue

                        try:
                            chunk = next_chunk_task.result()
                        except StopAsyncIteration:
                            break

                        next_chunk_task = asyncio.create_task(raw_iter.__anext__())
                        if chunk:
                            yield chunk
                except Exception:
                    if not _disconnected:
                        raise
                finally:
                    if next_chunk_task is not None:
                        if not next_chunk_task.done():
                            next_chunk_task.cancel()
                            try:
                                await next_chunk_task
                            except (asyncio.CancelledError, Exception):
                                pass
                        else:
                            try:
                                next_chunk_task.exception()
                            except (asyncio.CancelledError, Exception):
                                pass
                    disconnect_task.cancel()
                    try:
                        await disconnect_task
                    except (asyncio.CancelledError, Exception):
                        pass
                    await release_resources()

            return StreamingResponse(
                event_stream(),
                media_type="text/event-stream",
                headers={
                    "Cache-Control": "no-cache",
                    "X-Accel-Buffering": "no",
                    "Connection": "keep-alive",
                },
            )
        except HTTPException:
            await release_resources()
            raise
        except Exception as exc:
            await release_resources()
            raise HTTPException(status_code=502, detail="Gateway subscribe proxy error") from exc

    @router.post("/tool-approval")
    async def gateway_tool_approval(
        approval_request: GatewayToolApprovalRequest,
        user: dict[str, Any] = Depends(get_current_user),
    ):
        """Proxy tool approval responses via the same gateway session token."""

        user_key = _get_user_key(user)
        conversation_id = (
            str(approval_request.conversation_id).strip()
            if approval_request.conversation_id is not None and str(approval_request.conversation_id).strip()
            else None
        )
        session_token = session_manager.lookup_token(user_key, conversation_id)
        if not session_token:
            raise HTTPException(
                status_code=400,
                detail="No gateway session exists for this user. Start a chat first.",
            )

        payload: dict[str, Any] = {
            "tool_call_id": approval_request.tool_call_id,
            "nonce": approval_request.nonce,
            "approved": approval_request.approved,
        }
        if approval_request.allow_tool_type is not None:
            payload["allow_tool_type"] = approval_request.allow_tool_type

        client = _create_http_client()
        try:
            response = await client.post(
                f"{config.resolve_url()}/api/chat/tool-approval",
                headers={"Authorization": f"Bearer {session_token}"},
                json=payload,
            )
        except Exception as exc:
            raise HTTPException(status_code=502, detail="Gateway approval proxy error") from exc
        finally:
            await client.aclose()

        if response.status_code >= 400:
            error_code = "approval_expired" if response.status_code == 404 else "approval_failed"
            result = {
                "detail": (
                    "Gateway approval expired"
                    if response.status_code == 404
                    else "Gateway approval failed"
                ),
                "error_code": error_code,
                "upstream_status": response.status_code,
            }
            return JSONResponse(content=result, status_code=response.status_code)

        body_text = response.text
        if body_text:
            try:
                return JSONResponse(content=response.json(), status_code=response.status_code)
            except ValueError:
                return Response(
                    content=body_text,
                    status_code=response.status_code,
                    media_type="text/plain",
                )

        return JSONResponse({"success": True}, status_code=response.status_code)

    @router.api_route(
        "/control/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
    )
    async def gateway_control_proxy(
        path: str,
        request: Request,
        user: dict[str, Any] = Depends(get_current_user),
    ):
        """Proxy browser-safe control-plane requests to the gateway."""

        _require_min_chat_tier(user, config)
        user_key = _get_user_key(user)
        user_email = _user_email(user)
        normalized_path, segments = _validate_control_path(path, request.method)
        if segments == ("events",) and request.method == "GET":
            return await _proxy_control_stream(
                request=request,
                user_key=user_key,
                user_email=user_email,
                path=normalized_path,
                segments=segments,
            )

        payload: Any = None
        if request.method in {"POST", "PUT", "PATCH"}:
            try:
                payload = await request.json()
            except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                if control_request_contract_applies(segments):
                    return _control_request_contract_error(
                        ControlContractValidationError([
                            {"path": "$", "message": "control request must be valid JSON", "type": "value_error"}
                        ])
                    )
                raise HTTPException(status_code=400, detail="Invalid JSON body") from exc

        return await _proxy_control_request(
            request=request,
            user=user,
            user_key=user_key,
            user_email=user_email,
            path=normalized_path,
            segments=segments,
            method=request.method,
            payload=payload,
        )

    @router.api_route(
        "/artifacts/{path:path}",
        methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        include_in_schema=False,
    )
    async def gateway_artifact_detail_proxy(
        path: str,
        request: Request,
        user: dict[str, Any] = Depends(get_current_user),
    ):
        """Proxy typed artifact sidecar reads to the gateway artifact API."""

        _require_min_chat_tier(user, config)
        user_key = _get_user_key(user)
        user_email = _user_email(user)
        normalized_path, segments = _validate_artifact_detail_path(path, request.method)

        client = _create_http_client()
        try:
            gateway_url = config.resolve_url()
            await _ensure_gateway_contracts(client, gateway_url)
            session_token = await _control_token(user_key, user_email, client)
            retried = False
            while True:
                response = await client.get(
                    f"{gateway_url}/api/artifacts/{normalized_path}",
                    headers={"Authorization": f"Bearer {session_token}"},
                    params=dict(request.query_params),
                )
                if response.status_code != 401 or retried:
                    return await _artifact_detail_json_or_text_response(
                        response,
                        user_key=user_key,
                        segments=("artifacts", *segments),
                        client=client,
                        gateway_url=gateway_url,
                        session_token=session_token,
                    )
                retried = True
                session_manager.invalidate_control_token(user_key)
                session_token = await _control_token(user_key, user_email, client, force_refresh=True)
        except httpx.TimeoutException as exc:
            # Same CORS-bypass hazard as the control proxy: a cold/slow upstream must yield a
            # CORS-traversing 504, not a bare 500 that the browser sees as net::ERR_FAILED.
            raise HTTPException(
                status_code=504,
                detail={
                    "error": "control_upstream_timeout",
                    "message": "Agent control gateway timed out.",
                },
            ) from exc
        except httpx.RequestError as exc:
            raise HTTPException(
                status_code=502,
                detail={
                    "error": "control_upstream_unavailable",
                    "message": "Agent control gateway is unavailable.",
                },
            ) from exc
        finally:
            await client.aclose()

    return router


__all__ = [
    "GatewayConfig",
    "create_gateway_router",
    "default_http_client_factory",
    "_parse_ssl_verify",
]
