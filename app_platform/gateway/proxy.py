"""Gateway proxy router factory."""

from __future__ import annotations

import asyncio
import copy
import json
import logging
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from app_platform.auth.dependencies import TIER_ORDER
from .models import GatewayChatRequest, GatewayToolApprovalRequest
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


@dataclass
class GatewayConfig:
    """Gateway configuration with request-time resolvers."""

    gateway_url: str | Callable[[], str] = ""
    api_key: str | Callable[[], str] = ""
    ssl_verify: bool | str | Callable[[], bool | str] = True
    channel: str = "web"
    request_headers_factory: Callable[[Any], dict[str, str]] | None = None
    context_enricher: Callable[[Any, Any, dict[str, Any]], dict[str, Any]] | None = None
    min_chat_tier: str = "paid"

    def __post_init__(self) -> None:
        self.min_chat_tier = str(self.min_chat_tier or "paid").strip().lower() or "paid"
        if self.min_chat_tier not in TIER_ORDER:
            raise ValueError(
                f"Invalid min_chat_tier={self.min_chat_tier!r}; must be one of {sorted(TIER_ORDER)}"
            )

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
    return httpx.AsyncClient(timeout=timeout, verify=ssl_verify)


def _get_user_key(user: dict[str, Any]) -> str:
    """Build a stable user key for per-user state."""

    if user.get("user_id") is not None:
        return str(user["user_id"])
    if user.get("google_user_id") is not None:
        return str(user["google_user_id"])
    if user.get("email"):
        return str(user["email"])
    raise HTTPException(status_code=401, detail="Invalid user identity")


def _build_gateway_chat_payload(
    chat_request: GatewayChatRequest,
    channel: str,
    user_key: str | None = None,
    request_id: str | None = None,
) -> dict[str, Any]:
    """Build upstream chat payload with enforced channel/user_id and no model field."""

    upstream_context = {**(chat_request.context or {}), "channel": channel}
    if user_key is not None:
        upstream_context["user_id"] = user_key
    payload = {
        "messages": chat_request.messages,
        "context": upstream_context,
        "metadata": chat_request.metadata or {},
    }
    if user_key is not None:
        payload["user_id"] = user_key
    if request_id is not None:
        payload["request_id"] = request_id
    return payload


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
    return await client.send(request, stream=True)


async def _classify_upstream_error(response: httpx.Response) -> tuple[str, dict[str, Any] | None]:
    """Classify gateway pre-stream errors without parsing SSE streams."""

    body_bytes = await response.aread()
    try:
        body = json.loads(body_bytes)
    except (ValueError, TypeError):
        body = None

    if isinstance(body, dict):
        error_code = body.get("error")
        if error_code in _KNOWN_UPSTREAM_ERRORS:
            return str(error_code), body

    if response.status_code == 401:
        return "session_expired", body if isinstance(body, dict) else None

    return "unknown", body if isinstance(body, dict) else None


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

    def _create_http_client() -> httpx.AsyncClient:
        if http_client_factory is not None:
            return http_client_factory()
        return default_http_client_factory(config.resolve_ssl_verify())

    router._session_manager = session_manager  # type: ignore[attr-defined]
    router._create_http_client = _create_http_client  # type: ignore[attr-defined]

    @router.post("/chat")
    async def gateway_chat(
        chat_request: GatewayChatRequest,
        request: Request,
        user: dict[str, Any] = Depends(get_current_user),
    ):
        """Proxy web-channel chat stream to the gateway."""

        purpose = str((chat_request.context or {}).get("purpose") or "chat").strip().lower() or "chat"
        conversation_id: str | None = None
        if purpose == "research_workspace":
            _thread_id = (chat_request.context or {}).get("thread_id")
            if _thread_id is not None and str(_thread_id).strip():
                conversation_id = str(_thread_id).strip()
        user_tier = str(user.get("tier") or "registered").strip().lower() or "registered"
        if purpose != "normalizer" and TIER_ORDER.get(user_tier, 0) < TIER_ORDER[config.min_chat_tier]:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "upgrade_required",
                    "message": f"AI chat requires a {config.min_chat_tier} subscription.",
                    "tier_required": config.min_chat_tier,
                    "tier_current": user_tier,
                },
            )

        user_key = _get_user_key(user)
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
                except Exception:
                    logger.warning("request_headers_factory raised; skipping extra headers", exc_info=True)

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
                except Exception:
                    logger.warning("context_enricher raised; skipping", exc_info=True)
            session_token = await session_manager.get_token(
                user_key=user_key,
                client=client,
                api_key_fn=config.resolve_api_key,
                gateway_url_fn=config.resolve_url,
                conversation_id=conversation_id,
            )
            gateway_url = config.resolve_url()

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

                error_code, _error_body = await _classify_upstream_error(upstream_response)
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
                    )
                    continue

                detail_bytes = await upstream_response.aread()
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
                try:
                    assert upstream_response is not None
                    async for chunk in upstream_response.aiter_raw():
                        if chunk:
                            yield chunk
                except Exception:
                    if not _disconnected:
                        raise
                finally:
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
            raise HTTPException(status_code=502, detail=f"Gateway proxy error: {exc}") from exc

    @router.post("/tool-approval")
    async def gateway_tool_approval(
        approval_request: GatewayToolApprovalRequest,
        user: dict[str, Any] = Depends(get_current_user),
    ):
        """Proxy tool approval responses via the same gateway session token."""

        user_key = _get_user_key(user)
        session_token = session_manager.lookup_token(user_key)
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
            raise HTTPException(status_code=502, detail=f"Gateway approval proxy error: {exc}") from exc
        finally:
            await client.aclose()

        body_text = response.text
        if response.status_code >= 400:
            error_code = "approval_expired" if response.status_code == 404 else "approval_failed"
            try:
                upstream_body = response.json()
                if not isinstance(upstream_body, dict):
                    upstream_body = {"detail": str(upstream_body)}
            except (ValueError, TypeError):
                upstream_body = {"detail": body_text or "Gateway approval failed"}

            result = {**upstream_body, "error_code": error_code, "upstream_status": response.status_code}
            return JSONResponse(content=result, status_code=response.status_code)

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

    return router


__all__ = [
    "GatewayConfig",
    "create_gateway_router",
    "default_http_client_factory",
    "_parse_ssl_verify",
]
