"""Gateway proxy router factory."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Callable, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from .models import GatewayChatRequest, GatewayToolApprovalRequest
from .session import GatewaySessionManager


@dataclass
class GatewayConfig:
    """Gateway configuration with request-time resolvers."""

    gateway_url: str | Callable[[], str] = ""
    api_key: str | Callable[[], str] = ""
    ssl_verify: bool | str | Callable[[], bool | str] = True
    channel: str = "web"

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
) -> dict[str, Any]:
    """Build upstream chat payload with enforced channel/user_id and no model field."""

    upstream_context = {**(chat_request.context or {}), "channel": channel}
    if user_key is not None:
        upstream_context["user_id"] = user_key
    return {
        "messages": chat_request.messages,
        "context": upstream_context,
    }


async def _open_gateway_chat_stream(
    client: httpx.AsyncClient,
    gateway_url: str,
    session_token: str,
    payload: dict[str, Any],
) -> httpx.Response:
    request = client.build_request(
        "POST",
        f"{gateway_url}/api/chat",
        headers={"Authorization": f"Bearer {session_token}"},
        json=payload,
    )
    return await client.send(request, stream=True)


def create_gateway_router(
    config: GatewayConfig,
    get_current_user: Callable[..., Any],
    http_client_factory: Optional[Callable[[], httpx.AsyncClient]] = None,
) -> APIRouter:
    """Create a gateway proxy router with injected config and auth."""

    router = APIRouter(tags=["gateway-proxy"])
    session_manager = GatewaySessionManager()

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

        user_key = _get_user_key(user)
        user_lock = await session_manager.get_stream_lock(user_key)
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
            upstream_payload = _build_gateway_chat_payload(chat_request, config.channel, user_key)
            session_token = await session_manager.get_token(
                user_key=user_key,
                client=client,
                api_key_fn=config.resolve_api_key,
                gateway_url_fn=config.resolve_url,
            )
            gateway_url = config.resolve_url()

            upstream_response = await _open_gateway_chat_stream(
                client=client,
                gateway_url=gateway_url,
                session_token=session_token,
                payload=upstream_payload,
            )

            if upstream_response.status_code == 401:
                await upstream_response.aclose()
                upstream_response = None
                session_token = await session_manager.get_token(
                    user_key=user_key,
                    client=client,
                    api_key_fn=config.resolve_api_key,
                    gateway_url_fn=config.resolve_url,
                    force_refresh=True,
                )
                upstream_response = await _open_gateway_chat_stream(
                    client=client,
                    gateway_url=gateway_url,
                    session_token=session_token,
                    payload=upstream_payload,
                )

            if upstream_response.status_code != 200:
                detail_bytes = await upstream_response.aread()
                detail = detail_bytes.decode("utf-8", errors="ignore")
                await release_resources()
                return Response(
                    content=detail or f"Gateway error ({upstream_response.status_code})",
                    status_code=upstream_response.status_code,
                    media_type="text/plain",
                )

            async def event_stream():
                try:
                    assert upstream_response is not None
                    async for chunk in upstream_response.aiter_raw():
                        if await request.is_disconnected():
                            break
                        if chunk:
                            yield chunk
                except asyncio.CancelledError:
                    raise
                finally:
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
            raise HTTPException(status_code=502, detail=f"Gateway proxy error: {exc}") from exc

    @router.post("/tool-approval")
    async def gateway_tool_approval(
        approval_request: GatewayToolApprovalRequest,
        user: dict[str, Any] = Depends(get_current_user),
    ):
        """Proxy tool approval responses via the same gateway session token."""

        user_key = _get_user_key(user)
        session_token = session_manager._tokens.get(user_key)
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
            return Response(
                content=body_text or "Gateway approval failed",
                status_code=response.status_code,
                media_type="text/plain",
            )

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
