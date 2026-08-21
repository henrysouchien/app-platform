import asyncio
import json
import logging

from fastapi import FastAPI, HTTPException, Request
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict

from app_platform.app_setup import (
    add_csrf_token_route,
    bind_dev_monitor_loop,
    build_http_exception_handler,
    configure_core_middleware,
    configure_exception_handlers,
)
from app_platform.db.exceptions import (
    ConnectionError as DBConnectionError,
    PoolExhaustionError,
    SessionLookupError,
)
from app_platform.middleware import CSRF_HEADER_NAME
from database import DatabaseUnavailableError


class StrictValidationPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str


def _configured_validation_app(logger: logging.Logger) -> FastAPI:
    app = FastAPI()
    configure_exception_handlers(
        app,
        is_production=False,
        validation_logger=logger,
    )

    @app.post("/auth/google/sheets/connect")
    async def consent_validation(payload: StrictValidationPayload):
        return payload.model_dump()

    @app.post("/api/internal/google/sheets-broker-session")
    async def broker_validation(payload: StrictValidationPayload):
        return payload.model_dump()

    @app.post("/ordinary-validation")
    async def ordinary_validation(payload: StrictValidationPayload):
        return payload.model_dump()

    return app


def test_http_exception_handler_sanitizes_production_5xx():
    handler = build_http_exception_handler(is_production=True)

    response = asyncio.run(
        handler(
            None,
            HTTPException(status_code=500, detail="driver leaked password"),
        )
    )

    assert response.status_code == 500
    assert json.loads(response.body) == {"detail": "Internal server error"}


def test_http_exception_handler_preserves_development_detail():
    handler = build_http_exception_handler(is_production=False)

    response = asyncio.run(
        handler(
            None,
            HTTPException(status_code=503, detail="upstream diagnostic"),
        )
    )

    assert response.status_code == 503
    assert json.loads(response.body) == {"detail": "upstream diagnostic"}


def test_configure_exception_handlers_registers_platform_handlers():
    app = FastAPI()

    configure_exception_handlers(
        app,
        is_production=True,
        validation_logger=logging.getLogger("test-app-setup"),
    )

    assert PoolExhaustionError in app.exception_handlers
    assert DBConnectionError in app.exception_handlers
    assert DatabaseUnavailableError in app.exception_handlers
    assert HTTPException in app.exception_handlers
    assert SessionLookupError in app.exception_handlers


def test_configured_app_redacts_consent_validation_secrets(caplog):
    logger = logging.getLogger("test-consent-validation-redaction")
    caplog.set_level(logging.ERROR, logger=logger.name)
    client = TestClient(_configured_validation_app(logger))
    sentinel = "sentinel-consent-oauth-code"

    response = client.post(
        "/auth/google/sheets/connect",
        json={"code": sentinel, "unexpected": sentinel},
        headers={
            "Authorization": f"Bearer {sentinel}",
            "Cookie": f"session={sentinel}",
            "X-CSRF-Token": sentinel,
        },
    )

    assert response.status_code == 422
    assert sentinel not in caplog.text
    assert sentinel not in response.text
    assert response.json()["validation_details"][0]["input_value"] == "[REDACTED]"
    assert response.json()["raw_body_logged"] is False


def test_configured_app_redacts_broker_validation_secrets(caplog):
    logger = logging.getLogger("test-broker-validation-redaction")
    caplog.set_level(logging.ERROR, logger=logger.name)
    client = TestClient(_configured_validation_app(logger))
    sentinel = "sentinel-broker-signature"

    response = client.post(
        "/api/internal/google/sheets-broker-session",
        json={"code": sentinel, "unexpected": sentinel},
        headers={
            "Authorization": f"Bearer {sentinel}",
            "X-Resolver-Signature": sentinel,
        },
    )

    assert response.status_code == 422
    assert sentinel not in caplog.text
    assert sentinel not in response.text
    assert response.json()["detail"][0]["input"] == "[REDACTED]"
    assert response.json()["raw_body_logged"] is False


def test_configured_app_redacts_ordinary_validation_values(caplog):
    logger = logging.getLogger("test-ordinary-validation-logging")
    caplog.set_level(logging.ERROR, logger=logger.name)
    client = TestClient(_configured_validation_app(logger))
    body_sentinel = "sentinel-ordinary-body"
    header_sentinel = "sentinel-ordinary-header"
    credential_sentinel = "sentinel-ordinary-credential"

    response = client.post(
        "/ordinary-validation",
        json={"code": "valid-code", "unexpected": body_sentinel},
        headers={
            "Authorization": f"Bearer {credential_sentinel}",
            "X-Diagnostic": header_sentinel,
        },
    )

    assert response.status_code == 422
    assert "Raw request body:" not in caplog.text
    assert header_sentinel not in caplog.text
    assert credential_sentinel not in caplog.text
    assert body_sentinel not in caplog.text
    assert body_sentinel not in response.text
    assert response.json()["raw_body_logged"] is False


def test_validation_observability_failure_is_value_free_and_counted():
    secret = "validation-observability-secret-canary"

    class _FailingOnceLogger:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def error(self, message, *args) -> None:
            if not self.calls:
                self.calls.append("initial_failure")
                raise RuntimeError(secret)
            self.calls.append(message % args if args else message)

    logger = _FailingOnceLogger()
    response = TestClient(_configured_validation_app(logger)).post(
        "/ordinary-validation",
        json={"code": "valid", "unexpected": secret},
    )

    assert response.status_code == 422
    assert logger.calls[-1] == (
        "validation_error_observability_failed failure_count=1"
    )
    assert secret not in "\n".join(logger.calls)


def test_core_middleware_and_csrf_route_preserve_runtime_behavior():
    app = FastAPI()
    add_csrf_token_route(
        app,
        session_secret="test-session-secret",
        secure_cookie=False,
    )
    configure_core_middleware(
        app,
        session_secret="test-session-secret",
        is_production=False,
        cors_origins=["http://localhost:3000"],
    )

    @app.get("/session")
    async def session_route(request: Request):
        request.session["user_id"] = 42
        return {"ok": True}

    client = TestClient(app)

    csrf_response = client.get("/api/csrf-token")
    session_response = client.get("/session")
    cors_response = client.options(
        "/session",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": CSRF_HEADER_NAME,
        },
    )

    assert csrf_response.status_code == 200
    assert "csrf_token" in csrf_response.json()
    assert session_response.status_code == 200
    assert "session=" in session_response.headers["set-cookie"]
    assert cors_response.headers["access-control-allow-origin"] == (
        "http://localhost:3000"
    )
    allowed_headers = {
        header.strip().lower()
        for header in cors_response.headers[
            "access-control-allow-headers"
        ].split(",")
    }
    assert CSRF_HEADER_NAME.lower() in allowed_headers


def test_bind_dev_monitor_loop_sets_loop_when_enabled():
    calls = []

    class Hub:
        def set_loop(self, loop):
            calls.append(loop)

    bind_dev_monitor_loop(
        get_env_fn=lambda key, default=None: "true",
        init_monitor_fn=Hub,
        get_running_loop_fn=lambda: "loop",
    )

    assert calls == ["loop"]


def test_bind_dev_monitor_loop_skips_when_disabled():
    calls = []

    bind_dev_monitor_loop(
        get_env_fn=lambda key, default=None: "false",
        init_monitor_fn=lambda: calls.append("init"),
        get_running_loop_fn=lambda: "loop",
    )

    assert calls == []


def test_bind_dev_monitor_loop_skips_when_env_is_empty():
    calls = []

    bind_dev_monitor_loop(
        get_env_fn=lambda key, default=None: "",
        init_monitor_fn=lambda: calls.append("init"),
        get_running_loop_fn=lambda: "loop",
    )

    assert calls == []


def test_bind_dev_monitor_loop_tolerates_missing_running_loop():
    class Hub:
        def set_loop(self, loop):
            raise AssertionError("set_loop should not receive a missing loop")

    bind_dev_monitor_loop(
        get_env_fn=lambda key, default=None: "true",
        init_monitor_fn=Hub,
        get_running_loop_fn=lambda: (_ for _ in ()).throw(RuntimeError("no loop")),
    )
