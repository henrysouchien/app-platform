import asyncio
import json
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from limits import parse
from pydantic import BaseModel
from slowapi.errors import RateLimitExceeded
from slowapi.wrappers import Limit
from starlette.middleware.sessions import SessionMiddleware

from app_platform.middleware import (
    ApiKeyRegistry,
    MiddlewareConfig,
    RateLimitConfig,
    add_rate_limit_handler,
    configure_middleware,
    configure_sessions,
    create_limiter,
    parse_cors_origins,
    validate_cors_origins,
)


class Payload(BaseModel):
    count: int


def _build_rate_limit_error(message: str = "Too many requests"):
    limit = Limit(
        parse("5/minute"),
        key_func=lambda request: "client",
        scope=None,
        per_method=False,
        methods=None,
        error_message=message,
        exempt_when=None,
        cost=1,
        override_defaults=False,
    )
    return RateLimitExceeded(limit)


def _build_app(*, dev_mode: bool = False, validation_error_logging: bool = True):
    app = FastAPI()
    limiter = create_limiter(
        RateLimitConfig(
            dev_mode=dev_mode,
            key_registry=ApiKeyRegistry.from_dict({"public": "public_key_123"}),
        )
    )
    configure_middleware(
        app,
        MiddlewareConfig(
            cors_origins=["http://localhost:3000"],
            cors_credentials=True,
            session_secret="test-session-secret",
            rate_limiter=limiter,
            validation_error_logging=validation_error_logging,
        ),
    )

    @app.post("/validate")
    async def validate(payload: Payload):
        return payload.model_dump()

    @app.get("/limited")
    async def limited():
        raise _build_rate_limit_error()

    @app.get("/session")
    async def session_route(request: Request):
        request.session["user_id"] = 42
        return {"ok": True}

    return app, limiter


def _build_validation_policy_app(*, expose_details: bool):
    app = FastAPI()
    configure_middleware(
        app,
        MiddlewareConfig(
            cors_origins=["http://localhost:3000"],
            session_secret="test-session-secret",
            validation_error_logging=True,
            validation_error_expose_details=expose_details,
            validation_error_log_request_body=expose_details,
        ),
    )

    @app.post("/validate")
    async def validate(payload: Payload):
        return payload.model_dump()

    return app


def test_configure_sessions_uses_env_secret(monkeypatch):
    monkeypatch.setenv("FLASK_SECRET_KEY", "env-session-secret")
    app = FastAPI()

    configure_sessions(app, "")

    middleware = next(
        item for item in app.user_middleware if item.cls is SessionMiddleware
    )
    assert middleware.kwargs["secret_key"] == "env-session-secret"


def test_configure_middleware_wires_cors_session_and_handlers():
    app, limiter = _build_app()
    client = TestClient(app)

    cors_response = client.options(
        "/session",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "GET",
        },
    )
    session_response = client.get("/session")
    validation_response = client.post("/validate", json={"count": "bad"})
    rate_limit_response = client.get("/limited")

    assert app.state.limiter is limiter
    assert cors_response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert cors_response.headers["access-control-allow-credentials"] == "true"
    assert session_response.status_code == 200
    assert "session=" in session_response.headers["set-cookie"]

    validation_body = validation_response.json()
    assert validation_response.status_code == 422
    assert validation_body["message"] == (
        "Request validation failed - check field names and structure"
    )
    assert validation_body["endpoint"] == "/validate"
    assert validation_body["method"] == "POST"
    assert validation_body["raw_body_logged"] is True
    assert validation_body["validation_details"][0]["field"] == "body.count"

    assert rate_limit_response.status_code == 429
    assert rate_limit_response.json() == {
        "error": "Rate limit exceeded",
        "message": "Too many requests",
        "type": "rate_limit_exceeded",
    }


def test_rate_limit_handler_logs_user_context_when_configured():
    app = FastAPI()
    calls = []

    def get_current_user(request):
        return {"user_id": 42}

    add_rate_limit_handler(
        app,
        public_key="public-key",
        tier_map={"paid-key": "paid"},
        get_current_user_fn=get_current_user,
        log_rate_limit_hit_fn=lambda **kwargs: calls.append(kwargs),
    )

    @app.get("/limited")
    async def limited():
        raise _build_rate_limit_error()

    response = TestClient(app).get(
        "/limited",
        headers={"X-API-Key": "paid-key"},
    )

    assert response.status_code == 429
    assert calls == [
        {
            "user_id": 42,
            "endpoint": "/limited",
            "limit_type": "daily",
            "retry_after": None,
            "user_tier": "paid",
        }
    ]


def test_rate_limit_handler_resolves_public_key_and_tier_map_at_call_time():
    app = FastAPI()
    calls = []
    public_key = {"value": "public-old"}
    tier_map = {"value": {"public-old": "public"}}

    add_rate_limit_handler(
        app,
        get_public_key_fn=lambda: public_key["value"],
        get_tier_map_fn=lambda: tier_map["value"],
        log_rate_limit_hit_fn=lambda **kwargs: calls.append(kwargs),
    )

    public_key["value"] = "public-new"
    tier_map["value"] = {"public-new": "paid"}

    @app.get("/limited-dynamic")
    async def limited_dynamic():
        raise _build_rate_limit_error()

    response = TestClient(app).get("/limited-dynamic")

    assert response.status_code == 429
    assert calls[0]["user_tier"] == "paid"


def test_rate_limit_handler_resolves_dev_mode_at_call_time():
    app = FastAPI()
    dev_mode = {"value": False}

    add_rate_limit_handler(
        app,
        get_dev_mode_fn=lambda: dev_mode["value"],
    )

    dev_mode["value"] = True

    @app.get("/limited-dev")
    async def limited_dev():
        raise _build_rate_limit_error()

    response = TestClient(app).get("/limited-dev")

    assert response.status_code == 500
    assert response.json()["type"] == "dev_mode_error"


def test_app_rate_limit_handler_keeps_app_level_monkeypatch_seams(monkeypatch):
    import app as app_module

    calls = []
    request = SimpleNamespace(
        headers={},
        query_params={},
        url=SimpleNamespace(path="/limited-app"),
    )
    monkeypatch.setattr(app_module, "IS_DEV", False)
    monkeypatch.setattr(app_module, "PUBLIC_KEY", "dynamic-public")
    monkeypatch.setattr(app_module, "TIER_MAP", {"dynamic-public": "paid"})
    monkeypatch.setattr(
        app_module,
        "get_current_user",
        lambda request: {"user_id": 99},
    )
    monkeypatch.setattr(
        app_module,
        "log_rate_limit_hit",
        lambda **kwargs: calls.append(kwargs),
    )

    response = asyncio.run(
        app_module.rate_limit_handler(request, _build_rate_limit_error())
    )

    assert response.status_code == 429
    assert json.loads(response.body)["type"] == "rate_limit_exceeded"
    assert calls == [
        {
            "user_id": 99,
            "endpoint": "/limited-app",
            "limit_type": "daily",
            "retry_after": None,
            "user_tier": "paid",
        }
    ]


def test_validation_handler_can_hide_details():
    app = _build_validation_policy_app(expose_details=False)
    response = TestClient(app).post("/validate", json={"count": "secret-ish-invalid"})

    assert response.status_code == 422
    assert response.json() == {
        "detail": "Request validation failed",
        "message": "Request validation failed",
        "error_code": "request_validation_failed",
    }


def test_validation_handler_keeps_details_when_enabled():
    app = _build_validation_policy_app(expose_details=True)
    response = TestClient(app).post("/validate", json={"count": "bad"})

    body = response.json()
    assert response.status_code == 422
    assert body["message"] == (
        "Request validation failed - check field names and structure"
    )
    assert body["endpoint"] == "/validate"
    assert body["method"] == "POST"
    assert body["raw_body_logged"] is True
    assert body["validation_details"][0]["field"] == "body.count"
    assert body["validation_details"][0]["input_value"] == "bad"


def test_validation_logging_records_header_names_without_values(caplog):
    raw_api_key = "canary-validation-api-key"
    app = _build_validation_policy_app(expose_details=True)

    with caplog.at_level("ERROR"):
        response = TestClient(app).post(
            "/validate",
            json={"count": "bad"},
            headers={"X-API-Key": raw_api_key},
        )

    assert response.status_code == 422
    assert raw_api_key not in caplog.text
    assert "x-api-key" in caplog.text.lower()


def test_configure_middleware_allows_conversation_id_in_cors_preflight():
    app, _ = _build_app()
    client = TestClient(app)

    response = client.options(
        "/session",
        headers={
            "Origin": "http://localhost:3000",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "X-Conversation-ID",
        },
    )

    allowed_headers = {
        header.strip().lower()
        for header in response.headers["access-control-allow-headers"].split(",")
    }

    assert response.status_code == 200
    assert "x-conversation-id" in allowed_headers


def test_parse_cors_origins_uses_dev_default_when_unset():
    assert parse_cors_origins(None) == [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "https://localhost:8000",
    ]


def test_validate_cors_origins_allows_exact_https_production_origins():
    origins = validate_cors_origins(
        ["https://hank.investments", "https://www.hank.investments"],
        is_production=True,
    )

    assert origins == ["https://hank.investments", "https://www.hank.investments"]


def test_validate_cors_origins_rejects_missing_production_origins():
    with pytest.raises(RuntimeError, match="at least one exact HTTPS"):
        validate_cors_origins([], is_production=True)


def test_validate_cors_origins_rejects_wildcard_in_production():
    with pytest.raises(RuntimeError, match="must not contain"):
        validate_cors_origins(["*"], is_production=True)


def test_validate_cors_origins_rejects_localhost_in_production():
    with pytest.raises(RuntimeError, match="localhost/loopback"):
        validate_cors_origins(["http://localhost:3000"], is_production=True)


def test_validate_cors_origins_rejects_non_https_in_production():
    with pytest.raises(RuntimeError, match="must use HTTPS"):
        validate_cors_origins(["http://hank.investments"], is_production=True)


def test_validate_cors_origins_rejects_paths_in_production():
    with pytest.raises(RuntimeError, match="without paths"):
        validate_cors_origins(["https://hank.investments/app"], is_production=True)


def test_validate_cors_origins_allows_localhost_in_development():
    origins = validate_cors_origins(["http://localhost:3000"], is_production=False)

    assert origins == ["http://localhost:3000"]


def test_configure_middleware_uses_dev_mode_rate_limit_handler():
    app, _ = _build_app(dev_mode=True, validation_error_logging=False)
    client = TestClient(app)

    response = client.get("/limited")

    assert response.status_code == 500
    assert response.json() == {
        "error": "Development mode - rate limiting disabled",
        "message": "This error should not occur in development mode",
        "type": "dev_mode_error",
    }
