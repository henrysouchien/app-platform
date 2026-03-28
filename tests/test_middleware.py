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
    configure_middleware,
    configure_sessions,
    create_limiter,
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


def test_configure_sessions_uses_env_secret(monkeypatch):
    monkeypatch.setenv("FLASK_SECRET_KEY", "env-session-secret")
    app = FastAPI()

    configure_sessions(app, "")

    middleware = next(item for item in app.user_middleware if item.cls is SessionMiddleware)
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
    assert validation_body["message"] == "Request validation failed - check field names and structure"
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
