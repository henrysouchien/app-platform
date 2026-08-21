from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.testclient import TestClient

from app_platform.middleware import (
    CSRF_COOKIE_NAME,
    CSRF_HEADER_NAME,
    CsrfProtectionMiddleware,
    create_csrf_token_response,
    sign_csrf_token,
    validate_csrf_token,
)


SECRET = "test-csrf-secret"


def _build_client() -> TestClient:
    app = FastAPI()

    @app.get("/api/csrf-token")
    async def csrf_token(request: Request):
        return create_csrf_token_response(request, secret_key=SECRET)

    @app.get("/unsafe")
    async def safe_get():
        return {"ok": True}

    @app.post("/unsafe")
    async def unsafe_post():
        return {"ok": True}

    @app.post("/auth/google")
    async def google_auth():
        return {"ok": True}

    app.add_middleware(CsrfProtectionMiddleware, secret_key=SECRET)
    return TestClient(app)


def test_unsafe_request_with_session_cookie_requires_csrf_token():
    client = _build_client()
    client.cookies.set("session_id", "session-1")

    response = client.post("/unsafe", json={"value": 1})

    assert response.status_code == 403
    assert response.json() == {
        "detail": "CSRF token missing or invalid",
        "error": "csrf_failed",
    }


def test_csrf_failure_from_browser_origin_includes_cors_headers():
    app = FastAPI()

    @app.post("/unsafe")
    async def unsafe_post():
        return {"ok": True}

    app.add_middleware(CsrfProtectionMiddleware, secret_key=SECRET)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000"],
        allow_credentials=True,
        allow_methods=["POST"],
        allow_headers=["Content-Type", CSRF_HEADER_NAME],
    )
    client = TestClient(app)
    client.cookies.set("session_id", "session-1")

    response = client.post(
        "/unsafe",
        json={"value": 1},
        headers={"Origin": "http://localhost:3000"},
    )

    assert response.status_code == 403
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert response.headers["access-control-allow-credentials"] == "true"
    assert response.json()["error"] == "csrf_failed"


def test_unsafe_request_with_valid_csrf_token_passes():
    client = _build_client()
    client.cookies.set("session_id", "session-1")

    token_response = client.get("/api/csrf-token")
    token = token_response.json()["csrf_token"]
    response = client.post("/unsafe", json={"value": 1}, headers={CSRF_HEADER_NAME: token})

    assert token_response.status_code == 200
    assert CSRF_COOKIE_NAME in token_response.cookies
    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_unsafe_request_with_signed_header_passes_without_csrf_cookie():
    client = _build_client()
    client.cookies.set("session_id", "session-1")

    token = client.get("/api/csrf-token").json()["csrf_token"]
    client.cookies.delete(CSRF_COOKIE_NAME)
    response = client.post("/unsafe", json={"value": 1}, headers={CSRF_HEADER_NAME: token})

    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_unsafe_request_rejects_unsigned_header_without_csrf_cookie():
    client = _build_client()
    client.cookies.set("session_id", "session-1")

    response = client.post("/unsafe", json={"value": 1}, headers={CSRF_HEADER_NAME: "raw-token"})

    assert response.status_code == 403
    assert response.json()["error"] == "csrf_failed"


def test_csrf_token_endpoint_reuses_valid_cookie_for_session():
    client = _build_client()
    client.cookies.set("session_id", "session-1")

    first = client.get("/api/csrf-token")
    second = client.get("/api/csrf-token")

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["csrf_token"] == first.json()["csrf_token"]


def test_csrf_token_endpoint_rotates_when_session_cookie_changes():
    client = _build_client()
    client.cookies.set("session_id", "session-1")
    first_token = client.get("/api/csrf-token").json()["csrf_token"]

    client.cookies.set("session_id", "session-2")
    second_token = client.get("/api/csrf-token").json()["csrf_token"]

    assert second_token != first_token


def test_csrf_token_is_bound_to_session_cookie():
    client = _build_client()
    client.cookies.set("session_id", "session-1")
    token = client.get("/api/csrf-token").json()["csrf_token"]

    client.cookies.set("session_id", "session-2")
    response = client.post("/unsafe", json={"value": 1}, headers={CSRF_HEADER_NAME: token})

    assert response.status_code == 403
    assert response.json()["error"] == "csrf_failed"


def test_requests_without_session_cookie_are_not_blocked():
    client = _build_client()

    response = client.post("/unsafe", json={"value": 1})

    assert response.status_code == 200
    assert response.json() == {"ok": True}


def test_safe_methods_and_exempt_paths_are_not_blocked():
    client = _build_client()
    client.cookies.set("session_id", "session-1")

    safe_response = client.get("/unsafe")
    exempt_response = client.post("/auth/google", json={"token": "google-token"})

    assert safe_response.status_code == 200
    assert exempt_response.status_code == 200


def test_validate_csrf_token_rejects_expired_cookie_token():
    token = "csrf-token"
    signed = sign_csrf_token(SECRET, token, "session-1", timestamp=100)

    assert not validate_csrf_token(
        secret_key=SECRET,
        header_token=token,
        cookie_token=signed,
        session_id="session-1",
        max_age_seconds=10,
        now=111,
    )
