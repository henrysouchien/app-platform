from fastapi import FastAPI, Response
from fastapi.testclient import TestClient

from app_platform.middleware import (
    BASE_SECURITY_HEADERS,
    DEFAULT_CONTENT_SECURITY_POLICY,
    SecurityHeadersMiddleware,
    SOURCE_HTML_CONTENT_SECURITY_POLICY,
)


def _build_client(*, is_production: bool) -> TestClient:
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, is_production=is_production)

    @app.get("/ok")
    async def ok():
        return {"ok": True}

    return TestClient(app)


def test_security_headers_added_to_development_responses():
    client = _build_client(is_production=False)

    response = client.get("/ok")

    assert response.status_code == 200
    for name, value in BASE_SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert "strict-transport-security" not in response.headers
    assert "content-security-policy" not in response.headers


def test_security_headers_add_hsts_and_csp_in_production():
    client = _build_client(is_production=True)

    response = client.get("/ok")

    assert response.status_code == 200
    for name, value in BASE_SECURITY_HEADERS.items():
        assert response.headers[name] == value
    assert response.headers["strict-transport-security"] == (
        "max-age=31536000; includeSubDomains; preload"
    )
    assert response.headers["content-security-policy"] == DEFAULT_CONTENT_SECURITY_POLICY


def test_security_headers_override_weaker_route_headers():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, is_production=True)

    @app.get("/framed")
    async def framed(response: Response):
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        return {"ok": True}

    response = TestClient(app).get("/framed")

    assert response.headers["x-frame-options"] == "DENY"


def test_source_html_route_can_be_framed_same_origin_with_restrictive_csp():
    app = FastAPI()
    app.add_middleware(SecurityHeadersMiddleware, is_production=True)

    @app.get("/api/research/content/documents/source-html")
    async def source_html(response: Response):
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        return Response("<html><body>filing</body></html>", media_type="text/html")

    response = TestClient(app).get("/api/research/content/documents/source-html")

    assert response.headers["x-frame-options"] == "SAMEORIGIN"
    assert response.headers["content-security-policy"] == SOURCE_HTML_CONTENT_SECURITY_POLICY
    assert response.headers["referrer-policy"] == "no-referrer"
    for directive in (
        "default-src 'none'",
        "script-src 'none'",
        "object-src 'none'",
        "connect-src 'none'",
        "frame-src 'none'",
        "frame-ancestors 'self'",
    ):
        assert directive in response.headers["content-security-policy"]
