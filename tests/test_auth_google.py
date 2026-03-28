from __future__ import annotations

import app_platform.auth.google as google_module
from app_platform.auth.google import GoogleTokenVerifier


def test_google_token_verifier_returns_dev_user_without_google_call(monkeypatch):
    monkeypatch.setattr(
        google_module.id_token,
        "verify_oauth2_token",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("unexpected call")),
    )
    verifier = GoogleTokenVerifier(client_id="client-123", dev_mode=True)

    user_info, error = verifier.verify("dev-token")

    assert error is None
    assert user_info == {
        "user_id": "dev_user_123",
        "email": "dev@example.com",
        "name": "Development User",
        "google_user_id": "dev_google_123",
    }


def test_google_token_verifier_uses_google_auth_library(monkeypatch):
    calls = {}
    monkeypatch.setattr(google_module.google_requests, "Request", lambda: "request-sentinel")

    def fake_verify_oauth2_token(token, request, client_id):
        calls["token"] = token
        calls["request"] = request
        calls["client_id"] = client_id
        return {
            "sub": "google-user-1",
            "email": "user@example.com",
            "name": "Example User",
        }

    monkeypatch.setattr(
        google_module.id_token,
        "verify_oauth2_token",
        fake_verify_oauth2_token,
    )
    verifier = GoogleTokenVerifier(client_id="client-456")

    user_info, error = verifier.verify("real-token")

    assert error is None
    assert calls == {
        "token": "real-token",
        "request": "request-sentinel",
        "client_id": "client-456",
    }
    assert user_info == {
        "user_id": "google-user-1",
        "email": "user@example.com",
        "name": "Example User",
        "google_user_id": "google-user-1",
    }


def test_google_token_verifier_returns_error_when_google_verification_fails(monkeypatch):
    def fake_verify_oauth2_token(token, request, client_id):
        del token, request, client_id
        raise ValueError("invalid token")

    monkeypatch.setattr(
        google_module.id_token,
        "verify_oauth2_token",
        fake_verify_oauth2_token,
    )
    verifier = GoogleTokenVerifier(client_id="client-789")

    user_info, error = verifier.verify("bad-token")

    assert user_info is None
    assert error == "Google token verification failed: invalid token"
