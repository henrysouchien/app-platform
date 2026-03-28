from __future__ import annotations

from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

from app_platform.auth.dependencies import create_auth_dependency, create_tier_dependency


class DummyAuthService:
    def __init__(self, user):
        self.user = user
        self.session_ids = []

    def get_user_by_session(self, session_id):
        self.session_ids.append(session_id)
        return self.user


def _build_app(auth_service, cookie_name: str = "session_id"):
    app = FastAPI()
    dependency = create_auth_dependency(auth_service, cookie_name=cookie_name)

    @app.get("/me")
    def me(current_user=Depends(dependency)):
        return current_user

    return app


def _build_tier_app(auth_service, minimum_tier: str = "paid"):
    app = FastAPI()
    dependency = create_tier_dependency(auth_service, minimum_tier=minimum_tier)

    @app.get("/paid")
    def paid(current_user=Depends(dependency)):
        return current_user

    return app


def test_create_auth_dependency_returns_authenticated_user():
    auth_service = DummyAuthService({"user_id": 1, "email": "user@example.com"})
    client = TestClient(_build_app(auth_service))

    response = client.get("/me", cookies={"session_id": "session-1"})

    assert response.status_code == 200
    assert response.json() == {"user_id": 1, "email": "user@example.com"}
    assert auth_service.session_ids == ["session-1"]


def test_create_auth_dependency_returns_401_when_session_missing():
    auth_service = DummyAuthService(None)
    client = TestClient(_build_app(auth_service))

    response = client.get("/me")

    assert response.status_code == 401
    assert response.json() == {"detail": "Authentication required"}
    assert auth_service.session_ids == [None]


def test_create_auth_dependency_respects_custom_cookie_name():
    auth_service = DummyAuthService({"user_id": 2})
    client = TestClient(_build_app(auth_service, cookie_name="custom_session"))

    response = client.get("/me", cookies={"custom_session": "session-2"})

    assert response.status_code == 200
    assert response.json() == {"user_id": 2}
    assert auth_service.session_ids == ["session-2"]


def test_create_tier_dependency_allows_paid_user():
    auth_service = DummyAuthService({"user_id": 3, "tier": "paid"})
    client = TestClient(_build_tier_app(auth_service))

    response = client.get("/paid", cookies={"session_id": "session-3"})

    assert response.status_code == 200
    assert response.json() == {"user_id": 3, "tier": "paid"}
    assert auth_service.session_ids == ["session-3"]


def test_create_tier_dependency_returns_upgrade_required_for_registered_user():
    auth_service = DummyAuthService({"user_id": 4, "tier": "registered"})
    client = TestClient(_build_tier_app(auth_service))

    response = client.get("/paid", cookies={"session_id": "session-4"})

    assert response.status_code == 403
    assert response.json() == {
        "detail": {
            "error": "upgrade_required",
            "message": "This feature requires a paid subscription.",
            "tier_required": "paid",
            "tier_current": "registered",
        }
    }
    assert auth_service.session_ids == ["session-4"]
