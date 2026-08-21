from fastapi import FastAPI
from fastapi.testclient import TestClient

from app_platform.middleware.consent import ConsentEnforcementMiddleware


class _Auth:
    def get_user_by_session(self, session_id):
        return {"user_id": 7} if session_id == "valid" else None


class _Session:
    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def rollback(self):
        return None


def _client(*, accepted: bool) -> TestClient:
    app = FastAPI()

    @app.get("/api/private")
    def private():
        return {"ok": True}

    @app.get("/api/legal/consents/current")
    def current():
        return {"consent_required": not accepted}

    app.add_middleware(
        ConsentEnforcementMiddleware,
        auth_service=_Auth(),
        session_factory=lambda: _Session(),
        consent_checker=lambda _conn, *, user_id: accepted and user_id == 7,
    )
    return TestClient(app)


def test_blocks_authenticated_api_traffic_without_current_consent() -> None:
    response = _client(accepted=False).get(
        "/api/private", cookies={"session_id": "valid"}
    )

    assert response.status_code == 428
    assert response.json()["detail"]["error"] == "consent_required"
    assert response.headers["cache-control"] == "private, no-store"


def test_allows_consent_route_and_current_users() -> None:
    blocked_client = _client(accepted=False)
    assert blocked_client.get(
        "/api/legal/consents/current", cookies={"session_id": "valid"}
    ).status_code == 200
    assert _client(accepted=True).get(
        "/api/private", cookies={"session_id": "valid"}
    ).json() == {"ok": True}


def test_leaves_unauthenticated_requests_to_route_authority() -> None:
    assert _client(accepted=False).get("/api/private").json() == {"ok": True}
