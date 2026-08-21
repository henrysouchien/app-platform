from __future__ import annotations

from contextlib import contextmanager

from services.auth_service import AuthService, auth_service


def test_auth_service_singleton_and_legacy_method_exist():
    assert isinstance(auth_service, AuthService)
    assert callable(auth_service.verify_google_token)
    assert isinstance(auth_service.use_database, bool)


def test_auth_service_memory_constructor_preserves_legacy_surface():
    service = AuthService(use_database=False)
    session_id = service.create_user_session(
        {
            "user_id": "shim-user-1",
            "google_user_id": "shim-user-1",
            "email": "shim@example.com",
            "name": "Shim User",
        }
    )

    resolved_user = service.get_user_by_session(session_id)

    assert service.use_database is False
    assert service.session_duration.total_seconds() > 0
    assert service.cleanup_interval.total_seconds() > 0
    assert service.last_cleanup is not None
    assert resolved_user == {
        "user_id": "shim-user-1",
        "google_user_id": "shim-user-1",
        "email": "shim@example.com",
        "name": "Shim User",
        "tier": "registered",
    }


def test_build_dev_user_supports_mapping_rows(monkeypatch):
    import database
    import services.auth_service as auth_module

    class _FakeCursor:
        def execute(self, query):
            assert "SELECT email, name, google_user_id FROM users" in query

        def fetchone(self):
            return {
                "email": "hc@henrychien.com",
                "name": "Hc",
                "google_user_id": "dev_hc@henrychien.com",
            }

        def close(self):
            return None

    class _FakeConnection:
        def cursor(self):
            return _FakeCursor()

    @contextmanager
    def _fake_db_session():
        yield _FakeConnection()

    monkeypatch.setattr(auth_module, "DEV_AUTH_EMAIL", "")
    monkeypatch.setattr(auth_module, "USE_DATABASE", True)
    monkeypatch.setattr(database, "get_db_session", _fake_db_session)

    assert auth_module._build_dev_user() == {
        "email": "hc@henrychien.com",
        "name": "Hc",
        "google_user_id": "dev_hc@henrychien.com",
        "sub": "dev_hc@henrychien.com",
    }


def test_dev_auth_bypass_preserves_memory_fallback_under_strict_database_mode(monkeypatch):
    import services.auth_service as auth_module

    @contextmanager
    def _broken_db_session():
        raise OSError(5, "Input/output error")
        yield

    monkeypatch.setattr(auth_module, "STRICT_DATABASE_MODE", True)
    monkeypatch.setattr(auth_module, "_IS_PRODUCTION", False)
    monkeypatch.setattr(auth_module, "DEV_AUTH_BYPASS", True)
    monkeypatch.setattr(auth_module, "GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.setattr(auth_module, "DEV_AUTH_EMAIL", "dev@example.com")
    monkeypatch.setattr(auth_module, "get_db_session", _broken_db_session)

    service = auth_module.AuthService(use_database=True)
    session_id = service.create_user_session(
        {
            "user_id": "dev-user",
            "google_user_id": "dev-user",
            "email": "dev@example.com",
            "name": "Dev User",
        }
    )

    resolved_user = service.get_user_by_session(session_id)

    assert service.strict_mode is False
    assert resolved_user == {
        "user_id": "dev-user",
        "google_user_id": "dev-user",
        "email": "dev@example.com",
        "name": "Dev User",
        "tier": "registered",
    }


def test_strict_database_mode_stays_strict_for_real_auth(monkeypatch):
    import services.auth_service as auth_module

    monkeypatch.setattr(auth_module, "STRICT_DATABASE_MODE", True)
    monkeypatch.setattr(auth_module, "_IS_PRODUCTION", False)
    monkeypatch.setattr(auth_module, "DEV_AUTH_BYPASS", False)
    monkeypatch.setattr(auth_module, "GOOGLE_CLIENT_ID", "client-id")

    service = auth_module.AuthService(use_database=True)

    assert service.strict_mode is True
