from __future__ import annotations

import pytest

from app_platform.auth.stores import PostgresUserStore
from inputs.database_client import DatabaseClient
from services.credentials import google_sheets


class _Cursor:
    def __init__(self, connection):
        self.connection = connection
        self.result = None

    def execute(self, query, params=None):
        normalized = " ".join(str(query).split())
        if "WHERE google_user_id = %s" in normalized:
            self.result = None
        elif normalized.startswith("SELECT google_user_id FROM users"):
            self.result = {"google_user_id": self.connection.user["google_user_id"]}
        elif "WHERE email = %s" in normalized:
            self.result = dict(self.connection.user)
        elif normalized.startswith("UPDATE users SET"):
            if "google_user_id = %s" in normalized:
                self.connection.user["google_user_id"] = params[-2]
        else:
            raise AssertionError(f"Unexpected SQL: {normalized}")

    def fetchone(self):
        return self.result

    def close(self):
        return None


class _Connection:
    def __init__(self):
        self.user = {
            "id": 42,
            "email": "alice@example.com",
            "name": "Alice",
            "tier": "paid",
            "google_user_id": "real-google-subject",
        }
        self.commits = 0
        self.rollbacks = 0

    def cursor(self):
        return _Cursor(self)

    def commit(self):
        self.commits += 1

    def rollback(self):
        self.rollbacks += 1


class _Context:
    def __init__(self, connection):
        self.connection = connection

    def __enter__(self):
        return self.connection

    def __exit__(self, *_args):
        return False


def test_dev_relogin_preserves_existing_real_google_binding() -> None:
    connection = _Connection()
    store = PostgresUserStore(lambda: _Context(connection))

    user_id, user = store.get_or_create_user(
        "dev_alice@example.com", "alice@example.com", "Alice Dev"
    )

    assert user_id == 42
    assert user["google_user_id"] == "real-google-subject"
    assert connection.user["google_user_id"] == "real-google-subject"
    assert connection.commits == 1

    with pytest.raises(
        google_sheets.GoogleSheetsOAuthError, match="google_account_mismatch"
    ):
        google_sheets.validate_and_bind_subject(
            42, "different-google-subject", DatabaseClient(connection)
        )

    assert connection.user["google_user_id"] == "real-google-subject"
    assert connection.rollbacks == 1
