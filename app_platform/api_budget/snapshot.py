"""Redis-to-Postgres snapshotting for API budget counters."""

from __future__ import annotations

from typing import Any

from database.session import SessionManager
from utils.logging import portfolio_logger

from .store import scan_counter_entries

GLOBAL_UPSERT_SQL = """
INSERT INTO api_call_counters (
    provider, operation, scope, user_id, window_kind, window_start, call_count, updated_at
)
VALUES (%s, %s, 'global', NULL, %s, %s, %s, NOW())
ON CONFLICT (provider, operation, window_kind, window_start) WHERE scope='global'
DO UPDATE SET
    call_count = EXCLUDED.call_count,
    updated_at = NOW()
"""

USER_UPSERT_SQL = """
INSERT INTO api_call_counters (
    provider, operation, scope, user_id, window_kind, window_start, call_count, updated_at
)
VALUES (%s, %s, 'user', %s, %s, %s, %s, NOW())
ON CONFLICT (provider, operation, user_id, window_kind, window_start) WHERE scope='user'
DO UPDATE SET
    call_count = EXCLUDED.call_count,
    updated_at = NOW()
"""


def snapshot_to_postgres(*, provider: str | None = None) -> dict[str, Any]:
    entries = scan_counter_entries(provider=provider)
    if not entries:
        return {"ok": True, "provider": provider, "scanned": 0, "upserted": 0}

    manager = SessionManager()
    upserted = 0
    with manager.get_db_session() as conn:
        cursor = conn.cursor()
        try:
            for entry in entries:
                if entry["scope"] == "global":
                    cursor.execute(
                        GLOBAL_UPSERT_SQL,
                        (
                            entry["provider"],
                            entry["operation"],
                            entry["window_kind"],
                            entry["window_start"],
                            int(entry["call_count"]),
                        ),
                    )
                else:
                    cursor.execute(
                        USER_UPSERT_SQL,
                        (
                            entry["provider"],
                            entry["operation"],
                            int(entry["user_id"]),
                            entry["window_kind"],
                            entry["window_start"],
                            int(entry["call_count"]),
                        ),
                    )
                upserted += 1
            conn.commit()
        except Exception:
            rollback = getattr(conn, "rollback", None)
            if callable(rollback):
                rollback()
            raise
        finally:
            close = getattr(cursor, "close", None)
            if callable(close):
                close()

    portfolio_logger.info(
        "API budget snapshot complete provider=%s scanned=%s upserted=%s",
        provider,
        len(entries),
        upserted,
    )
    return {"ok": True, "provider": provider, "scanned": len(entries), "upserted": upserted}


__all__ = ["GLOBAL_UPSERT_SQL", "USER_UPSERT_SQL", "snapshot_to_postgres"]
