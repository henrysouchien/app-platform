"""Fresh user-owned brokerage connection check at provider mutation boundaries."""

from __future__ import annotations

from typing import Literal

from .models import StrictCommercialModel


class BrokerageBindingError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class BrokerageBindingResult(StrictCommercialModel):
    user_id: int
    account_connection_id: int
    account_id: str
    provider: str
    status: Literal["connected"] = "connected"


def authorize_brokerage_account(
    connection, *, user_id: int, account_id: str, provider: str
) -> BrokerageBindingResult:
    """Lock an active provider account owned by the exact commercial user."""

    normalized_account = str(account_id or "").strip()
    normalized_provider = str(provider or "").strip().lower()
    if not normalized_account or not normalized_provider or user_id <= 0:
        raise BrokerageBindingError(
            "brokerage.connection_required", "A connected brokerage account is required"
        )
    with connection.cursor() as cursor:
        cursor.execute(
            """SELECT account.id, account.user_id, account.account_id_external,
                      COALESCE(source.provider, account.position_source)
                 FROM accounts account
                 JOIN data_sources source ON source.id=account.data_source_id
                  AND source.user_id=account.user_id
                WHERE account.account_id_external=%s
                  AND provider_account_family(%s) IN (
                      provider_account_family(account.position_source),
                      provider_account_family(source.provider))
                  AND COALESCE(account.is_active,TRUE)
                  AND NOT COALESCE(account.user_deactivated,FALSE)
                  AND source.status='active'
                  AND NOT COALESCE(source.user_deactivated,FALSE)
                ORDER BY account.id FOR SHARE OF account,source""",
            (normalized_account, normalized_provider),
        )
        rows = cursor.fetchall()
    owned = [row for row in rows if int(row[1]) == user_id]
    if len(owned) == 1:
        row = owned[0]
        return BrokerageBindingResult(
            user_id=user_id, account_connection_id=int(row[0]),
            account_id=normalized_account, provider=normalized_provider,
        )
    if owned or rows:
        raise BrokerageBindingError(
            "brokerage.account_owner_mismatch",
            "The brokerage account is not owned by the authorized user",
        )
    raise BrokerageBindingError(
        "brokerage.connection_required",
        "Connect the requested brokerage account before submitting this operation",
    )


__all__ = [
    "BrokerageBindingError", "BrokerageBindingResult", "authorize_brokerage_account",
]
