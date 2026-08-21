"""Alert delivery for the API budget guard."""

from __future__ import annotations

import json
import urllib.request

from utils.logging import log_alert, portfolio_logger

from .config import get_budget_config
from .store import get_redis_client


def _send_telegram(
    *,
    bot_token: str,
    chat_id: str,
    message: str,
    details: dict[str, object],
) -> None:
    if not bot_token or not chat_id:
        return

    text = message
    if details:
        text += "\n" + json.dumps(details, default=str, sort_keys=True)

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    data = json.dumps({"chat_id": chat_id, "text": text}).encode()
    request = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(request, timeout=10)


def send_alert(severity: str, provider: str, message: str, **details) -> None:
    severity_key = str(severity or "").strip().lower()
    provider_key = str(provider or "").strip().lower()
    payload = dict(details or {})

    log_alert(
        "api_budget_guard",
        severity_key,
        message,
        source="api_budget",
        provider=provider_key,
        details=payload,
    )

    if severity_key not in {"high", "critical"}:
        return

    config = get_budget_config()
    if not config.telegram_bot_token or not config.telegram_chat_id:
        return

    try:
        redis_client = get_redis_client()
        dedup_key = f"budget:alert:{provider_key}:{severity_key}"
        claimed = redis_client.set(
            dedup_key,
            "1",
            nx=True,
            ex=config.alert_dedup_seconds,
        )
    except Exception as exc:
        portfolio_logger.warning(
            "Budget alert dedup unavailable provider=%s severity=%s: %s",
            provider_key,
            severity_key,
            exc,
        )
        return

    if not claimed:
        return

    try:
        _send_telegram(
            bot_token=config.telegram_bot_token,
            chat_id=config.telegram_chat_id,
            message=message,
            details={"provider": provider_key, **payload},
        )
    except Exception:
        try:
            redis_client.delete(dedup_key)
        except Exception as delete_exc:
            portfolio_logger.warning(
                "Failed to release budget alert dedup key=%s: %s",
                dedup_key,
                delete_exc,
            )
        raise


__all__ = ["send_alert"]
