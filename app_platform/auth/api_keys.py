"""Safe, non-authenticating identifiers for request API keys."""

from __future__ import annotations

import hashlib


def api_key_fingerprint(api_key: str) -> str:
    """Return a stable identifier that cannot be used to authenticate."""
    return "sha256:" + hashlib.sha256(api_key.encode("utf-8")).hexdigest()


__all__ = ["api_key_fingerprint"]
