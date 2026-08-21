"""Shared hosted connector token primitives."""

from __future__ import annotations

import hashlib


CONNECTOR_SCOPE = "connector:hank-mcp"


def hash_connector_token(token: str) -> str:
    return "sha256:" + hashlib.sha256(token.encode("utf-8")).hexdigest()


__all__ = ["CONNECTOR_SCOPE", "hash_connector_token"]
