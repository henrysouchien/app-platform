"""SlowAPI rate-limiter helpers for app_platform."""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from fastapi import Request
from slowapi import Limiter
from slowapi.util import get_remote_address


_MISSING = object()


def _env_flag(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() == "true"


class ApiKeyRegistry:
    """Tracks API keys and their tiers without app-specific globals."""

    def __init__(self) -> None:
        self._valid_keys: set[str] = set()
        self._tier_map: dict[str, str] = {}
        self._default_keys: dict[str, str] = {}

    def add_key(self, key: str, tier: str) -> None:
        if not key:
            raise ValueError("key is required")
        if not tier:
            raise ValueError("tier is required")

        self._valid_keys.add(key)
        self._tier_map[key] = tier
        self._default_keys[tier] = key

    @classmethod
    def from_dict(cls, keys_by_tier: dict[str, str] | None) -> "ApiKeyRegistry":
        registry = cls()
        for tier, key in (keys_by_tier or {}).items():
            registry.add_key(key=key, tier=tier)
        return registry

    @property
    def valid_keys(self) -> set[str]:
        return self._valid_keys

    @property
    def tier_map(self) -> dict[str, str]:
        return self._tier_map

    @property
    def public_key(self) -> str:
        return self._default_keys.get("public", "")

    @property
    def default_keys(self) -> dict[str, str]:
        return self._default_keys


@dataclass(init=False)
class RateLimitConfig:
    dev_mode: bool = field(default=False)
    key_registry: ApiKeyRegistry | None = field(default=None)
    _dev_mode_explicit: bool = field(default=False, repr=False, compare=False)

    def __init__(self, dev_mode=_MISSING, key_registry: ApiKeyRegistry | None = None):
        self.dev_mode = False if dev_mode is _MISSING else bool(dev_mode)
        self.key_registry = key_registry
        self._dev_mode_explicit = dev_mode is not _MISSING

    @property
    def resolved_dev_mode(self) -> bool:
        if self._dev_mode_explicit:
            return self.dev_mode
        return _env_flag("IS_DEV")

    @property
    def resolved_registry(self) -> ApiKeyRegistry:
        return self.key_registry or ApiKeyRegistry()


def _build_key_func(dev_mode: bool, key_registry: ApiKeyRegistry):
    public_key = key_registry.public_key
    tier_map = key_registry.tier_map

    def get_rate_limit_key(request: Request | None = None):
        if dev_mode:
            return None

        if request is None:
            return "127.0.0.1"

        user_key = request.query_params.get("key", public_key)
        user_tier = tier_map.get(user_key, "public")
        if user_tier == "public":
            return get_remote_address(request)
        return user_key

    return get_rate_limit_key


def create_limiter(config: RateLimitConfig | None = None) -> Limiter:
    config = config or RateLimitConfig()
    dev_mode = config.resolved_dev_mode
    registry = config.resolved_registry
    return Limiter(
        key_func=_build_key_func(dev_mode, registry),
        enabled=not dev_mode,
    )


__all__ = ["ApiKeyRegistry", "RateLimitConfig", "create_limiter"]
