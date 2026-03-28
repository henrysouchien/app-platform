import importlib

from slowapi import Limiter
from starlette.requests import Request


def _request(query_string: bytes = b"", client_host: str = "198.51.100.10"):
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/limited",
            "headers": [],
            "query_string": query_string,
            "client": (client_host, 1234),
        }
    )


def test_api_key_registry_from_dict_preserves_legacy_shapes():
    module = importlib.import_module("app_platform.middleware.rate_limiter")

    registry = module.ApiKeyRegistry.from_dict(
        {
            "public": "public_key_123",
            "registered": "registered_key_456",
            "paid": "paid_key_789",
        }
    )

    assert registry.valid_keys == {
        "public_key_123",
        "registered_key_456",
        "paid_key_789",
    }
    assert registry.tier_map["public_key_123"] == "public"
    assert registry.tier_map["registered_key_456"] == "registered"
    assert registry.public_key == "public_key_123"
    assert registry.default_keys["paid"] == "paid_key_789"


def test_api_key_registry_add_key_updates_all_views():
    module = importlib.import_module("app_platform.middleware.rate_limiter")
    registry = module.ApiKeyRegistry()

    registry.add_key("customer_key_001", "paid")

    assert registry.valid_keys == {"customer_key_001"}
    assert registry.tier_map == {"customer_key_001": "paid"}
    assert registry.default_keys == {"paid": "customer_key_001"}
    assert registry.public_key == ""


def test_create_limiter_resolves_keys_by_tier():
    module = importlib.import_module("app_platform.middleware.rate_limiter")
    registry = module.ApiKeyRegistry.from_dict(
        {
            "public": "public_key_123",
            "registered": "registered_key_456",
            "paid": "paid_key_789",
        }
    )

    limiter = module.create_limiter(
        module.RateLimitConfig(dev_mode=False, key_registry=registry)
    )

    assert isinstance(limiter, Limiter)
    assert limiter.enabled is True
    assert limiter._key_func(_request(client_host="203.0.113.2")) == "203.0.113.2"
    assert (
        limiter._key_func(_request(b"key=registered_key_456", client_host="203.0.113.3"))
        == "registered_key_456"
    )
    assert limiter._key_func(_request(b"key=paid_key_789", client_host="203.0.113.4")) == "paid_key_789"
    assert limiter._key_func(_request(b"key=unknown", client_host="203.0.113.5")) == "203.0.113.5"
    assert limiter._key_func(None) == "127.0.0.1"


def test_create_limiter_dev_mode_bypasses_rate_limiting(monkeypatch):
    module = importlib.import_module("app_platform.middleware.rate_limiter")
    monkeypatch.setenv("IS_DEV", "true")

    limiter = module.create_limiter(module.RateLimitConfig())

    assert isinstance(limiter, Limiter)
    assert limiter.enabled is False
    assert limiter._key_func(_request(client_host="203.0.113.9")) is None
