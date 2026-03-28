import importlib

from slowapi import Limiter


def _reload_legacy_rate_limiter():
    module = importlib.import_module("utils.rate_limiter")
    return importlib.reload(module)


def test_legacy_rate_limiter_exports_preserve_types(monkeypatch):
    monkeypatch.setenv("IS_DEV", "false")
    legacy = _reload_legacy_rate_limiter()
    namespace = {}

    exec(
        "from utils.rate_limiter import limiter, VALID_KEYS, TIER_MAP, PUBLIC_KEY, DEFAULT_KEYS, IS_DEV",
        namespace,
    )

    assert isinstance(namespace["limiter"], Limiter)
    assert isinstance(namespace["VALID_KEYS"], set)
    assert isinstance(namespace["TIER_MAP"], dict)
    assert isinstance(namespace["PUBLIC_KEY"], str)
    assert isinstance(namespace["DEFAULT_KEYS"], dict)
    assert isinstance(namespace["IS_DEV"], bool)
    assert callable(legacy.get_rate_limit_key)
    assert namespace["VALID_KEYS"] == set(namespace["DEFAULT_KEYS"].values())
    assert namespace["PUBLIC_KEY"] == namespace["DEFAULT_KEYS"]["public"]


def test_legacy_rate_limiter_reads_dev_mode_from_env(monkeypatch):
    monkeypatch.setenv("IS_DEV", "true")
    legacy = _reload_legacy_rate_limiter()

    assert legacy.IS_DEV is True
    assert legacy.limiter.enabled is False
