from __future__ import annotations

import app_platform.app_factory as app_factory


def test_create_app_instance_configures_development_app() -> None:
    calls: dict[str, object] = {}

    def _configure(app, **kwargs):
        calls["configure"] = (app, kwargs)

    def _lifespan(**kwargs):
        calls["lifespan"] = kwargs
        return None

    app = app_factory.create_app_instance(
        is_production=False,
        cors_origins=["http://localhost:3000"],
        validation_logger="validation-logger",
        lifespan_logger="lifespan-logger",
        log_critical_alert_fn=lambda *args: calls.setdefault("alert", args),
        configure_app_platform_fn=_configure,
        create_app_lifespan_fn=_lifespan,
        get_env_fn=lambda key: {"DATABASE_URL": "db", "FMP_API_KEY": "fmp"}.get(key),
    )

    assert app.title == "Risk Module API"
    assert app.docs_url == "/docs"
    assert app.redoc_url == "/redoc"
    assert app.openapi_url == "/openapi.json"
    assert calls["lifespan"] == {"logger": "lifespan-logger"}
    assert calls["configure"] == (
        app,
        {
            "is_production": False,
            "cors_origins": ["http://localhost:3000"],
            "validation_logger": "validation-logger",
        },
    )
    assert "alert" not in calls


def test_create_app_instance_disables_docs_in_production() -> None:
    app = app_factory.create_app_instance(
        is_production=True,
        cors_origins=[],
        validation_logger=None,
        lifespan_logger=None,
        log_critical_alert_fn=lambda *args: None,
        configure_app_platform_fn=lambda *args, **kwargs: None,
        create_app_lifespan_fn=lambda **kwargs: None,
        get_env_fn=lambda key: {"DATABASE_URL": "db", "FMP_API_KEY": "fmp"}.get(key),
    )

    assert app.docs_url is None
    assert app.redoc_url is None
    assert app.openapi_url is None


def test_create_app_instance_logs_missing_required_environment() -> None:
    alerts: list[tuple[str, str, str, str]] = []

    app_factory.create_app_instance(
        is_production=False,
        cors_origins=[],
        validation_logger=None,
        lifespan_logger=None,
        log_critical_alert_fn=lambda *args: alerts.append(args),
        configure_app_platform_fn=lambda *args, **kwargs: None,
        create_app_lifespan_fn=lambda **kwargs: None,
        get_env_fn=lambda key: None,
    )

    assert [alert[0] for alert in alerts] == [
        "missing_database_url",
        "missing_fmp_api_key",
    ]
    assert all(alert[1] == "high" for alert in alerts)
