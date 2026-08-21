import asyncio
import importlib
import json
import logging
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient


def _read_jsonl(path: Path):
    if not path.exists():
        return []
    rows = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if line:
            rows.append(json.loads(line))
    return rows


def _flush_manager(manager):
    for logger in (
        logging.getLogger(),
        manager.error_event_logger,
        manager.usage_event_logger,
        manager.frontend_event_logger,
        manager.timing_event_logger,
    ):
        for handler in logger.handlers:
            handler.flush()


@pytest.fixture(autouse=True)
def _reset_logging_state():
    core = importlib.import_module("app_platform.logging.core")
    core.LoggingManager._reset_for_tests()
    yield
    core.LoggingManager._reset_for_tests()


def _build_client(tmp_path: Path) -> tuple[TestClient, object]:
    core = importlib.import_module("app_platform.logging.core")
    timing = importlib.import_module("app_platform.middleware.timing")
    manager = core.configure_logging(
        app_name="platform_app",
        log_dir=str(tmp_path / "logs"),
        environment="development",
    )

    app = FastAPI()
    app.add_middleware(timing.RequestTimingMiddleware)

    @app.get("/normal")
    async def normal():
        return {"ok": True}

    async def _stream():
        yield b"chunk-1"
        yield b"chunk-2"

    @app.get("/stream")
    async def stream():
        return StreamingResponse(_stream(), media_type="text/plain")

    return TestClient(app), manager


def test_request_timing_middleware_logs_normal_requests(tmp_path):
    client, manager = _build_client(tmp_path)

    response = client.get("/normal")

    assert response.status_code == 200
    _flush_manager(manager)

    rows = _read_jsonl(Path(manager.timing_log_path))
    assert rows[-1]["kind"] == "request"
    assert rows[-1]["name"] == "GET /normal"
    assert rows[-1]["status"] == 200
    assert rows[-1]["duration_ms"] >= 0
    assert rows[-1]["details"]["streaming"] is False


def test_request_timing_middleware_does_not_persist_query_credentials(tmp_path):
    client, manager = _build_client(tmp_path)
    raw_api_key = "canary-query-api-key"

    response = client.get("/normal", params={"key": raw_api_key, "view": "summary"})

    assert response.status_code == 200
    _flush_manager(manager)

    persisted = Path(manager.timing_log_path).read_text()
    rows = _read_jsonl(Path(manager.timing_log_path))
    assert raw_api_key not in persisted
    assert "query" not in rows[-1]["details"]
    assert rows[-1]["name"] == "GET /normal"


def test_request_timing_middleware_marks_streaming_responses(tmp_path):
    client, manager = _build_client(tmp_path)

    response = client.get("/stream")

    assert response.status_code == 200
    assert response.text == "chunk-1chunk-2"
    _flush_manager(manager)

    rows = _read_jsonl(Path(manager.timing_log_path))
    assert rows[-1]["kind"] == "request"
    assert rows[-1]["name"] == "GET /stream"
    assert rows[-1]["status"] == 200
    assert rows[-1]["details"]["streaming"] is True


def test_request_timing_middleware_omits_duration_header_for_streaming(tmp_path):
    client, _ = _build_client(tmp_path)

    response = client.get("/stream")

    assert response.status_code == 200
    assert "x-request-duration-ms" not in response.headers


def test_request_timing_middleware_forwards_silent_sse_start_immediately(monkeypatch):
    timing = importlib.import_module("app_platform.middleware.timing")
    logged_events = []

    monkeypatch.setattr(
        timing,
        "log_timing_event",
        lambda **kwargs: logged_events.append(kwargs),
    )

    async def run() -> list[dict]:
        start_seen = asyncio.Event()
        never_send_body = asyncio.Event()
        messages = []

        async def app(scope, receive, send):
            await send(
                {
                    "type": "http.response.start",
                    "status": 200,
                    "headers": [(b"content-type", b"text/event-stream")],
                }
            )
            await never_send_body.wait()

        async def receive():
            return {"type": "http.request", "body": b"", "more_body": False}

        async def send(message):
            messages.append(message)
            if message["type"] == "http.response.start":
                start_seen.set()

        middleware = timing.RequestTimingMiddleware(app)
        task = asyncio.create_task(
            middleware(
                {
                    "type": "http",
                    "method": "GET",
                    "path": "/events",
                    "query_string": b"",
                },
                receive,
                send,
            )
        )

        await asyncio.wait_for(start_seen.wait(), timeout=0.1)
        assert [message["type"] for message in messages] == ["http.response.start"]

        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

        return messages

    messages = asyncio.run(run())

    assert messages[0]["status"] == 200
    assert logged_events[-1]["status"] == 200
    assert logged_events[-1]["streaming"] is False
