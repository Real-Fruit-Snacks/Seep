"""Tests for the Seep HTTP server — index, agent, upload endpoints."""

from __future__ import annotations

import json
import random
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import HTTPServer
from pathlib import Path

import pytest

from server.agent.composer import AgentComposer
from server.config import ServerConfig
from server.http.serve import SeepHTTPHandler, create_handler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Pick a random high port that is currently free."""
    base = 19500 + random.randint(0, 499)
    for port in range(base, base + 100):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise RuntimeError("Could not find a free port in range 19500-19999")


class _ServerContext:
    """Context manager that starts an HTTPServer in a background thread."""

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        self.composer = AgentComposer()
        handler_cls = create_handler(config, self.composer)
        self.port = config.http_port
        self.server = HTTPServer(("127.0.0.1", self.port), handler_cls)
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "_ServerContext":
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        # Give the server a moment to start
        time.sleep(0.05)
        return self

    def __exit__(self, *_) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._thread:
            self._thread.join(timeout=3)

    def get(self, path: str) -> tuple[int, bytes, dict]:
        """Perform a GET request. Returns (status, body_bytes, headers_dict)."""
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), {}

    def post(
        self, path: str, body: bytes, content_type: str = "application/json"
    ) -> tuple[int, bytes]:
        """Perform a POST request. Returns (status, body_bytes)."""
        url = f"http://127.0.0.1:{self.port}{path}"
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers={
                "Content-Type": content_type,
                "Content-Length": str(len(body)),
            },
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()


@pytest.fixture
def server_ctx(tmp_path: Path):
    """Start a test HTTP server on a random high port; tear it down after the test."""
    port = _free_port()
    config = ServerConfig(
        http_port=port,
        upload_port=port + 1,
        bind_address="127.0.0.1",
        workdir=tmp_path,
    )
    with _ServerContext(config) as ctx:
        yield ctx


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_create_handler_returns_class() -> None:
    """create_handler returns a class (subclass of SeepHTTPHandler)."""
    config = ServerConfig()
    composer = AgentComposer()
    handler_cls = create_handler(config, composer)
    assert isinstance(handler_cls, type)
    assert issubclass(handler_cls, SeepHTTPHandler)


def test_create_handler_injects_config() -> None:
    """Handler class has config and composer attributes set."""
    config = ServerConfig(http_port=19999)
    composer = AgentComposer()
    handler_cls = create_handler(config, composer)
    assert handler_cls.config is config
    assert handler_cls.composer is composer


def test_index_page_returns_200(server_ctx: _ServerContext) -> None:
    """GET / returns HTTP 200."""
    status, _, _ = server_ctx.get("/")
    assert status == 200


def test_index_page_contains_seep(server_ctx: _ServerContext) -> None:
    """GET / body contains the string 'Seep' or 'SEEP'."""
    _, body, _ = server_ctx.get("/")
    text = body.decode("utf-8", errors="replace")
    assert "Seep" in text or "SEEP" in text


def test_index_page_content_type_html(server_ctx: _ServerContext) -> None:
    """GET / returns text/html content-type."""
    _, _, headers = server_ctx.get("/")
    ct = headers.get("Content-Type", "")
    assert "text/html" in ct


def test_agent_endpoint_returns_200(server_ctx: _ServerContext) -> None:
    """GET /agent.ps1 returns HTTP 200."""
    status, _, _ = server_ctx.get("/agent.ps1")
    assert status == 200


def test_agent_endpoint_contains_invoke_seep(server_ctx: _ServerContext) -> None:
    """GET /agent.ps1 body contains 'Invoke-Seep'."""
    _, body, _ = server_ctx.get("/agent.ps1")
    text = body.decode("utf-8", errors="replace")
    assert "Invoke-Seep" in text


def test_agent_endpoint_content_type_text(server_ctx: _ServerContext) -> None:
    """GET /agent.ps1 returns text/plain content-type."""
    _, _, headers = server_ctx.get("/agent.ps1")
    ct = headers.get("Content-Type", "")
    assert "text/plain" in ct


def test_agent_endpoint_alt_url(server_ctx: _ServerContext) -> None:
    """GET /Seep.ps1 also serves the agent."""
    status, body, _ = server_ctx.get("/Seep.ps1")
    assert status == 200
    assert b"Invoke-Seep" in body


def test_cradle_endpoint_returns_200(server_ctx: _ServerContext) -> None:
    """GET /cradle returns HTTP 200."""
    status, _, _ = server_ctx.get("/cradle")
    assert status == 200


def test_cradle_endpoint_contains_powershell(server_ctx: _ServerContext) -> None:
    """GET /cradle body contains 'powershell'."""
    _, body, _ = server_ctx.get("/cradle")
    text = body.decode("utf-8", errors="replace").lower()
    assert "powershell" in text


def test_upload_endpoint_json(server_ctx: _ServerContext, tmp_path: Path) -> None:
    """POST /upload with valid JSON results in HTTP 200 and a saved file."""
    payload = {
        "meta": {
            "hostname": "TESTHOST",
            "username": "tester",
            "domain": "",
            "os_version": "10.0",
        },
        "findings": [
            {
                "check_id": "test_check",
                "finding_id": "test_finding",
                "severity": "info",
                "title": "Test Finding",
                "tags": [],
            }
        ],
        "summary": {"total_findings": 1},
    }
    body = json.dumps(payload).encode("utf-8")
    status, resp_body = server_ctx.post("/upload", body)

    assert status == 200, f"Expected 200, got {status}: {resp_body.decode()}"

    resp = json.loads(resp_body)
    assert resp["status"] == "ok"
    assert resp["hostname"] == "TESTHOST"
    assert resp["findings_count"] == 1

    # Verify the file was actually saved
    results_dir = server_ctx.config.workdir / server_ctx.config.results.output_dir
    saved_files = list(results_dir.glob("results_*.json"))
    assert len(saved_files) == 1


def test_upload_endpoint_api_results_alias(server_ctx: _ServerContext) -> None:
    """POST /api/results also accepts uploads."""
    payload = {
        "meta": {"hostname": "HOST2"},
        "findings": [],
        "summary": {"total_findings": 0},
    }
    body = json.dumps(payload).encode("utf-8")
    status, resp_body = server_ctx.post("/api/results", body)
    assert status == 200


def test_upload_empty_body_returns_400(server_ctx: _ServerContext) -> None:
    """POST /upload with empty body returns HTTP 400."""
    status, _ = server_ctx.post("/upload", b"")
    assert status == 400


def test_api_results_get_returns_json(server_ctx: _ServerContext) -> None:
    """GET /api/results returns a JSON array."""
    status, body, headers = server_ctx.get("/api/results")
    assert status == 200
    ct = headers.get("Content-Type", "")
    assert "application/json" in ct
    data = json.loads(body)
    assert isinstance(data, list)


def test_unknown_path_returns_404(server_ctx: _ServerContext) -> None:
    """GET on an unknown path returns HTTP 404."""
    status, _, _ = server_ctx.get("/this-does-not-exist")
    assert status == 404
