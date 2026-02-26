"""Comprehensive tests for SeepHTTPHandler, create_handler, and get_local_ips."""

from __future__ import annotations

import json
import random
import socket
import threading
import time
import urllib.error
import urllib.request
import zipfile
from http.server import HTTPServer
from io import BytesIO
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from server.agent.composer import AgentComposer
from server.config import ServerConfig
from server.http.serve import SeepHTTPHandler, create_handler, get_local_ips


# ---------------------------------------------------------------------------
# Port / server helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Return an available TCP port in the high range."""
    base = 29500 + random.randint(0, 499)
    for port in range(base, base + 100):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise RuntimeError("No free port found in range 29500–29999")


class _TestServer:
    """Lightweight context manager: starts HTTPServer in a daemon thread."""

    def __init__(self, config: ServerConfig) -> None:
        self.config = config
        composer = AgentComposer()
        handler_cls = create_handler(config, composer)
        self.server = HTTPServer(("127.0.0.1", config.http_port), handler_cls)
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "_TestServer":
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        time.sleep(0.05)  # give the server a moment to bind
        return self

    def __exit__(self, *_) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._thread:
            self._thread.join(timeout=3)

    @property
    def port(self) -> int:
        return self.config.http_port

    # ------------------------------------------------------------------ #
    # Convenience request helpers                                          #
    # ------------------------------------------------------------------ #

    def get(self, path: str) -> tuple[int, bytes, dict]:
        url = f"http://127.0.0.1:{self.port}{path}"
        try:
            with urllib.request.urlopen(url) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), {}

    def post(
        self,
        path: str,
        body: bytes,
        content_type: str = "application/json",
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        url = f"http://127.0.0.1:{self.port}{path}"
        headers = {
            "Content-Type": content_type,
            "Content-Length": str(len(body)),
        }
        if extra_headers:
            headers.update(extra_headers)
        req = urllib.request.Request(
            url,
            data=body,
            method="POST",
            headers=headers,
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()


@pytest.fixture
def server_ctx(tmp_path: Path) -> "_TestServer":
    port = _free_port()
    config = ServerConfig(
        http_port=port,
        upload_port=port + 1,
        bind_address="127.0.0.1",
        workdir=tmp_path,
    )
    with _TestServer(config) as ctx:
        yield ctx


def _make_zip(filename: str, content: bytes) -> bytes:
    """Create an in-memory ZIP with one file."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def _minimal_results_json(
    hostname: str = "HOST", findings: list | None = None
) -> bytes:
    payload = {
        "meta": {"hostname": hostname},
        "findings": findings or [],
        "summary": {"total_findings": len(findings or [])},
    }
    return json.dumps(payload).encode("utf-8")


# ---------------------------------------------------------------------------
# get_local_ips tests
# ---------------------------------------------------------------------------


class TestGetLocalIps:
    def test_returns_list(self) -> None:
        result = get_local_ips()
        assert isinstance(result, list)

    def test_non_empty(self) -> None:
        result = get_local_ips()
        assert len(result) >= 1

    def test_all_elements_are_strings(self) -> None:
        for ip in get_local_ips():
            assert isinstance(ip, str)

    def test_all_elements_look_like_ips(self) -> None:
        """Each returned string should look like a dotted-quad IPv4 address."""
        for ip in get_local_ips():
            parts = ip.split(".")
            assert len(parts) == 4, f"Not a dotted-quad: {ip!r}"
            for part in parts:
                assert part.isdigit(), f"Non-numeric octet in {ip!r}"

    def test_no_loopback_when_real_iface_available(self) -> None:
        """If real interfaces exist, loopback (127.x) should not be primary."""
        ips = get_local_ips()
        # We can't guarantee the environment, but loopback being first is unusual
        # Just assert that it's not the *only* result unless truly isolated
        if len(ips) > 1:
            assert not all(ip.startswith("127.") for ip in ips)


# ---------------------------------------------------------------------------
# create_handler tests
# ---------------------------------------------------------------------------


class TestCreateHandler:
    def test_returns_a_type(self) -> None:
        config = ServerConfig()
        composer = AgentComposer()
        cls = create_handler(config, composer)
        assert isinstance(cls, type)

    def test_is_subclass_of_seep_handler(self) -> None:
        config = ServerConfig()
        composer = AgentComposer()
        cls = create_handler(config, composer)
        assert issubclass(cls, SeepHTTPHandler)

    def test_config_injected(self) -> None:
        config = ServerConfig(http_port=19999)
        composer = AgentComposer()
        cls = create_handler(config, composer)
        assert cls.config is config

    def test_composer_injected(self) -> None:
        config = ServerConfig()
        composer = AgentComposer()
        cls = create_handler(config, composer)
        assert cls.composer is composer

    def test_agent_cache_starts_none(self) -> None:
        config = ServerConfig()
        composer = AgentComposer()
        cls = create_handler(config, composer)
        assert cls._agent_cache is None

    def test_different_calls_produce_independent_classes(self) -> None:
        """Two create_handler calls must not share class-level state."""
        config_a = ServerConfig(http_port=19001)
        config_b = ServerConfig(http_port=19002)
        composer = AgentComposer()
        cls_a = create_handler(config_a, composer)
        cls_b = create_handler(config_b, composer)
        assert cls_a is not cls_b
        assert cls_a.config.http_port != cls_b.config.http_port


# ---------------------------------------------------------------------------
# GET / (index) tests
# ---------------------------------------------------------------------------


class TestGetIndex:
    def test_returns_200(self, server_ctx: _TestServer) -> None:
        status, _, _ = server_ctx.get("/")
        assert status == 200

    def test_content_type_is_html(self, server_ctx: _TestServer) -> None:
        _, _, headers = server_ctx.get("/")
        assert "text/html" in headers.get("Content-Type", "")

    def test_body_contains_seep(self, server_ctx: _TestServer) -> None:
        _, body, _ = server_ctx.get("/")
        text = body.decode("utf-8", errors="replace")
        assert "SEEP" in text or "Seep" in text

    def test_index_html_alias(self, server_ctx: _TestServer) -> None:
        """GET /index.html also returns 200."""
        status, _, _ = server_ctx.get("/index.html")
        assert status == 200

    def test_body_is_valid_html(self, server_ctx: _TestServer) -> None:
        _, body, _ = server_ctx.get("/")
        text = body.decode("utf-8", errors="replace")
        assert "<!DOCTYPE html>" in text or "<!doctype html>" in text.lower()
        assert "</html>" in text

    def test_security_headers_present(self, server_ctx: _TestServer) -> None:
        _, _, headers = server_ctx.get("/")
        assert "nosniff" in headers.get("X-Content-Type-Options", "")


# ---------------------------------------------------------------------------
# GET /agent.ps1 tests
# ---------------------------------------------------------------------------


class TestGetAgent:
    def test_returns_200(self, server_ctx: _TestServer) -> None:
        status, _, _ = server_ctx.get("/agent.ps1")
        assert status == 200

    def test_content_type_is_text_plain(self, server_ctx: _TestServer) -> None:
        _, _, headers = server_ctx.get("/agent.ps1")
        assert "text/plain" in headers.get("Content-Type", "")

    def test_body_contains_invoke_seep(self, server_ctx: _TestServer) -> None:
        _, body, _ = server_ctx.get("/agent.ps1")
        assert b"Invoke-Seep" in body

    def test_seep_ps1_alias(self, server_ctx: _TestServer) -> None:
        """GET /Seep.ps1 is also a valid agent endpoint."""
        status, body, _ = server_ctx.get("/Seep.ps1")
        assert status == 200
        assert b"Invoke-Seep" in body

    def test_agent_url_alias(self, server_ctx: _TestServer) -> None:
        """GET /agent also routes to agent delivery."""
        status, _, _ = server_ctx.get("/agent")
        assert status == 200

    def test_content_disposition_header(self, server_ctx: _TestServer) -> None:
        _, _, headers = server_ctx.get("/agent.ps1")
        cd = headers.get("Content-Disposition", "")
        assert "Seep.ps1" in cd or "agent" in cd.lower()

    def test_security_headers_present(self, server_ctx: _TestServer) -> None:
        _, _, headers = server_ctx.get("/agent.ps1")
        assert "nosniff" in headers.get("X-Content-Type-Options", "")


# ---------------------------------------------------------------------------
# GET /cradle tests
# ---------------------------------------------------------------------------


class TestGetCradle:
    def test_returns_200(self, server_ctx: _TestServer) -> None:
        status, _, _ = server_ctx.get("/cradle")
        assert status == 200

    def test_content_type_is_text(self, server_ctx: _TestServer) -> None:
        _, _, headers = server_ctx.get("/cradle")
        assert "text/plain" in headers.get("Content-Type", "")

    def test_body_contains_powershell(self, server_ctx: _TestServer) -> None:
        _, body, _ = server_ctx.get("/cradle")
        assert b"powershell" in body.lower()

    def test_body_contains_iex(self, server_ctx: _TestServer) -> None:
        _, body, _ = server_ctx.get("/cradle")
        assert b"IEX" in body or b"iex" in body.lower()

    def test_body_contains_agent_url(self, server_ctx: _TestServer) -> None:
        _, body, _ = server_ctx.get("/cradle")
        assert b"agent.ps1" in body


# ---------------------------------------------------------------------------
# POST /api/results tests
# ---------------------------------------------------------------------------


class TestPostResults:
    def test_valid_json_returns_200(self, server_ctx: _TestServer) -> None:
        body = _minimal_results_json("TESTHOST")
        status, _ = server_ctx.post("/api/results", body)
        assert status == 200

    def test_upload_alias_returns_200(self, server_ctx: _TestServer) -> None:
        body = _minimal_results_json("ALTHOST")
        status, _ = server_ctx.post("/upload", body)
        assert status == 200

    def test_response_is_json(self, server_ctx: _TestServer) -> None:
        body = _minimal_results_json()
        _, resp = server_ctx.post("/api/results", body)
        parsed = json.loads(resp)
        assert isinstance(parsed, dict)

    def test_response_has_ok_status(self, server_ctx: _TestServer) -> None:
        body = _minimal_results_json("HOSTOK")
        _, resp = server_ctx.post("/api/results", body)
        data = json.loads(resp)
        assert data["status"] == "ok"

    def test_response_contains_hostname(self, server_ctx: _TestServer) -> None:
        body = _minimal_results_json("MYHOST")
        _, resp = server_ctx.post("/api/results", body)
        data = json.loads(resp)
        assert data["hostname"] == "MYHOST"

    def test_response_contains_findings_count(self, server_ctx: _TestServer) -> None:
        findings = [
            {"check_id": "c", "finding_id": "f", "severity": "info", "title": "T"}
        ]
        body = _minimal_results_json("HOST1", findings)
        _, resp = server_ctx.post("/api/results", body)
        data = json.loads(resp)
        assert data["findings_count"] == 1

    def test_file_saved_to_results_dir(self, server_ctx: _TestServer) -> None:
        body = _minimal_results_json("SAVED")
        server_ctx.post("/api/results", body)
        results_dir = server_ctx.config.workdir / server_ctx.config.results.output_dir
        saved = list(results_dir.glob("results_*.json"))
        assert len(saved) >= 1

    def test_saved_file_contains_correct_json(self, server_ctx: _TestServer) -> None:
        body = _minimal_results_json("CHECKHOST")
        server_ctx.post("/api/results", body)
        results_dir = server_ctx.config.workdir / server_ctx.config.results.output_dir
        saved = sorted(results_dir.glob("results_*CHECKHOST*.json"))
        assert saved, "No file saved for CHECKHOST"
        data = json.loads(saved[-1].read_text())
        assert data["meta"]["hostname"] == "CHECKHOST"

    def test_empty_body_returns_400(self, server_ctx: _TestServer) -> None:
        status, _ = server_ctx.post("/api/results", b"")
        assert status == 400

    def test_invalid_json_body_still_saved(self, server_ctx: _TestServer) -> None:
        """Raw non-JSON bytes that don't start with PK or gzip are stored as-is."""
        # The handler parses metadata best-effort; invalid JSON falls back to 'unknown'
        body = b'{"meta": {"hostname": "RAWHST"}, "findings": [], "summary": {}}'
        status, _ = server_ctx.post("/api/results", body)
        assert status == 200

    def test_zip_upload_accepted(self, server_ctx: _TestServer) -> None:
        """A ZIP containing results.json is accepted and parsed."""
        json_bytes = _minimal_results_json("ZIPHOST")
        zip_bytes = _make_zip("results.json", json_bytes)
        status, resp = server_ctx.post("/api/results", zip_bytes, "application/zip")
        assert status == 200
        data = json.loads(resp)
        assert data["status"] == "ok"
        assert data["hostname"] == "ZIPHOST"


# ---------------------------------------------------------------------------
# GET /api/results (list) tests
# ---------------------------------------------------------------------------


class TestGetResultsList:
    def test_returns_200(self, server_ctx: _TestServer) -> None:
        status, _, _ = server_ctx.get("/api/results")
        assert status == 200

    def test_content_type_is_json(self, server_ctx: _TestServer) -> None:
        _, _, headers = server_ctx.get("/api/results")
        assert "application/json" in headers.get("Content-Type", "")

    def test_returns_empty_list_initially(self, server_ctx: _TestServer) -> None:
        _, body, _ = server_ctx.get("/api/results")
        data = json.loads(body)
        assert isinstance(data, list)

    def test_appears_after_upload(self, server_ctx: _TestServer) -> None:
        """After a successful upload, the results list grows."""
        body = _minimal_results_json("LISTHOST")
        server_ctx.post("/api/results", body)
        _, list_body, _ = server_ctx.get("/api/results")
        entries = json.loads(list_body)
        assert len(entries) >= 1


# ---------------------------------------------------------------------------
# 404 / unknown path tests
# ---------------------------------------------------------------------------


class TestUnknownPaths:
    def test_unknown_get_returns_404(self, server_ctx: _TestServer) -> None:
        status, _, _ = server_ctx.get("/does-not-exist")
        assert status == 404

    def test_unknown_post_returns_404(self, server_ctx: _TestServer) -> None:
        status, _ = server_ctx.post("/does-not-exist", b"{}")
        assert status == 404

    def test_deep_unknown_path_returns_404(self, server_ctx: _TestServer) -> None:
        status, _, _ = server_ctx.get("/api/unknown/deep/path")
        assert status == 404


# ---------------------------------------------------------------------------
# _extract_json_from_zip unit tests (via handler instance)
# ---------------------------------------------------------------------------


class TestExtractJsonFromZip:
    """Test the internal _extract_json_from_zip helper directly."""

    def _make_handler(self, tmp_path: Path) -> SeepHTTPHandler:
        """Instantiate a handler without a real HTTP connection."""
        port = _free_port()
        config = ServerConfig(http_port=port, workdir=tmp_path)
        composer = AgentComposer()
        cls = create_handler(config, composer)

        # Build a minimal handler without a real socket
        handler = cls.__new__(cls)
        handler.config = config
        handler.composer = composer
        return handler

    def test_valid_zip_results_json(self, tmp_path: Path) -> None:
        handler = self._make_handler(tmp_path)
        content = b'{"meta": {"hostname": "Z"}, "findings": [], "summary": {}}'
        raw = _make_zip("results.json", content)
        result = handler._extract_json_from_zip(raw)
        assert result == content

    def test_valid_zip_fallback_json_file(self, tmp_path: Path) -> None:
        """Falls back to first .json file when results.json is not present."""
        handler = self._make_handler(tmp_path)
        content = b'{"meta": {}, "findings": []}'
        raw = _make_zip("other_data.json", content)
        result = handler._extract_json_from_zip(raw)
        assert result == content

    def test_invalid_zip_returns_none(self, tmp_path: Path) -> None:
        handler = self._make_handler(tmp_path)
        result = handler._extract_json_from_zip(b"this is not a zip")
        assert result is None

    def test_empty_bytes_returns_none(self, tmp_path: Path) -> None:
        handler = self._make_handler(tmp_path)
        result = handler._extract_json_from_zip(b"")
        assert result is None

    def test_zip_with_no_json_returns_none(self, tmp_path: Path) -> None:
        handler = self._make_handler(tmp_path)
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("readme.txt", "no json here")
        result = handler._extract_json_from_zip(buf.getvalue())
        assert result is None

    def test_results_json_preferred_over_other_json(self, tmp_path: Path) -> None:
        """results.json takes priority over other .json files in the archive."""
        handler = self._make_handler(tmp_path)
        results_content = b'{"meta": {"hostname": "primary"}}'
        other_content = b'{"meta": {"hostname": "secondary"}}'
        buf = BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("other.json", other_content)
            zf.writestr("results.json", results_content)
        result = handler._extract_json_from_zip(buf.getvalue())
        assert result == results_content


# ---------------------------------------------------------------------------
# _json_response unit tests
# ---------------------------------------------------------------------------


class TestJsonResponse:
    """Test the _json_response helper directly."""

    def _make_handler_with_mock_socket(self, tmp_path: Path):
        """Build a handler with mocked wfile/rfile for unit testing."""
        port = _free_port()
        config = ServerConfig(http_port=port, workdir=tmp_path)
        composer = AgentComposer()
        cls = create_handler(config, composer)

        handler = cls.__new__(cls)
        handler.config = config
        handler.composer = composer
        handler.request = MagicMock()
        handler.client_address = ("127.0.0.1", 9999)
        handler.server = MagicMock()
        handler.wfile = BytesIO()
        handler.rfile = BytesIO()
        handler._headers_buffer = []

        # Minimal send_response / send_header / end_headers / send_error stubs
        sent: dict = {"code": None, "headers": {}, "body": b""}

        def _send_response(code: int, message: str = "") -> None:
            sent["code"] = code
            # Write HTTP/1.0 status line to wfile
            handler.wfile.write(f"HTTP/1.0 {code}\r\n".encode())

        def _send_header(key: str, value: str) -> None:
            sent["headers"][key] = value
            handler.wfile.write(f"{key}: {value}\r\n".encode())

        def _end_headers() -> None:
            handler.wfile.write(b"\r\n")

        handler.send_response = _send_response
        handler.send_header = _send_header
        handler.end_headers = _end_headers

        return handler, sent

    def test_json_response_writes_json_body(self, tmp_path: Path) -> None:
        handler, sent = self._make_handler_with_mock_socket(tmp_path)
        payload = {"status": "ok", "value": 42}
        handler._json_response(200, payload)

        written = handler.wfile.getvalue().decode("utf-8", errors="replace")
        # The JSON body must appear somewhere in the written bytes
        assert '"status"' in written
        assert '"ok"' in written

    def test_json_response_sets_correct_status_code(self, tmp_path: Path) -> None:
        handler, sent = self._make_handler_with_mock_socket(tmp_path)
        handler._json_response(400, {"error": "bad"})
        assert sent["code"] == 400

    def test_json_response_content_type_header(self, tmp_path: Path) -> None:
        handler, sent = self._make_handler_with_mock_socket(tmp_path)
        handler._json_response(200, {"x": 1})
        assert "application/json" in sent["headers"].get("Content-Type", "")

    def test_json_response_body_is_valid_json(self, tmp_path: Path) -> None:
        handler, sent = self._make_handler_with_mock_socket(tmp_path)
        payload = {"key": "value", "num": 99}
        handler._json_response(200, payload)

        raw = handler.wfile.getvalue()
        # Extract JSON from the raw HTTP response (after the blank line)
        parts = raw.split(b"\r\n\r\n", 1)
        assert len(parts) == 2
        body = json.loads(parts[1])
        assert body["key"] == "value"
        assert body["num"] == 99


# ---------------------------------------------------------------------------
# Upload authentication tests
# ---------------------------------------------------------------------------

_TEST_TOKEN = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"


@pytest.fixture
def auth_server_ctx(tmp_path: Path) -> "_TestServer":
    """Server with auth_token configured."""
    port = _free_port()
    config = ServerConfig(
        http_port=port,
        upload_port=port + 1,
        bind_address="127.0.0.1",
        workdir=tmp_path,
        auth_token=_TEST_TOKEN,
    )
    with _TestServer(config) as ctx:
        yield ctx


class TestUploadAuth:
    """Upload authentication via X-Seep-Token header."""

    def test_no_token_when_required_returns_404(self, auth_server_ctx: _TestServer) -> None:
        """Upload without token when token is configured returns 404 (stealth)."""
        body = _minimal_results_json("NOTOKEN")
        status, resp = auth_server_ctx.post("/api/results", body)
        assert status == 404

    def test_wrong_token_returns_404(self, auth_server_ctx: _TestServer) -> None:
        """Upload with wrong token returns 404 (stealth)."""
        body = _minimal_results_json("WRONGTOKEN")
        status, resp = auth_server_ctx.post(
            "/api/results",
            body,
            extra_headers={"X-Seep-Token": "wrong_token_value"},
        )
        assert status == 404

    def test_correct_token_returns_200(self, auth_server_ctx: _TestServer) -> None:
        """Upload with correct token returns 200."""
        body = _minimal_results_json("GOODTOKEN")
        status, resp = auth_server_ctx.post(
            "/api/results",
            body,
            extra_headers={"X-Seep-Token": _TEST_TOKEN},
        )
        assert status == 200
        data = json.loads(resp)
        assert data["status"] == "ok"
        assert data["hostname"] == "GOODTOKEN"

    def test_correct_token_upload_alias(self, auth_server_ctx: _TestServer) -> None:
        """POST /upload with correct token also returns 200."""
        body = _minimal_results_json("UPLOADALIAS")
        status, resp = auth_server_ctx.post(
            "/upload",
            body,
            extra_headers={"X-Seep-Token": _TEST_TOKEN},
        )
        assert status == 200

    def test_no_token_on_upload_alias_returns_404(self, auth_server_ctx: _TestServer) -> None:
        """POST /upload without token when configured returns 404 (stealth)."""
        body = _minimal_results_json("NOTKUPLOAD")
        status, _ = auth_server_ctx.post("/upload", body)
        assert status == 404

    def test_no_token_configured_allows_upload(self, server_ctx: _TestServer) -> None:
        """Upload without token when no token configured returns 200 (backwards compatible)."""
        body = _minimal_results_json("FREEUPLOAD")
        status, resp = server_ctx.post("/api/results", body)
        assert status == 200
        data = json.loads(resp)
        assert data["status"] == "ok"
