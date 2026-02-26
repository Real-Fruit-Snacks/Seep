"""Integration tests for the Seep HTTP server.

Starts a real server on a random free port and exercises all HTTP endpoints
end-to-end using only stdlib (urllib.request).  No external dependencies.
"""

from __future__ import annotations

import gzip
import json
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
from server.http.serve import create_handler


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Bind to port 0 and return the OS-assigned free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LiveServer:
    """Start an HTTPServer in a background thread and expose helper methods."""

    def __init__(self, workdir: Path) -> None:
        port = _free_port()
        self.config = ServerConfig(
            http_port=port,
            upload_port=port + 1,
            bind_address="127.0.0.1",
            workdir=workdir,
        )
        self.composer = AgentComposer()
        handler_cls = create_handler(self.config, self.composer)
        self.server = HTTPServer(("127.0.0.1", port), handler_cls)
        self.port = port
        self._thread: threading.Thread | None = None

    # -- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()
        # Wait until the socket is actually accepting connections
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.2):
                    return
            except OSError:
                time.sleep(0.02)
        raise RuntimeError(f"Server on port {self.port} did not start in time")

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        if self._thread:
            self._thread.join(timeout=5)

    # -- HTTP helpers --------------------------------------------------------

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.port}{path}"

    def get(self, path: str) -> tuple[int, bytes, dict]:
        """GET *path*.  Returns (status_code, body_bytes, headers_dict)."""
        req = urllib.request.Request(self.url(path))
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), {}

    def post(
        self,
        path: str,
        body: bytes,
        content_type: str = "application/json",
    ) -> tuple[int, bytes, dict]:
        """POST *body* to *path*.  Returns (status_code, body_bytes, headers_dict)."""
        req = urllib.request.Request(
            self.url(path),
            data=body,
            method="POST",
            headers={
                "Content-Type": content_type,
                "Content-Length": str(len(body)),
            },
        )
        try:
            with urllib.request.urlopen(req) as resp:
                return resp.status, resp.read(), dict(resp.headers)
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read(), {}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def live_server(tmp_path_factory: pytest.TempPathFactory):
    """Module-scoped live server — one server for the whole integration module."""
    workdir = tmp_path_factory.mktemp("integration_workspace")
    srv = LiveServer(workdir)
    srv.start()
    yield srv
    srv.stop()


# ---------------------------------------------------------------------------
# Test 1 — server startup / connectivity
# ---------------------------------------------------------------------------


class TestServerStartup:
    def test_server_is_listening(self, live_server: LiveServer) -> None:
        """Server must accept TCP connections on the chosen port."""
        with socket.create_connection(("127.0.0.1", live_server.port), timeout=2):
            pass  # connection established — server is alive


# ---------------------------------------------------------------------------
# Test 2 — GET /  (index page)
# ---------------------------------------------------------------------------


class TestIndexEndpoint:
    def test_returns_200(self, live_server: LiveServer) -> None:
        status, _, _ = live_server.get("/")
        assert status == 200

    def test_content_type_html(self, live_server: LiveServer) -> None:
        _, _, headers = live_server.get("/")
        assert "text/html" in headers.get("Content-Type", "")

    def test_body_contains_dark_theme_css(self, live_server: LiveServer) -> None:
        """Index page uses the dark CSS theme (--bg variable)."""
        _, body, _ = live_server.get("/")
        text = body.decode("utf-8", errors="replace")
        assert "--bg" in text, "Expected dark-theme CSS variable --bg in response"

    def test_body_contains_seep(self, live_server: LiveServer) -> None:
        _, body, _ = live_server.get("/")
        text = body.decode("utf-8", errors="replace")
        assert "SEEP" in text or "Seep" in text

    def test_body_contains_endpoints_section(self, live_server: LiveServer) -> None:
        """Index lists the /agent.ps1 endpoint."""
        _, body, _ = live_server.get("/")
        assert b"/agent.ps1" in body

    def test_index_html_alias(self, live_server: LiveServer) -> None:
        """GET /index.html also returns 200."""
        status, _, _ = live_server.get("/index.html")
        assert status == 200


# ---------------------------------------------------------------------------
# Test 3 — GET /agent.ps1
# ---------------------------------------------------------------------------


class TestAgentEndpoint:
    def test_returns_200(self, live_server: LiveServer) -> None:
        status, _, _ = live_server.get("/agent.ps1")
        assert status == 200

    def test_content_type_text_plain(self, live_server: LiveServer) -> None:
        _, _, headers = live_server.get("/agent.ps1")
        assert "text/plain" in headers.get("Content-Type", "")

    def test_body_contains_invoke_seep(self, live_server: LiveServer) -> None:
        _, body, _ = live_server.get("/agent.ps1")
        assert b"Invoke-Seep" in body

    def test_alternate_url_seep_ps1(self, live_server: LiveServer) -> None:
        """/Seep.ps1 is an alias for the agent."""
        status, body, _ = live_server.get("/Seep.ps1")
        assert status == 200
        assert b"Invoke-Seep" in body


# ---------------------------------------------------------------------------
# Test 4 — GET /agent.ps1?checks=system_info,network  (filtered agent)
# ---------------------------------------------------------------------------


class TestAgentFilteredEndpoint:
    def test_checks_param_returns_200(self, live_server: LiveServer) -> None:
        status, _, _ = live_server.get("/agent.ps1?checks=system_info,network")
        assert status == 200

    def test_checks_param_returns_powershell(self, live_server: LiveServer) -> None:
        """Filtered agent is still valid PowerShell (contains Invoke-Seep)."""
        _, body, _ = live_server.get("/agent.ps1?checks=system_info,network")
        assert b"Invoke-Seep" in body

    def test_exclude_param_returns_200(self, live_server: LiveServer) -> None:
        status, _, _ = live_server.get("/agent.ps1?exclude=patches")
        assert status == 200

    def test_filtered_and_full_agents_can_differ(self, live_server: LiveServer) -> None:
        """Filtered agent content may differ from the full agent (or at least both work)."""
        _, full_body, _ = live_server.get("/agent.ps1")
        _, filtered_body, _ = live_server.get("/agent.ps1?checks=system_info")
        # Both are valid PowerShell content — filtered may be shorter
        assert b"Invoke-Seep" in full_body
        assert b"Invoke-Seep" in filtered_body


# ---------------------------------------------------------------------------
# Test 5 — GET /cradle
# ---------------------------------------------------------------------------


class TestCradleEndpoint:
    def test_returns_200(self, live_server: LiveServer) -> None:
        status, _, _ = live_server.get("/cradle")
        assert status == 200

    def test_content_type_text(self, live_server: LiveServer) -> None:
        _, _, headers = live_server.get("/cradle")
        assert "text/plain" in headers.get("Content-Type", "")

    def test_body_contains_powershell(self, live_server: LiveServer) -> None:
        _, body, _ = live_server.get("/cradle")
        text = body.decode("utf-8", errors="replace").lower()
        assert "powershell" in text

    def test_body_contains_invoke_seep(self, live_server: LiveServer) -> None:
        _, body, _ = live_server.get("/cradle")
        assert b"Invoke-Seep" in body


# ---------------------------------------------------------------------------
# Test 6 — POST /api/results  (plain JSON upload)
# ---------------------------------------------------------------------------

_SAMPLE_RESULTS = {
    "meta": {
        "hostname": "INTEG-HOST",
        "username": "integtester",
        "domain": "CORP.LOCAL",
        "os_version": "10.0.19045",
    },
    "findings": [
        {
            "check_id": "user_privileges",
            "finding_id": "se_impersonate_enabled",
            "severity": "critical",
            "title": "SeImpersonatePrivilege Enabled",
            "tags": ["token", "potato"],
        },
        {
            "check_id": "system_info",
            "finding_id": "system_info_raw",
            "severity": "info",
            "title": "System Information",
            "tags": ["context"],
        },
    ],
    "summary": {"total_findings": 2},
}


class TestPostResultsJson:
    def test_returns_200(self, live_server: LiveServer) -> None:
        body = json.dumps(_SAMPLE_RESULTS).encode()
        status, _, _ = live_server.post("/api/results", body)
        assert status == 200

    def test_response_contains_hostname(self, live_server: LiveServer) -> None:
        body = json.dumps(_SAMPLE_RESULTS).encode()
        _, resp_body, _ = live_server.post("/api/results", body)
        resp = json.loads(resp_body)
        assert resp["hostname"] == "INTEG-HOST"

    def test_response_status_ok(self, live_server: LiveServer) -> None:
        body = json.dumps(_SAMPLE_RESULTS).encode()
        _, resp_body, _ = live_server.post("/api/results", body)
        resp = json.loads(resp_body)
        assert resp["status"] == "ok"

    def test_response_findings_count(self, live_server: LiveServer) -> None:
        body = json.dumps(_SAMPLE_RESULTS).encode()
        _, resp_body, _ = live_server.post("/api/results", body)
        resp = json.loads(resp_body)
        assert resp["findings_count"] == 2

    def test_file_saved_to_disk(self, live_server: LiveServer) -> None:
        body = json.dumps(_SAMPLE_RESULTS).encode()
        live_server.post("/api/results", body)
        results_dir = live_server.config.workdir / live_server.config.results.output_dir
        saved = list(results_dir.glob("results_*.json"))
        assert len(saved) >= 1


# ---------------------------------------------------------------------------
# Test 7 — POST /api/results  (gzip-compressed upload)
# ---------------------------------------------------------------------------


class TestPostResultsGzip:
    def test_gzip_upload_returns_200(self, live_server: LiveServer) -> None:
        raw = json.dumps(_SAMPLE_RESULTS).encode()
        buf = gzip.compress(raw)
        status, _, _ = live_server.post(
            "/api/results", buf, content_type="application/octet-stream"
        )
        assert status == 200

    def test_gzip_upload_response_hostname(self, live_server: LiveServer) -> None:
        raw = json.dumps(_SAMPLE_RESULTS).encode()
        buf = gzip.compress(raw)
        _, resp_body, _ = live_server.post(
            "/api/results", buf, content_type="application/octet-stream"
        )
        resp = json.loads(resp_body)
        assert resp["hostname"] == "INTEG-HOST"

    def test_gzip_upload_saves_file(self, live_server: LiveServer) -> None:
        raw = json.dumps(_SAMPLE_RESULTS).encode()
        buf = gzip.compress(raw)
        live_server.post("/api/results", buf, content_type="application/octet-stream")
        results_dir = live_server.config.workdir / live_server.config.results.output_dir
        saved = list(results_dir.glob("results_*.json"))
        assert len(saved) >= 1


# ---------------------------------------------------------------------------
# Test 8 — GET /api/results  (list uploaded results)
# ---------------------------------------------------------------------------


class TestGetResultsList:
    def test_returns_200(self, live_server: LiveServer) -> None:
        status, _, _ = live_server.get("/api/results")
        assert status == 200

    def test_content_type_json(self, live_server: LiveServer) -> None:
        _, _, headers = live_server.get("/api/results")
        assert "application/json" in headers.get("Content-Type", "")

    def test_returns_list(self, live_server: LiveServer) -> None:
        _, body, _ = live_server.get("/api/results")
        data = json.loads(body)
        assert isinstance(data, list)

    def test_list_has_entries_after_upload(self, live_server: LiveServer) -> None:
        """After at least one upload, the results list must be non-empty."""
        # Ensure at least one result exists (prior tests may have uploaded)
        payload = json.dumps(_SAMPLE_RESULTS).encode()
        live_server.post("/api/results", payload)

        _, body, _ = live_server.get("/api/results")
        data = json.loads(body)
        assert len(data) >= 1

    def test_list_entries_have_expected_fields(self, live_server: LiveServer) -> None:
        """Each entry in the results list has filename, hostname, timestamp fields."""
        payload = json.dumps(_SAMPLE_RESULTS).encode()
        live_server.post("/api/results", payload)

        _, body, _ = live_server.get("/api/results")
        data = json.loads(body)
        assert len(data) >= 1
        entry = data[0]
        assert "filename" in entry
        assert "hostname" in entry
        assert "timestamp" in entry
        assert "findings_count" in entry


# ---------------------------------------------------------------------------
# Test 9 — unknown path returns 404
# ---------------------------------------------------------------------------


class TestNotFound:
    def test_unknown_path_returns_404(self, live_server: LiveServer) -> None:
        status, _, _ = live_server.get("/this-path-does-not-exist")
        assert status == 404

    def test_another_unknown_path(self, live_server: LiveServer) -> None:
        status, _, _ = live_server.get("/api/nonexistent")
        assert status == 404

    def test_post_unknown_path_returns_404(self, live_server: LiveServer) -> None:
        status, _, _ = live_server.post("/api/notaroute", b"{}")
        assert status == 404


# ---------------------------------------------------------------------------
# Test 10 — POST /api/results with empty body → 400
# ---------------------------------------------------------------------------


class TestEmptyUpload:
    def test_empty_body_returns_400(self, live_server: LiveServer) -> None:
        status, _, _ = live_server.post("/api/results", b"")
        assert status == 400

    def test_empty_body_response_contains_error(self, live_server: LiveServer) -> None:
        _, body, _ = live_server.post("/api/results", b"")
        resp = json.loads(body)
        assert resp.get("status") == "error"


# ---------------------------------------------------------------------------
# Test 11 — full end-to-end workflow
# ---------------------------------------------------------------------------


class TestFullWorkflow:
    """Start server → get agent → upload results → list results → verify count."""

    def test_full_workflow(self, tmp_path: Path) -> None:
        # Fresh server with isolated workdir for this workflow test
        srv = LiveServer(tmp_path)
        srv.start()

        try:
            # Step 1: server is reachable
            with socket.create_connection(("127.0.0.1", srv.port), timeout=2):
                pass

            # Step 2: download the agent
            status, agent_body, _ = srv.get("/agent.ps1")
            assert status == 200, f"Agent download failed: {status}"
            assert b"Invoke-Seep" in agent_body, "Agent missing Invoke-Seep function"

            # Step 3: upload results (simulate what the agent would send)
            results_payload = {
                "meta": {
                    "hostname": "WORKFLOW-HOST",
                    "username": "wf_user",
                    "domain": "",
                    "os_version": "10.0",
                },
                "findings": [
                    {
                        "check_id": "quick_wins",
                        "finding_id": "autologon_credentials",
                        "severity": "critical",
                        "title": "AutoLogon Credentials Found",
                        "tags": ["credentials"],
                    }
                ],
                "summary": {"total_findings": 1},
            }
            upload_body = json.dumps(results_payload).encode()
            status, resp_body, _ = srv.post("/api/results", upload_body)
            assert status == 200, f"Upload failed: {status} — {resp_body.decode()}"

            upload_resp = json.loads(resp_body)
            assert upload_resp["status"] == "ok"
            assert upload_resp["hostname"] == "WORKFLOW-HOST"
            assert upload_resp["findings_count"] == 1

            # Step 4: list results — must contain our uploaded result
            status, list_body, _ = srv.get("/api/results")
            assert status == 200, f"Results list failed: {status}"
            results_list = json.loads(list_body)
            assert isinstance(results_list, list)
            assert len(results_list) >= 1, "Expected at least 1 result after upload"

            # Step 5: verify the uploaded entry is in the list
            hostnames = [r.get("hostname") for r in results_list]
            assert "WORKFLOW-HOST" in hostnames, (
                f"Uploaded host not found in results list: {hostnames}"
            )

            # Step 6: verify file was written to disk
            results_dir = srv.config.workdir / srv.config.results.output_dir
            saved_files = list(results_dir.glob("results_*.json"))
            assert len(saved_files) == 1, (
                f"Expected 1 saved file, found {len(saved_files)}"
            )

        finally:
            srv.stop()
