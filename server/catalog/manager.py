"""Download manager for fetching tools from GitHub Releases with SHA256 verification."""

from __future__ import annotations

import hashlib
import json
import os
import re
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

from .schemas import ToolCatalog, ToolEntry

_USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
_CONNECT_TIMEOUT = 30
_READ_TIMEOUT = 120


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------


@dataclass
class DownloadResult:
    tool_name: str
    success: bool
    path: Path | None
    sha256_verified: bool
    error: str | None
    size_bytes: int


@dataclass
class VerifyResult:
    tool_name: str
    status: str  # "ok" | "missing" | "corrupted" | "no_hash"
    expected_sha256: str
    actual_sha256: str
    path: Path | None


@dataclass
class VerifyReport:
    ok: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    corrupted: list[tuple[str, str, str]] = field(
        default_factory=list
    )  # (name, expected, actual)
    unrecognized: list[str] = field(default_factory=list)
    no_hash: list[str] = field(default_factory=list)


@dataclass
class UpdateCheckResult:
    current_release: str
    latest_release: str
    update_available: bool
    release_url: str


# ---------------------------------------------------------------------------
# CatalogManager
# ---------------------------------------------------------------------------


class CatalogManager:
    def __init__(
        self,
        catalog: ToolCatalog,
        tools_dir: Path,
        verify: bool = True,
    ) -> None:
        self.catalog = catalog
        self.tools_dir = tools_dir
        self.verify = verify
        self._print_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def download_tool(self, tool: ToolEntry, progress_callback=None) -> DownloadResult:
        """Download a single tool from GitHub Releases. Returns DownloadResult."""
        _validate_path_component(tool.folder, "tool.folder")
        _validate_path_component(tool.name, "tool.name")
        url = self.catalog.get_tool_url(tool)
        dest_dir = self.tools_dir / tool.folder
        dest_dir.mkdir(parents=True, exist_ok=True)
        dest_path = dest_dir / tool.name
        # Guard against symlink/TOCTOU tricks: resolved path must stay inside tools_dir
        try:
            dest_path.resolve().relative_to(self.tools_dir.resolve())
        except ValueError:
            return DownloadResult(
                tool_name=tool.name,
                success=False,
                path=None,
                sha256_verified=False,
                error=f"Path traversal detected: {dest_path} escapes tools_dir",
                size_bytes=0,
            )

        try:
            size_bytes = self._fetch_file(url, dest_path)
        except urllib.error.HTTPError as exc:
            return DownloadResult(
                tool_name=tool.name,
                success=False,
                path=None,
                sha256_verified=False,
                error=f"HTTP {exc.code}: {exc.reason} — {url}",
                size_bytes=0,
            )
        except urllib.error.URLError as exc:
            return DownloadResult(
                tool_name=tool.name,
                success=False,
                path=None,
                sha256_verified=False,
                error=f"URL error: {exc.reason}",
                size_bytes=0,
            )
        except OSError as exc:
            return DownloadResult(
                tool_name=tool.name,
                success=False,
                path=None,
                sha256_verified=False,
                error=f"I/O error: {exc}",
                size_bytes=0,
            )

        # SHA256 verification
        sha256_verified = False
        if self.verify and tool.sha256:
            actual = _sha256_file(dest_path)
            if actual != tool.sha256.lower():
                dest_path.unlink(missing_ok=True)
                return DownloadResult(
                    tool_name=tool.name,
                    success=False,
                    path=None,
                    sha256_verified=False,
                    error=(f"SHA256 mismatch — expected {tool.sha256}, got {actual}"),
                    size_bytes=size_bytes,
                )
            sha256_verified = True

        # Symlinks
        try:
            self.setup_symlinks(tool)
        except OSError as exc:
            # Non-fatal — log but don't fail the download
            self._print(f"  [warn] symlink setup failed for {tool.name}: {exc}")

        if progress_callback is not None:
            try:
                progress_callback(tool.name, size_bytes)
            except Exception as exc:
                self._print(f"  [warn] progress callback error for {tool.name}: {exc}")

        return DownloadResult(
            tool_name=tool.name,
            success=True,
            path=dest_path,
            sha256_verified=sha256_verified,
            error=None,
            size_bytes=size_bytes,
        )

    def download_tools(
        self,
        tools: list[ToolEntry],
        max_workers: int = 4,
    ) -> list[DownloadResult]:
        """Download multiple tools concurrently. Prints progress as each completes."""
        total = len(tools)
        completed_count = 0
        results: list[DownloadResult] = []
        count_lock = threading.Lock()

        def _progress(tool_name: str, size_bytes: int) -> None:
            nonlocal completed_count
            with count_lock:
                completed_count += 1
                n = completed_count
            kb = size_bytes / 1024
            self._print(f"  [{n}/{total}] {tool_name} ({kb:.0f} KB)")

        self._print(f"Downloading {total} tool(s) with {max_workers} worker(s)...")

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_tool = {
                executor.submit(self.download_tool, tool, _progress): tool
                for tool in tools
            }
            for future in as_completed(future_to_tool):
                result = future.result()
                results.append(result)
                if not result.success:
                    self._print(f"  [FAIL] {result.tool_name}: {result.error}")

        ok = sum(1 for r in results if r.success)
        self._print(f"Download complete: {ok}/{total} succeeded.")
        return results

    def verify_tool(self, tool: ToolEntry) -> VerifyResult:
        """Verify SHA256 of a single downloaded tool."""
        _validate_path_component(tool.folder, "tool.folder")
        _validate_path_component(tool.name, "tool.name")
        dest_path = self.tools_dir / tool.folder / tool.name

        if not dest_path.exists():
            return VerifyResult(
                tool_name=tool.name,
                status="missing",
                expected_sha256=tool.sha256,
                actual_sha256="",
                path=None,
            )

        if not tool.sha256:
            return VerifyResult(
                tool_name=tool.name,
                status="no_hash",
                expected_sha256="",
                actual_sha256=_sha256_file(dest_path),
                path=dest_path,
            )

        actual = _sha256_file(dest_path)
        status = "ok" if actual == tool.sha256.lower() else "corrupted"
        return VerifyResult(
            tool_name=tool.name,
            status=status,
            expected_sha256=tool.sha256.lower(),
            actual_sha256=actual,
            path=dest_path,
        )

    def verify_all(self) -> VerifyReport:
        """Verify all downloaded tools. Returns a summary report."""
        report = VerifyReport()

        # Index tools by (folder/name) for unrecognized detection
        known_paths: set[Path] = set()
        tool_by_name: dict[str, ToolEntry] = {}
        for tool in self.catalog.tools:
            known_paths.add((self.tools_dir / tool.folder / tool.name).resolve())
            tool_by_name[tool.name] = tool

        for tool in self.catalog.tools:
            result = self.verify_tool(tool)
            if result.status == "ok":
                report.ok.append(tool.name)
            elif result.status == "no_hash":
                report.no_hash.append(tool.name)
            elif result.status == "missing":
                report.missing.append(tool.name)
            elif result.status == "corrupted":
                report.corrupted.append(
                    (tool.name, result.expected_sha256, result.actual_sha256)
                )

        # Walk tools_dir for files not in the catalog
        if self.tools_dir.exists():
            for p in self.tools_dir.rglob("*"):
                if (
                    p.is_file()
                    and not p.is_symlink()
                    and p.resolve() not in known_paths
                ):
                    report.unrecognized.append(str(p.relative_to(self.tools_dir)))

        return report

    def setup_symlinks(self, tool: ToolEntry) -> None:
        """Create relative symlinks in all/ and each category dir for a downloaded tool."""
        _validate_path_component(tool.folder, "tool.folder")
        _validate_path_component(tool.name, "tool.name")
        source = self.tools_dir / tool.folder / tool.name
        if not source.exists():
            return

        # Symlink in all/
        all_dir = self.tools_dir / "all"
        all_dir.mkdir(parents=True, exist_ok=True)
        all_link = all_dir / tool.name
        _create_relative_symlink(source, all_link)

        # Symlink in each category dir the tool belongs to
        for category in tool.categories:
            _validate_path_component(category, "tool.category")
            cat_dir = self.tools_dir / "categories" / category
            cat_dir.mkdir(parents=True, exist_ok=True)
            cat_link = cat_dir / tool.name
            _create_relative_symlink(source, cat_link)

    _GITHUB_REPO_RE = re.compile(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$")

    def check_updates(self, github_repo: str) -> UpdateCheckResult | None:
        """Check GitHub Releases API for a newer tools release.

        Returns None if the check cannot be completed (network error, auth, etc.).
        """
        if not self._GITHUB_REPO_RE.match(github_repo):
            raise ValueError(
                f"github_repo must be in 'org/repo' format, got: {github_repo!r}"
            )
        api_url = f"https://api.github.com/repos/{github_repo}/releases/latest"
        req = urllib.request.Request(
            api_url,
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "application/vnd.github+json",
            },
        )
        try:
            ctx = _ssl_context()
            with urllib.request.urlopen(
                req,
                timeout=_CONNECT_TIMEOUT,
                context=ctx,
            ) as resp:
                body = resp.read()
        except urllib.error.HTTPError as exc:
            self._print(f"[warn] GitHub API returned HTTP {exc.code}: {exc.reason}")
            return None
        except urllib.error.URLError as exc:
            self._print(f"[warn] GitHub API unreachable: {exc.reason}")
            return None
        except OSError as exc:
            self._print(f"[warn] GitHub API error: {exc}")
            return None

        try:
            data = json.loads(body)
        except json.JSONDecodeError as exc:
            self._print(f"[warn] Could not parse GitHub API response: {exc}")
            return None

        latest_tag = data.get("tag_name", "")
        release_url = data.get("html_url", "")
        current = self.catalog.tools_release

        return UpdateCheckResult(
            current_release=current,
            latest_release=latest_tag,
            update_available=bool(latest_tag and latest_tag != current),
            release_url=release_url,
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _print(self, msg: str) -> None:
        with self._print_lock:
            print(msg)

    def _fetch_file(self, url: str, dest: Path) -> int:
        """Stream-download url to dest. Returns bytes written. Raises on error."""
        req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
        ctx = _ssl_context()
        with urllib.request.urlopen(
            req,
            timeout=_READ_TIMEOUT,
            context=ctx,
        ) as resp:
            chunk_size = 64 * 1024
            total = 0
            with open(dest, "wb") as fh:
                while True:
                    chunk = resp.read(chunk_size)
                    if not chunk:
                        break
                    fh.write(chunk)
                    total += len(chunk)
        return total


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------


def _sha256_file(path: Path) -> str:
    """Return lowercase hex SHA256 of a file."""
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _create_relative_symlink(source: Path, link: Path) -> None:
    """Create (or replace) a relative symlink at *link* pointing at *source*."""
    if link.exists() or link.is_symlink():
        link.unlink()
    rel_target = os.path.relpath(source, link.parent)
    link.symlink_to(rel_target)


def _ssl_context():
    """Return a default SSL context, or None to let urllib use its default."""
    try:
        import ssl

        return ssl.create_default_context()
    except ImportError:
        return None


_SAFE_COMPONENT_RE = re.compile(r'^[^/\\<>:"|?*\x00]+$')


def _validate_path_component(value: str, label: str) -> None:
    """Raise ValueError if *value* is not a safe single path component.

    Rejects strings that contain path separators, null bytes, or directory
    traversal sequences (``..``).  This prevents a malicious catalog YAML
    from writing files outside the tools directory.
    """
    if not value:
        raise ValueError(f"{label} must not be empty")
    if ".." in value:
        raise ValueError(f"{label} contains directory traversal sequence: {value!r}")
    if not _SAFE_COMPONENT_RE.match(value):
        raise ValueError(f"{label} contains invalid characters: {value!r}")
