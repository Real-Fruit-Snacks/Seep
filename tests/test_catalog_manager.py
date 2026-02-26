"""Tests for CatalogManager — verify, symlinks, download results."""

from __future__ import annotations

import hashlib
from pathlib import Path


from server.catalog.manager import (
    CatalogManager,
    DownloadResult,
    VerifyResult,
    VerifyReport,
)
from server.catalog.schemas import ToolCatalog


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _make_tool(catalog: ToolCatalog):
    """Return the first tool entry from the catalog."""
    return catalog.tools[0]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_verify_all_empty_dir(catalog: ToolCatalog, tmp_path: Path) -> None:
    """With an empty tools directory, all 93 tools are reported missing."""
    manager = CatalogManager(catalog, tools_dir=tmp_path)
    report = manager.verify_all()
    assert len(report.missing) == 93
    assert len(report.ok) == 0
    assert len(report.corrupted) == 0


def test_verify_tool_missing(catalog: ToolCatalog, tmp_path: Path) -> None:
    """verify_tool returns status='missing' when the file does not exist."""
    manager = CatalogManager(catalog, tools_dir=tmp_path)
    tool = _make_tool(catalog)
    result = manager.verify_tool(tool)
    assert result.status == "missing"
    assert result.path is None
    assert result.tool_name == tool.name


def test_verify_tool_ok(catalog: ToolCatalog, tmp_path: Path) -> None:
    """verify_tool returns status='ok' when the file matches its SHA256."""
    tool = _make_tool(catalog)
    # Place a file whose hash matches the catalog entry
    content = b"fake-tool-content"
    real_hash = _sha256(content)

    # Clone the tool entry with our known hash so we can control it
    from dataclasses import replace as dc_replace

    tool_with_hash = dc_replace(tool, sha256=real_hash)

    dest_dir = tmp_path / tool_with_hash.folder
    dest_dir.mkdir(parents=True, exist_ok=True)
    (dest_dir / tool_with_hash.name).write_bytes(content)

    # Build a minimal catalog that includes only our patched tool
    from server.catalog.schemas import ToolCatalog as TC

    mini_catalog = TC(
        version=catalog.version,
        release_base_url=catalog.release_base_url,
        tools_release=catalog.tools_release,
        tools=[tool_with_hash],
        categories=catalog.categories,
    )
    manager = CatalogManager(mini_catalog, tools_dir=tmp_path)
    result = manager.verify_tool(tool_with_hash)
    assert result.status == "ok"
    assert result.path is not None


def test_verify_tool_corrupted(catalog: ToolCatalog, tmp_path: Path) -> None:
    """verify_tool returns status='corrupted' when the file hash does not match."""
    tool = _make_tool(catalog)
    from dataclasses import replace as dc_replace

    tool_with_hash = dc_replace(tool, sha256="a" * 64)  # known-wrong hash

    dest_dir = tmp_path / tool_with_hash.folder
    dest_dir.mkdir(parents=True, exist_ok=True)
    (dest_dir / tool_with_hash.name).write_bytes(b"wrong content")

    from server.catalog.schemas import ToolCatalog as TC

    mini_catalog = TC(
        version=catalog.version,
        release_base_url=catalog.release_base_url,
        tools_release=catalog.tools_release,
        tools=[tool_with_hash],
        categories=catalog.categories,
    )
    manager = CatalogManager(mini_catalog, tools_dir=tmp_path)
    result = manager.verify_tool(tool_with_hash)
    assert result.status == "corrupted"
    assert result.actual_sha256 != result.expected_sha256


def test_setup_symlinks(catalog: ToolCatalog, tmp_path: Path) -> None:
    """setup_symlinks creates symlinks in all/ and in each category dir."""
    tool = _make_tool(catalog)
    content = b"binary payload"

    dest_dir = tmp_path / tool.folder
    dest_dir.mkdir(parents=True, exist_ok=True)
    (dest_dir / tool.name).write_bytes(content)

    manager = CatalogManager(catalog, tools_dir=tmp_path)
    manager.setup_symlinks(tool)

    # Check all/ symlink
    all_link = tmp_path / "all" / tool.name
    assert all_link.exists() or all_link.is_symlink(), "all/ symlink should exist"
    assert all_link.read_bytes() == content

    # Check at least one category symlink
    for category in tool.categories:
        cat_link = tmp_path / "categories" / category / tool.name
        assert cat_link.exists() or cat_link.is_symlink(), (
            f"categories/{category}/ symlink should exist"
        )


def test_download_result_dataclass() -> None:
    """DownloadResult can be constructed and its fields are accessible."""
    dr = DownloadResult(
        tool_name="test.exe",
        success=True,
        path=Path("/tmp/test.exe"),
        sha256_verified=True,
        error=None,
        size_bytes=1024,
    )
    assert dr.tool_name == "test.exe"
    assert dr.success is True
    assert dr.sha256_verified is True
    assert dr.error is None
    assert dr.size_bytes == 1024


def test_verify_result_dataclass() -> None:
    """VerifyResult can be constructed and its fields are accessible."""
    vr = VerifyResult(
        tool_name="test.exe",
        status="ok",
        expected_sha256="abc",
        actual_sha256="abc",
        path=Path("/tmp/test.exe"),
    )
    assert vr.status == "ok"
    assert vr.expected_sha256 == vr.actual_sha256


def test_verify_report_dataclass() -> None:
    """VerifyReport initialises with empty lists."""
    report = VerifyReport()
    assert report.ok == []
    assert report.missing == []
    assert report.corrupted == []
    assert report.unrecognized == []


def test_check_updates_no_network(catalog: ToolCatalog, tmp_path: Path) -> None:
    """check_updates returns None gracefully when network is unavailable."""
    manager = CatalogManager(catalog, tools_dir=tmp_path)
    # Use a non-routable address to guarantee network failure
    result = manager.check_updates("192.0.2.1/nonexistent-repo")
    assert result is None
