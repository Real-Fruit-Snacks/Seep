"""Tests for CatalogLoader and ToolCatalog search/filter methods."""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from server.catalog.loader import CatalogLoadError, CatalogLoader
from server.catalog.schemas import ToolCatalog


def test_load_catalog(catalog: ToolCatalog) -> None:
    """Catalog loads successfully with 106 tools and 7 categories."""
    assert len(catalog.tools) == 106
    assert len(catalog.categories) == 7


def test_catalog_search_potato(catalog: ToolCatalog) -> None:
    """search('potato') returns at least 5 results."""
    results = catalog.search("potato")
    assert len(results) >= 5


def test_catalog_search_mimikatz(catalog: ToolCatalog) -> None:
    """search('mimikatz') returns at least 1 result."""
    results = catalog.search("mimikatz")
    assert len(results) >= 1
    names = [t.name.lower() for t in results]
    assert any("mimikatz" in n for n in names)


def test_catalog_get_by_category_token_abuse(catalog: ToolCatalog) -> None:
    """TokenAbuse category contains at least 8 tools."""
    tools = catalog.get_by_category("TokenAbuse")
    assert len(tools) >= 8


def test_catalog_get_by_category_all_non_empty(catalog: ToolCatalog) -> None:
    """Every defined category returns at least one tool."""
    for cat_name in catalog.categories:
        tools = catalog.get_by_category(cat_name)
        assert len(tools) > 0, f"Category '{cat_name}' returned no tools"


def test_catalog_get_by_platform_windows(catalog: ToolCatalog) -> None:
    """Windows-platform tools exist in the catalog."""
    windows_tools = catalog.get_by_platform("windows")
    assert len(windows_tools) > 0


def test_catalog_get_by_platform_linux(catalog: ToolCatalog) -> None:
    """Linux-platform tools exist in the catalog."""
    linux_tools = catalog.get_by_platform("linux")
    assert len(linux_tools) > 0


def test_catalog_get_tool_url(catalog: ToolCatalog) -> None:
    """get_tool_url returns a non-empty URL containing the tool name."""
    tool = catalog.tools[0]
    url = catalog.get_tool_url(tool)
    assert url
    assert tool.name in url
    # Must look like a URL
    assert url.startswith("http")


def test_loader_missing_file(tmp_path: Path) -> None:
    """CatalogLoader raises CatalogLoadError when the file does not exist."""
    loader = CatalogLoader(catalog_path=tmp_path / "nonexistent.yaml")
    with pytest.raises(CatalogLoadError, match="not found"):
        loader.load()


def test_loader_invalid_yaml(tmp_path: Path) -> None:
    """CatalogLoader raises CatalogLoadError when the YAML is malformed."""
    bad_yaml = tmp_path / "bad.yaml"
    bad_yaml.write_text("key: [unclosed bracket\n", encoding="utf-8")
    loader = CatalogLoader(catalog_path=bad_yaml)
    with pytest.raises(CatalogLoadError):
        loader.load()


def test_loader_missing_required_keys(tmp_path: Path) -> None:
    """CatalogLoader raises CatalogLoadError when top-level keys are absent."""
    incomplete = tmp_path / "incomplete.yaml"
    incomplete.write_text("version: '1.0'\n", encoding="utf-8")
    loader = CatalogLoader(catalog_path=incomplete)
    with pytest.raises(CatalogLoadError, match="missing top-level key"):
        loader.load()


def test_loader_invalid_platform(tmp_path: Path) -> None:
    """CatalogLoader raises CatalogLoadError when a tool has an invalid platform."""
    bad = tmp_path / "bad_platform.yaml"
    bad.write_text(
        textwrap.dedent("""\
            version: '1.0'
            release_base_url: 'https://example.com'
            tools_release: 'v1'
            categories: {}
            tools:
              - name: bad.exe
                display_name: Bad Tool
                description: Test
                project_url: https://example.com
                upstream_url: https://example.com/bad.exe
                upstream_version: '1.0'
                license: MIT
                sha256: ''
                folder: Bad
                categories: []
                platform: dos
                architecture: x64
                tags: []
                finding_triggers: []
                notes: ''
        """),
        encoding="utf-8",
    )
    loader = CatalogLoader(catalog_path=bad)
    with pytest.raises(CatalogLoadError, match="invalid platform"):
        loader.load()
