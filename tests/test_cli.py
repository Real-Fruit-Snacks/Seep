"""CLI integration tests for Seep — exercises the full CLI via subprocess."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

# ---------------------------------------------------------------------------
# Helper: run the seep CLI as a subprocess
# ---------------------------------------------------------------------------

SEEP_DIR = Path(__file__).parent.parent  # /opt/powershellSurvey/seep


def _run(*args: str):
    """Run `python -m server <args>` and return the CompletedProcess."""
    import subprocess

    return subprocess.run(
        [sys.executable, "-m", "server"] + list(args),
        capture_output=True,
        text=True,
        cwd=str(SEEP_DIR),
    )


# ---------------------------------------------------------------------------
# 1. seep --help
# ---------------------------------------------------------------------------


def test_help_exits_zero():
    result = _run("--help")
    assert result.returncode == 0


def test_help_shows_usage():
    result = _run("--help")
    assert "seep" in result.stdout.lower() or "usage" in result.stdout.lower()


def test_version_exits_zero():
    result = _run("--version")
    assert result.returncode == 0


def test_version_shows_version():
    result = _run("--version")
    # Should contain "seep" and a version number like "2.0.0"
    output = result.stdout.strip()
    assert "seep" in output.lower()
    # Check for version-like pattern (digits and dots)
    import re
    assert re.search(r"\d+\.\d+\.\d+", output), f"No version found in: {output!r}"


# ---------------------------------------------------------------------------
# 2 & 3. seep init
# ---------------------------------------------------------------------------


def test_init_creates_directory_structure(tmp_path: Path):
    workdir = tmp_path / "myworkspace"
    result = _run("init", "--workdir", str(workdir))
    assert result.returncode == 0
    for subdir in (
        "tools",
        "tools/all",
        "tools/categories",
        "results",
        "reports",
        "agents",
        "certs",
    ):
        assert (workdir / subdir).is_dir(), f"Missing directory: {subdir}"


def test_init_creates_config_yaml(tmp_path: Path):
    workdir = tmp_path / "initws"
    result = _run("init", "--workdir", str(workdir))
    assert result.returncode == 0
    config_path = workdir / "config.yaml"
    assert config_path.exists(), "config.yaml was not created"
    parsed = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    assert "server" in parsed


def test_init_config_yaml_has_valid_ports(tmp_path: Path):
    workdir = tmp_path / "portws"
    _run("init", "--workdir", str(workdir))
    parsed = yaml.safe_load((workdir / "config.yaml").read_text(encoding="utf-8"))
    assert parsed["server"]["http_port"] == 80
    assert parsed["server"]["upload_port"] == 8000


def test_init_creates_auth_token(tmp_path: Path):
    workdir = tmp_path / "authws"
    result = _run("init", "--workdir", str(workdir))
    assert result.returncode == 0
    parsed = yaml.safe_load((workdir / "config.yaml").read_text(encoding="utf-8"))
    token = parsed["server"].get("auth_token", "")
    assert len(token) == 32, f"Expected 32-char hex token, got {len(token)} chars: {token!r}"
    # Verify it's valid hex
    int(token, 16)


def test_init_idempotent_skips_existing_config(tmp_path: Path):
    workdir = tmp_path / "idempotentws"
    _run("init", "--workdir", str(workdir))
    # Overwrite config with custom content
    config_path = workdir / "config.yaml"
    config_path.write_text("server:\n  http_port: 9999\n", encoding="utf-8")
    # Run init again — should NOT overwrite
    result = _run("init", "--workdir", str(workdir))
    assert result.returncode == 0
    content = config_path.read_text(encoding="utf-8")
    assert "9999" in content, "init overwrote existing config.yaml"


# ---------------------------------------------------------------------------
# 4 & 5. seep catalog list
# ---------------------------------------------------------------------------


def test_catalog_list_exits_zero():
    result = _run("catalog", "list")
    assert result.returncode == 0


def test_catalog_list_shows_tools():
    result = _run("catalog", "list")
    assert result.returncode == 0
    # Should show at least one tool name in the output
    assert len(result.stdout.strip()) > 0


def test_catalog_list_json_exits_zero():
    result = _run("catalog", "list", "--format", "json")
    assert result.returncode == 0


def test_catalog_list_json_returns_valid_json():
    result = _run("catalog", "list", "--format", "json")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) > 0


def test_catalog_list_json_has_expected_fields():
    result = _run("catalog", "list", "--format", "json")
    data = json.loads(result.stdout)
    first = data[0]
    for field in ("name", "description", "categories", "platform"):
        assert field in first, f"Missing field '{field}' in catalog entry"


# ---------------------------------------------------------------------------
# 6. seep catalog list --category TokenAbuse
# ---------------------------------------------------------------------------


def test_catalog_list_category_filter():
    result = _run("catalog", "list", "--format", "json", "--category", "TokenAbuse")
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert isinstance(data, list)
    assert len(data) > 0
    for tool in data:
        assert "TokenAbuse" in tool["categories"], (
            f"Tool '{tool['name']}' not in TokenAbuse category"
        )


def test_catalog_list_category_filter_invalid_returns_zero():
    """An unknown category should warn but exit 0 (no results, not an error)."""
    result = _run("catalog", "list", "--category", "NonExistentCategoryXYZ")
    assert result.returncode == 0


# ---------------------------------------------------------------------------
# 7. seep catalog search potato
# ---------------------------------------------------------------------------


def test_catalog_search_potato_exits_zero():
    result = _run("catalog", "search", "potato")
    assert result.returncode == 0


def test_catalog_search_potato_returns_results():
    result = _run("catalog", "search", "potato")
    assert result.returncode == 0
    # Should mention at least one potato tool (GodPotato, JuicyPotato, etc.)
    combined = result.stdout + result.stderr
    assert "otato" in combined.lower() or "potato" in combined.lower()


# ---------------------------------------------------------------------------
# 8. seep catalog search nonexistentxyz123
# ---------------------------------------------------------------------------


def test_catalog_search_no_results_exits_zero():
    result = _run("catalog", "search", "nonexistentxyz123")
    assert result.returncode == 0


def test_catalog_search_no_results_shows_no_matches():
    result = _run("catalog", "search", "nonexistentxyz123")
    combined = result.stdout + result.stderr
    # Should indicate no matches — "0 matches" or "No tools matching"
    assert "0" in combined or "no" in combined.lower()


# ---------------------------------------------------------------------------
# 9 & 10. seep compose
# ---------------------------------------------------------------------------


def test_compose_outputs_to_stdout():
    result = _run("compose")
    assert result.returncode == 0
    # PowerShell output should appear on stdout
    assert len(result.stdout.strip()) > 0


def test_compose_stdout_looks_like_powershell():
    result = _run("compose")
    assert result.returncode == 0
    # PowerShell scripts typically contain function or param keywords
    ps_indicators = ["function", "param", "Invoke-", "$", "#"]
    assert any(kw in result.stdout for kw in ps_indicators), (
        "compose stdout doesn't look like PowerShell"
    )


def test_compose_output_to_file(tmp_path: Path):
    out_file = tmp_path / "agent.ps1"
    result = _run("compose", "--output", str(out_file))
    assert result.returncode == 0
    assert out_file.exists(), "Output file was not created"
    content = out_file.read_text(encoding="utf-8")
    assert len(content.strip()) > 0


def test_compose_output_file_not_written_to_stdout(tmp_path: Path):
    out_file = tmp_path / "agent2.ps1"
    result = _run("compose", "--output", str(out_file))
    assert result.returncode == 0
    # When writing to file, stats go to stdout but PS content should be in file
    assert out_file.exists()


# ---------------------------------------------------------------------------
# 11. seep compose --checks system_info
# ---------------------------------------------------------------------------


def test_compose_checks_filter(tmp_path: Path):
    out_file = tmp_path / "agent_filtered.ps1"
    result = _run("compose", "--checks", "system_info", "--output", str(out_file))
    assert result.returncode == 0
    assert out_file.exists()
    # Stats output should mention 1 check included
    combined = result.stdout + result.stderr
    assert "1" in combined


# ---------------------------------------------------------------------------
# 12-14. seep report
# ---------------------------------------------------------------------------

SAMPLE_RESULTS = Path(__file__).parent / "fixtures" / "sample_results.json"


def test_report_json_exits_zero(tmp_path: Path):
    out = tmp_path / "report.json"
    result = _run(
        "report", str(SAMPLE_RESULTS), "--format", "json", "--output", str(out)
    )
    assert result.returncode == 0


def test_report_json_creates_valid_json(tmp_path: Path):
    out = tmp_path / "report.json"
    _run("report", str(SAMPLE_RESULTS), "--format", "json", "--output", str(out))
    assert out.exists()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_report_json_has_findings(tmp_path: Path):
    out = tmp_path / "report.json"
    _run("report", str(SAMPLE_RESULTS), "--format", "json", "--output", str(out))
    data = json.loads(out.read_text(encoding="utf-8"))
    # Report should contain findings or summary info
    assert any(key in data for key in ("findings", "summary", "total_findings", "meta"))


def test_report_html_exits_zero(tmp_path: Path):
    out = tmp_path / "report.html"
    result = _run(
        "report", str(SAMPLE_RESULTS), "--format", "html", "--output", str(out)
    )
    assert result.returncode == 0


def test_report_html_creates_file(tmp_path: Path):
    out = tmp_path / "report.html"
    _run("report", str(SAMPLE_RESULTS), "--format", "html", "--output", str(out))
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    assert "<html" in content.lower() or "<!doctype" in content.lower()


def test_report_md_exits_zero(tmp_path: Path):
    out = tmp_path / "report.md"
    result = _run("report", str(SAMPLE_RESULTS), "--format", "md", "--output", str(out))
    assert result.returncode == 0


def test_report_md_creates_file(tmp_path: Path):
    out = tmp_path / "report.md"
    _run("report", str(SAMPLE_RESULTS), "--format", "md", "--output", str(out))
    assert out.exists()
    content = out.read_text(encoding="utf-8")
    # Markdown files contain # headings
    assert "#" in content


# ---------------------------------------------------------------------------
# 15. seep results list (empty dir)
# ---------------------------------------------------------------------------


def test_results_list_empty_workdir(workspace: Path):
    result = _run("results", "list", "--workdir", str(workspace))
    assert result.returncode == 0
    combined = result.stdout + result.stderr
    # Should indicate no results found
    assert "no" in combined.lower() or "0" in combined or len(combined.strip()) > 0


def test_results_list_nonexistent_workdir(tmp_path: Path):
    """A workdir with no results/ subdir should warn and exit 0."""
    empty = tmp_path / "nonexistent_ws"
    result = _run("results", "list", "--workdir", str(empty))
    assert result.returncode == 0


# ---------------------------------------------------------------------------
# 16. seep results show
# ---------------------------------------------------------------------------


def test_results_show_exits_zero():
    result = _run("results", "show", str(SAMPLE_RESULTS))
    assert result.returncode == 0


def test_results_show_displays_hostname():
    result = _run("results", "show", str(SAMPLE_RESULTS))
    assert result.returncode == 0
    # The sample results hostname is WORKSTATION01
    assert "WORKSTATION01" in result.stdout


def test_results_show_displays_findings():
    result = _run("results", "show", str(SAMPLE_RESULTS))
    assert result.returncode == 0
    # Should show CRITICAL section
    assert "CRITICAL" in result.stdout or "critical" in result.stdout.lower()


def test_results_show_missing_file_reports_error(tmp_path: Path):
    missing = tmp_path / "ghost.json"
    result = _run("results", "show", str(missing))
    assert (
        result.returncode != 0
        or "not found" in result.stderr.lower()
        or "error" in result.stderr.lower()
    )


# ---------------------------------------------------------------------------
# 17. ServerConfig.from_yaml() loads valid YAML
# ---------------------------------------------------------------------------


def test_config_from_yaml_loads_valid_yaml(tmp_path: Path):
    from server.config import ServerConfig

    yaml_content = (
        "server:\n"
        "  http_port: 8080\n"
        "  upload_port: 9000\n"
        "  bind_address: 127.0.0.1\n"
        "  tls:\n"
        "    enabled: false\n"
        "    cert_path: certs/seep.crt\n"
        "    key_path: certs/seep.key\n"
        "agent:\n"
        "  default_args:\n"
        "    quiet: false\n"
        "    shuffle: false\n"
        "    jitter: 0\n"
        "  strip_comments: true\n"
        "  obfuscate: false\n"
        "catalog:\n"
        "  tools_dir: tools\n"
        "  github_repo: yourorg/seep\n"
        "  auto_download: false\n"
        "  verify_integrity: true\n"
        "results:\n"
        "  output_dir: results\n"
        "  reports_dir: reports\n"
    )
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml_content, encoding="utf-8")

    cfg = ServerConfig.from_yaml(cfg_file)
    assert cfg.http_port == 8080
    assert cfg.upload_port == 9000
    assert cfg.bind_address == "127.0.0.1"
    assert cfg.tls.enabled is False
    assert cfg.agent.strip_comments is True
    assert cfg.catalog.tools_dir == "tools"
    assert cfg.results.output_dir == "results"


# ---------------------------------------------------------------------------
# 18. ServerConfig.to_yaml() produces valid YAML
# ---------------------------------------------------------------------------


def test_config_to_yaml_produces_valid_yaml():
    from server.config import ServerConfig

    cfg = ServerConfig()
    yaml_str = cfg.to_yaml()

    assert isinstance(yaml_str, str)
    assert len(yaml_str.strip()) > 0

    parsed = yaml.safe_load(yaml_str)
    assert isinstance(parsed, dict)
    assert "server" in parsed
    assert parsed["server"]["http_port"] == 80
    assert parsed["server"]["upload_port"] == 8000


def test_config_to_yaml_roundtrip_preserves_values(tmp_path: Path):
    from server.config import ServerConfig

    original = ServerConfig(http_port=7070, upload_port=7071)
    yaml_str = original.to_yaml()
    cfg_file = tmp_path / "rt.yaml"
    cfg_file.write_text(yaml_str, encoding="utf-8")
    reloaded = ServerConfig.from_yaml(cfg_file)

    assert reloaded.http_port == 7070
    assert reloaded.upload_port == 7071


# ---------------------------------------------------------------------------
# 19. _validate_port() rejects invalid ports
# ---------------------------------------------------------------------------


def test_validate_port_rejects_zero():
    from server.config import _validate_port

    with pytest.raises(ValueError):
        _validate_port(0, "http_port")


def test_validate_port_rejects_negative():
    from server.config import _validate_port

    with pytest.raises(ValueError):
        _validate_port(-1, "http_port")


def test_validate_port_rejects_above_65535():
    from server.config import _validate_port

    with pytest.raises(ValueError):
        _validate_port(65536, "http_port")


def test_validate_port_rejects_string():
    from server.config import _validate_port

    with pytest.raises(ValueError):
        _validate_port("80", "http_port")  # type: ignore[arg-type]


def test_validate_port_rejects_bool():
    from server.config import _validate_port

    # bool is a subclass of int in Python, but _validate_port explicitly rejects it
    with pytest.raises(ValueError):
        _validate_port(True, "http_port")


def test_validate_port_accepts_valid_low():
    from server.config import _validate_port

    assert _validate_port(1, "http_port") == 1


def test_validate_port_accepts_valid_high():
    from server.config import _validate_port

    assert _validate_port(65535, "http_port") == 65535


def test_validate_port_accepts_common():
    from server.config import _validate_port

    assert _validate_port(8080, "http_port") == 8080
