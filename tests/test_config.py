"""Tests for ServerConfig — defaults, YAML roundtrip, custom values."""

from __future__ import annotations

from pathlib import Path

import yaml

from server.config import (
    AgentConfig,
    CatalogConfig,
    ResultsConfig,
    ServerConfig,
    TlsConfig,
)


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------


def test_default_http_port() -> None:
    cfg = ServerConfig()
    assert cfg.http_port == 80


def test_default_upload_port() -> None:
    cfg = ServerConfig()
    assert cfg.upload_port == 8000


def test_default_bind_address() -> None:
    cfg = ServerConfig()
    assert cfg.bind_address == "0.0.0.0"


def test_default_tls_disabled() -> None:
    cfg = ServerConfig()
    assert cfg.tls.enabled is False


def test_default_tls_cert_path() -> None:
    cfg = ServerConfig()
    assert cfg.tls.cert_path == "certs/seep.crt"


def test_default_tls_key_path() -> None:
    cfg = ServerConfig()
    assert cfg.tls.key_path == "certs/seep.key"


def test_default_agent_strip_comments() -> None:
    cfg = ServerConfig()
    assert cfg.agent.strip_comments is True


def test_default_agent_obfuscate_false() -> None:
    cfg = ServerConfig()
    assert cfg.agent.obfuscate is False


def test_default_catalog_tools_dir() -> None:
    cfg = ServerConfig()
    assert cfg.catalog.tools_dir == "tools"


def test_default_catalog_verify_integrity() -> None:
    cfg = ServerConfig()
    assert cfg.catalog.verify_integrity is True


def test_default_results_output_dir() -> None:
    cfg = ServerConfig()
    assert cfg.results.output_dir == "results"


def test_default_results_reports_dir() -> None:
    cfg = ServerConfig()
    assert cfg.results.reports_dir == "reports"


def test_default_auth_token_empty() -> None:
    cfg = ServerConfig()
    assert cfg.auth_token == ""


def test_generate_token_length() -> None:
    token = ServerConfig.generate_token()
    assert len(token) == 32


def test_generate_token_is_hex() -> None:
    token = ServerConfig.generate_token()
    int(token, 16)  # Will raise ValueError if not valid hex


def test_generate_token_unique() -> None:
    token1 = ServerConfig.generate_token()
    token2 = ServerConfig.generate_token()
    assert token1 != token2


# ---------------------------------------------------------------------------
# YAML roundtrip
# ---------------------------------------------------------------------------


def test_yaml_roundtrip_basic(tmp_path: Path) -> None:
    """Default config serialises to YAML and deserialises back to equivalent values."""
    original = ServerConfig()
    yaml_str = original.to_yaml()

    yaml_file = tmp_path / "seep.yaml"
    yaml_file.write_text(yaml_str, encoding="utf-8")

    reloaded = ServerConfig.from_yaml(yaml_file)

    assert reloaded.http_port == original.http_port
    assert reloaded.upload_port == original.upload_port
    assert reloaded.bind_address == original.bind_address
    assert reloaded.tls.enabled == original.tls.enabled
    assert reloaded.tls.cert_path == original.tls.cert_path
    assert reloaded.agent.strip_comments == original.agent.strip_comments
    assert reloaded.agent.obfuscate == original.agent.obfuscate
    assert reloaded.catalog.tools_dir == original.catalog.tools_dir
    assert reloaded.catalog.verify_integrity == original.catalog.verify_integrity
    assert reloaded.results.output_dir == original.results.output_dir


def test_yaml_roundtrip_custom_values(tmp_path: Path) -> None:
    """Non-default values survive a YAML roundtrip."""
    original = ServerConfig(
        http_port=8080,
        upload_port=9000,
        bind_address="127.0.0.1",
        tls=TlsConfig(enabled=True, cert_path="my.crt", key_path="my.key"),
        agent=AgentConfig(
            quiet=True, shuffle=True, jitter=5, strip_comments=False, obfuscate=True
        ),
        catalog=CatalogConfig(
            tools_dir="mytoolsdir",
            github_repo="myorg/myrepo",
            auto_download=True,
            verify_integrity=False,
        ),
        results=ResultsConfig(output_dir="out", reports_dir="rep"),
    )

    yaml_str = original.to_yaml()
    yaml_file = tmp_path / "custom.yaml"
    yaml_file.write_text(yaml_str, encoding="utf-8")

    reloaded = ServerConfig.from_yaml(yaml_file)

    assert reloaded.http_port == 8080
    assert reloaded.upload_port == 9000
    assert reloaded.bind_address == "127.0.0.1"
    assert reloaded.tls.enabled is True
    assert reloaded.tls.cert_path == "my.crt"
    assert reloaded.tls.key_path == "my.key"
    assert reloaded.agent.quiet is True
    assert reloaded.agent.shuffle is True
    assert reloaded.agent.jitter == 5
    assert reloaded.agent.strip_comments is False
    assert reloaded.agent.obfuscate is True
    assert reloaded.catalog.tools_dir == "mytoolsdir"
    assert reloaded.catalog.github_repo == "myorg/myrepo"
    assert reloaded.catalog.auto_download is True
    assert reloaded.catalog.verify_integrity is False
    assert reloaded.results.output_dir == "out"
    assert reloaded.results.reports_dir == "rep"


def test_to_yaml_is_valid_yaml() -> None:
    """to_yaml() output is parseable by PyYAML."""
    cfg = ServerConfig()
    yaml_str = cfg.to_yaml()
    parsed = yaml.safe_load(yaml_str)
    assert isinstance(parsed, dict)
    assert "server" in parsed


def test_yaml_roundtrip_auth_token(tmp_path: Path) -> None:
    """auth_token survives a YAML roundtrip."""
    original = ServerConfig(auth_token="deadbeef12345678abcdef0123456789")
    yaml_str = original.to_yaml()
    yaml_file = tmp_path / "auth.yaml"
    yaml_file.write_text(yaml_str, encoding="utf-8")
    reloaded = ServerConfig.from_yaml(yaml_file)
    assert reloaded.auth_token == "deadbeef12345678abcdef0123456789"


def test_from_yaml_empty_file(tmp_path: Path) -> None:
    """from_yaml on an empty YAML file returns defaults without error."""
    empty = tmp_path / "empty.yaml"
    empty.write_text("", encoding="utf-8")
    cfg = ServerConfig.from_yaml(empty)
    assert cfg.http_port == 80
    assert cfg.upload_port == 8000
