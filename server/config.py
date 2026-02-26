"""Seep server configuration."""

from __future__ import annotations
import secrets
from dataclasses import dataclass, field
from pathlib import Path
import yaml


def _validate_port(value: int, name: str) -> int:
    """Return *value* if it is a valid TCP port (1-65535), else raise ValueError."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"{name} must be an integer, got {value!r}")
    if not 1 <= value <= 65535:
        raise ValueError(f"{name} must be between 1 and 65535, got {value}")
    return value


@dataclass
class TlsConfig:
    enabled: bool = False
    cert_path: str = "certs/seep.crt"
    key_path: str = "certs/seep.key"


@dataclass
class AgentConfig:
    quiet: bool = False
    shuffle: bool = False
    jitter: int = 0
    strip_comments: bool = True
    obfuscate: bool = False


@dataclass
class CatalogConfig:
    tools_dir: str = "tools"
    github_repo: str = "yourorg/seep"
    auto_download: bool = False
    verify_integrity: bool = True


@dataclass
class ResultsConfig:
    output_dir: str = "results"
    reports_dir: str = "reports"


@dataclass
class ServerConfig:
    http_port: int = 80
    upload_port: int = 8000
    bind_address: str = "0.0.0.0"
    auth_token: str = ""
    tls: TlsConfig = field(default_factory=TlsConfig)
    agent: AgentConfig = field(default_factory=AgentConfig)
    catalog: CatalogConfig = field(default_factory=CatalogConfig)
    results: ResultsConfig = field(default_factory=ResultsConfig)
    workdir: Path = field(default_factory=lambda: Path("./seep-workspace"))

    @staticmethod
    def generate_token() -> str:
        """Generate a random 32-character hex token for upload authentication."""
        return secrets.token_hex(16)

    @classmethod
    def from_yaml(cls, path: Path) -> ServerConfig:
        """Load config from a YAML file."""
        with open(path, encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}

        server = raw.get("server", {})
        tls_raw = server.get("tls", {})
        agent_raw = raw.get("agent", {}).get("default_args", {})
        agent_opts = raw.get("agent", {})
        catalog_raw = raw.get("catalog", {})
        results_raw = raw.get("results", {})

        return cls(
            http_port=_validate_port(server.get("http_port", 80), "http_port"),
            upload_port=_validate_port(server.get("upload_port", 8000), "upload_port"),
            bind_address=server.get("bind_address", "0.0.0.0"),
            auth_token=server.get("auth_token", ""),
            tls=TlsConfig(
                enabled=tls_raw.get("enabled", False),
                cert_path=tls_raw.get("cert_path", "certs/seep.crt"),
                key_path=tls_raw.get("key_path", "certs/seep.key"),
            ),
            agent=AgentConfig(
                quiet=agent_raw.get("quiet", False),
                shuffle=agent_raw.get("shuffle", False),
                jitter=agent_raw.get("jitter", 0),
                strip_comments=agent_opts.get("strip_comments", True),
                obfuscate=agent_opts.get("obfuscate", False),
            ),
            catalog=CatalogConfig(
                tools_dir=catalog_raw.get("tools_dir", "tools"),
                github_repo=catalog_raw.get("github_repo", "yourorg/seep"),
                auto_download=catalog_raw.get("auto_download", False),
                verify_integrity=catalog_raw.get("verify_integrity", True),
            ),
            results=ResultsConfig(
                output_dir=results_raw.get("output_dir", "results"),
                reports_dir=results_raw.get("reports_dir", "reports"),
            ),
        )

    def to_yaml(self) -> str:
        """Serialize config to YAML string."""
        data = {
            "server": {
                "http_port": self.http_port,
                "upload_port": self.upload_port,
                "bind_address": self.bind_address,
                "auth_token": self.auth_token,
                "tls": {
                    "enabled": self.tls.enabled,
                    "cert_path": self.tls.cert_path,
                    "key_path": self.tls.key_path,
                },
            },
            "agent": {
                "default_args": {
                    "quiet": self.agent.quiet,
                    "shuffle": self.agent.shuffle,
                    "jitter": self.agent.jitter,
                },
                "strip_comments": self.agent.strip_comments,
                "obfuscate": self.agent.obfuscate,
            },
            "catalog": {
                "tools_dir": self.catalog.tools_dir,
                "github_repo": self.catalog.github_repo,
                "auto_download": self.catalog.auto_download,
                "verify_integrity": self.catalog.verify_integrity,
            },
            "results": {
                "output_dir": self.results.output_dir,
                "reports_dir": self.results.reports_dir,
            },
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False)
