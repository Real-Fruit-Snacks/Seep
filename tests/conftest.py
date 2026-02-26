"""Shared pytest fixtures for the Seep test suite."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from server.catalog.loader import CatalogLoader
from server.catalog.schemas import ToolCatalog
from server.report.recommendations import RecommendationEngine
from server.results.parser import AgentResults, ResultsParser

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def catalog() -> ToolCatalog:
    """Load the real tools.yaml catalog once per session."""
    return CatalogLoader().load()


@pytest.fixture(scope="session")
def sample_results() -> AgentResults:
    """Load and parse sample_results.json into AgentResults once per session."""
    data = (FIXTURES_DIR / "sample_results.json").read_bytes()
    return ResultsParser().parse_upload(data)


@pytest.fixture
def tmp_workdir(tmp_path: Path):
    """Yield a temporary working directory; cleaned up by pytest's tmp_path."""
    yield tmp_path


@pytest.fixture(scope="session")
def engine(catalog: ToolCatalog) -> RecommendationEngine:
    """RecommendationEngine backed by the real catalog."""
    return RecommendationEngine(catalog)


# ---------------------------------------------------------------------------
# CLI / integration test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def sample_results_dict():
    """A complete valid results document as a Python dict."""
    return {
        "meta": {
            "agent_version": "2.0.0",
            "timestamp": "2026-02-25T12:00:00Z",
            "hostname": "TESTHOST",
            "domain": "CORP.LOCAL",
            "username": "CORP\\testuser",
            "is_admin": False,
            "is_domain_joined": True,
            "os_version": "10.0.19045",
            "os_name": "Microsoft Windows 10 Pro",
            "ps_version": "5.1.19041.1",
            "architecture": "AMD64",
            "execution_mode": "fileless",
            "checks_run": ["system_info", "user_privileges", "network"],
            "total_duration_seconds": 12.5,
        },
        "findings": [
            {
                "check_id": "user_privileges",
                "finding_id": "se_impersonate_enabled",
                "severity": "critical",
                "title": "SeImpersonatePrivilege Enabled",
                "description": "The current user has SeImpersonatePrivilege enabled.",
                "evidence": "SeImpersonatePrivilege  Enabled",
                "remediation": "Remove SeImpersonatePrivilege if not required.",
                "tags": ["token", "impersonation", "potato"],
                "tool_hint": ["GodPotato", "PrintSpoofer"],
                "timestamp": "2026-02-25T12:00:05Z",
            },
            {
                "check_id": "system_info",
                "finding_id": "system_info_raw",
                "severity": "info",
                "title": "System Information",
                "description": "Basic system information.",
                "evidence": "Windows 10 Pro",
                "tags": ["context"],
            },
            {
                "check_id": "quick_wins",
                "finding_id": "autologon_credentials",
                "severity": "critical",
                "title": "AutoLogon Credentials Found",
                "description": "DefaultPassword found in Winlogon registry.",
                "evidence": "DefaultUserName=admin, DefaultPassword=P@ss123",
                "remediation": "Remove autologon credentials from registry.",
                "tags": ["credentials", "registry", "plaintext"],
            },
        ],
        "summary": {
            "total_findings": 3,
            "by_severity": {"critical": 2, "info": 1},
        },
    }


@pytest.fixture
def sample_results_json(tmp_path: Path, sample_results_dict):
    """Write sample_results_dict to a temp JSON file and return its Path."""
    path = tmp_path / "results.json"
    path.write_text(json.dumps(sample_results_dict, indent=2), encoding="utf-8")
    return path


@pytest.fixture
def workspace(tmp_path: Path):
    """Create a minimal seep workspace directory tree and return its Path."""
    for d in (
        "tools",
        "tools/all",
        "tools/categories",
        "results",
        "reports",
        "agents",
        "certs",
    ):
        (tmp_path / d).mkdir(parents=True, exist_ok=True)
    return tmp_path
