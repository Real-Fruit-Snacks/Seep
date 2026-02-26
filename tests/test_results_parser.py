"""Tests for ResultsParser — JSON, ZIP, validation, edge cases."""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path

import pytest

from server.results.parser import (
    AgentResults,
    ResultsParseError,
    ResultsParser,
)

FIXTURES_DIR = Path(__file__).parent / "fixtures"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_zip(json_bytes: bytes, filename: str = "results.json") -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, json_bytes)
    return buf.getvalue()


def _sample_results(findings=None):
    return {
        "meta": {
            "hostname": "TEST-PC",
            "agent_version": "2.0.0",
            "timestamp": "2026-01-01T00:00:00Z",
            "username": "TEST\\user",
            "is_admin": False,
            "is_domain_joined": False,
            "os_version": "10.0.19045",
            "os_name": "Windows 10 Pro",
            "ps_version": "5.1",
            "architecture": "AMD64",
            "execution_mode": "fileless",
            "checks_run": ["system_info"],
            "total_duration_seconds": 5.0,
        },
        "findings": findings or [],
        "summary": {"total_findings": len(findings or []), "by_severity": {}},
    }


def _make_finding(
    finding_id="test_finding",
    check_id="test_check",
    severity="info",
    title="Test Finding",
    **kwargs,
) -> dict:
    base = {
        "check_id": check_id,
        "finding_id": finding_id,
        "severity": severity,
        "title": title,
        "description": "A test finding.",
        "evidence": "",
        "tags": [],
        "tool_hint": [],
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Tests — fixture-based (integration)
# ---------------------------------------------------------------------------


def test_parse_json_findings_count(sample_results: AgentResults) -> None:
    """Sample results contain exactly 10 findings."""
    assert len(sample_results.findings) == 10


def test_parse_json_hostname(sample_results: AgentResults) -> None:
    """Meta hostname is WORKSTATION01."""
    assert sample_results.meta.hostname == "WORKSTATION01"


def test_parse_severities(sample_results: AgentResults) -> None:
    """Severity counts match: 2 critical, 2 high, 2 medium, 4 info."""
    by_sev = {
        s: sum(1 for f in sample_results.findings if f.severity == s)
        for s in ("critical", "high", "medium", "info")
    }
    assert by_sev["critical"] == 2
    assert by_sev["high"] == 2
    assert by_sev["medium"] == 2
    assert by_sev["info"] == 4


def test_finding_fields(sample_results: AgentResults) -> None:
    """Each Finding has all required fields populated."""
    for finding in sample_results.findings:
        assert finding.finding_id, f"finding_id empty on {finding}"
        assert finding.severity, f"severity empty on {finding.finding_id}"
        assert finding.title, f"title empty on {finding.finding_id}"
        assert isinstance(finding.evidence, str)
        assert isinstance(finding.tags, list)
        assert isinstance(finding.tool_hint, list)


def test_meta_fields(sample_results: AgentResults) -> None:
    """AgentMeta has the expected field values from the fixture."""
    meta = sample_results.meta
    assert meta.hostname == "WORKSTATION01"
    assert meta.domain == "CORP.LOCAL"
    assert meta.username == "CORP\\svc_web"
    assert meta.os_version == "10.0.19045"
    assert meta.os_name == "Microsoft Windows 10 Pro"


def test_parse_file_json(tmp_path: Path) -> None:
    """parse_file works for a .json file on disk."""
    src = FIXTURES_DIR / "sample_results.json"
    dest = tmp_path / "results.json"
    dest.write_bytes(src.read_bytes())
    results = ResultsParser().parse_file(dest)
    assert len(results.findings) == 10


def test_parse_zip_upload() -> None:
    """parse_upload handles a ZIP containing results.json."""
    src = FIXTURES_DIR / "sample_results.json"
    zip_bytes = _make_zip(src.read_bytes())
    results = ResultsParser().parse_upload(zip_bytes)
    assert len(results.findings) == 10
    assert results.meta.hostname == "WORKSTATION01"


def test_parse_invalid_json() -> None:
    """parse_upload raises ResultsParseError on malformed JSON."""
    with pytest.raises(ResultsParseError, match="Invalid JSON"):
        ResultsParser().parse_upload(b"{ not valid json !!!")


def test_parse_missing_findings_key() -> None:
    """parse_upload raises ResultsParseError when 'findings' key is absent."""
    bad = json.dumps({"meta": {"hostname": "HOST"}}).encode()
    with pytest.raises(ResultsParseError):
        ResultsParser().parse_upload(bad)


def test_parse_empty_bytes() -> None:
    """parse_upload raises ResultsParseError on empty input."""
    with pytest.raises(ResultsParseError, match="empty"):
        ResultsParser().parse_upload(b"")


def test_parse_bad_zip() -> None:
    """parse_upload raises ResultsParseError on a corrupted ZIP."""
    with pytest.raises(ResultsParseError):
        # PK magic but not a real ZIP
        ResultsParser().parse_upload(b"PK\x03\x04garbage")


def test_critical_findings_property(sample_results: AgentResults) -> None:
    """critical_findings property filters correctly."""
    crits = sample_results.critical_findings
    assert len(crits) == 2
    assert all(f.severity == "critical" for f in crits)


def test_actionable_findings_property(sample_results: AgentResults) -> None:
    """actionable_findings returns critical + high findings."""
    actionable = sample_results.actionable_findings
    assert len(actionable) == 4
    assert all(f.severity in ("critical", "high") for f in actionable)


def test_summary_counts(sample_results: AgentResults) -> None:
    """Summary total_findings matches the actual findings list length."""
    assert sample_results.summary.total_findings == len(sample_results.findings)


def test_validate_missing_meta() -> None:
    """validate() reports error when 'meta' key is missing."""
    errors = ResultsParser().validate({"findings": []})
    assert any("meta" in e for e in errors)


def test_validate_invalid_severity() -> None:
    """validate() reports an error for an unrecognised severity value."""
    raw = {
        "meta": {"hostname": "H"},
        "findings": [
            {
                "check_id": "c1",
                "finding_id": "f1",
                "severity": "ultra_critical",
                "title": "Test",
            }
        ],
    }
    errors = ResultsParser().validate(raw)
    assert any("severity" in e for e in errors)


# ---------------------------------------------------------------------------
# Tests — inline data (unit-level, no fixture dependency)
# ---------------------------------------------------------------------------


def test_parse_complete_valid_document() -> None:
    """parse_upload succeeds with a complete, fully-populated results document."""
    raw = _sample_results(
        [
            _make_finding(
                "f1", severity="critical", title="Critical Issue", tags=["token-abuse"]
            ),
            _make_finding("f2", severity="high", title="High Issue"),
            _make_finding("f3", severity="info", title="Info Item"),
        ]
    )
    data = json.dumps(raw).encode()
    results = ResultsParser().parse_upload(data)

    assert results.meta.hostname == "TEST-PC"
    assert results.meta.agent_version == "2.0.0"
    assert results.meta.os_name == "Windows 10 Pro"
    assert len(results.findings) == 3
    assert results.findings[0].finding_id == "f1"
    assert results.findings[0].severity == "critical"
    assert results.findings[1].severity == "high"
    assert results.findings[2].severity == "info"


def test_parse_minimal_valid_document() -> None:
    """parse_upload succeeds with only 'meta' (hostname) and empty 'findings'."""
    raw = {
        "meta": {"hostname": "MINIMAL-HOST"},
        "findings": [],
    }
    data = json.dumps(raw).encode()
    results = ResultsParser().parse_upload(data)

    assert results.meta.hostname == "MINIMAL-HOST"
    assert results.findings == []
    assert results.summary.total_findings == 0


def test_parse_file_json_inline(tmp_path: Path) -> None:
    """parse_file() reads a .json file and returns correct AgentResults."""
    raw = _sample_results([_make_finding("finding_a", severity="high", title="A")])
    json_file = tmp_path / "results.json"
    json_file.write_bytes(json.dumps(raw).encode())

    results = ResultsParser().parse_file(json_file)
    assert results.meta.hostname == "TEST-PC"
    assert len(results.findings) == 1
    assert results.findings[0].finding_id == "finding_a"


def test_parse_file_nonexistent_raises() -> None:
    """parse_file() raises ResultsParseError for a path that does not exist."""
    with pytest.raises(ResultsParseError, match="File not found"):
        ResultsParser().parse_file(Path("/nonexistent/path/results.json"))


def test_parse_upload_empty_raises() -> None:
    """parse_upload() raises ResultsParseError when data is empty bytes."""
    with pytest.raises(ResultsParseError, match="empty"):
        ResultsParser().parse_upload(b"")


def test_parse_upload_invalid_json_raises() -> None:
    """parse_upload() raises ResultsParseError on malformed JSON bytes."""
    with pytest.raises(ResultsParseError, match="Invalid JSON"):
        ResultsParser().parse_upload(b"[[[not json at all")


def test_parse_zip_with_results_json(tmp_path: Path) -> None:
    """parse_file() extracts results.json from a ZIP archive and parses it."""
    raw = _sample_results(
        [_make_finding("zip_finding", severity="medium", title="From ZIP")]
    )
    zip_bytes = _make_zip(json.dumps(raw).encode(), filename="results.json")
    zip_file = tmp_path / "upload.zip"
    zip_file.write_bytes(zip_bytes)

    results = ResultsParser().parse_file(zip_file)
    assert results.meta.hostname == "TEST-PC"
    assert len(results.findings) == 1
    assert results.findings[0].finding_id == "zip_finding"


def test_parse_zip_no_json_raises() -> None:
    """parse_upload() raises ResultsParseError when ZIP contains no JSON file."""
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.txt", "no json here")
    zip_bytes = buf.getvalue()

    with pytest.raises(ResultsParseError, match="No JSON file"):
        ResultsParser().parse_upload(zip_bytes)


def test_build_meta_missing_fields_uses_defaults() -> None:
    """_build_meta() fills missing fields with sane defaults."""
    parser = ResultsParser()
    meta = parser._build_meta({})

    assert meta.hostname == "unknown"
    assert meta.agent_version == ""
    assert meta.timestamp == ""
    assert meta.domain == ""
    assert meta.username == ""
    assert meta.is_admin is False
    assert meta.is_domain_joined is False
    assert meta.os_version == ""
    assert meta.architecture == ""
    assert meta.checks_run == []
    assert meta.total_duration_seconds == 0.0


def test_build_meta_partial_fields() -> None:
    """_build_meta() fills only missing fields when some are provided."""
    parser = ResultsParser()
    meta = parser._build_meta({"hostname": "PARTIAL-HOST", "is_admin": True})

    assert meta.hostname == "PARTIAL-HOST"
    assert meta.is_admin is True
    assert meta.domain == ""
    assert meta.checks_run == []


def test_build_finding_normalizes_severity_to_lowercase() -> None:
    """_build_finding() lowercases the severity value."""
    parser = ResultsParser()
    finding = parser._build_finding(
        {
            "check_id": "c1",
            "finding_id": "f1",
            "severity": "CRITICAL",
            "title": "Upper case severity",
        }
    )
    assert finding.severity == "critical"


def test_build_finding_normalizes_mixed_case_severity() -> None:
    """_build_finding() lowercases mixed-case severity (e.g. 'High')."""
    parser = ResultsParser()
    finding = parser._build_finding(
        {
            "check_id": "c1",
            "finding_id": "f1",
            "severity": "High",
            "title": "Mixed case",
        }
    )
    assert finding.severity == "high"


def test_build_finding_invalid_severity_defaults_to_info() -> None:
    """_build_finding() replaces unrecognised severity values with 'info'."""
    parser = ResultsParser()
    finding = parser._build_finding(
        {
            "check_id": "c1",
            "finding_id": "f1",
            "severity": "definitely_not_valid",
            "title": "Bad severity",
        }
    )
    assert finding.severity == "info"


def test_build_summary_computes_by_severity_from_findings() -> None:
    """_build_summary() computes by_severity counts from the findings list."""
    parser = ResultsParser()
    findings = [
        parser._build_finding(_make_finding("f1", severity="critical")),
        parser._build_finding(_make_finding("f2", severity="critical")),
        parser._build_finding(_make_finding("f3", severity="high")),
        parser._build_finding(_make_finding("f4", severity="info")),
    ]
    # Pass empty raw so by_severity must be computed from findings
    summary = parser._build_summary({}, findings)

    assert summary.by_severity.get("critical") == 2
    assert summary.by_severity.get("high") == 1
    assert summary.by_severity.get("info") == 1
    assert summary.total_findings == 4


def test_build_summary_uses_provided_total_when_present() -> None:
    """_build_summary() uses total_findings from raw dict when present."""
    parser = ResultsParser()
    summary = parser._build_summary({"total_findings": 99}, [])
    assert summary.total_findings == 99


def test_agent_results_critical_findings_inline() -> None:
    """AgentResults.critical_findings returns only critical-severity findings."""
    parser = ResultsParser()
    raw = _sample_results(
        [
            _make_finding("c1", severity="critical", title="Crit1"),
            _make_finding("c2", severity="critical", title="Crit2"),
            _make_finding("h1", severity="high", title="High1"),
            _make_finding("i1", severity="info", title="Info1"),
        ]
    )
    results = parser._parse_json(json.dumps(raw).encode())

    crits = results.critical_findings
    assert len(crits) == 2
    assert all(f.severity == "critical" for f in crits)
    assert {f.finding_id for f in crits} == {"c1", "c2"}


def test_agent_results_actionable_findings_inline() -> None:
    """AgentResults.actionable_findings returns critical and high severity findings."""
    parser = ResultsParser()
    raw = _sample_results(
        [
            _make_finding("c1", severity="critical", title="Crit"),
            _make_finding("h1", severity="high", title="High"),
            _make_finding("m1", severity="medium", title="Medium"),
            _make_finding("i1", severity="info", title="Info"),
        ]
    )
    results = parser._parse_json(json.dumps(raw).encode())

    actionable = results.actionable_findings
    assert len(actionable) == 2
    assert all(f.severity in ("critical", "high") for f in actionable)


def test_validate_catches_missing_meta_key() -> None:
    """validate() returns an error when the top-level 'meta' key is absent."""
    errors = ResultsParser().validate({"findings": []})
    assert any("meta" in e.lower() for e in errors)


def test_validate_catches_missing_required_finding_fields() -> None:
    """validate() reports errors for findings missing required fields."""
    raw = {
        "meta": {"hostname": "HOST"},
        "findings": [
            # Missing 'finding_id', 'severity', and 'title' — only check_id present
            {"check_id": "c1"},
        ],
    }
    errors = ResultsParser().validate(raw)
    missing_fields = {e for e in errors if "missing required field" in e}
    reported_fields = set()
    for e in missing_fields:
        for field_name in ("finding_id", "severity", "title"):
            if field_name in e:
                reported_fields.add(field_name)

    assert "finding_id" in reported_fields
    assert "severity" in reported_fields
    assert "title" in reported_fields


def test_validate_all_required_finding_fields_present() -> None:
    """validate() produces no field errors when all required fields are present."""
    raw = {
        "meta": {"hostname": "HOST"},
        "findings": [
            {
                "check_id": "c1",
                "finding_id": "f1",
                "severity": "info",
                "title": "All fields present",
            }
        ],
    }
    errors = ResultsParser().validate(raw)
    assert errors == []
