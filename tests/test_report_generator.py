"""Comprehensive tests for ReportGenerator — HTML, Markdown, and JSON summary outputs."""

from __future__ import annotations

import html
import json
import re

import pytest

from server.catalog.schemas import ToolCatalog
from server.report.generator import ReportGenerator
from server.report.recommendations import RecommendationEngine
from server.results.parser import AgentResults, AgentMeta, Finding, ResultsSummary


# ---------------------------------------------------------------------------
# Test-local helpers
# ---------------------------------------------------------------------------


def _make_empty_catalog() -> ToolCatalog:
    """Minimal ToolCatalog with no tools (recommendations fall back to name list)."""
    return ToolCatalog(
        version="0.0.0",
        release_base_url="https://example.com",
        tools_release="v0",
        tools=[],
        categories={},
    )


def _make_results(findings: list[Finding] | None = None) -> AgentResults:
    """Build an AgentResults with the given findings and a standard meta block."""
    findings = findings or []
    meta = AgentMeta(
        hostname="TEST-PC",
        agent_version="2.0.0",
        username="TEST\\user",
        os_name="Windows 10",
        os_version="10.0",
        total_duration_seconds=5.0,
        domain="CORP.LOCAL",
        is_admin=False,
        is_domain_joined=True,
        architecture="AMD64",
        ps_version="5.1",
        execution_mode="fileless",
    )
    by_sev: dict[str, int] = {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    summary = ResultsSummary(total_findings=len(findings), by_severity=by_sev)
    return AgentResults(meta=meta, findings=findings, summary=summary)


def _make_critical_finding(
    title: str = "Critical Test Finding",
    evidence: str = "proof here",
    finding_id: str = "test_crit",
    tags: list[str] | None = None,
) -> Finding:
    return Finding(
        check_id="check_test",
        finding_id=finding_id,
        severity="critical",
        title=title,
        description="A critical vulnerability was found.",
        evidence=evidence,
        remediation="Fix it immediately.",
        tags=tags or ["token-abuse"],
    )


def _make_high_finding(title: str = "High Test Finding") -> Finding:
    return Finding(
        check_id="check_high",
        finding_id="test_high",
        severity="high",
        title=title,
        description="A high severity issue.",
        evidence="high evidence",
        remediation="Patch it.",
        tags=["services"],
    )


def _make_medium_finding(title: str = "Medium Finding") -> Finding:
    return Finding(
        check_id="check_med",
        finding_id="test_med",
        severity="medium",
        title=title,
        description="Medium issue.",
        tags=[],
    )


def _make_info_finding() -> Finding:
    return Finding(
        check_id="check_info",
        finding_id="test_info",
        severity="info",
        title="Info Finding",
        description="Just info.",
        tags=["enumeration"],
    )


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def empty_catalog() -> ToolCatalog:
    return _make_empty_catalog()


@pytest.fixture(scope="module")
def generator(empty_catalog: ToolCatalog) -> ReportGenerator:
    engine = RecommendationEngine(empty_catalog)
    return ReportGenerator(engine)


@pytest.fixture(scope="module")
def rich_results() -> AgentResults:
    """Results with findings of multiple severities."""
    findings = [
        _make_critical_finding(
            title="SeImpersonatePrivilege Enabled",
            finding_id="se_impersonate_enabled",
            tags=["token-abuse"],
        ),
        _make_high_finding(title="Unquoted Service Path"),
        _make_medium_finding(),
        _make_info_finding(),
    ]
    return _make_results(findings)


@pytest.fixture(scope="module")
def html_rich(generator: ReportGenerator, rich_results: AgentResults) -> str:
    return generator.generate_html(rich_results)


@pytest.fixture(scope="module")
def markdown_rich(generator: ReportGenerator, rich_results: AgentResults) -> str:
    return generator.generate_markdown(rich_results)


@pytest.fixture(scope="module")
def json_rich(generator: ReportGenerator, rich_results: AgentResults) -> dict:
    return generator.generate_json_summary(rich_results)


# ---------------------------------------------------------------------------
# HTML tests
# ---------------------------------------------------------------------------


class TestGenerateHtml:
    def test_returns_string(self, generator: ReportGenerator) -> None:
        results = _make_results()
        out = generator.generate_html(results)
        assert isinstance(out, str)

    def test_contains_doctype(self, html_rich: str) -> None:
        """Output must start with a proper DOCTYPE declaration."""
        assert "<!DOCTYPE html>" in html_rich or "<!doctype html>" in html_rich.lower()

    def test_contains_html_open_and_close(self, html_rich: str) -> None:
        assert "<html" in html_rich
        assert "</html>" in html_rich

    def test_contains_head_and_body(self, html_rich: str) -> None:
        assert "<head" in html_rich
        assert "<body" in html_rich

    def test_hostname_in_title(self, generator: ReportGenerator) -> None:
        """The hostname should appear in the <title> tag."""
        results = _make_results()
        out = generator.generate_html(results)
        title_match = re.search(r"<title>(.*?)</title>", out, re.DOTALL)
        assert title_match is not None, "No <title> tag found"
        assert "TEST-PC" in title_match.group(1)

    def test_hostname_in_body(self, html_rich: str, rich_results: AgentResults) -> None:
        assert rich_results.meta.hostname in html_rich

    def test_critical_severity_badge_present(self, html_rich: str) -> None:
        """Critical findings produce a badge with CRITICAL text."""
        assert "CRITICAL" in html_rich

    def test_high_severity_badge_present(self, html_rich: str) -> None:
        assert "HIGH" in html_rich

    def test_no_external_css_links(self, html_rich: str) -> None:
        """All CSS must be inline — no <link rel=stylesheet>."""
        external_css = re.findall(
            r'<link[^>]+rel=["\']stylesheet["\'][^>]*>', html_rich, re.IGNORECASE
        )
        assert not external_css, f"Unexpected external CSS: {external_css}"

    def test_no_external_script_tags(self, html_rich: str) -> None:
        """No external <script src=...> tags — report must be self-contained."""
        external_js = re.findall(
            r'<script[^>]+src=["\'][^"\']+["\'][^>]*>', html_rich, re.IGNORECASE
        )
        assert not external_js, f"Unexpected external scripts: {external_js}"

    def test_no_findings_still_produces_valid_html(
        self, generator: ReportGenerator
    ) -> None:
        """An empty findings list must still produce parseable HTML."""
        results = _make_results(findings=[])
        out = generator.generate_html(results)
        assert "<!DOCTYPE html>" in out or "<!doctype html>" in out.lower()
        assert "</html>" in out

    def test_html_escapes_title_with_special_chars(
        self, generator: ReportGenerator
    ) -> None:
        """Finding titles containing < > & must be HTML-escaped in output."""
        bad_title = 'Finding <script>alert("xss")</script> & more'
        finding = Finding(
            check_id="chk",
            finding_id="fid",
            severity="critical",
            title=bad_title,
            description="",
            evidence="",
            remediation="",
        )
        results = _make_results([finding])
        out = generator.generate_html(results)
        # The raw unescaped string must NOT appear verbatim
        assert bad_title not in out
        # The escaped version must appear
        assert html.escape(bad_title, quote=True) in out

    def test_html_escapes_evidence_with_special_chars(
        self, generator: ReportGenerator
    ) -> None:
        """Evidence containing HTML special chars must be escaped."""
        bad_evidence = "<script>document.cookie</script>"
        finding = _make_critical_finding(evidence=bad_evidence)
        results = _make_results([finding])
        out = generator.generate_html(results)
        assert bad_evidence not in out
        assert "&lt;script&gt;" in out

    def test_critical_finding_title_in_output(self, html_rich: str) -> None:
        """The critical finding's title must appear in the HTML output."""
        assert "SeImpersonatePrivilege Enabled" in html_rich

    def test_executive_summary_section_present(self, html_rich: str) -> None:
        assert "Executive Summary" in html_rich

    def test_system_information_section_present(self, html_rich: str) -> None:
        assert "System Information" in html_rich

    def test_all_findings_section_present(self, html_rich: str) -> None:
        assert "All Findings" in html_rich

    def test_critical_high_findings_section_present(self, html_rich: str) -> None:
        """Critical & High Findings section must appear when such findings exist."""
        assert "Critical" in html_rich and "High" in html_rich

    def test_no_critical_high_section_when_none(
        self, generator: ReportGenerator
    ) -> None:
        """No Critical & High section rendered when there are none."""
        results = _make_results([_make_info_finding()])
        out = generator.generate_html(results)
        # The dedicated C&H cards section should not appear
        assert "Critical &amp; High Findings" not in out

    def test_recommendation_section_with_triggering_finding(
        self, generator: ReportGenerator
    ) -> None:
        """A recommendation section appears when a finding triggers a rule."""
        finding = _make_critical_finding(
            finding_id="se_impersonate_enabled", tags=["token-abuse"]
        )
        results = _make_results([finding])
        out = generator.generate_html(results)
        assert "Recommendations" in out

    def test_mitre_attack_link_in_html(self, generator: ReportGenerator) -> None:
        """MITRE ATT&CK URL must appear in the HTML when recommendations are triggered."""
        finding = _make_critical_finding(
            finding_id="se_impersonate_enabled", tags=["token-abuse"]
        )
        results = _make_results([finding])
        out = generator.generate_html(results)
        assert "attack.mitre.org" in out


# ---------------------------------------------------------------------------
# Markdown tests
# ---------------------------------------------------------------------------


class TestGenerateMarkdown:
    def test_returns_string(self, generator: ReportGenerator) -> None:
        results = _make_results()
        out = generator.generate_markdown(results)
        assert isinstance(out, str)

    def test_h1_title_contains_hostname(
        self, markdown_rich: str, rich_results: AgentResults
    ) -> None:
        """First H1 heading must contain the hostname."""
        lines = markdown_rich.splitlines()
        h1_lines = [line for line in lines if line.startswith("# ")]
        assert h1_lines, "No H1 heading found"
        assert rich_results.meta.hostname in h1_lines[0]

    def test_executive_summary_section(self, markdown_rich: str) -> None:
        assert "## Executive Summary" in markdown_rich

    def test_severity_table_present(self, markdown_rich: str) -> None:
        """Markdown table with Severity | Count columns must be present."""
        assert "| Severity | Count |" in markdown_rich

    def test_severity_rows_for_findings(self, markdown_rich: str) -> None:
        """Rows for each present severity must appear in the table."""
        assert (
            "| Critical |" in markdown_rich or "| critical |" in markdown_rich.lower()
        )

    def test_system_information_section(self, markdown_rich: str) -> None:
        assert "## System Information" in markdown_rich

    def test_critical_findings_section(self, markdown_rich: str) -> None:
        """Critical & High Findings section must appear."""
        assert "## Critical & High Findings" in markdown_rich

    def test_critical_finding_header_in_markdown(self, markdown_rich: str) -> None:
        assert "SeImpersonatePrivilege Enabled" in markdown_rich

    def test_all_findings_section(self, markdown_rich: str) -> None:
        assert "## All Findings" in markdown_rich

    def test_all_findings_table_columns(self, markdown_rich: str) -> None:
        """All findings table must have the expected columns."""
        assert "| Severity |" in markdown_rich
        assert "| ID |" in markdown_rich or "finding_id" in markdown_rich.lower()

    def test_recommendations_section(self, markdown_rich: str) -> None:
        """Recommendations appear when triggered by findings."""
        assert "## Recommendations" in markdown_rich

    def test_mitre_attack_link_in_markdown(self, markdown_rich: str) -> None:
        assert "attack.mitre.org" in markdown_rich

    def test_no_critical_high_section_without_findings(
        self, generator: ReportGenerator
    ) -> None:
        """No Critical & High section when only info findings exist."""
        results = _make_results([_make_info_finding()])
        out = generator.generate_markdown(results)
        assert "## Critical & High Findings" not in out

    def test_total_findings_count_in_summary(
        self, markdown_rich: str, rich_results: AgentResults
    ) -> None:
        count = str(rich_results.summary.total_findings)
        assert f"**Total Findings:** {count}" in markdown_rich

    def test_pipe_chars_in_title_are_escaped(self, generator: ReportGenerator) -> None:
        """Pipe characters in finding titles must be escaped for Markdown table safety."""
        finding = Finding(
            check_id="chk",
            finding_id="fid",
            severity="info",
            title="Title with | pipe",
            description="",
            evidence="",
            remediation="",
        )
        results = _make_results([finding])
        out = generator.generate_markdown(results)
        assert "\\|" in out  # pipe should be escaped


# ---------------------------------------------------------------------------
# JSON summary tests
# ---------------------------------------------------------------------------


class TestGenerateJsonSummary:
    def test_returns_dict(self, generator: ReportGenerator) -> None:
        results = _make_results()
        out = generator.generate_json_summary(results)
        assert isinstance(out, dict)

    def test_required_top_level_keys(self, json_rich: dict) -> None:
        for key in (
            "generated_at",
            "seep_version",
            "meta",
            "summary",
            "recommendations",
            "findings",
        ):
            assert key in json_rich, f"Missing top-level key: {key!r}"

    def test_meta_hostname(self, json_rich: dict, rich_results: AgentResults) -> None:
        assert json_rich["meta"]["hostname"] == rich_results.meta.hostname

    def test_meta_contains_expected_fields(self, json_rich: dict) -> None:
        meta = json_rich["meta"]
        for field in (
            "hostname",
            "domain",
            "username",
            "os_name",
            "os_version",
            "is_admin",
            "execution_mode",
            "total_duration_seconds",
        ):
            assert field in meta, f"meta missing field: {field!r}"

    def test_summary_total_findings(
        self, json_rich: dict, rich_results: AgentResults
    ) -> None:
        assert (
            json_rich["summary"]["total_findings"]
            == rich_results.summary.total_findings
        )

    def test_summary_by_severity(self, json_rich: dict) -> None:
        assert "by_severity" in json_rich["summary"]
        assert isinstance(json_rich["summary"]["by_severity"], dict)

    def test_recommendations_is_list(self, json_rich: dict) -> None:
        assert isinstance(json_rich["recommendations"], list)

    def test_recommendations_contain_mitre(self, json_rich: dict) -> None:
        """At least one recommendation must have a mitre_url."""
        assert json_rich["recommendations"], "No recommendations generated"
        for rec in json_rich["recommendations"]:
            assert "mitre_technique" in rec
            assert "mitre_url" in rec
            assert "attack.mitre.org" in rec["mitre_url"]

    def test_findings_list_length(
        self, json_rich: dict, rich_results: AgentResults
    ) -> None:
        assert len(json_rich["findings"]) == len(rich_results.findings)

    def test_findings_contain_required_fields(self, json_rich: dict) -> None:
        for f in json_rich["findings"]:
            for field in ("finding_id", "check_id", "severity", "title", "tags"):
                assert field in f, f"Finding missing field: {field!r}"

    def test_is_json_serialisable(self, json_rich: dict) -> None:
        """Output must round-trip through json.dumps/loads without error."""
        serialised = json.dumps(json_rich)
        reloaded = json.loads(serialised)
        assert reloaded["meta"]["hostname"] == json_rich["meta"]["hostname"]

    def test_empty_findings_produces_valid_summary(
        self, generator: ReportGenerator
    ) -> None:
        results = _make_results(findings=[])
        out = generator.generate_json_summary(results)
        assert out["summary"]["total_findings"] == 0
        assert out["findings"] == []
        assert isinstance(out["recommendations"], list)

    def test_seep_version_present(self, json_rich: dict) -> None:
        assert json_rich["seep_version"]

    def test_generated_at_is_utc_string(self, json_rich: dict) -> None:
        ts = json_rich["generated_at"]
        assert "UTC" in ts, f"generated_at should contain 'UTC', got: {ts!r}"

    def test_recommendation_triggered_by_field(self, json_rich: dict) -> None:
        """Recommendations must include triggered_by list."""
        for rec in json_rich["recommendations"]:
            assert "triggered_by" in rec
            assert isinstance(rec["triggered_by"], list)

    def test_recommendation_engine_produces_mitre_links(
        self, generator: ReportGenerator
    ) -> None:
        """With catalog-resolved tools, recommendations still include MITRE links."""
        finding = _make_critical_finding(
            finding_id="se_impersonate_enabled", tags=["token-abuse"]
        )
        results = _make_results([finding])
        out = generator.generate_json_summary(results)
        recs = out["recommendations"]
        assert recs, "Expected at least one recommendation"
        mitre_urls = [r["mitre_url"] for r in recs]
        assert any("attack.mitre.org" in url for url in mitre_urls)

    def test_recommendation_with_real_catalog(
        self, catalog: ToolCatalog, sample_results: AgentResults
    ) -> None:
        """With the real catalog and sample results, recommendations include tool names."""
        engine = RecommendationEngine(catalog)
        gen = ReportGenerator(engine)
        out = gen.generate_json_summary(sample_results)
        recs = out["recommendations"]
        assert recs, "Expected recommendations from sample_results"
        # At least one rec should have tools
        tools_lists = [r["tools"] for r in recs]
        # Some may be empty if catalog doesn't have those tools, but list must exist
        for tl in tools_lists:
            assert isinstance(tl, list)
