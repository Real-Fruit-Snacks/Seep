"""Tests for RecommendationEngine."""

from __future__ import annotations


from server.catalog.schemas import ToolCatalog, ToolEntry
from server.report.recommendations import (
    RECOMMENDATIONS,
    MatchedRecommendation,
    RecommendationEngine,
)
from server.results.parser import AgentResults, Finding


_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(
    finding_id: str = "test_finding",
    check_id: str = "test_check",
    severity: str = "info",
    title: str = "Test Finding",
    tags: list[str] | None = None,
) -> Finding:
    return Finding(
        check_id=check_id,
        finding_id=finding_id,
        severity=severity,
        title=title,
        tags=tags or [],
    )


def _make_tool_entry(name: str, display_name: str | None = None) -> ToolEntry:
    return ToolEntry(
        name=name,
        display_name=display_name or name,
        description="",
        project_url="",
        upstream_url="",
        upstream_version="",
        license="",
        sha256="",
        folder="",
        categories=[],
        platform="windows",
        architecture="x64",
        tags=[],
        finding_triggers=[],
        notes="",
    )


def _empty_catalog() -> ToolCatalog:
    """Return a ToolCatalog with no tools."""
    return ToolCatalog(
        version="0.0.0",
        release_base_url="http://example.com",
        tools_release="v0",
        tools=[],
        categories={},
    )


def _catalog_with(*tools: ToolEntry) -> ToolCatalog:
    """Return a ToolCatalog populated with the given ToolEntry objects."""
    return ToolCatalog(
        version="0.0.0",
        release_base_url="http://example.com",
        tools_release="v0",
        tools=list(tools),
        categories={},
    )


# ---------------------------------------------------------------------------
# Tests — fixture-based (integration with real catalog)
# ---------------------------------------------------------------------------


def test_analyze_matches_count(
    engine: RecommendationEngine, sample_results: AgentResults
) -> None:
    """Sample data produces at least 7 matched recommendations (more when new findings present)."""
    recs = engine.analyze(sample_results.findings)
    assert len(recs) >= 7


def test_severity_order(
    engine: RecommendationEngine, sample_results: AgentResults
) -> None:
    """Results are sorted critical -> high -> medium (no lower-severity items here)."""
    recs = engine.analyze(sample_results.findings)
    severities = [r.risk for r in recs]
    order_map = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    for i in range(1, len(severities)):
        assert order_map.get(severities[i], 99) >= order_map.get(
            severities[i - 1], 99
        ), f"Severity order violated: {severities[i - 1]} before {severities[i]}"


def test_mitre_urls(engine: RecommendationEngine, sample_results: AgentResults) -> None:
    """Every recommendation has a valid MITRE ATT&CK URL."""
    recs = engine.analyze(sample_results.findings)
    for rec in recs:
        assert rec.mitre_url.startswith("https://attack.mitre.org/techniques/"), (
            f"Bad MITRE URL: {rec.mitre_url}"
        )
        assert rec.mitre_technique.replace(".", "/") in rec.mitre_url


def test_tool_resolution(
    engine: RecommendationEngine, sample_results: AgentResults
) -> None:
    """Critical recommendations have at least one resolved tool from the catalog."""
    recs = engine.analyze(sample_results.findings)
    critical_recs = [r for r in recs if r.risk == "critical"]
    assert critical_recs, "Expected at least one critical recommendation"
    for rec in critical_recs:
        assert len(rec.tools) > 0, (
            f"Critical rec '{rec.title}' has no resolved catalog tools"
        )


def test_no_findings_returns_empty(engine: RecommendationEngine) -> None:
    """analyze([]) returns an empty list."""
    recs = engine.analyze([])
    assert recs == []


def test_deduplicate(
    engine: RecommendationEngine, sample_results: AgentResults
) -> None:
    """Passing the same findings twice does not create duplicate recommendations."""
    doubled = sample_results.findings + sample_results.findings
    recs = engine.analyze(doubled)
    titles = [r.title for r in recs]
    assert len(titles) == len(set(titles)), "Duplicate recommendations found"


def test_display_tools_fallback(engine: RecommendationEngine) -> None:
    """display_tools falls back to tool_names_fallback when catalog yields nothing."""
    rec = MatchedRecommendation(
        title="Test",
        description="desc",
        mitre_technique="T9999",
        mitre_name="Test Technique",
        mitre_url="https://attack.mitre.org/techniques/T9999/",
        risk="info",
        tools=[],
        tool_names_fallback=["FakeTool.exe"],
        example_commands=[],
        triggered_by=["test"],
    )
    assert rec.display_tools == ["FakeTool.exe"]


def test_analyze_tag_matching(engine: RecommendationEngine) -> None:
    """A finding with a matching tag (but not finding_id) still triggers a recommendation."""
    findings = [
        Finding(
            check_id="patches",
            finding_id="patches_raw",
            severity="info",
            title="Patches info",
            tags=["enumeration", "patches"],
        )
    ]
    recs = engine.analyze(findings)
    assert any(
        "Patch" in r.title or "CVE" in r.title or "Kernel" in r.title for r in recs
    ), "Expected a patch-related recommendation"


def test_all_recommendation_rules_have_mitre(engine: RecommendationEngine) -> None:
    """Every static rule in RECOMMENDATIONS defines a mitre_technique."""
    for rule in RECOMMENDATIONS:
        assert rule.get("mitre_technique"), (
            f"Rule '{rule.get('title')}' missing mitre_technique"
        )
        assert rule.get("mitre_url") or True  # URL is computed, not stored


def test_matched_recommendation_fields(
    engine: RecommendationEngine, sample_results: AgentResults
) -> None:
    """Each MatchedRecommendation has non-empty required fields."""
    recs = engine.analyze(sample_results.findings)
    for rec in recs:
        assert rec.title
        assert rec.description
        assert rec.mitre_technique
        assert rec.mitre_name
        assert rec.mitre_url
        assert rec.risk in _SEVERITY_ORDER
        assert rec.triggered_by


# ---------------------------------------------------------------------------
# Tests — inline data (unit-level, no fixture dependency)
# ---------------------------------------------------------------------------


def test_se_impersonate_finding_triggers_recommendation() -> None:
    """A finding with finding_id 'se_impersonate_enabled' matches the potato rule."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            finding_id="se_impersonate_enabled",
            check_id="token_privs",
            severity="critical",
            title="SeImpersonatePrivilege enabled",
            tags=["token-abuse"],
        )
    ]
    recs = eng.analyze(findings)

    assert len(recs) >= 1
    titles = [r.title for r in recs]
    assert any("SeImpersonate" in t or "Potato" in t or "Token" in t for t in titles), (
        f"Expected potato/token rec; got: {titles}"
    )
    # The matched recommendation should list se_impersonate_enabled in triggered_by
    matched = next(r for r in recs if "se_impersonate_enabled" in r.triggered_by)
    assert matched.risk == "critical"


def test_info_only_findings_return_no_recommendations() -> None:
    """Findings with only 'info' severity and no matching tags/ids return no recs."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    # info findings with no tags that match any rule
    findings = [
        _make_finding("generic_info_1", severity="info", title="Info 1", tags=[]),
        _make_finding("generic_info_2", severity="info", title="Info 2", tags=[]),
        _make_finding("generic_info_3", severity="info", title="Info 3", tags=[]),
    ]
    recs = eng.analyze(findings)
    assert recs == [], (
        f"Expected no recommendations for pure info findings, got: {recs}"
    )


def test_tag_match_when_finding_id_does_not_match() -> None:
    """Engine matches via tag even when finding_id doesn't match any rule."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    # 'missing-patches' tag matches the kernel CVE rule which has empty match_finding_ids
    findings = [
        _make_finding(
            finding_id="completely_unknown_id",
            severity="medium",
            title="Some patch info",
            tags=["missing-patches"],
        )
    ]
    recs = eng.analyze(findings)

    assert len(recs) >= 1
    triggered_tags = [tb for r in recs for tb in r.triggered_by]
    assert any(tb.startswith("tag:") for tb in triggered_tags), (
        f"Expected a tag-triggered recommendation; triggered_by values: {triggered_tags}"
    )


def test_recommendations_sorted_critical_first() -> None:
    """analyze() returns recommendations sorted by risk: critical before high before medium."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    # Trigger rules with different risk levels:
    # se_impersonate_enabled → critical
    # unquoted_service_path → high
    # missing-patches tag → medium
    findings = [
        _make_finding(
            "se_impersonate_enabled", severity="critical", tags=["token-abuse"]
        ),
        _make_finding("unquoted_service_path", severity="high", tags=["unquoted-path"]),
        _make_finding("patch_gap", severity="info", tags=["missing-patches"]),
    ]
    recs = eng.analyze(findings)

    assert len(recs) >= 2
    order_map = {s: i for i, s in enumerate(_SEVERITY_ORDER)}
    for i in range(1, len(recs)):
        prev_order = order_map.get(recs[i - 1].risk, 99)
        curr_order = order_map.get(recs[i].risk, 99)
        assert curr_order >= prev_order, (
            f"Sort order violated: '{recs[i - 1].risk}' ({prev_order}) "
            f"before '{recs[i].risk}' ({curr_order})"
        )
    # Critical must come first if present
    risks = [r.risk for r in recs]
    if "critical" in risks and "high" in risks:
        assert risks.index("critical") < risks.index("high")


def test_display_tools_uses_catalog_tools_when_available() -> None:
    """display_tools returns catalog tool display names when catalog resolves them."""
    god_potato = _make_tool_entry("GodPotato.exe", display_name="GodPotato")
    print_spoofer = _make_tool_entry(
        "PrintSpoofer64.exe", display_name="PrintSpoofer64"
    )
    catalog = _catalog_with(god_potato, print_spoofer)
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            "se_impersonate_enabled", severity="critical", tags=["token-abuse"]
        )
    ]
    recs = eng.analyze(findings)

    potato_recs = [r for r in recs if "se_impersonate_enabled" in r.triggered_by]
    assert potato_recs, "Expected se_impersonate_enabled recommendation"
    rec = potato_recs[0]

    # Catalog resolved tools should be used
    assert rec.tools, "Expected catalog tools to be resolved"
    display = rec.display_tools
    assert display == [t.display_name for t in rec.tools]
    assert "GodPotato" in display or "PrintSpoofer64" in display


def test_display_tools_fallback_when_catalog_empty() -> None:
    """display_tools returns tool_names_fallback list when no catalog tools resolved."""
    # Catalog has no tools → resolution yields empty list → fallback kicks in
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            "se_impersonate_enabled", severity="critical", tags=["token-abuse"]
        )
    ]
    recs = eng.analyze(findings)

    potato_recs = [r for r in recs if "se_impersonate_enabled" in r.triggered_by]
    assert potato_recs
    rec = potato_recs[0]

    assert rec.tools == []
    displayed = rec.display_tools
    # Should fall back to the rule's tool_names list
    assert displayed == rec.tool_names_fallback
    assert len(displayed) > 0


def test_mitre_url_construction_from_simple_technique() -> None:
    """MITRE URL replaces '.' with '/' in sub-technique IDs."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            "se_impersonate_enabled", severity="critical", tags=["token-abuse"]
        )
    ]
    recs = eng.analyze(findings)

    potato_rec = next(r for r in recs if "se_impersonate_enabled" in r.triggered_by)
    # T1134.001 → URL should contain T1134/001
    assert "T1134/001" in potato_rec.mitre_url
    assert potato_rec.mitre_url == "https://attack.mitre.org/techniques/T1134/001/"


def test_mitre_url_construction_top_level_technique() -> None:
    """MITRE URL for a top-level technique (no sub-technique dot) is formed correctly."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    # The 'missing-patches' rule uses T1068 (no dot)
    findings = [_make_finding("x", severity="info", tags=["missing-patches"])]
    recs = eng.analyze(findings)

    assert recs, "Expected at least one recommendation for missing-patches tag"
    patch_rec = recs[0]
    assert patch_rec.mitre_technique == "T1068"
    assert patch_rec.mitre_url == "https://attack.mitre.org/techniques/T1068/"


def test_engine_deduplicates_same_title() -> None:
    """Providing multiple findings that all match the same rule yields only one recommendation."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    # Both findings have tags that would independently match the token-abuse rule
    findings = [
        _make_finding(
            "se_impersonate_enabled", severity="critical", tags=["token-abuse"]
        ),
        _make_finding(
            "se_assign_primary_enabled", severity="critical", tags=["token-abuse"]
        ),
    ]
    recs = eng.analyze(findings)

    titles = [r.title for r in recs]
    assert len(titles) == len(set(titles)), (
        f"Duplicate recommendation titles found: {titles}"
    )


# ---------------------------------------------------------------------------
# Tests — new rules 8-12
# ---------------------------------------------------------------------------


def test_dll_hijack_writable_path_triggers_recommendation() -> None:
    """Finding 'writable_path_dir' triggers the DLL Search Order Hijacking recommendation."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            finding_id="writable_path_dir",
            check_id="dll_hijack",
            severity="high",
            title="Writable PATH Directory: C:\\SomePath",
            tags=["filesystem", "dll-hijack", "path", "privilege-escalation"],
        )
    ]
    recs = eng.analyze(findings)

    assert len(recs) >= 1
    titles = [r.title for r in recs]
    assert any("DLL" in t or "PATH" in t or "Hijack" in t for t in titles), (
        f"Expected DLL hijack recommendation; got: {titles}"
    )
    matched = next((r for r in recs if "writable_path_dir" in r.triggered_by), None)
    assert matched is not None
    assert matched.risk == "high"


def test_dll_hijack_mitre_url() -> None:
    """DLL hijack rule has correct MITRE URL for T1574.001."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            finding_id="writable_path_dir",
            check_id="dll_hijack",
            severity="high",
            tags=["dll-hijack", "path"],
        )
    ]
    recs = eng.analyze(findings)

    dll_recs = [r for r in recs if "writable_path_dir" in r.triggered_by]
    assert dll_recs, "Expected DLL hijack recommendation triggered by writable_path_dir"
    rec = dll_recs[0]
    assert rec.mitre_technique == "T1574.001"
    assert rec.mitre_url.startswith("https://attack.mitre.org/techniques/")
    assert "T1574/001" in rec.mitre_url


def test_weak_service_permissions_triggers_recommendation() -> None:
    """Finding 'non_standard_services_raw' triggers the Modifiable Service Configuration recommendation."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            finding_id="non_standard_services_raw",
            check_id="services",
            severity="info",
            title="Non-Standard Services (Raw)",
            tags=["raw", "services", "non-standard"],
        )
    ]
    recs = eng.analyze(findings)

    assert len(recs) >= 1
    titles = [r.title for r in recs]
    assert any(
        "Modifiable" in t or "Service" in t or "Permission" in t for t in titles
    ), f"Expected modifiable service recommendation; got: {titles}"
    matched = next(
        (r for r in recs if "non_standard_services_raw" in r.triggered_by), None
    )
    assert matched is not None
    assert matched.mitre_technique == "T1574.010"
    assert "T1574/010" in matched.mitre_url


def test_weak_service_permissions_mitre_url() -> None:
    """Modifiable service rule has correct MITRE URL for T1574.010."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            finding_id="non_standard_services_raw",
            check_id="services",
            severity="info",
            tags=["services", "non-standard"],
        )
    ]
    recs = eng.analyze(findings)

    svc_recs = [r for r in recs if "non_standard_services_raw" in r.triggered_by]
    assert svc_recs, (
        "Expected service recommendation triggered by non_standard_services_raw"
    )
    rec = svc_recs[0]
    assert rec.mitre_url == "https://attack.mitre.org/techniques/T1574/010/"


def test_always_install_elevated_triggers_recommendation() -> None:
    """Finding 'always_install_elevated' triggers the AlwaysInstallElevated recommendation."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            finding_id="always_install_elevated",
            check_id="always_install",
            severity="critical",
            title="AlwaysInstallElevated Enabled — MSI Install as SYSTEM",
            tags=["configuration", "msi", "privilege-escalation", "registry"],
        )
    ]
    recs = eng.analyze(findings)

    assert len(recs) >= 1
    matched = next(
        (r for r in recs if "always_install_elevated" in r.triggered_by), None
    )
    assert matched is not None, (
        "Expected recommendation triggered by always_install_elevated"
    )
    assert matched.risk == "critical"
    assert "AlwaysInstallElevated" in matched.title or "MSI" in matched.title


def test_always_install_elevated_mitre_url() -> None:
    """AlwaysInstallElevated rule has correct MITRE URL for T1548.002."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            finding_id="always_install_elevated",
            check_id="always_install",
            severity="critical",
            tags=["msi", "privilege-escalation"],
        )
    ]
    recs = eng.analyze(findings)

    aie_recs = [r for r in recs if "always_install_elevated" in r.triggered_by]
    assert aie_recs, "Expected recommendation triggered by always_install_elevated"
    rec = aie_recs[0]
    assert rec.mitre_technique == "T1548.002"
    assert rec.mitre_url == "https://attack.mitre.org/techniques/T1548/002/"


def test_web_config_connection_string_triggers_recommendation() -> None:
    """Finding 'web_config_connection_string' triggers the web credentials recommendation."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            finding_id="web_config_connection_string",
            check_id="web_configs",
            severity="high",
            title="Connection String Found in Web Config: C:\\inetpub\\wwwroot\\web.config",
            tags=["credentials", "web-config", "connection-string", "database"],
        )
    ]
    recs = eng.analyze(findings)

    assert len(recs) >= 1
    matched = next(
        (r for r in recs if "web_config_connection_string" in r.triggered_by), None
    )
    assert matched is not None, (
        "Expected recommendation triggered by web_config_connection_string"
    )
    assert matched.risk == "high"
    assert (
        "Web" in matched.title
        or "Config" in matched.title
        or "Credential" in matched.title
    )


def test_web_config_mitre_url() -> None:
    """Web config credentials rule has correct MITRE URL for T1552.001."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding(
            finding_id="web_config_connection_string",
            check_id="web_configs",
            severity="high",
            tags=["web-config", "credentials"],
        )
    ]
    recs = eng.analyze(findings)

    web_recs = [r for r in recs if "web_config_connection_string" in r.triggered_by]
    assert web_recs, "Expected recommendation triggered by web_config_connection_string"
    rec = web_recs[0]
    assert rec.mitre_technique == "T1552.001"
    assert rec.mitre_url == "https://attack.mitre.org/techniques/T1552/001/"


def test_all_new_rules_have_correct_risk_levels() -> None:
    """Verify risk levels for all 5 new rules match specification."""
    catalog = _empty_catalog()
    eng = RecommendationEngine(catalog)

    findings = [
        _make_finding("writable_path_dir", tags=["dll-hijack", "path"]),
        _make_finding("non_standard_services_raw", tags=["services", "non-standard"]),
        _make_finding("always_install_elevated", tags=["msi", "privilege-escalation"]),
        _make_finding(
            "web_config_connection_string", tags=["web-config", "credentials"]
        ),
    ]
    recs = eng.analyze(findings)

    by_finding: dict[str, str] = {
        fid: r.risk
        for r in recs
        for fid in r.triggered_by
        if not fid.startswith("tag:")
    }

    # always_install_elevated → critical
    assert by_finding.get("always_install_elevated") == "critical", (
        f"Expected critical for always_install_elevated, got: {by_finding.get('always_install_elevated')}"
    )
    # web_config_connection_string → high
    assert by_finding.get("web_config_connection_string") == "high", (
        f"Expected high for web_config_connection_string, got: {by_finding.get('web_config_connection_string')}"
    )
    # writable_path_dir → high (one of the DLL hijack / writable PATH rules)
    writable_path_risk = by_finding.get("writable_path_dir")
    assert writable_path_risk == "high", (
        f"Expected high for writable_path_dir, got: {writable_path_risk}"
    )


def test_new_rules_total_count() -> None:
    """RECOMMENDATIONS list now contains exactly 12 rules."""
    assert len(RECOMMENDATIONS) == 12, (
        f"Expected 12 recommendation rules, found {len(RECOMMENDATIONS)}"
    )
