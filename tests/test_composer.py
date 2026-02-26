"""Tests for AgentComposer — check discovery, composition, obfuscation."""

from __future__ import annotations


from server.agent.composer import AgentComposer


def test_list_checks_count() -> None:
    """list_checks returns at least 16 check modules."""
    composer = AgentComposer()
    checks = composer.list_checks()
    assert len(checks) >= 16


def test_check_metadata_fields() -> None:
    """Every CheckMetadata object has the required fields populated."""
    composer = AgentComposer()
    checks = composer.list_checks()
    assert checks, "Expected at least one check"
    for check in checks:
        assert check.check_id, f"check_id missing on {check}"
        assert check.check_name, f"check_name missing on {check}"
        assert check.category, f"category missing on {check}"
        assert check.opsec_impact in ("low", "medium", "high"), (
            f"Invalid opsec_impact '{check.opsec_impact}' on {check.check_id}"
        )
        assert isinstance(check.estimated_time_seconds, int)
        assert isinstance(check.requires_admin, bool)


def test_compose_all_contains_invoke_seep() -> None:
    """Composed agent contains the 'Invoke-Seep' function entry point."""
    composer = AgentComposer()
    agent = composer.compose()
    assert "Invoke-Seep" in agent


def test_compose_all_contains_new_finding() -> None:
    """Composed agent contains the 'New-Finding' helper."""
    composer = AgentComposer()
    agent = composer.compose()
    assert "New-Finding" in agent


def test_compose_subset_smaller() -> None:
    """Composing 3 checks produces a shorter agent than composing all."""
    composer = AgentComposer()
    all_checks = composer.list_checks()
    assert len(all_checks) >= 3

    subset_ids = [
        all_checks[0].check_id,
        all_checks[1].check_id,
        all_checks[2].check_id,
    ]
    full_agent = composer.compose()
    subset_agent = composer.compose(checks=subset_ids)

    assert len(subset_agent) < len(full_agent), (
        "Subset agent should be smaller than the full agent"
    )


def test_compose_subset_still_functional() -> None:
    """Subset agent still contains Invoke-Seep and New-Finding."""
    composer = AgentComposer()
    checks = composer.list_checks()
    ids = [checks[0].check_id]
    agent = composer.compose(checks=ids)
    assert "Invoke-Seep" in agent
    assert "New-Finding" in agent


def test_compose_obfuscate_no_plain_mimikatz() -> None:
    """Obfuscated agent does not contain the plain string 'Mimikatz' in quotes."""
    composer = AgentComposer()
    agent = composer.compose(obfuscate=True)
    # The obfuscator replaces "Mimikatz" / 'Mimikatz' with concatenated form
    assert '"Mimikatz"' not in agent
    assert "'Mimikatz'" not in agent


def test_compose_strip_comments_default() -> None:
    """Default composition strips comments but the agent remains functional."""
    composer = AgentComposer()
    agent = composer.compose(strip_comments=True)
    # Agent is still usable
    assert "Invoke-Seep" in agent
    assert len(agent) > 100


def test_compose_no_strip_vs_strip() -> None:
    """Agent with comments kept is longer than agent with comments stripped."""
    composer = AgentComposer()
    with_comments = composer.compose(strip_comments=False)
    without_comments = composer.compose(strip_comments=True)
    assert len(with_comments) > len(without_comments)


def test_compose_requires_version_first_line() -> None:
    """First non-empty line of composed agent is the #Requires directive."""
    composer = AgentComposer()
    agent = composer.compose()
    first_nonempty = next(line for line in agent.splitlines() if line.strip())
    assert first_nonempty.strip().lower().startswith("#requires")


def test_compose_exclude() -> None:
    """Excluding a check ID produces a different (shorter or same) agent."""
    composer = AgentComposer()
    checks = composer.list_checks()
    assert checks
    exclude_id = checks[0].check_id
    full = composer.compose()
    excluded = composer.compose(exclude=[exclude_id])
    assert len(excluded) <= len(full)


def test_compose_cradle_contains_invoke_seep() -> None:
    """compose_cradle output contains 'Invoke-Seep' in the IEX cradle lines."""
    composer = AgentComposer()
    cradle = composer.compose_cradle("http://10.10.14.5")
    assert "Invoke-Seep" in cradle
    assert "10.10.14.5" in cradle
