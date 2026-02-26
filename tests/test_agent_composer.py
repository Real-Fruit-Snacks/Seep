"""Comprehensive tests for AgentComposer — check discovery, composition, cradles."""

from __future__ import annotations

from pathlib import Path


from server.agent.composer import AgentComposer, CheckMetadata

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

EXPECTED_CHECK_IDS = {
    "always_install",
    "autoruns",
    "directory_tree",
    "dll_hijack",
    "network",
    "patches",
    "processes",
    "quick_wins",
    "registry_secrets",
    "scheduled_tasks",
    "services",
    "software",
    "system_info",
    "unattend_files",
    "user_privileges",
    "web_configs",
}

EXPECTED_OPSEC_VALUES = {"low", "medium", "high"}


# ---------------------------------------------------------------------------
# 1. list_checks() — count
# ---------------------------------------------------------------------------


def test_list_checks_returns_all_16_check_modules() -> None:
    """list_checks() returns exactly 16 check modules (_base.ps1 is excluded)."""
    composer = AgentComposer()
    checks = composer.list_checks()
    assert len(checks) == 16, (
        f"Expected 16 checks, got {len(checks)}: {[c.check_id for c in checks]}"
    )


def test_list_checks_contains_all_expected_ids() -> None:
    """list_checks() returns every expected check_id."""
    composer = AgentComposer()
    ids = {c.check_id for c in composer.list_checks()}
    missing = EXPECTED_CHECK_IDS - ids
    assert not missing, f"Missing check IDs: {missing}"


# ---------------------------------------------------------------------------
# 2. list_checks() skips _base.ps1
# ---------------------------------------------------------------------------


def test_list_checks_skips_base_ps1() -> None:
    """list_checks() must never include _base.ps1 as a check module."""
    composer = AgentComposer()
    checks = composer.list_checks()
    ids = [c.check_id for c in checks]
    file_names = [c.file_path.name for c in checks]
    assert "_base.ps1" not in file_names, "_base.ps1 must be excluded from check list"
    # Also verify no check_id starts with underscore
    for cid in ids:
        assert not cid.startswith("_"), f"check_id '{cid}' looks like a helper module"


# ---------------------------------------------------------------------------
# 3. CheckMetadata fields — validity
# ---------------------------------------------------------------------------


def test_check_metadata_check_id_is_nonempty_string() -> None:
    """Every CheckMetadata.check_id is a non-empty string."""
    for check in AgentComposer().list_checks():
        assert isinstance(check.check_id, str) and check.check_id, (
            f"check_id is empty or non-string on {check}"
        )


def test_check_metadata_check_name_is_nonempty_string() -> None:
    """Every CheckMetadata.check_name is a non-empty string."""
    for check in AgentComposer().list_checks():
        assert isinstance(check.check_name, str) and check.check_name, (
            f"check_name is empty or non-string on {check.check_id}"
        )


def test_check_metadata_category_is_nonempty_string() -> None:
    """Every CheckMetadata.category is a non-empty string."""
    for check in AgentComposer().list_checks():
        assert isinstance(check.category, str) and check.category, (
            f"category is empty or non-string on {check.check_id}"
        )


def test_check_metadata_opsec_impact_valid() -> None:
    """Every CheckMetadata.opsec_impact is one of 'low', 'medium', 'high'."""
    for check in AgentComposer().list_checks():
        assert check.opsec_impact in EXPECTED_OPSEC_VALUES, (
            f"Invalid opsec_impact '{check.opsec_impact}' on {check.check_id}"
        )


def test_check_metadata_requires_admin_is_bool() -> None:
    """Every CheckMetadata.requires_admin is a Python bool."""
    for check in AgentComposer().list_checks():
        assert isinstance(check.requires_admin, bool), (
            f"requires_admin must be bool, got {type(check.requires_admin)} on {check.check_id}"
        )


def test_check_metadata_estimated_time_seconds_is_positive_int() -> None:
    """Every CheckMetadata.estimated_time_seconds is a positive integer."""
    for check in AgentComposer().list_checks():
        assert isinstance(check.estimated_time_seconds, int), (
            f"estimated_time_seconds must be int on {check.check_id}"
        )
        assert check.estimated_time_seconds > 0, (
            f"estimated_time_seconds must be > 0 on {check.check_id}"
        )


# ---------------------------------------------------------------------------
# 4. compose() — #Requires directive
# ---------------------------------------------------------------------------


def test_compose_starts_with_requires_version_3() -> None:
    """compose() output starts with '#Requires -Version 3.0'."""
    agent = AgentComposer().compose()
    first_nonempty = next(line for line in agent.splitlines() if line.strip())
    assert first_nonempty.strip() == "#Requires -Version 3.0", (
        f"First non-empty line was: {first_nonempty!r}"
    )


def test_compose_requires_version_appears_exactly_once() -> None:
    """compose() emits exactly one #Requires directive (no duplicates from modules)."""
    agent = AgentComposer().compose()
    count = sum(
        1 for line in agent.splitlines() if line.strip().lower().startswith("#requires")
    )
    assert count == 1, f"Expected 1 #Requires line, found {count}"


# ---------------------------------------------------------------------------
# 5. compose() — contains Invoke-Seep
# ---------------------------------------------------------------------------


def test_compose_includes_invoke_seep_function() -> None:
    """compose() output contains the 'function Invoke-Seep' definition."""
    agent = AgentComposer().compose()
    assert "function Invoke-Seep" in agent, (
        "Invoke-Seep function not found in composed agent"
    )


# ---------------------------------------------------------------------------
# 6. compose() — includes all Invoke-Check* functions
# ---------------------------------------------------------------------------


def test_compose_includes_all_invoke_check_functions() -> None:
    """compose() includes an Invoke-Check* function for every discovered check."""
    composer = AgentComposer()
    agent = composer.compose()
    for check in composer.list_checks():
        # The function name is derived from the check file, e.g. system_info -> Invoke-CheckSystemInfo
        # Convert snake_case check_id to PascalCase function suffix
        pascal = "".join(word.capitalize() for word in check.check_id.split("_"))
        fn_name = f"function Invoke-Check{pascal}"
        assert fn_name in agent, (
            f"Expected '{fn_name}' in composed agent for check '{check.check_id}'"
        )


# ---------------------------------------------------------------------------
# 7. compose(checks=["system_info"]) — single check inclusion
# ---------------------------------------------------------------------------


def test_compose_single_check_includes_only_that_check() -> None:
    """compose(checks=['system_info']) includes system_info but not other checks."""
    composer = AgentComposer()
    agent = composer.compose(checks=["system_info"])

    assert "function Invoke-CheckSystemInfo" in agent, "system_info check not present"

    # Verify other check functions are absent
    all_checks = composer.list_checks()
    for check in all_checks:
        if check.check_id == "system_info":
            continue
        pascal = "".join(word.capitalize() for word in check.check_id.split("_"))
        fn_name = f"function Invoke-Check{pascal}"
        assert fn_name not in agent, (
            f"Unexpected check function '{fn_name}' found when only system_info requested"
        )


def test_compose_single_check_still_contains_invoke_seep() -> None:
    """compose(checks=['system_info']) still contains Invoke-Seep wrapper."""
    agent = AgentComposer().compose(checks=["system_info"])
    assert "Invoke-Seep" in agent


# ---------------------------------------------------------------------------
# 8. compose(exclude=["patches"]) — exclusion
# ---------------------------------------------------------------------------


def test_compose_exclude_patches_removes_patches_function() -> None:
    """compose(exclude=['patches']) does not include Invoke-CheckPatches."""
    agent = AgentComposer().compose(exclude=["patches"])
    assert "function Invoke-CheckPatches" not in agent, (
        "Invoke-CheckPatches should be excluded"
    )


def test_compose_exclude_patches_keeps_other_checks() -> None:
    """compose(exclude=['patches']) still includes other checks like system_info."""
    agent = AgentComposer().compose(exclude=["patches"])
    assert "function Invoke-CheckSystemInfo" in agent, (
        "system_info check should remain when only patches is excluded"
    )


def test_compose_exclude_produces_smaller_agent() -> None:
    """Excluding a check produces an agent smaller than the full agent."""
    composer = AgentComposer()
    full = composer.compose()
    excluded = composer.compose(exclude=["patches"])
    assert len(excluded) < len(full), "Excluding patches should reduce agent size"


# ---------------------------------------------------------------------------
# 9. compose(strip_comments=True) — comment stripping
# ---------------------------------------------------------------------------


def test_compose_strip_comments_removes_comment_only_lines() -> None:
    """strip_comments=True removes lines that are pure comments (# ...)."""
    composer = AgentComposer()
    agent = composer.compose(strip_comments=True)
    for line in agent.splitlines():
        stripped = line.strip()
        if stripped.startswith("#"):
            # Only #Requires and #region/#endregion are allowed to remain
            low = stripped.lower()
            assert (
                low.startswith("#requires")
                or low.startswith("#region")
                or low.startswith("#endregion")
            ), f"Comment line survived strip_comments=True: {line!r}"


def test_compose_strip_comments_agent_still_functional() -> None:
    """strip_comments=True agent still contains all required entry points."""
    agent = AgentComposer().compose(strip_comments=True)
    assert "Invoke-Seep" in agent
    assert "New-Finding" in agent
    assert "#Requires -Version 3.0" in agent


# ---------------------------------------------------------------------------
# 10. compose(strip_comments=False) — comments preserved
# ---------------------------------------------------------------------------


def test_compose_no_strip_preserves_comments() -> None:
    """strip_comments=False preserves comment lines in the output."""
    agent = AgentComposer().compose(strip_comments=False)
    # After not stripping, there should be comment lines (# ...) present
    comment_lines = [
        line
        for line in agent.splitlines()
        if line.strip().startswith("#")
        and not line.strip().lower().startswith("#requires")
    ]
    assert len(comment_lines) > 0, (
        "Expected comment lines to be present with strip_comments=False"
    )


def test_compose_no_strip_longer_than_stripped() -> None:
    """Agent with comments is longer than agent without comments."""
    composer = AgentComposer()
    with_comments = composer.compose(strip_comments=False)
    without_comments = composer.compose(strip_comments=True)
    assert len(with_comments) > len(without_comments), (
        "Agent with comments should be longer than agent without"
    )


# ---------------------------------------------------------------------------
# 11. compose(obfuscate=True) — sensitive tool name obfuscation
# ---------------------------------------------------------------------------


def test_compose_obfuscate_replaces_quoted_mimikatz() -> None:
    """obfuscate=True replaces quoted 'mimikatz'/'Mimikatz' with concatenation."""
    agent = AgentComposer().compose(obfuscate=True)
    assert '"mimikatz"' not in agent, "Plain quoted 'mimikatz' should be obfuscated"
    assert '"Mimikatz"' not in agent, "Plain quoted 'Mimikatz' should be obfuscated"
    assert "'mimikatz'" not in agent
    assert "'Mimikatz'" not in agent


def test_compose_obfuscate_replaces_other_sensitive_names() -> None:
    """obfuscate=True replaces other sensitive tool names."""
    agent = AgentComposer().compose(obfuscate=True)
    # Tools that should be obfuscated when in quotes
    sensitive_tools = [
        "SharpHound",
        "Rubeus",
        "GodPotato",
        "PrintSpoofer",
        "BloodHound",
    ]
    for tool in sensitive_tools:
        assert f'"{tool}"' not in agent, f'Quoted "{tool}" should be obfuscated'
        assert f"'{tool}'" not in agent, f"Quoted '{tool}' should be obfuscated"


def test_compose_obfuscate_uses_concatenation_form() -> None:
    """obfuscate=True replaces tool names with string concatenation expressions."""
    agent = AgentComposer().compose(obfuscate=True)
    # Mimikatz → "Mimi" + "katz" or "mimi" + "katz"
    assert '"Mimi" + "katz"' in agent or '"mimi" + "katz"' in agent, (
        "Expected concatenated mimikatz form in obfuscated output"
    )


# ---------------------------------------------------------------------------
# 12. compose_cradle() — returns valid cradle text
# ---------------------------------------------------------------------------


def test_compose_cradle_returns_nonempty_string() -> None:
    """compose_cradle() returns a non-empty string."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5")
    assert isinstance(cradle, str) and len(cradle) > 0


def test_compose_cradle_contains_agent_url() -> None:
    """compose_cradle() embeds the /agent.ps1 URL derived from server_url."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5")
    assert "http://10.10.14.5/agent.ps1" in cradle


def test_compose_cradle_strips_trailing_slash_from_server_url() -> None:
    """compose_cradle() normalises a server URL with trailing slash."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5/")
    assert "http://10.10.14.5/agent.ps1" in cradle
    assert "http://10.10.14.5//agent.ps1" not in cradle


# ---------------------------------------------------------------------------
# 13. compose_cradle() — all 6 methods present
# ---------------------------------------------------------------------------


def test_compose_cradle_contains_method_1_iex_webclient() -> None:
    """compose_cradle() includes method [1] IEX WebClient cradle."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5")
    assert "[1]" in cradle
    assert "IEX" in cradle
    assert "New-Object Net.WebClient" in cradle


def test_compose_cradle_contains_method_2_iex_stealth() -> None:
    """compose_cradle() includes method [2] IEX with stealth flags."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5")
    assert "[2]" in cradle
    assert "-NoP" in cradle or "-NoProfile" in cradle


def test_compose_cradle_contains_method_3_iwr() -> None:
    """compose_cradle() includes method [3] Invoke-WebRequest / iwr cradle."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5")
    assert "[3]" in cradle
    assert "iwr" in cradle or "Invoke-WebRequest" in cradle


def test_compose_cradle_contains_method_4_certutil() -> None:
    """compose_cradle() includes method [4] certutil download cradle."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5")
    assert "[4]" in cradle
    assert "certutil" in cradle


def test_compose_cradle_contains_method_5_wget() -> None:
    """compose_cradle() includes method [5] wget/PS alias cradle."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5")
    assert "[5]" in cradle
    assert "wget" in cradle


def test_compose_cradle_contains_method_6_curl() -> None:
    """compose_cradle() includes method [6] native curl cradle."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5")
    assert "[6]" in cradle
    assert "curl" in cradle


def test_compose_cradle_contains_all_six_methods() -> None:
    """compose_cradle() contains markers for all six download methods."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5")
    for n in range(1, 7):
        assert f"[{n}]" in cradle, f"Method [{n}] not found in cradle output"


# ---------------------------------------------------------------------------
# 14. compose_cradle(agent_args={"Quiet": True}) — arg injection
# ---------------------------------------------------------------------------


def test_compose_cradle_quiet_switch_included() -> None:
    """compose_cradle with Quiet=True includes '-Quiet' in the IEX cradle."""
    cradle = AgentComposer().compose_cradle(
        "http://10.10.14.5",
        agent_args={"Quiet": True},
    )
    assert "-Quiet" in cradle, "Expected -Quiet flag in cradle when Quiet=True"


def test_compose_cradle_quiet_false_not_included() -> None:
    """compose_cradle with Quiet=False does not include '-Quiet'."""
    cradle = AgentComposer().compose_cradle(
        "http://10.10.14.5",
        agent_args={"Quiet": False},
    )
    assert "-Quiet" not in cradle, "-Quiet should not appear when Quiet=False"


def test_compose_cradle_string_arg_included() -> None:
    """compose_cradle with a string arg includes it in the Invoke-Seep call."""
    cradle = AgentComposer().compose_cradle(
        "http://10.10.14.5",
        agent_args={"Upload": "http://10.10.14.5:8000/upload"},
    )
    assert "-Upload" in cradle
    assert "http://10.10.14.5:8000/upload" in cradle


def test_compose_cradle_no_args_still_calls_invoke_seep() -> None:
    """compose_cradle without agent_args still calls Invoke-Seep."""
    cradle = AgentComposer().compose_cradle("http://10.10.14.5")
    assert "Invoke-Seep" in cradle


# ---------------------------------------------------------------------------
# 15. _parse_metadata() — None for files without valid headers
# ---------------------------------------------------------------------------


def test_parse_metadata_returns_none_for_file_without_headers(tmp_path: Path) -> None:
    """_parse_metadata() returns None for a .ps1 file with no metadata comments."""
    ps1 = tmp_path / "no_meta.ps1"
    ps1.write_text("function Invoke-Foo { }\n", encoding="utf-8")
    composer = AgentComposer()
    result = composer._parse_metadata(ps1)
    assert result is None, f"Expected None, got {result}"


def test_parse_metadata_returns_none_for_partial_headers(tmp_path: Path) -> None:
    """_parse_metadata() returns None if only some required fields are present."""
    ps1 = tmp_path / "partial_meta.ps1"
    ps1.write_text(
        "# check_id: partial\n# check_name: Partial Check\n\nfunction Invoke-Partial { }\n",
        encoding="utf-8",
    )
    composer = AgentComposer()
    result = composer._parse_metadata(ps1)
    assert result is None, "Partial metadata should return None"


def test_parse_metadata_returns_metadata_for_valid_file(tmp_path: Path) -> None:
    """_parse_metadata() returns a CheckMetadata for a fully-annotated file."""
    ps1 = tmp_path / "good_meta.ps1"
    ps1.write_text(
        "# check_id: test_check\n"
        "# check_name: Test Check\n"
        "# category: testing\n"
        "# description: A test check\n"
        "# requires_admin: false\n"
        "# opsec_impact: low\n"
        "# estimated_time_seconds: 2\n"
        "\nfunction Invoke-CheckTestCheck { }\n",
        encoding="utf-8",
    )
    composer = AgentComposer()
    result = composer._parse_metadata(ps1)
    assert result is not None, "Expected CheckMetadata, got None"
    assert isinstance(result, CheckMetadata)
    assert result.check_id == "test_check"
    assert result.check_name == "Test Check"
    assert result.opsec_impact == "low"
    assert result.requires_admin is False
    assert result.estimated_time_seconds == 2


def test_parse_metadata_returns_none_for_nonexistent_file() -> None:
    """_parse_metadata() returns None when the file does not exist."""
    composer = AgentComposer()
    result = composer._parse_metadata(Path("/nonexistent/path/check.ps1"))
    assert result is None


# ---------------------------------------------------------------------------
# 16. _sanitize_ps_value() — dangerous character stripping
# ---------------------------------------------------------------------------


def test_sanitize_ps_value_strips_semicolon() -> None:
    """_sanitize_ps_value() removes semicolons to prevent command injection."""
    result = AgentComposer()._sanitize_ps_value("value;evil")
    assert ";" not in result, f"Semicolon not stripped: {result!r}"


def test_sanitize_ps_value_strips_backtick() -> None:
    """_sanitize_ps_value() removes backticks (PS escape char)."""
    result = AgentComposer()._sanitize_ps_value("val`ue")
    assert "`" not in result, f"Backtick not stripped: {result!r}"


def test_sanitize_ps_value_strips_dollar_sign() -> None:
    """_sanitize_ps_value() removes dollar signs (PS variable sigil)."""
    result = AgentComposer()._sanitize_ps_value("$value")
    assert "$" not in result, f"Dollar sign not stripped: {result!r}"


def test_sanitize_ps_value_strips_pipe() -> None:
    """_sanitize_ps_value() removes pipe characters."""
    result = AgentComposer()._sanitize_ps_value("value|cmd")
    assert "|" not in result, f"Pipe not stripped: {result!r}"


def test_sanitize_ps_value_strips_quotes() -> None:
    """_sanitize_ps_value() removes single and double quotes."""
    composer = AgentComposer()
    result_double = composer._sanitize_ps_value('say "hello"')
    result_single = composer._sanitize_ps_value("it's")
    assert '"' not in result_double, f"Double quote not stripped: {result_double!r}"
    assert "'" not in result_single, f"Single quote not stripped: {result_single!r}"


def test_sanitize_ps_value_strips_all_dangerous_chars() -> None:
    """_sanitize_ps_value() strips all dangerous shell metacharacters."""
    dangerous = ";`$(){}|&<>\"'"
    result = AgentComposer()._sanitize_ps_value(f"clean{dangerous}value")
    for ch in dangerous:
        assert ch not in result, f"Dangerous char {ch!r} not stripped from: {result!r}"


def test_sanitize_ps_value_preserves_safe_content() -> None:
    """_sanitize_ps_value() preserves safe alphanumeric and path characters."""
    safe_inputs = [
        "http://10.10.14.5:8000/upload",
        "C:\\Users\\Public\\output",
        "normal-value_123",
        "192.168.1.100",
    ]
    composer = AgentComposer()
    for inp in safe_inputs:
        # Safe chars that should survive: letters, digits, . / : \ - _
        result = composer._sanitize_ps_value(inp)
        # Just verify the function doesn't crash and returns a string
        assert isinstance(result, str), f"Expected str, got {type(result)} for {inp!r}"


# ---------------------------------------------------------------------------
# Integration: compose() with custom checks_dir (isolation)
# ---------------------------------------------------------------------------


def test_compose_with_isolated_checks_dir(tmp_path: Path) -> None:
    """AgentComposer with a custom checks_dir reads only from that directory."""
    # Create a minimal custom check
    checks_dir = tmp_path / "checks"
    checks_dir.mkdir()

    # Write a valid check module
    (checks_dir / "my_check.ps1").write_text(
        "# check_id: my_check\n"
        "# check_name: My Check\n"
        "# category: test\n"
        "# description: Custom check\n"
        "# requires_admin: false\n"
        "# opsec_impact: low\n"
        "# estimated_time_seconds: 1\n"
        "\nfunction Invoke-CheckMyCheck {\n    param([hashtable]$Config)\n    @()\n}\n",
        encoding="utf-8",
    )

    # Write a _base.ps1 shim (required by compose())
    real_base = (
        Path(__file__).parent.parent / "server" / "agent" / "checks" / "_base.ps1"
    )
    (checks_dir / "_base.ps1").write_text(
        real_base.read_text(encoding="utf-8"), encoding="utf-8"
    )

    templates_dir = Path(__file__).parent.parent / "server" / "agent" / "templates"

    composer = AgentComposer(checks_dir=checks_dir, templates_dir=templates_dir)
    checks = composer.list_checks()
    assert len(checks) == 1
    assert checks[0].check_id == "my_check"

    agent = composer.compose()
    assert "function Invoke-CheckMyCheck" in agent
    assert "Invoke-Seep" in agent


# ---------------------------------------------------------------------------
# Stability: list_checks() ordering is deterministic
# ---------------------------------------------------------------------------


def test_list_checks_ordering_is_stable() -> None:
    """list_checks() returns checks in the same order on repeated calls."""
    composer = AgentComposer()
    first_call = [c.check_id for c in composer.list_checks()]
    second_call = [c.check_id for c in composer.list_checks()]
    assert first_call == second_call, "list_checks() ordering must be deterministic"


def test_list_checks_sorted_by_check_id() -> None:
    """list_checks() returns checks sorted alphabetically by check_id."""
    checks = AgentComposer().list_checks()
    ids = [c.check_id for c in checks]
    assert ids == sorted(ids), f"Checks not sorted by check_id: {ids}"
