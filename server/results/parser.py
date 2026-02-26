"""Seep results parser — handles JSON and ZIP uploads from agents."""

from __future__ import annotations
import json
import zipfile
from dataclasses import dataclass, field
from io import BytesIO
from pathlib import Path

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "error"}

ZIP_MAGIC = b"PK\x03\x04"

_MAX_DECOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MB


@dataclass
class Finding:
    check_id: str
    finding_id: str
    severity: str          # critical, high, medium, low, info, error
    title: str
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    tags: list[str] = field(default_factory=list)
    tool_hint: list[str] = field(default_factory=list)
    timestamp: str = ""


@dataclass
class AgentMeta:
    agent_version: str = ""
    timestamp: str = ""
    hostname: str = "unknown"
    domain: str = ""
    username: str = ""
    is_admin: bool = False
    is_domain_joined: bool = False
    os_version: str = ""
    os_name: str = ""
    ps_version: str = ""
    architecture: str = ""
    execution_mode: str = ""
    checks_run: list[str] = field(default_factory=list)
    total_duration_seconds: float = 0.0


@dataclass
class ResultsSummary:
    total_findings: int = 0
    by_severity: dict[str, int] = field(default_factory=dict)
    by_category: dict[str, int] = field(default_factory=dict)


@dataclass
class AgentResults:
    meta: AgentMeta
    findings: list[Finding]
    summary: ResultsSummary
    raw_data: dict = field(default_factory=dict)

    @property
    def critical_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "critical"]

    @property
    def high_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == "high"]

    @property
    def actionable_findings(self) -> list[Finding]:
        """Findings that are critical or high severity."""
        return [f for f in self.findings if f.severity in ("critical", "high")]


class ResultsParseError(Exception):
    pass


class ResultsParser:
    def parse_upload(self, data: bytes, content_type: str = "") -> AgentResults:
        """Parse uploaded data (ZIP or raw JSON) into structured results.

        Detection: if data starts with PK magic bytes (0x50, 0x4B), treat as ZIP.
        Otherwise treat as JSON.
        """
        if not data:
            raise ResultsParseError("Upload data is empty")

        if data[:4] == ZIP_MAGIC:
            return self._parse_zip(data)
        else:
            return self._parse_json(data)

    def parse_file(self, path: Path) -> AgentResults:
        """Parse a results file from disk. Handles .json and .zip files."""
        path = Path(path)
        if not path.exists():
            raise ResultsParseError(f"File not found: {path}")

        data = path.read_bytes()

        # Prefer extension-based detection, fall back to magic bytes
        suffix = path.suffix.lower()
        if suffix == ".zip":
            return self._parse_zip(data)
        elif suffix == ".json":
            return self._parse_json(data)
        else:
            # Fall back to content-based detection
            return self.parse_upload(data)

    def validate(self, raw: dict) -> list[str]:
        """Validate results dict against expected schema. Returns list of error messages."""
        errors = []

        # Check top-level structure
        if not isinstance(raw, dict):
            errors.append("Root must be a JSON object")
            return errors

        # Check 'meta' key
        if "meta" not in raw:
            errors.append("Missing required key: 'meta'")
        elif not isinstance(raw["meta"], dict):
            errors.append("'meta' must be an object")
        else:
            meta = raw["meta"]
            if "hostname" not in meta:
                errors.append("meta.hostname is required")

        # Check 'findings' key
        if "findings" not in raw:
            errors.append("Missing required key: 'findings'")
        elif not isinstance(raw["findings"], list):
            errors.append("'findings' must be an array")
        else:
            for i, finding in enumerate(raw["findings"]):
                if not isinstance(finding, dict):
                    errors.append(f"findings[{i}] must be an object")
                    continue

                for required_field in ("check_id", "finding_id", "severity", "title"):
                    if required_field not in finding:
                        errors.append(
                            f"findings[{i}] missing required field: '{required_field}'"
                        )

                severity = finding.get("severity", "")
                if severity and severity not in VALID_SEVERITIES:
                    errors.append(
                        f"findings[{i}] has invalid severity '{severity}'; "
                        f"must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
                    )

        return errors

    def _parse_json(self, data: bytes) -> AgentResults:
        """Parse raw JSON bytes into AgentResults."""
        try:
            raw = json.loads(data)
        except json.JSONDecodeError as exc:
            raise ResultsParseError(f"Invalid JSON: {exc}") from exc

        errors = self.validate(raw)
        if errors:
            # Non-fatal: warn but continue with best-effort parsing
            # (raise only if completely unusable)
            if "Root must be a JSON object" in errors or "Missing required key: 'findings'" in errors:
                raise ResultsParseError(
                    f"Results failed validation: {'; '.join(errors)}"
                )

        meta = self._build_meta(raw.get("meta", {}))

        findings_raw = raw.get("findings", [])
        findings: list[Finding] = []
        for item in findings_raw:
            if isinstance(item, dict):
                findings.append(self._build_finding(item))

        summary = self._build_summary(raw.get("summary", {}), findings)

        return AgentResults(
            meta=meta,
            findings=findings,
            summary=summary,
            raw_data=raw,
        )

    def _parse_zip(self, data: bytes) -> AgentResults:
        """Extract results.json from ZIP and parse."""
        try:
            buf = BytesIO(data)
            with zipfile.ZipFile(buf, "r") as zf:
                names = zf.namelist()

                # Look for results.json first (exact match or any path ending with it)
                target = None
                for name in names:
                    if name == "results.json" or name.endswith("/results.json"):
                        target = name
                        break

                # Fall back to first .json file in the archive
                if target is None:
                    for name in names:
                        if name.lower().endswith(".json"):
                            target = name
                            break

                if target is None:
                    raise ResultsParseError(
                        f"No JSON file found in ZIP archive. Contents: {names}"
                    )

                with zf.open(target) as entry_file:
                    chunks = []
                    total = 0
                    while True:
                        chunk = entry_file.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > _MAX_DECOMPRESSED_BYTES:
                            raise ResultsParseError("Decompressed ZIP entry exceeds size limit")
                        chunks.append(chunk)
                    json_bytes = b"".join(chunks)
        except zipfile.BadZipFile as exc:
            raise ResultsParseError(f"Invalid ZIP archive: {exc}") from exc

        return self._parse_json(json_bytes)

    def _build_meta(self, raw: dict) -> AgentMeta:
        """Build AgentMeta from raw dict, using defaults for missing fields."""
        if not isinstance(raw, dict):
            raw = {}

        checks_run = raw.get("checks_run", [])
        if not isinstance(checks_run, list):
            checks_run = []

        duration = raw.get("total_duration_seconds", 0.0)
        try:
            duration = float(duration)
        except (TypeError, ValueError):
            duration = 0.0

        is_admin = raw.get("is_admin", False)
        if not isinstance(is_admin, bool):
            is_admin = bool(is_admin)

        is_domain_joined = raw.get("is_domain_joined", False)
        if not isinstance(is_domain_joined, bool):
            is_domain_joined = bool(is_domain_joined)

        return AgentMeta(
            agent_version=str(raw.get("agent_version", "")),
            timestamp=str(raw.get("timestamp", "")),
            hostname=str(raw.get("hostname", "unknown")) or "unknown",
            domain=str(raw.get("domain", "")),
            username=str(raw.get("username", "")),
            is_admin=is_admin,
            is_domain_joined=is_domain_joined,
            os_version=str(raw.get("os_version", "")),
            os_name=str(raw.get("os_name", "")),
            ps_version=str(raw.get("ps_version", "")),
            architecture=str(raw.get("architecture", "")),
            execution_mode=str(raw.get("execution_mode", "")),
            checks_run=checks_run,
            total_duration_seconds=duration,
        )

    def _build_finding(self, raw: dict) -> Finding:
        """Build Finding from raw dict."""
        if not isinstance(raw, dict):
            raw = {}

        tags = raw.get("tags", [])
        if not isinstance(tags, list):
            tags = []

        tool_hint = raw.get("tool_hint", [])
        if not isinstance(tool_hint, list):
            tool_hint = []

        severity = str(raw.get("severity", "info")).lower()
        if severity not in VALID_SEVERITIES:
            severity = "info"

        return Finding(
            check_id=str(raw.get("check_id", "")),
            finding_id=str(raw.get("finding_id", "")),
            severity=severity,
            title=str(raw.get("title", "")),
            description=str(raw.get("description", "")),
            evidence=str(raw.get("evidence", "")),
            remediation=str(raw.get("remediation", "")),
            tags=tags,
            tool_hint=tool_hint,
            timestamp=str(raw.get("timestamp", "")),
        )

    def _build_summary(self, raw: dict, findings: list[Finding]) -> ResultsSummary:
        """Build summary from raw dict or compute from findings."""
        if not isinstance(raw, dict):
            raw = {}

        # Compute by_severity from findings (source of truth)
        computed_by_severity: dict[str, int] = {}
        for f in findings:
            computed_by_severity[f.severity] = computed_by_severity.get(f.severity, 0) + 1

        # Use provided by_severity only if present, else use computed
        by_severity = raw.get("by_severity")
        if not isinstance(by_severity, dict):
            by_severity = computed_by_severity

        # by_category: use provided or empty (we don't have category info on findings)
        by_category = raw.get("by_category", {})
        if not isinstance(by_category, dict):
            by_category = {}

        total = raw.get("total_findings")
        if not isinstance(total, int):
            total = len(findings)

        return ResultsSummary(
            total_findings=total,
            by_severity=by_severity,
            by_category=by_category,
        )
