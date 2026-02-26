"""Seep - Windows Privilege Escalation Enumeration Framework CLI."""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path


def _get_version() -> str:
    """Return the package version from metadata, with fallback."""
    try:
        from importlib.metadata import version

        return version("seep")
    except Exception:
        return "2.0.0"

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

COLORS = {
    "red": "\033[91m",
    "green": "\033[92m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "magenta": "\033[95m",
    "cyan": "\033[96m",
    "white": "\033[97m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

SEVERITY_COLORS = {
    "critical": "red",
    "high": "yellow",
    "medium": "blue",
    "low": "cyan",
    "info": "white",
    "error": "magenta",
}


def _no_color() -> bool:
    return not sys.stdout.isatty() or bool(os.environ.get("NO_COLOR"))


def _color(color_name: str, text: str) -> str:
    """Wrap text in ANSI color codes (no-op if not a TTY)."""
    if _no_color():
        return text
    code = COLORS.get(color_name, "")
    return f"{code}{text}{COLORS['reset']}"


def bold(text: str) -> str:
    return _color("bold", text)


def dim(text: str) -> str:
    return _color("dim", text)


def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity.lower(), "white")
    return _color(color, f"[{severity.upper():8s}]")


def print_error(msg: str) -> None:
    print(f"{_color('red', '[!]')} {msg}", file=sys.stderr)


def print_info(msg: str) -> None:
    print(f"{_color('cyan', '[*]')} {msg}")


def print_ok(msg: str) -> None:
    print(f"{_color('green', '[+]')} {msg}")


def print_warn(msg: str) -> None:
    print(f"{_color('yellow', '[~]')} {msg}")


# ---------------------------------------------------------------------------
# Table formatting
# ---------------------------------------------------------------------------


def _col_widths(headers: list[str], rows: list[list[str]]) -> list[int]:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            if i < len(widths):
                widths[i] = max(widths[i], len(str(cell)))
    return widths


def print_table(
    headers: list[str],
    rows: list[list[str]],
    col_colors: list[str | None] | None = None,
) -> None:
    """Print a simple ANSI-colored table."""
    if not rows:
        print(dim("  (no results)"))
        return

    widths = _col_widths(headers, rows)
    sep = "  "

    # Header row
    header_parts = []
    for i, h in enumerate(headers):
        header_parts.append(bold(h.ljust(widths[i])))
    print(sep.join(header_parts))

    # Divider
    print(dim(sep.join("-" * w for w in widths)))

    # Data rows
    for row in rows:
        parts = []
        for i, cell in enumerate(row):
            cell_str = str(cell).ljust(widths[i]) if i < len(widths) - 1 else str(cell)
            if col_colors and i < len(col_colors) and col_colors[i]:
                parts.append(_color(col_colors[i], cell_str))  # type: ignore[arg-type]
            else:
                parts.append(cell_str)
        print(sep.join(parts))


# ---------------------------------------------------------------------------
# Config loading helper
# ---------------------------------------------------------------------------

DEFAULT_WORKDIR = "./seep-workspace"


def load_config(workdir: str):
    """Load ServerConfig from workdir/config.yaml, falling back to defaults."""
    from server.config import ServerConfig

    workdir_path = Path(workdir)
    config_file = workdir_path / "config.yaml"

    if config_file.exists():
        try:
            cfg = ServerConfig.from_yaml(config_file)
        except Exception as exc:
            print_warn(f"Could not load config.yaml: {exc} — using defaults")
            cfg = ServerConfig()
    else:
        cfg = ServerConfig()

    cfg.workdir = workdir_path
    return cfg


def _load_catalog():
    """Load the tool catalog, printing an error and returning None on failure."""
    try:
        from server.catalog.loader import CatalogLoader, CatalogLoadError

        return CatalogLoader().load()
    except CatalogLoadError as exc:
        print_error(f"Failed to load catalog: {exc}")
        return None


# ---------------------------------------------------------------------------
# Command: init
# ---------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    from server.config import ServerConfig

    workdir = Path(args.workdir)

    print_info(f"Initializing workspace at {bold(str(workdir))}")

    # Create directory structure
    dirs = [
        workdir,
        workdir / "tools",
        workdir / "tools" / "all",
        workdir / "tools" / "categories",
        workdir / "results",
        workdir / "reports",
        workdir / "agents",
        workdir / "certs",
    ]

    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)
        print(f"  {_color('green', 'created')}  {d}")

    # Write default config.yaml
    config_path = workdir / "config.yaml"
    if config_path.exists():
        print_warn("config.yaml already exists — skipping (delete to regenerate)")
    else:
        cfg = ServerConfig()
        cfg.workdir = workdir
        cfg.auth_token = ServerConfig.generate_token()
        config_path.write_text(cfg.to_yaml(), encoding="utf-8")
        print(f"  {_color('green', 'created')}  {config_path}")
        print()
        print(
            f"  {_color('yellow', 'Auth Token')}: {_color('magenta', cfg.auth_token)}"
        )
        print(f"  {dim('This token is required for upload authentication.')}")
        print(f"  {dim('It is saved in config.yaml and embedded in composed agents.')}")

    print()
    print_ok("Workspace initialized successfully!")
    print()
    print(bold("Next steps:"))
    print(f"  1. Edit {_color('cyan', str(config_path))} to configure your server")
    print(f"  2. {_color('cyan', 'seep catalog download --all')} to populate tools/")
    print(
        f"  3. {_color('cyan', f'seep serve --workdir {workdir}')} to start the server"
    )
    print(
        f"  4. {_color('cyan', f'seep compose --output {workdir}/agents/seep.ps1')} to build the agent"
    )
    print()

    return 0


# ---------------------------------------------------------------------------
# Command: serve
# ---------------------------------------------------------------------------


def cmd_serve(args: argparse.Namespace) -> int:
    from server.http.serve import start_server

    cfg = load_config(args.workdir)

    # Apply CLI overrides
    if args.port is not None:
        cfg.http_port = args.port
    if args.upload_port is not None:
        cfg.upload_port = args.upload_port
    if args.bind is not None:
        cfg.bind_address = args.bind
    if args.tls:
        cfg.tls.enabled = True

    try:
        start_server(cfg)
    except PermissionError:
        print_error(
            f"Permission denied binding to port {cfg.http_port}. Try sudo or use --port 8080."
        )
        return 1
    except OSError as exc:
        print_error(f"Failed to start server: {exc}")
        return 1

    return 0


# ---------------------------------------------------------------------------
# Command: catalog list
# ---------------------------------------------------------------------------


def cmd_catalog_list(args: argparse.Namespace) -> int:
    catalog = _load_catalog()
    if catalog is None:
        return 1

    tools = catalog.tools

    # Filter by category
    if args.category:
        tools = catalog.get_by_category(args.category)
        if not tools:
            print_warn(f"No tools found in category '{args.category}'")
            valid = ", ".join(sorted(catalog.categories.keys()))
            print(f"  Valid categories: {valid}")
            return 0

    # Filter by platform
    if args.platform:
        tools = [t for t in tools if t.platform in (args.platform, "both")]
        if not tools:
            print_warn(f"No tools found for platform '{args.platform}'")
            return 0

    if args.format == "json":
        data = [
            {
                "name": t.name,
                "display_name": t.display_name,
                "description": t.description,
                "categories": t.categories,
                "platform": t.platform,
                "architecture": t.architecture,
                "version": t.upstream_version,
                "tags": t.tags,
            }
            for t in tools
        ]
        print(json.dumps(data, indent=2))
    else:
        # Table format
        cat_filter = f" [{args.category}]" if args.category else ""
        plat_filter = f" [{args.platform}]" if args.platform else ""
        print()
        print(
            bold(f"Tool Catalog{cat_filter}{plat_filter}")
            + dim(f"  ({len(tools)} tools)")
        )
        print()

        headers = ["Name", "Version", "Platform", "Arch", "Categories", "Description"]
        rows = [
            [
                t.name,
                t.upstream_version,
                t.platform,
                t.architecture,
                ", ".join(t.categories),
                t.description[:60] + ("..." if len(t.description) > 60 else ""),
            ]
            for t in tools
        ]
        plat_colors = [None, None, "cyan", "dim", "yellow", "dim"]
        print_table(headers, rows, plat_colors)
        print()

    return 0


# ---------------------------------------------------------------------------
# Command: catalog search
# ---------------------------------------------------------------------------


def cmd_catalog_search(args: argparse.Namespace) -> int:
    catalog = _load_catalog()
    if catalog is None:
        return 1

    results = catalog.search(args.query)

    print()
    print(
        bold(f"Search results for '{args.query}'") + dim(f"  ({len(results)} matches)")
    )
    print()

    if not results:
        print_warn(f"No tools matching '{args.query}'")
        return 0

    headers = ["Name", "Version", "Categories", "Tags", "Description"]
    rows = [
        [
            t.name,
            t.upstream_version,
            ", ".join(t.categories),
            ", ".join(t.tags[:3]) + ("..." if len(t.tags) > 3 else ""),
            t.description[:65] + ("..." if len(t.description) > 65 else ""),
        ]
        for t in results
    ]
    print_table(headers, rows, [None, None, "yellow", "cyan", "dim"])
    print()

    return 0


# ---------------------------------------------------------------------------
# Command: catalog download
# ---------------------------------------------------------------------------


def cmd_catalog_download(args: argparse.Namespace) -> int:
    from server.catalog.manager import CatalogManager

    catalog = _load_catalog()
    if catalog is None:
        return 1

    workdir = Path(args.workdir)
    tools_dir = workdir / "tools"

    # Determine which tools to download
    if args.category:
        tools = catalog.get_by_category(args.category)
        if not tools:
            print_warn(f"No tools in category '{args.category}'")
            valid = ", ".join(sorted(catalog.categories.keys()))
            print(f"  Valid categories: {valid}")
            return 1
        scope = f"category '{args.category}'"
    elif args.all:
        tools = catalog.tools
        scope = "all tools"
    else:
        print_error("Specify --category CAT or --all")
        return 1

    print()
    print_info(f"Downloading {scope} ({len(tools)} tools) to {tools_dir}")
    print()

    # Create directory structure
    tools_dir.mkdir(parents=True, exist_ok=True)
    (tools_dir / "all").mkdir(exist_ok=True)
    (tools_dir / "categories").mkdir(exist_ok=True)

    for cat_name in catalog.categories:
        (tools_dir / "categories" / cat_name).mkdir(parents=True, exist_ok=True)

    mgr = CatalogManager(catalog, tools_dir, verify=args.verify)
    results = mgr.download_tools(tools)

    succeeded = [r for r in results if r.success]
    failed = [r for r in results if not r.success]
    total_bytes = sum(r.size_bytes for r in succeeded)

    print()
    if failed:
        print_warn(
            f"{len(succeeded)} succeeded, {len(failed)} failed  ({total_bytes / 1024:.0f} KB total)"
        )
        for r in failed:
            print_error(f"  {r.tool_name}: {r.error}")
    else:
        print_ok(
            f"{len(succeeded)} succeeded, 0 failed  ({total_bytes / 1024:.0f} KB total)"
        )

    return 0 if not failed else 1


# ---------------------------------------------------------------------------
# Command: catalog verify
# ---------------------------------------------------------------------------


def cmd_catalog_verify(args: argparse.Namespace) -> int:
    from server.catalog.manager import CatalogManager, VerifyReport

    catalog = _load_catalog()
    if catalog is None:
        return 1

    workdir = Path(args.workdir)
    tools_dir = workdir / "tools"

    print()
    print_info(f"Verifying tools in {tools_dir}")
    print()

    if not tools_dir.exists():
        print_warn(f"Tools directory does not exist: {tools_dir}")
        print(
            f"  Run {_color('cyan', f'seep catalog download --all --workdir {args.workdir}')} first."
        )
        return 1

    mgr = CatalogManager(catalog, tools_dir)
    report: VerifyReport = mgr.verify_all()

    if report.ok:
        print(f"  {_color('green', 'OK')}           {len(report.ok)} tools verified")

    if report.missing:
        print(
            f"  {_color('yellow', 'MISSING')}      {len(report.missing)} tools not downloaded:"
        )
        for name in report.missing[:15]:
            print(f"    {dim('-')} {name}")
        if len(report.missing) > 15:
            print(f"    {dim(f'... and {len(report.missing) - 15} more')}")

    if report.corrupted:
        print(
            f"  {_color('red', 'CORRUPTED')}    {len(report.corrupted)} tools failed SHA256:"
        )
        for name, expected, actual in report.corrupted:
            print(f"    {dim('-')} {name}")
            print(f"        expected: {dim(expected[:16])}...")
            print(f"        actual:   {_color('red', actual[:16])}...")

    if report.unrecognized:
        print(
            f"  {_color('cyan', 'UNKNOWN')}      {len(report.unrecognized)} unrecognized files:"
        )
        for name in report.unrecognized[:10]:
            print(f"    {dim('-')} {name}")

    print()
    if not report.missing and not report.corrupted:
        print_ok("All downloaded tools verified successfully!")
    else:
        issues = len(report.missing) + len(report.corrupted)
        print_warn(f"{issues} issue(s) found.")

    return 0 if not report.corrupted else 1


# ---------------------------------------------------------------------------
# Command: catalog update
# ---------------------------------------------------------------------------


def cmd_catalog_update(args: argparse.Namespace) -> int:
    from server.catalog.manager import CatalogManager

    catalog = _load_catalog()
    if catalog is None:
        return 1

    workdir = Path(args.workdir)
    tools_dir = workdir / "tools"

    # Derive GitHub repo from catalog release URL if not in config
    # release_base_url is typically "https://github.com/ORG/REPO/releases/download/TAG"
    github_repo: str | None = None
    base = catalog.release_base_url or ""
    if "github.com/" in base:
        # Extract "org/repo" from the URL
        after = base.split("github.com/", 1)[1]
        parts = after.split("/")
        if len(parts) >= 2:
            github_repo = f"{parts[0]}/{parts[1]}"

    if not github_repo:
        print_error("Cannot determine GitHub repo from catalog release_base_url.")
        print(f"  release_base_url: {_color('cyan', base or '(empty)')}")
        print(
            "  Expected format: https://github.com/ORG/REPO/releases/download/TAG/..."
        )
        return 1

    print()
    print_info(f"Checking for updates on {_color('cyan', github_repo)}")
    print(f"  Current release : {_color('cyan', catalog.tools_release or '(unknown)')}")

    mgr = CatalogManager(catalog, tools_dir)
    result = mgr.check_updates(github_repo)

    if result is None:
        print_warn("Could not reach GitHub API. Check your network connection.")
        return 1

    print(f"  Latest release  : {_color('cyan', result.latest_release or '(unknown)')}")
    print()

    if result.update_available:
        print_warn(
            f"Update available: {result.current_release} -> {result.latest_release}"
        )
        print(f"  Release URL: {_color('cyan', result.release_url)}")
        print()
        print("  To update, download the new catalog and re-run:")
        print(f"    {_color('cyan', 'seep catalog download --all')}")
    else:
        print_ok("Already up to date.")

    return 0


# ---------------------------------------------------------------------------
# Command: compose
# ---------------------------------------------------------------------------


def cmd_compose(args: argparse.Namespace) -> int:
    from server.agent.composer import AgentComposer

    composer = AgentComposer()

    # Parse check lists
    checks_list = None
    if args.checks:
        checks_list = [ch.strip() for ch in args.checks.split(",")]

    exclude_list = None
    if args.exclude:
        exclude_list = [e.strip() for e in args.exclude.split(",")]

    strip = args.strip_comments if hasattr(args, "strip_comments") else True

    # Load auth token: explicit --token overrides config
    auth_token = ""
    if args.token:
        auth_token = args.token
    else:
        cfg = load_config(args.workdir)
        auth_token = cfg.auth_token

    print_info("Composing agent...")

    try:
        content = composer.compose(
            checks=checks_list,
            exclude=exclude_list,
            obfuscate=args.obfuscate,
            strip_comments=strip,
            auth_token=auth_token,
        )
    except FileNotFoundError as exc:
        print_error(f"Missing required file: {exc}")
        print("  Ensure the agent checks and templates directories are populated.")
        return 1
    except Exception as exc:
        print_error(f"Composition failed: {exc}")
        return 1

    lines = content.count("\n") + 1
    chars = len(content)

    # Get check stats
    available = composer.list_checks()
    if checks_list:
        cl = [ch.lower() for ch in checks_list]
        included = [m for m in available if m.check_id.lower() in cl]
    elif exclude_list:
        el = [e.lower() for e in exclude_list]
        included = [m for m in available if m.check_id.lower() not in el]
    else:
        included = available

    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(content, encoding="utf-8")
        print_ok(f"Agent written to {bold(str(out_path))}")
    else:
        sys.stdout.write(content)
        if not content.endswith("\n"):
            sys.stdout.write("\n")

    # Stats (always to stderr when outputting to stdout so it doesn't contaminate)
    stats_out = sys.stderr if not args.output else sys.stdout
    print(f"\n  {bold('Stats:')}", file=stats_out)
    print(f"  Checks included : {_color('cyan', str(len(included)))}", file=stats_out)
    print(f"  Lines           : {_color('cyan', str(lines))}", file=stats_out)
    print(f"  Size            : {_color('cyan', str(chars))} chars", file=stats_out)
    print(f"  Obfuscated      : {'yes' if args.obfuscate else 'no'}", file=stats_out)
    print(f"  Strip comments  : {'yes' if strip else 'no'}", file=stats_out)
    if included:
        print(f"\n  {bold('Included checks:')}", file=stats_out)
        for m in included:
            opsec_color = (
                "green"
                if m.opsec_impact == "low"
                else "yellow"
                if m.opsec_impact == "medium"
                else "red"
            )
            print(
                f"    {_color('cyan', m.check_id):<30} {dim(m.category):<20} "
                f"opsec={_color(opsec_color, m.opsec_impact)}",
                file=stats_out,
            )
    print(file=stats_out)

    return 0


# ---------------------------------------------------------------------------
# Command: report
# ---------------------------------------------------------------------------


def cmd_report(args: argparse.Namespace) -> int:
    from server.results.parser import ResultsParser, ResultsParseError
    from server.catalog.loader import CatalogLoader, CatalogLoadError
    from server.report.recommendations import RecommendationEngine
    from server.report.generator import ReportGenerator

    results_path = Path(args.results_file)
    if not results_path.exists():
        print_error(f"Results file not found: {results_path}")
        return 1

    # Parse results
    print_info(f"Parsing results from {bold(str(results_path))}")
    parser = ResultsParser()
    try:
        results = parser.parse_file(results_path)
    except ResultsParseError as exc:
        print_error(f"Failed to parse results: {exc}")
        return 1

    # Load catalog (best-effort)
    try:
        catalog = CatalogLoader().load()
    except CatalogLoadError as exc:
        print_warn(f"Could not load tool catalog: {exc}")
        print("  Recommendations will use fallback tool names.")
        from server.catalog.schemas import ToolCatalog

        catalog = ToolCatalog(
            version="0", release_base_url="", tools_release="", tools=[], categories={}
        )

    engine = RecommendationEngine(catalog)
    generator = ReportGenerator(engine)

    fmt = args.format
    include_raw = getattr(args, "include_raw", False)

    print_info(
        f"Generating {bold(fmt.upper())} report for {bold(results.meta.hostname)}"
    )

    try:
        if fmt == "html":
            content = generator.generate_html(results, include_raw=include_raw)
            suffix = ".html"
        elif fmt == "md":
            content = generator.generate_markdown(results)
            suffix = ".md"
        elif fmt == "json":
            data = generator.generate_json_summary(results)
            content = json.dumps(data, indent=2)
            suffix = ".json"
        else:
            print_error(f"Unknown format: {fmt}")
            return 1
    except Exception as exc:
        print_error(f"Report generation failed: {exc}")
        return 1

    # Determine output path
    if args.output:
        out_path = Path(args.output)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_host = "".join(
            ch if ch.isalnum() or ch in "-_" else "_" for ch in results.meta.hostname
        )[:32]
        out_path = (
            results_path.parent.parent / "reports" / f"report_{ts}_{safe_host}{suffix}"
        )

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(content, encoding="utf-8")

    print_ok(f"Report written to {bold(str(out_path))}")
    print()

    # Summary
    by_sev = results.summary.by_severity
    total = results.summary.total_findings
    print(f"  {bold('Target:')}   {results.meta.hostname}")
    print(f"  {bold('Total:')}    {total} finding(s)")
    for sev in ("critical", "high", "medium", "low", "info"):
        n = by_sev.get(sev, 0)
        if n:
            print(f"  {severity_badge(sev)}  {n}")
    print()

    return 0


# ---------------------------------------------------------------------------
# Command: results list
# ---------------------------------------------------------------------------


def cmd_results_list(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir)
    results_dir = workdir / "results"

    print()
    print_info(f"Results in {bold(str(results_dir))}")
    print()

    if not results_dir.exists():
        print_warn(f"Results directory does not exist: {results_dir}")
        print(
            f"  Run {_color('cyan', f'seep serve --workdir {args.workdir}')} and upload results from an agent."
        )
        return 0

    result_files = sorted(results_dir.glob("*.json"), reverse=True)
    if not result_files:
        result_files = sorted(results_dir.glob("*.zip"), reverse=True)

    if not result_files:
        print_warn("No result files found.")
        return 0

    from server.results.parser import ResultsParser, ResultsParseError

    parser = ResultsParser()
    headers = [
        "File",
        "Hostname",
        "Timestamp",
        "Critical",
        "High",
        "Medium",
        "Low",
        "Info",
        "Total",
    ]
    rows = []

    for f in result_files:
        try:
            res = parser.parse_file(f)
            by_sev = res.summary.by_severity
            rows.append(
                [
                    f.name,
                    res.meta.hostname,
                    res.meta.timestamp[:19] if res.meta.timestamp else "—",
                    str(by_sev.get("critical", 0)),
                    str(by_sev.get("high", 0)),
                    str(by_sev.get("medium", 0)),
                    str(by_sev.get("low", 0)),
                    str(by_sev.get("info", 0)),
                    str(res.summary.total_findings),
                ]
            )
        except ResultsParseError as exc:
            rows.append(
                [f.name, "parse error", "—", "—", "—", "—", "—", "—", str(exc)[:30]]
            )

    print_table(headers, rows)
    print()
    print(dim(f"  {len(rows)} result file(s) found"))
    print()

    return 0


# ---------------------------------------------------------------------------
# Command: results show
# ---------------------------------------------------------------------------


def cmd_results_show(args: argparse.Namespace) -> int:
    from server.results.parser import ResultsParser, ResultsParseError

    results_path = Path(args.results_file)
    if not results_path.exists():
        print_error(f"Results file not found: {results_path}")
        return 1

    parser = ResultsParser()
    try:
        results = parser.parse_file(results_path)
    except ResultsParseError as exc:
        print_error(f"Failed to parse results: {exc}")
        return 1

    meta = results.meta
    print()
    print(_color("cyan", "=" * 70))
    print(bold(f"  SEEP RESULTS — {meta.hostname}"))
    print(_color("cyan", "=" * 70))
    print()

    # System info block
    print(bold("System Information"))
    print(dim("-" * 40))
    info_rows = [
        ("Hostname", meta.hostname),
        ("Domain", meta.domain or "—"),
        ("Username", meta.username or "—"),
        ("OS", f"{meta.os_name} {meta.os_version}".strip() or "—"),
        ("Architecture", meta.architecture or "—"),
        ("PowerShell", meta.ps_version or "—"),
        ("Admin", _color("red", "YES") if meta.is_admin else _color("green", "No")),
        ("Domain Joined", "Yes" if meta.is_domain_joined else "No"),
        ("Execution Mode", meta.execution_mode or "—"),
        ("Agent Version", meta.agent_version or "—"),
        ("Timestamp", meta.timestamp or "—"),
        ("Duration", f"{meta.total_duration_seconds:.1f}s"),
        ("Checks Run", ", ".join(meta.checks_run) if meta.checks_run else "—"),
    ]
    for label, value in info_rows:
        print(f"  {_color('dim', label + ':'): <25} {value}")
    print()

    # Summary
    by_sev = results.summary.by_severity
    total = results.summary.total_findings
    print(bold("Finding Summary"))
    print(dim("-" * 40))
    for sev in ("critical", "high", "medium", "low", "info", "error"):
        n = by_sev.get(sev, 0)
        if n or sev in ("critical", "high"):
            bar = _color(SEVERITY_COLORS.get(sev, "white"), "█" * min(n, 40))
            print(f"  {sev.capitalize():<10} {n:>4}  {bar}")
    print(f"  {'Total':<10} {total:>4}")
    print()

    # Findings grouped by severity
    if not results.findings:
        print_warn("No findings in this result set.")
        return 0

    severity_order = ["critical", "high", "medium", "low", "info", "error"]
    for sev in severity_order:
        sev_findings = [f for f in results.findings if f.severity == sev]
        if not sev_findings:
            continue

        sev_color = SEVERITY_COLORS.get(sev, "white")
        print(_color(sev_color, f"{'━' * 60}"))
        print(_color(sev_color, f"  {sev.upper()} ({len(sev_findings)})"))
        print(_color(sev_color, f"{'━' * 60}"))
        print()

        for finding in sev_findings:
            badge = severity_badge(finding.severity)
            print(f"{badge} {bold(finding.title)}")
            print(f"  {dim('ID:')}      {finding.finding_id}")
            print(f"  {dim('Check:')}   {finding.check_id}")
            if finding.description:
                # Wrap description to ~70 chars
                desc = finding.description
                words = desc.split()
                line = "  "
                for word in words:
                    if len(line) + len(word) + 1 > 72:
                        print(_color("dim", line))
                        line = "  " + word
                    else:
                        line = (line + " " + word).lstrip()
                        line = "  " + line.lstrip()
                if line.strip():
                    print(_color("dim", line))
            if finding.evidence:
                print(f"  {dim('Evidence:')}")
                for ev_line in finding.evidence.splitlines()[:8]:
                    print(f"    {_color('white', ev_line)}")
                ev_lines = finding.evidence.splitlines()
                if len(ev_lines) > 8:
                    print(f"    {dim(f'... ({len(ev_lines) - 8} more lines)')}")
            if finding.remediation:
                print(f"  {dim('Remediation:')}")
                print(f"    {_color('green', finding.remediation[:120])}")
            if finding.tags:
                tags_str = "  ".join(_color("cyan", f"[{t}]") for t in finding.tags)
                print(f"  {tags_str}")
            if finding.tool_hint:
                tools_str = ", ".join(_color("yellow", t) for t in finding.tool_hint)
                print(f"  {dim('Tools:')} {tools_str}")
            print()

    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="seep",
        description=bold("Seep")
        + " — Windows Privilege Escalation Enumeration Framework\n\n"
        + "A modular toolkit for authorized Windows privilege escalation\n"
        + "enumeration. Compose custom agents, serve tools, and analyze results.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  seep init --workdir /tmp/seep          Initialize a workspace\n"
            "  seep serve --port 8080                 Start the C2 server\n"
            "  seep catalog list --category TokenAbuse List tools by category\n"
            "  seep catalog search potato              Search for tools\n"
            "  seep compose --output agents/seep.ps1   Build the agent script\n"
            "  seep report results/r.json --format html Generate HTML report\n"
            "  seep results list                       List uploaded results\n"
            "  seep results show results/r.json        Pretty-print results\n"
            "\n"
            "Documentation: https://github.com/yourorg/seep\n"
        ),
    )

    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # ---- init ----
    init_p = sub.add_parser("init", help="Initialize a new workspace with config and directory structure")
    init_p.add_argument(
        "--workdir",
        "-w",
        default=DEFAULT_WORKDIR,
        metavar="DIR",
        help=f"Workspace directory (default: {DEFAULT_WORKDIR})",
    )

    # ---- serve ----
    serve_p = sub.add_parser("serve", help="Start the C2 HTTP server (agent delivery + result upload)")
    serve_p.add_argument(
        "--port",
        "-p",
        type=int,
        default=None,
        metavar="PORT",
        help="HTTP port (default: 80)",
    )
    serve_p.add_argument(
        "--upload-port",
        "-u",
        type=int,
        default=None,
        dest="upload_port",
        metavar="PORT",
        help="Upload port (default: 8000)",
    )
    serve_p.add_argument(
        "--tls", action="store_true", help="Enable HTTPS (requires certs/)"
    )
    serve_p.add_argument(
        "--bind", default=None, metavar="ADDR", help="Bind address (default: 0.0.0.0)"
    )
    serve_p.add_argument(
        "--workdir",
        "-w",
        default=DEFAULT_WORKDIR,
        metavar="DIR",
        help="Workspace directory",
    )

    # ---- catalog ----
    catalog_p = sub.add_parser("catalog", help="Browse, download, and verify privesc tools")
    catalog_sub = catalog_p.add_subparsers(dest="catalog_command", metavar="SUBCOMMAND")
    catalog_sub.required = True

    # catalog list
    cat_list_p = catalog_sub.add_parser("list", help="List tools in the catalog")
    cat_list_p.add_argument(
        "--category", "-c", default=None, metavar="CAT", help="Filter by category"
    )
    cat_list_p.add_argument(
        "--platform",
        default=None,
        choices=["windows", "linux", "both"],
        help="Filter by platform",
    )
    cat_list_p.add_argument(
        "--format",
        "-f",
        choices=["table", "json"],
        default="table",
        help="Output format",
    )

    # catalog search
    cat_search_p = catalog_sub.add_parser("search", help="Search the catalog")
    cat_search_p.add_argument("query", help="Search query (name, description, tags)")

    # catalog download
    cat_dl_p = catalog_sub.add_parser("download", help="Show/prepare tool downloads")
    cat_dl_p.add_argument(
        "--category",
        "-c",
        default=None,
        metavar="CAT",
        help="Download a specific category",
    )
    cat_dl_p.add_argument("--all", action="store_true", help="Download all tools")
    cat_dl_p.add_argument(
        "--verify",
        action="store_true",
        default=True,
        help="Verify SHA256 after download",
    )
    cat_dl_p.add_argument(
        "--workdir",
        "-w",
        default=DEFAULT_WORKDIR,
        metavar="DIR",
        help="Workspace directory",
    )

    # catalog verify
    cat_ver_p = catalog_sub.add_parser(
        "verify", help="Verify integrity of downloaded tools"
    )
    cat_ver_p.add_argument(
        "--workdir",
        "-w",
        default=DEFAULT_WORKDIR,
        metavar="DIR",
        help="Workspace directory",
    )

    # catalog update
    cat_up_p = catalog_sub.add_parser("update", help="Check for catalog/tool updates")
    cat_up_p.add_argument("--workdir", "-w", default=DEFAULT_WORKDIR, metavar="DIR")

    # ---- compose ----
    compose_p = sub.add_parser("compose", help="Compose a customized PowerShell enumeration agent")
    compose_p.add_argument(
        "--checks", metavar="CHECKS", help="Comma-separated check IDs to include"
    )
    compose_p.add_argument(
        "--exclude", metavar="CHECKS", help="Comma-separated check IDs to exclude"
    )
    compose_p.add_argument(
        "--obfuscate", action="store_true", help="Apply basic string obfuscation"
    )
    compose_p.add_argument(
        "--strip-comments",
        action="store_true",
        default=True,
        dest="strip_comments",
        help="Strip comments (default: on)",
    )
    compose_p.add_argument(
        "--no-strip-comments",
        action="store_false",
        dest="strip_comments",
        help="Keep comments",
    )
    compose_p.add_argument(
        "--output", "-o", metavar="FILE", help="Output file (default: stdout)"
    )
    compose_p.add_argument(
        "--workdir",
        "-w",
        default=DEFAULT_WORKDIR,
        metavar="DIR",
        help="Workspace directory (reads auth_token from config)",
    )
    compose_p.add_argument(
        "--token",
        default=None,
        metavar="TOKEN",
        help="Override auth token (default: read from config.yaml)",
    )

    # ---- report ----
    report_p = sub.add_parser("report", help="Generate a report from results")
    report_p.add_argument(
        "results_file", metavar="RESULTS_FILE", help="Path to results JSON or ZIP"
    )
    report_p.add_argument("--output", "-o", metavar="FILE", help="Output file path")
    report_p.add_argument(
        "--format",
        "-f",
        choices=["html", "json", "md"],
        default="html",
        help="Report format (default: html)",
    )
    report_p.add_argument(
        "--include-raw",
        action="store_true",
        dest="include_raw",
        help="Include raw results data in HTML report",
    )

    # ---- results ----
    results_p = sub.add_parser("results", help="Manage uploaded results")
    results_sub = results_p.add_subparsers(dest="results_command", metavar="SUBCOMMAND")
    results_sub.required = True

    # results list
    res_list_p = results_sub.add_parser("list", help="List received result files")
    res_list_p.add_argument(
        "--workdir",
        "-w",
        default=DEFAULT_WORKDIR,
        metavar="DIR",
        help="Workspace directory",
    )

    # results show
    res_show_p = results_sub.add_parser("show", help="Pretty-print a results file")
    res_show_p.add_argument(
        "results_file", metavar="RESULTS_FILE", help="Path to results JSON or ZIP"
    )

    return parser


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    try:
        if args.command == "init":
            return cmd_init(args)

        elif args.command == "serve":
            return cmd_serve(args)

        elif args.command == "catalog":
            if args.catalog_command == "list":
                return cmd_catalog_list(args)
            elif args.catalog_command == "search":
                return cmd_catalog_search(args)
            elif args.catalog_command == "download":
                return cmd_catalog_download(args)
            elif args.catalog_command == "verify":
                return cmd_catalog_verify(args)
            elif args.catalog_command == "update":
                return cmd_catalog_update(args)
            else:
                parser.error(f"Unknown catalog subcommand: {args.catalog_command}")

        elif args.command == "compose":
            return cmd_compose(args)

        elif args.command == "report":
            return cmd_report(args)

        elif args.command == "results":
            if args.results_command == "list":
                return cmd_results_list(args)
            elif args.results_command == "show":
                return cmd_results_show(args)
            else:
                parser.error(f"Unknown results subcommand: {args.results_command}")

        else:
            parser.print_help()
            return 1

    except KeyboardInterrupt:
        print(f"\n{_color('yellow', '[*]')} Interrupted")
        return 130
    except BrokenPipeError:
        return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
