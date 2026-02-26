"""Seep report generator — produces single-file HTML reports from agent results."""

from __future__ import annotations

import html
from datetime import datetime, timezone

from server.results.parser import AgentResults, Finding
from server.report.recommendations import MatchedRecommendation, RecommendationEngine

def _get_seep_version() -> str:
    try:
        from importlib.metadata import version, PackageNotFoundError
        return version("seep")
    except PackageNotFoundError:
        return "2.0.0"

_SEEP_VERSION = _get_seep_version()

_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info", "error"]

_SEVERITY_COLOR = {
    "critical": "#ff4444",
    "high": "#ff8800",
    "medium": "#ffcc00",
    "low": "#4488ff",
    "info": "#888888",
    "error": "#cc44cc",
}

_SEVERITY_BG = {
    "critical": "rgba(255,68,68,0.15)",
    "high": "rgba(255,136,0,0.15)",
    "medium": "rgba(255,204,0,0.12)",
    "low": "rgba(68,136,255,0.15)",
    "info": "rgba(136,136,136,0.12)",
    "error": "rgba(204,68,204,0.15)",
}


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return html.escape(str(text), quote=True)


def _md_escape(text: str) -> str:
    """Escape characters that break markdown table cells."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _severity_badge(severity: str) -> str:
    color = _SEVERITY_COLOR.get(severity, "#888888")
    return (
        f'<span class="badge" style="background:{color};color:#fff;">'
        f"{_esc(severity.upper())}</span>"
    )


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


class ReportGenerator:
    def __init__(self, recommendation_engine: RecommendationEngine) -> None:
        self.engine = recommendation_engine

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def generate_html(self, results: AgentResults, include_raw: bool = False) -> str:
        """Generate complete HTML report as a single self-contained string."""
        recs = self.engine.analyze(results.findings)

        html_parts = [
            self._html_head(results),
            self._html_header(results),
            self._html_executive_summary(results),
            self._html_system_info(results),
            self._html_critical_findings(results),
            self._html_recommendations(recs),
            self._html_all_findings(results, include_raw),
            self._html_footer(),
        ]
        return "\n".join(html_parts)

    def generate_markdown(self, results: AgentResults) -> str:
        """Generate a Markdown report."""
        recs = self.engine.analyze(results.findings)
        parts: list[str] = []

        meta = results.meta
        domain_str = f" ({meta.domain})" if meta.domain else ""
        as_str = f" as {meta.username}" if meta.username else ""
        parts.append(f"# Seep Report: {meta.hostname}")
        parts.append(f"**Generated:** {_now_utc()}")
        parts.append(f"**Agent Version:** {meta.agent_version or 'unknown'}")
        parts.append(f"**Target:** {meta.hostname}{domain_str}{as_str}")
        parts.append(f"**Mode:** {meta.execution_mode or 'unknown'}")
        parts.append("")

        # Executive summary
        parts.append("## Executive Summary")
        parts.append("")
        parts.append("| Severity | Count |")
        parts.append("|----------|-------|")
        by_sev = results.summary.by_severity
        for sev in _SEVERITY_ORDER:
            count = by_sev.get(sev, 0)
            if count:
                parts.append(f"| {sev.capitalize()} | {count} |")
        parts.append("")
        parts.append(f"**Total Findings:** {results.summary.total_findings}")
        parts.append("")

        # System info
        parts.append("## System Information")
        parts.append("")
        rows = [
            ("Hostname", meta.hostname),
            ("Domain", meta.domain or "—"),
            ("Username", meta.username or "—"),
            ("OS", f"{meta.os_name} {meta.os_version}".strip() or "—"),
            ("Architecture", meta.architecture or "—"),
            ("PowerShell Version", meta.ps_version or "—"),
            ("Admin", "Yes" if meta.is_admin else "No"),
            ("Domain Joined", "Yes" if meta.is_domain_joined else "No"),
            ("Execution Mode", meta.execution_mode or "—"),
            ("Duration", f"{meta.total_duration_seconds:.1f}s"),
        ]
        parts.append("| Field | Value |")
        parts.append("|-------|-------|")
        for k, v in rows:
            parts.append(f"| {k} | {v} |")
        parts.append("")

        # Critical & High findings
        actionable = [f for f in results.findings if f.severity in ("critical", "high")]
        if actionable:
            parts.append("## Critical & High Findings")
            parts.append("")
            for finding in actionable:
                sev_label = finding.severity.upper()
                parts.append(f"### [{sev_label}] {_md_escape(finding.title)}")
                if finding.description:
                    parts.append(f"**Description:** {finding.description}")
                    parts.append("")
                if finding.evidence:
                    safe_evidence = finding.evidence.replace("```", "` ` `")
                    parts.append("**Evidence:**")
                    parts.append("```")
                    parts.append(safe_evidence)
                    parts.append("```")
                    parts.append("")
                if finding.remediation:
                    parts.append(f"**Remediation:** {finding.remediation}")
                    parts.append("")
                if finding.tags:
                    parts.append(f"**Tags:** {', '.join(finding.tags)}")
                    parts.append("")

        # Recommendations
        if recs:
            parts.append("## Recommendations")
            parts.append("")
            for rec in recs:
                risk_label = rec.risk.upper()
                parts.append(f"### [{risk_label}] {rec.title} ({rec.mitre_technique})")
                parts.append(f"**MITRE ATT&CK:** [{rec.mitre_name}]({rec.mitre_url})")
                parts.append("")
                parts.append(rec.description)
                parts.append("")
                tool_names = rec.display_tools
                if tool_names:
                    parts.append(f"**Recommended Tools:** {', '.join(tool_names)}")
                    parts.append("")
                if rec.example_commands:
                    parts.append("**Example Commands:**")
                    parts.append("```")
                    parts.extend(rec.example_commands)
                    parts.append("```")
                    parts.append("")

        # All findings table
        parts.append("## All Findings")
        parts.append("")
        parts.append("| Severity | ID | Title | Tags |")
        parts.append("|----------|----|-------|------|")
        for sev in _SEVERITY_ORDER:
            for f in results.findings:
                if f.severity == sev:
                    tags_str = _md_escape(", ".join(f.tags) if f.tags else "—")
                    parts.append(
                        f"| {_md_escape(f.severity.upper())} | `{_md_escape(f.finding_id)}` | {_md_escape(f.title)} | {tags_str} |"
                    )
        parts.append("")

        return "\n".join(parts)

    def generate_json_summary(self, results: AgentResults) -> dict:
        """Generate JSON summary with recommendations."""
        recs = self.engine.analyze(results.findings)

        data = {
            "generated_at": _now_utc(),
            "seep_version": _SEEP_VERSION,
            "meta": {
                "hostname": results.meta.hostname,
                "domain": results.meta.domain,
                "username": results.meta.username,
                "os_name": results.meta.os_name,
                "os_version": results.meta.os_version,
                "is_admin": results.meta.is_admin,
                "execution_mode": results.meta.execution_mode,
                "total_duration_seconds": results.meta.total_duration_seconds,
            },
            "summary": {
                "total_findings": results.summary.total_findings,
                "by_severity": results.summary.by_severity,
            },
            "recommendations": [
                {
                    "title": r.title,
                    "risk": r.risk,
                    "mitre_technique": r.mitre_technique,
                    "mitre_name": r.mitre_name,
                    "mitre_url": r.mitre_url,
                    "tools": r.display_tools,
                    "triggered_by": r.triggered_by,
                }
                for r in recs
            ],
            "findings": [
                {
                    "finding_id": f.finding_id,
                    "check_id": f.check_id,
                    "severity": f.severity,
                    "title": f.title,
                    "tags": f.tags,
                }
                for f in results.findings
            ],
        }
        return data

    # ------------------------------------------------------------------
    # HTML helpers
    # ------------------------------------------------------------------

    def _html_head(self, results: AgentResults) -> str:
        hostname = _esc(results.meta.hostname)
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Seep Report — {hostname}</title>
<style>
/* ===== Reset & Base ===== */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
html {{ font-size: 16px; scroll-behavior: smooth; }}

body {{
    background: #1a1a2e;
    color: #e0e0e0;
    font-family: system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif;
    line-height: 1.6;
    min-height: 100vh;
}}

/* ===== Layout ===== */
.container {{
    max-width: 1200px;
    margin: 0 auto;
    padding: 0 1.5rem 3rem;
}}

/* ===== Header ===== */
.site-header {{
    background: linear-gradient(135deg, #0f0f23 0%, #16213e 60%, #0f3460 100%);
    border-bottom: 2px solid #4488ff;
    padding: 2rem 0 1.5rem;
    margin-bottom: 2rem;
}}
.site-header .container {{
    display: flex;
    align-items: flex-end;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 1rem;
    padding-bottom: 0;
}}
.logo {{
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 3rem;
    font-weight: 900;
    letter-spacing: 0.3rem;
    color: #4488ff;
    text-shadow: 0 0 30px rgba(68,136,255,0.5), 0 0 60px rgba(68,136,255,0.2);
    line-height: 1;
}}
.logo span {{
    color: #ff4444;
}}
.header-meta {{
    text-align: right;
    font-size: 0.85rem;
    color: #888;
    line-height: 1.8;
}}
.header-meta strong {{
    color: #e0e0e0;
}}
.header-subtitle {{
    font-size: 0.75rem;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    color: #4488ff;
    letter-spacing: 0.15rem;
    margin-top: 0.25rem;
}}

/* ===== Section titles ===== */
h2.section-title {{
    font-size: 1.2rem;
    font-weight: 700;
    letter-spacing: 0.08rem;
    text-transform: uppercase;
    color: #4488ff;
    border-left: 4px solid #4488ff;
    padding-left: 0.75rem;
    margin: 2rem 0 1rem;
}}

/* ===== Cards ===== */
.card {{
    background: #16213e;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1rem;
    box-shadow: 0 2px 8px rgba(0,0,0,0.4);
    transition: border-color 0.15s ease;
}}
.card:hover {{ border-color: #2a5080; }}
.card-title {{
    font-size: 1rem;
    font-weight: 700;
    margin-bottom: 0.5rem;
    color: #e0e0e0;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    flex-wrap: wrap;
}}
.card-desc {{
    font-size: 0.9rem;
    color: #aaa;
    margin: 0.5rem 0;
    line-height: 1.6;
}}
.card-label {{
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05rem;
    color: #888;
    margin-top: 0.75rem;
    margin-bottom: 0.25rem;
}}
.card-remediation {{
    font-size: 0.88rem;
    color: #b8d4b8;
    background: rgba(0,255,100,0.05);
    border-left: 3px solid #44bb66;
    padding: 0.5rem 0.75rem;
    border-radius: 0 4px 4px 0;
    margin-top: 0.75rem;
}}

/* Finding cards — colored left border by severity */
.card.sev-critical {{ border-left: 4px solid #ff4444; }}
.card.sev-high     {{ border-left: 4px solid #ff8800; }}
.card.sev-medium   {{ border-left: 4px solid #ffcc00; }}
.card.sev-low      {{ border-left: 4px solid #4488ff; }}
.card.sev-info     {{ border-left: 4px solid #888888; }}
.card.sev-error    {{ border-left: 4px solid #cc44cc; }}

/* ===== Badges ===== */
.badge {{
    display: inline-block;
    padding: 0.15rem 0.55rem;
    border-radius: 4px;
    font-size: 0.7rem;
    font-weight: 800;
    letter-spacing: 0.06rem;
    text-transform: uppercase;
    vertical-align: middle;
    white-space: nowrap;
    font-family: system-ui, -apple-system, sans-serif;
}}

/* ===== Executive Summary ===== */
.summary-grid {{
    display: flex;
    gap: 1rem;
    flex-wrap: wrap;
    margin-bottom: 0.5rem;
}}
.summary-box {{
    flex: 1;
    min-width: 110px;
    background: #16213e;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 1rem;
    text-align: center;
    position: relative;
    overflow: hidden;
}}
.summary-box::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
}}
.summary-box.sev-critical::before {{ background: #ff4444; }}
.summary-box.sev-high::before     {{ background: #ff8800; }}
.summary-box.sev-medium::before   {{ background: #ffcc00; }}
.summary-box.sev-low::before      {{ background: #4488ff; }}
.summary-box.sev-info::before     {{ background: #888888; }}
.summary-count {{
    font-size: 2.2rem;
    font-weight: 900;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    line-height: 1;
    margin-bottom: 0.25rem;
}}
.summary-label {{
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08rem;
    color: #888;
}}
.sev-critical .summary-count {{ color: #ff4444; }}
.sev-high .summary-count     {{ color: #ff8800; }}
.sev-medium .summary-count   {{ color: #ffcc00; }}
.sev-low .summary-count      {{ color: #4488ff; }}
.sev-info .summary-count     {{ color: #888888; }}

/* ===== System Info Table ===== */
.info-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.88rem;
    background: #16213e;
    border-radius: 8px;
    overflow: hidden;
    border: 1px solid #1e3a5f;
}}
.info-table tr:nth-child(even) {{ background: rgba(255,255,255,0.02); }}
.info-table td {{
    padding: 0.6rem 1rem;
    border-bottom: 1px solid #1e3a5f;
}}
.info-table td:first-child {{
    width: 40%;
    font-weight: 600;
    color: #888;
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.04rem;
}}
.info-table td:last-child {{
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    color: #e0e0e0;
    word-break: break-all;
}}
.info-table tr:last-child td {{ border-bottom: none; }}
.admin-yes {{ color: #ff8800 !important; font-weight: 700; }}
.admin-no  {{ color: #44bb66 !important; }}

/* ===== Code / Evidence blocks ===== */
.evidence-block {{
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 0.75rem 1rem;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 0.78rem;
    color: #c9d1d9;
    overflow-x: auto;
    white-space: pre;
    line-height: 1.5;
    max-height: 280px;
    overflow-y: auto;
    margin-top: 0.25rem;
}}
.cmd-block {{
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 6px;
    padding: 0.6rem 1rem;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 0.8rem;
    color: #a5d6ff;
    overflow-x: auto;
    white-space: pre;
    line-height: 1.6;
    margin-top: 0.25rem;
}}

/* ===== MITRE ATT&CK link ===== */
.mitre-link {{
    font-size: 0.78rem;
    color: #4488ff;
    text-decoration: none;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    border: 1px solid rgba(68,136,255,0.3);
    border-radius: 4px;
    padding: 0.1rem 0.4rem;
    display: inline-block;
    margin-top: 0.25rem;
}}
.mitre-link:hover {{ background: rgba(68,136,255,0.1); }}

/* ===== Tools list ===== */
.tools-list {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem;
    margin-top: 0.3rem;
}}
.tool-chip {{
    font-size: 0.75rem;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    background: rgba(68,136,255,0.12);
    border: 1px solid rgba(68,136,255,0.3);
    border-radius: 4px;
    padding: 0.15rem 0.5rem;
    color: #88bbff;
    white-space: nowrap;
}}

/* ===== Tags ===== */
.tag-list {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.3rem;
    margin-top: 0.4rem;
}}
.tag {{
    font-size: 0.68rem;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.12);
    border-radius: 4px;
    padding: 0.1rem 0.4rem;
    color: #999;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
}}

/* ===== Collapsible all-findings table ===== */
details.findings-section {{
    background: #16213e;
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    overflow: hidden;
}}
details.findings-section summary {{
    padding: 0.9rem 1.25rem;
    font-weight: 700;
    font-size: 0.9rem;
    cursor: pointer;
    user-select: none;
    list-style: none;
    display: flex;
    align-items: center;
    gap: 0.5rem;
    color: #aaa;
    text-transform: uppercase;
    letter-spacing: 0.06rem;
}}
details.findings-section summary::marker,
details.findings-section summary::-webkit-details-marker {{ display: none; }}
details.findings-section summary::before {{
    content: '▶';
    font-size: 0.65rem;
    transition: transform 0.15s;
    color: #4488ff;
}}
details.findings-section[open] summary::before {{
    transform: rotate(90deg);
}}
.findings-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 0.82rem;
}}
.findings-table thead tr {{
    background: rgba(68,136,255,0.08);
}}
.findings-table th {{
    padding: 0.5rem 0.9rem;
    text-align: left;
    font-size: 0.72rem;
    text-transform: uppercase;
    letter-spacing: 0.06rem;
    color: #666;
    border-bottom: 1px solid #1e3a5f;
    font-weight: 700;
}}
.findings-table td {{
    padding: 0.5rem 0.9rem;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    vertical-align: top;
    color: #ccc;
}}
.findings-table tr:hover td {{ background: rgba(255,255,255,0.02); }}
.findings-table .sev-group-header td {{
    background: rgba(68,136,255,0.05);
    color: #666;
    font-size: 0.7rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08rem;
    padding: 0.3rem 0.9rem;
    border-bottom: 1px solid #1e3a5f;
}}
.finding-id-cell {{
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
    font-size: 0.75rem;
    color: #666;
    white-space: nowrap;
}}

/* ===== Footer ===== */
.site-footer {{
    margin-top: 3rem;
    padding: 1.25rem 0;
    border-top: 1px solid #1e3a5f;
    text-align: center;
    font-size: 0.78rem;
    color: #444;
    font-family: 'Cascadia Code', 'Fira Code', 'Consolas', monospace;
}}
.site-footer a {{ color: #4488ff; text-decoration: none; }}

/* ===== Utility ===== */
.mt-sm {{ margin-top: 0.5rem; }}
.no-findings {{
    text-align: center;
    padding: 2rem;
    color: #555;
    font-size: 0.9rem;
}}

/* ===== Responsive ===== */
@media (max-width: 768px) {{
    .site-header .container {{ flex-direction: column; align-items: flex-start; }}
    .header-meta {{ text-align: left; }}
    .logo {{ font-size: 2rem; }}
    .summary-grid {{ gap: 0.5rem; }}
    .summary-box {{ min-width: 80px; padding: 0.6rem; }}
    .summary-count {{ font-size: 1.6rem; }}
}}

/* ===== Print ===== */
@media print {{
    body {{ background: #fff; color: #000; }}
    .site-header {{ background: #f0f0f0; border-color: #333; }}
    .logo {{ color: #000; text-shadow: none; }}
    .card, .info-table, details.findings-section {{
        background: #fff; border-color: #ccc;
        box-shadow: none;
    }}
    .evidence-block, .cmd-block {{
        background: #f5f5f5; border-color: #ccc; color: #333;
    }}
    details.findings-section {{ display: block; }}
    details.findings-section summary {{ display: none; }}
    .site-footer {{ color: #666; border-color: #ccc; }}
    .badge {{ border: 1px solid #ccc; }}
    a {{ color: #000; }}
}}
</style>
</head>
<body>"""

    def _html_header(self, results: AgentResults) -> str:
        meta = results.meta
        hostname = _esc(meta.hostname)
        domain_part = f" / {_esc(meta.domain)}" if meta.domain else ""
        user_part = _esc(meta.username) if meta.username else "unknown"
        generated = _now_utc()
        agent_ver = _esc(meta.agent_version) if meta.agent_version else "unknown"

        return f"""<header class="site-header">
  <div class="container">
    <div>
      <div class="logo">SE<span>E</span>P</div>
      <div class="header-subtitle">Windows Privilege Escalation Report</div>
    </div>
    <div class="header-meta">
      <div><strong>Target:</strong> {hostname}{domain_part}</div>
      <div><strong>User:</strong> {user_part}</div>
      <div><strong>Agent:</strong> v{agent_ver}</div>
      <div><strong>Generated:</strong> {_esc(generated)}</div>
    </div>
  </div>
</header>
<div class="container">"""

    def _html_executive_summary(self, results: AgentResults) -> str:
        by_sev = results.summary.by_severity
        total = results.summary.total_findings

        boxes = ""
        for sev in _SEVERITY_ORDER:
            count = by_sev.get(sev, 0)
            if sev in ("error",) and count == 0:
                continue
            color = _SEVERITY_COLOR.get(sev, "#888")
            boxes += (
                f'<div class="summary-box sev-{_esc(sev)}">'
                f'<div class="summary-count" style="color:{color};">{count}</div>'
                f'<div class="summary-label">{_esc(sev.capitalize())}</div>'
                f"</div>"
            )

        # Build a human-readable risk sentence
        critical_n = by_sev.get("critical", 0)
        high_n = by_sev.get("high", 0)
        risk_parts = []
        if critical_n:
            risk_parts.append(
                f'<span style="color:#ff4444;font-weight:700;">{critical_n} critical</span>'
            )
        if high_n:
            risk_parts.append(
                f'<span style="color:#ff8800;font-weight:700;">{high_n} high</span>'
            )
        if risk_parts:
            risk_sentence = (
                f'<p style="margin-top:1rem;font-size:0.9rem;color:#aaa;">'
                f"Immediate attention required: {' and '.join(risk_parts)} severity "
                f"finding{'s' if (critical_n + high_n) > 1 else ''} identified.</p>"
            )
        else:
            risk_sentence = (
                '<p style="margin-top:1rem;font-size:0.9rem;color:#44bb66;">'
                "No critical or high severity findings identified.</p>"
            )

        return f"""<h2 class="section-title">Executive Summary</h2>
<div class="card" style="padding:1.5rem;">
  <div class="summary-grid">{boxes}</div>
  <p style="font-size:0.82rem;color:#555;margin-top:0.75rem;">{total} total finding{"s" if total != 1 else ""} across all severity levels.</p>
  {risk_sentence}
</div>"""

    def _html_system_info(self, results: AgentResults) -> str:
        meta = results.meta
        os_str = f"{meta.os_name} {meta.os_version}".strip() or "—"
        duration = f"{meta.total_duration_seconds:.1f}s"
        admin_class = "admin-yes" if meta.is_admin else "admin-no"
        admin_val = "YES (elevated)" if meta.is_admin else "No"
        domain_joined = "Yes" if meta.is_domain_joined else "No"
        checks = ", ".join(meta.checks_run) if meta.checks_run else "—"

        rows = [
            ("Hostname", _esc(meta.hostname)),
            ("Domain", _esc(meta.domain) if meta.domain else "—"),
            ("Username", _esc(meta.username) if meta.username else "—"),
            ("OS", _esc(os_str)),
            ("Architecture", _esc(meta.architecture) if meta.architecture else "—"),
            ("PowerShell Version", _esc(meta.ps_version) if meta.ps_version else "—"),
            (
                "Admin Privileges",
                f'<span class="{admin_class}">{_esc(admin_val)}</span>',
            ),
            ("Domain Joined", _esc(domain_joined)),
            (
                "Execution Mode",
                _esc(meta.execution_mode) if meta.execution_mode else "—",
            ),
            ("Agent Version", _esc(meta.agent_version) if meta.agent_version else "—"),
            ("Scan Duration", _esc(duration)),
            ("Checks Run", _esc(checks)),
        ]

        rows_html = "".join(
            f"<tr><td>{label}</td><td>{value}</td></tr>" for label, value in rows
        )

        return f"""<h2 class="section-title">System Information</h2>
<table class="info-table">
  <tbody>{rows_html}</tbody>
</table>"""

    def _html_critical_findings(self, results: AgentResults) -> str:
        actionable = [f for f in results.findings if f.severity in ("critical", "high")]
        if not actionable:
            return ""

        cards = ""
        for finding in actionable:
            cards += self._finding_card(finding, show_evidence=True)

        return f"""<h2 class="section-title">Critical &amp; High Findings</h2>
{cards}"""

    def _html_recommendations(self, recs: list[MatchedRecommendation]) -> str:
        if not recs:
            return ""

        cards = ""
        for rec in recs:
            color = _SEVERITY_COLOR.get(rec.risk, "#888")
            bg = _SEVERITY_BG.get(rec.risk, "rgba(136,136,136,0.1)")
            badge = _severity_badge(rec.risk)

            tools_html = ""
            tool_names = rec.display_tools
            if tool_names:
                chips = "".join(
                    f'<span class="tool-chip">{_esc(t)}</span>' for t in tool_names
                )
                tools_html = f'<div class="card-label">Recommended Tools</div><div class="tools-list">{chips}</div>'

            cmds_html = ""
            if rec.example_commands:
                cmds_joined = "\n".join(rec.example_commands)
                cmds_html = f'<div class="card-label">Example Commands</div><pre class="cmd-block">{_esc(cmds_joined)}</pre>'

            mitre_html = (
                f'<a class="mitre-link" href="{_esc(rec.mitre_url)}" target="_blank" rel="noopener">'
                f"{_esc(rec.mitre_technique)} — {_esc(rec.mitre_name)}</a>"
            )

            cards += f"""<div class="card" style="border-left:4px solid {color};background:{bg};">
  <div class="card-title">{badge} {_esc(rec.title)}</div>
  {mitre_html}
  <p class="card-desc mt-sm">{_esc(rec.description)}</p>
  {tools_html}
  {cmds_html}
</div>
"""

        return f"""<h2 class="section-title">Recommendations</h2>
{cards}"""

    def _html_all_findings(
        self, results: AgentResults, include_raw: bool = False
    ) -> str:
        if not results.findings:
            return ""

        rows_html = ""
        for sev in _SEVERITY_ORDER:
            sev_findings = [f for f in results.findings if f.severity == sev]
            if not sev_findings:
                continue
            color = _SEVERITY_COLOR.get(sev, "#888")
            rows_html += (
                f'<tr class="sev-group-header">'
                f'<td colspan="5" style="border-left:3px solid {color};">'
                f"{sev.upper()} ({len(sev_findings)})</td></tr>"
            )
            for f in sev_findings:
                badge = _severity_badge(f.severity)
                tags_html = (
                    "".join(f'<span class="tag">{_esc(t)}</span>' for t in f.tags)
                    if f.tags
                    else '<span style="color:#444;">—</span>'
                )
                rows_html += f"""<tr>
  <td>{badge}</td>
  <td class="finding-id-cell">{_esc(f.finding_id)}</td>
  <td style="color:#ddd;">{_esc(f.title)}</td>
  <td class="finding-id-cell">{_esc(f.check_id)}</td>
  <td><div class="tag-list">{tags_html}</div></td>
</tr>"""

        table_html = f"""<table class="findings-table">
  <thead>
    <tr>
      <th>Severity</th>
      <th>Finding ID</th>
      <th>Title</th>
      <th>Check</th>
      <th>Tags</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>"""

        return f"""<h2 class="section-title">All Findings</h2>
<details class="findings-section">
  <summary>Show All {results.summary.total_findings} Finding{"s" if results.summary.total_findings != 1 else ""}</summary>
  {table_html}
</details>"""

    def _html_footer(self) -> str:
        generated = _now_utc()
        return f"""</div><!-- /container -->
<div class="container">
<footer class="site-footer">
  Generated by <strong>Seep v{_SEEP_VERSION}</strong> &mdash; Windows Privilege Escalation Report &mdash; {_esc(generated)}
</footer>
</div>
</body>
</html>"""

    # ------------------------------------------------------------------
    # Finding card
    # ------------------------------------------------------------------

    def _finding_card(self, finding: Finding, show_evidence: bool = True) -> str:
        badge = _severity_badge(finding.severity)
        sev_cls = _esc(finding.severity)

        evidence_html = ""
        if show_evidence and finding.evidence:
            evidence_html = (
                f'<div class="card-label">Evidence</div>'
                f'<pre class="evidence-block">{_esc(finding.evidence)}</pre>'
            )

        remediation_html = ""
        if finding.remediation:
            remediation_html = (
                f'<div class="card-remediation">'
                f'<strong style="font-size:0.75rem;text-transform:uppercase;letter-spacing:0.05rem;color:#88cc88;">Remediation</strong><br>'
                f"{_esc(finding.remediation)}"
                f"</div>"
            )

        tags_html = ""
        if finding.tags:
            chips = "".join(f'<span class="tag">{_esc(t)}</span>' for t in finding.tags)
            tags_html = f'<div class="tag-list mt-sm">{chips}</div>'

        desc_html = ""
        if finding.description:
            desc_html = f'<p class="card-desc">{_esc(finding.description)}</p>'

        return f"""<div class="card sev-{sev_cls}">
  <div class="card-title">{badge} {_esc(finding.title)}</div>
  {desc_html}
  {evidence_html}
  {remediation_html}
  {tags_html}
</div>
"""
