# Changelog

All notable changes to Seep will be documented in this file.

Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-04-04

### Added
- 16 PowerShell enumeration checks with metadata headers
- 97-tool catalog with SHA256 integrity verification
- MITRE ATT&CK-mapped recommendation engine
- Fileless agent execution via IEX cradle
- AES-256-CBC encrypted result transport with GZip compression
- Agent composer with check selection and identifier randomization
- Concurrent tool downloads (4-worker thread pool)
- Self-hosted tool distribution via GitHub Releases
- Self-signed TLS server support
- Single-file HTML reports (dark theme, self-contained)
- Markdown and JSON report generation
- AMSI bypass (reflection-based patch)
- ETW and Script Block Logging bypass
- IIS server header spoofing
- Token-authenticated endpoints (404 on auth failure)
- Benign index page for unauthenticated visitors
- Severity system (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Critical alert findings (SeImpersonate, AutoLogon, AlwaysInstallElevated)
- Workspace initialization and configuration
- CLI with subcommands (init, serve, catalog, compose, report, results)
