# Security Policy

## Supported Versions

Only the latest release of Seep is supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| latest  | :white_check_mark: |
| < latest | :x:               |

## Reporting a Vulnerability

**Do NOT open public issues for security vulnerabilities.**

If you discover a security vulnerability in Seep, please report it responsibly:

1. **Preferred:** Use [GitHub Security Advisories](https://github.com/Real-Fruit-Snacks/Seep/security/advisories/new) to create a private report.
2. **Alternative:** Email the maintainers directly with details of the vulnerability.

### What to Include

- Description of the vulnerability
- Steps to reproduce
- Affected versions
- Potential impact
- Suggested fix (if any)

### Response Timeline

- **Acknowledgment:** Within 48 hours of receipt
- **Assessment:** Within 7 days
- **Fix & Disclosure:** Within 90 days (coordinated responsible disclosure)

We follow a 90-day responsible disclosure timeline. If a fix is not released within 90 days, the reporter may disclose the vulnerability publicly.

## What is NOT a Vulnerability

Seep is a Windows privilege escalation enumeration framework designed for authorized security assessments. The following behaviors are **features, not bugs**:

- Fileless agent execution via IEX cradle
- AMSI and ETW bypass techniques
- AES-256-CBC encrypted result transport
- Identifier randomization and obfuscation
- Server header spoofing (IIS impersonation)
- Token-gated endpoints returning 404
- Enumerating Windows misconfigurations and credentials

These capabilities exist by design for legitimate security testing. Reports that simply describe Seep working as intended will be closed.

## Responsible Use

Seep is intended for authorized penetration testing, security research, and educational purposes only. Users are responsible for ensuring they have proper authorization before using this tool against any systems.
