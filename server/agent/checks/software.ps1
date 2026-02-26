# check_id: software
# check_name: Installed Software
# category: software
# description: Lists installed software from registry
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 2

function Invoke-CheckSoftware {
    [CmdletBinding()]
    param(
        [hashtable]$Config = @{}
    )

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    $regPaths = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )

    $allSoftware = foreach ($path in $regPaths) {
        try {
            Get-ItemProperty -Path $path -ErrorAction Stop |
                Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" } |
                Select-Object DisplayName, DisplayVersion, Publisher
        } catch {
            # path may not exist on all systems
        }
    }

    # Deduplicate by DisplayName+Version
    $unique = $allSoftware |
        Sort-Object DisplayName |
        Select-Object -Unique DisplayName, DisplayVersion, Publisher

    $formatted = $unique |
        Format-Table -AutoSize -Property DisplayName, DisplayVersion, Publisher |
        Out-String

    $evidence = @"
=== INSTALLED SOFTWARE (HKLM Uninstall + WOW6432Node) ===
Total entries: $($unique.Count)

$formatted
"@

    $findings += New-Finding `
        -CheckId    "software" `
        -FindingId  "software_raw" `
        -Severity   "info" `
        -Title      "Installed Software" `
        -Description "Installed software enumerated from HKLM Uninstall registry keys (64-bit and 32-bit). Useful for identifying vulnerable software versions, outdated applications, and privilege escalation candidates." `
        -Evidence   $evidence `
        -Tags       @("software", "registry", "raw")

    return $findings
}
