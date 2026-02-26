# check_id: patches
# check_name: Installed Patches
# category: configuration
# description: Lists installed hotfixes and patches
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 3

function Invoke-CheckPatches {
    [CmdletBinding()]
    param(
        [hashtable]$Config
    )

    $findings = @()
    $checkId  = "patches"

    # --- Get-HotFix (sorted descending by InstalledOn) ---
    $hotfixOut = ""
    $hotfixList = @()
    try {
        $hotfixList = Get-HotFix -ErrorAction Stop | Sort-Object -Property InstalledOn -Descending
        $hotfixOut = $hotfixList | Select-Object HotFixID, Description, InstalledOn, InstalledBy | Format-Table -AutoSize | Out-String
    } catch {
        $hotfixOut = "Get-HotFix failed: $_"
    }

    # --- wmic qfe list brief ---
    $wmicOut = ""
    try {
        $wmicOut = (wmic qfe list brief /format:table) 2>&1 | Out-String
    } catch {
        $wmicOut = "wmic qfe failed: $_"
    }

    # --- Most recent patch date (for staleness assessment) ---
    $patchStaleness = ""
    $mostRecentDate = $null
    if ($hotfixList.Count -gt 0) {
        try {
            $mostRecentDate = ($hotfixList | Where-Object { $_.InstalledOn } | Select-Object -First 1).InstalledOn
            if ($mostRecentDate) {
                $daysSince = (New-TimeSpan -Start $mostRecentDate -End (Get-Date)).Days
                $patchStaleness = "Most recent patch: $($mostRecentDate.ToString('yyyy-MM-dd')) ($($daysSince) days ago)`nTotal patches installed: $($hotfixList.Count)"
            }
        } catch {
            $patchStaleness = "Could not calculate patch staleness: $_"
        }
    } else {
        $patchStaleness = "No hotfix data available from Get-HotFix."
    }

    $evidence = @"
=== PATCH STALENESS SUMMARY ===
$patchStaleness

=== GET-HOTFIX (sorted by date descending) ===
$hotfixOut

=== WMIC QFE LIST BRIEF ===
$wmicOut
"@

    $findings += New-Finding `
        -CheckId     $checkId `
        -FindingId   "patches_raw" `
        -Severity    "info" `
        -Title       "Installed Patches and Hotfixes" `
        -Description "All installed Windows patches and hotfixes sorted by installation date (most recent first). Includes output from both Get-HotFix and wmic qfe for cross-validation." `
        -Evidence    $evidence `
        -Tags        @("patches", "configuration", "recon")

    # Analytical: stale patching
    if ($mostRecentDate) {
        try {
            $daysSince = (New-TimeSpan -Start $mostRecentDate -End (Get-Date)).Days
            if ($daysSince -gt 180) {
                $findings += New-Finding `
                    -CheckId     $checkId `
                    -FindingId   "patches_stale" `
                    -Severity    "high" `
                    -Title       "System Has Not Been Patched in $daysSince Days" `
                    -Description "The most recently installed patch is $daysSince days old (installed $($mostRecentDate.ToString('yyyy-MM-dd'))). Systems unpatched for more than 180 days are likely missing critical security updates including public exploit targets." `
                    -Evidence    $patchStaleness `
                    -Remediation "Apply all outstanding Windows security updates via Windows Update or WSUS. Prioritize patches rated Critical and Important. Investigate why patching has lapsed." `
                    -Tags        @("patches", "configuration", "unpatched")
            } elseif ($daysSince -gt 90) {
                $findings += New-Finding `
                    -CheckId     $checkId `
                    -FindingId   "patches_outdated" `
                    -Severity    "medium" `
                    -Title       "System Has Not Been Patched in $daysSince Days" `
                    -Description "The most recently installed patch is $daysSince days old (installed $($mostRecentDate.ToString('yyyy-MM-dd'))). Microsoft releases security patches monthly; systems should be patched within 30 days of release." `
                    -Evidence    $patchStaleness `
                    -Remediation "Apply outstanding Windows security updates. Review Windows Update configuration and WSUS/SCCM deployment policies." `
                    -Tags        @("patches", "configuration", "unpatched")
            }
        } catch {}
    }

    # Analytical: very few patches (possibly evading patch tracking or freshly installed)
    if ($hotfixList.Count -lt 5 -and $hotfixList.Count -ge 0) {
        $findings += New-Finding `
            -CheckId     $checkId `
            -FindingId   "patches_minimal" `
            -Severity    "low" `
            -Title       "Unusually Low Number of Installed Patches ($($hotfixList.Count))" `
            -Description "Only $($hotfixList.Count) patches were found. This may indicate a freshly provisioned system, an image with patches embedded in the base WIM, or a system where patch tracking has failed. Verify patch state via other means." `
            -Evidence    $patchStaleness `
            -Tags        @("patches", "configuration")
    }

    return $findings
}
