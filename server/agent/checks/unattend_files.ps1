# check_id: unattend_files
# check_name: Unattend Files
# category: credentials
# description: Searches for unattend and sysprep files that may contain credentials
# requires_admin: false
# opsec_impact: medium
# estimated_time_seconds: 10

function Invoke-CheckUnattendFiles {
    [CmdletBinding()]
    param([hashtable]$Config)

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    # Known high-value paths for unattend/sysprep files
    $knownPaths = @(
        "C:\Unattend.xml",
        "C:\Windows\Panther\Unattend.xml",
        "C:\Windows\Panther\Unattend\Unattend.xml",
        "C:\Windows\system32\sysprep\sysprep.xml",
        "C:\Windows\system32\sysprep.inf"
    )

    $knownFound    = @()
    $recursiveFound = @()
    $allSearchResults = [System.Collections.Generic.List[string]]::new()

    # Check known paths first - CRITICAL severity
    foreach ($path in $knownPaths) {
        if (Test-Path $path -PathType Leaf) {
            $knownFound += $path
            $allSearchResults.Add("[KNOWN PATH] $path")

            $content = ""
            try {
                $content = Get-Content $path -Raw -ErrorAction Stop
            } catch {
                $content = "(unable to read content: $($_.Exception.Message))"
            }

            $evidence = "File: $path`n`n--- Content ---`n$content"

            $findings += New-Finding `
                -CheckId    "unattend_files" `
                -FindingId  "unattend_file_found" `
                -Severity   "critical" `
                -Title      "Unattend/Sysprep File Found at Known Path: $path" `
                -Description "An unattend or sysprep XML file was found at a well-known location. These files are frequently left behind after Windows deployment and often contain plaintext or base64-encoded administrator credentials." `
                -Evidence   $evidence `
                -Remediation "Delete the file after confirming it is no longer required. If credentials are present, rotate them immediately. Review GPO/MDT/SCCM configurations to prevent future credential exposure in deployment files." `
                -Tags       @("credentials", "unattend", "sysprep", "plaintext-creds") `
                -ToolHint   @()
        }
    }

    # Recursive search across C:\ for any unattend/sysprep XML not already captured
    Write-Status "Searching C:\ recursively for unattend/sysprep files (may take a moment)..." -Type "INFO"
    $knownPathsNorm = $knownPaths | ForEach-Object { $_.ToLower() }

    try {
        $recurseHits = Get-ChildItem -Path "C:\" -Recurse -Include "*unattend*.xml","*sysprep*.xml" -File -ErrorAction SilentlyContinue |
            Where-Object { $knownPathsNorm -notcontains $_.FullName.ToLower() }

        foreach ($file in $recurseHits) {
            $recursiveFound += $file.FullName
            $allSearchResults.Add("[RECURSIVE] $($file.FullName)")

            $content = ""
            try {
                $content = Get-Content $file.FullName -Raw -ErrorAction Stop
            } catch {
                $content = "(unable to read content: $($_.Exception.Message))"
            }

            $evidence = "File: $($file.FullName)`nSize: $($file.Length) bytes`nModified: $($file.LastWriteTime)`n`n--- Content ---`n$content"

            $findings += New-Finding `
                -CheckId    "unattend_files" `
                -FindingId  "sysprep_file_found" `
                -Severity   "high" `
                -Title      "Unattend/Sysprep File Discovered via Recursive Search: $($file.FullName)" `
                -Description "A file matching unattend or sysprep naming patterns was found outside the standard deployment paths. These files may contain plaintext or base64-encoded credentials from a prior Windows installation or imaging process." `
                -Evidence   $evidence `
                -Remediation "Review file contents for credentials. Delete the file if no longer required. Audit the deployment process that produced this file." `
                -Tags       @("credentials", "unattend", "sysprep") `
                -ToolHint   @()
        }
    } catch {
        $allSearchResults.Add("[ERROR] Recursive search failed: $($_.Exception.Message)")
    }

    # Always emit raw context finding
    $totalFound = $knownFound.Count + $recursiveFound.Count
    $rawEvidence = "Known-path hits ($($knownFound.Count)):`n"
    if ($knownFound.Count -gt 0) {
        $rawEvidence += ($knownFound -join "`n") + "`n"
    } else {
        $rawEvidence += "  (none)`n"
    }
    $rawEvidence += "`nRecursive hits ($($recursiveFound.Count)):`n"
    if ($recursiveFound.Count -gt 0) {
        $rawEvidence += ($recursiveFound -join "`n") + "`n"
    } else {
        $rawEvidence += "  (none)`n"
    }
    $rawEvidence += "`nAll search results:`n" + ($allSearchResults -join "`n")

    $findings += New-Finding `
        -CheckId    "unattend_files" `
        -FindingId  "unattend_search_raw" `
        -Severity   "info" `
        -Title      "Unattend/Sysprep File Search Results (Raw)" `
        -Description "Raw output from the unattend and sysprep file search. Total files found: $totalFound." `
        -Evidence   $rawEvidence `
        -Remediation "" `
        -Tags       @("raw", "credentials", "unattend", "sysprep")

    return $findings
}
