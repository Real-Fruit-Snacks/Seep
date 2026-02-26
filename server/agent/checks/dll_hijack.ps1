# check_id: dll_hijack
# check_name: DLL Hijack Check
# category: filesystem
# description: Checks for writable directories in system PATH
# requires_admin: false
# opsec_impact: medium
# estimated_time_seconds: 3

function Invoke-CheckDllHijack {
    [CmdletBinding()]
    param(
        [hashtable]$Config = @{}
    )

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    # Split PATH and deduplicate
    $pathDirs = $env:PATH -split ";" |
        Where-Object { $_ -and $_.Trim() -ne "" } |
        ForEach-Object { $_.Trim().TrimEnd("\") } |
        Select-Object -Unique

    $rawLines = @()
    $writableDirs = @()

    foreach ($dir in $pathDirs) {
        if (-not (Test-Path -Path $dir -PathType Container)) {
            $rawLines += "[MISSING]  $dir"
            continue
        }

        # Use icacls - avoids creating temp files (better OPSEC than New-Item approach)
        $icaclsOut = (& icacls $dir 2>&1) | Out-String

        # Check for write-capable ACEs for low-priv principals
        # Matches: (W), (F), (M) for Users, Everyone, Authenticated Users, BUILTIN\Users, Creator Owner
        $writePatterns = @(
            "Everyone\):\(.*?[WFM]",
            "BUILTIN\\\\Users\):\(.*?[WFM]",
            "NT AUTHORITY\\\\Authenticated Users\):\(.*?[WFM]",
            "CREATOR OWNER\):\(.*?[WFM]",
            "\\(W\\)",
            "\\(F\\)",
            "\\(M\\)"
        )

        # Simpler reliable match: look for (W), (F), or (M) with low-priv principals
        $icaclsLines = $icaclsOut -split "`n"
        $isWritable = $false
        $writableLines = @()

        foreach ($line in $icaclsLines) {
            $lineTrim = $line.Trim()
            if ($lineTrim -eq "") { continue }

            # Check if line references a low-privilege principal with write access
            $lowPriv = $lineTrim -match "(?i)(Everyone|BUILTIN\\Users|Authenticated Users|CREATOR OWNER|Users)"
            $hasWrite = $lineTrim -match "\((W|F|M)[,)IO]"

            if ($lowPriv -and $hasWrite) {
                $isWritable = $true
                $writableLines += $lineTrim
            }
        }

        if ($isWritable) {
            $writableDirs += @{
                Dir          = $dir
                IcaclsOut    = $icaclsOut
                WritableAces = $writableLines -join "`n"
            }
            $rawLines += "[WRITABLE] $dir"
            $rawLines += "           ACEs: $($writableLines -join ' | ')"
        } else {
            $rawLines += "[ok]       $dir"
        }
    }

    # Raw context finding - always emitted
    $rawEvidence = @"
=== PATH DIRECTORIES WRITABILITY CHECK ===
Total dirs in PATH: $($pathDirs.Count)
Writable dirs    : $($writableDirs.Count)

$($rawLines -join "`n")
"@

    $findings += New-Finding `
        -CheckId    "dll_hijack" `
        -FindingId  "dll_hijack_raw" `
        -Severity   "info" `
        -Title      "DLL Hijack - PATH Directory Writability Summary" `
        -Description "All directories in the system PATH checked for write access by low-privileged users via icacls. Writable PATH directories may allow DLL planting for hijacking privileged processes." `
        -Evidence   $rawEvidence `
        -Tags       @("filesystem", "dll-hijack", "path", "raw")

    # Analytical finding - one per writable directory
    foreach ($entry in $writableDirs) {
        $dir = $entry.Dir
        $evidence = @"
Directory: $dir

=== ICACLS OUTPUT ===
$($entry.IcaclsOut)

=== WRITABLE ACE LINES ===
$($entry.WritableAces)
"@

        $findings += New-Finding `
            -CheckId     "dll_hijack" `
            -FindingId   "writable_path_dir" `
            -Severity    "high" `
            -Title       "Writable PATH Directory: $dir" `
            -Description ('The directory ''' + $dir + ''' is in the system PATH and is writable by low-privileged users. An attacker can plant a malicious DLL with the name expected by a privileged process that loads DLLs from PATH (e.g., services running as SYSTEM). When the privileged process starts or loads the DLL, the attacker''s code executes with elevated privileges.') `
            -Evidence    $evidence `
            -Remediation "Remove write permissions for non-administrative users on '$dir'. Review the directory's ACL and apply principle of least privilege. Consider relocating the directory to a protected path if modification is not feasible." `
            -Tags        @("filesystem", "dll-hijack", "path", "privilege-escalation") `
            -ToolHint    @("accesschk.exe")
    }

    return $findings
}
