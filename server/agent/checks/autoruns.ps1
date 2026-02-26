# check_id: autoruns
# check_name: Autoruns
# category: persistence
# description: Checks autorun locations in registry and startup folders
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 2

function Invoke-CheckAutoruns {
    [CmdletBinding()]
    param([hashtable]$Config)

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    $rawLines         = [System.Collections.Generic.List[string]]::new()
    $writableFindings = [System.Collections.Generic.List[hashtable]]::new()

    # -----------------------------------------------------------------------
    # 1. Registry autorun keys
    # -----------------------------------------------------------------------
    $registryKeys = @(
        @{ Hive = "HKLM"; Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "HKLM"; Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Hive = "HKLM"; Path = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "HKLM"; Path = "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce" },
        @{ Hive = "HKCU"; Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
        @{ Hive = "HKCU"; Path = "SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce" }
    )

    foreach ($regKey in $registryKeys) {
        $fullPath = "$($regKey.Hive):\$($regKey.Path)"
        $rawLines.Add("[REGISTRY] $fullPath")
        try {
            $key = Get-Item -Path $fullPath -ErrorAction Stop
            $values = $key.GetValueNames()
            if ($values.Count -eq 0) {
                $rawLines.Add("  (empty)")
            }
            foreach ($valName in $values) {
                $valData = $key.GetValue($valName)
                $rawLines.Add("  $valName = $valData")
            }
        } catch {
            $rawLines.Add("  (not accessible or does not exist: $($_.Exception.Message))")
        }
    }

    # -----------------------------------------------------------------------
    # 2. Startup folders
    # -----------------------------------------------------------------------
    $startupFolders = @()

    # All-users startup
    $allUsersStartup = [System.Environment]::GetFolderPath("CommonStartup")
    if (-not $allUsersStartup -or $allUsersStartup -eq "") {
        $allUsersStartup = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    }
    $startupFolders += $allUsersStartup

    # Current-user startup
    $currentUserStartup = [System.Environment]::GetFolderPath("Startup")
    if (-not $currentUserStartup -or $currentUserStartup -eq "") {
        $currentUserStartup = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    }
    $startupFolders += $currentUserStartup

    foreach ($folder in $startupFolders) {
        $rawLines.Add("[STARTUP FOLDER] $folder")

        if (-not (Test-Path $folder)) {
            $rawLines.Add("  (path does not exist)")
            continue
        }

        # List contents
        try {
            $items = Get-ChildItem -Path $folder -File -ErrorAction SilentlyContinue
            if ($items.Count -eq 0) {
                $rawLines.Add("  (empty folder)")
            }
            foreach ($item in $items) {
                $rawLines.Add("  $($item.Name) [$($item.Length) bytes, modified $($item.LastWriteTime)]")
            }
        } catch {
            $rawLines.Add("  (error listing contents: $($_.Exception.Message))")
        }

        # -----------------------------------------------------------------------
        # 3. Check write permissions via icacls
        # -----------------------------------------------------------------------
        $rawLines.Add("  [PERMISSIONS] icacls output for $folder")
        $icaclsOutput = ""
        try {
            $icaclsOutput = & icacls $folder 2>&1 | Out-String
            foreach ($line in ($icaclsOutput -split "`r?`n")) {
                $rawLines.Add("    $line")
            }
        } catch {
            $rawLines.Add("    (icacls failed: $($_.Exception.Message))")
            $icaclsOutput = ""
        }

        # Parse icacls for writable permissions on non-admin principals
        # Look for (W), (F), or (M) granted to Users, Everyone, BUILTIN\Users, Authenticated Users
        $writablePrincipals = [System.Collections.Generic.List[string]]::new()
        $writableAccessMasks = @('\(W\)', '\(F\)', '\(M\)', '\(WD\)', '\(AD\)')
        $unprivilegedPrincipals = @(
            'Everyone',
            'BUILTIN\\Users',
            'Users',
            'Authenticated Users',
            'NT AUTHORITY\\Authenticated Users',
            $env:USERNAME
        )

        foreach ($line in ($icaclsOutput -split "`r?`n")) {
            $lineHasWrite = $false
            foreach ($mask in $writableAccessMasks) {
                if ($line -imatch $mask) { $lineHasWrite = $true; break }
            }
            if (-not $lineHasWrite) { continue }

            foreach ($principal in $unprivilegedPrincipals) {
                if ($line -imatch [regex]::Escape($principal)) {
                    $writablePrincipals.Add($line.Trim())
                    break
                }
            }
        }

        if ($writablePrincipals.Count -gt 0) {
            $writableFindings.Add(@{
                Folder     = $folder
                Principals = $writablePrincipals
                Icacls     = $icaclsOutput
            })

            $evidence  = "Startup Folder : $folder`n"
            $evidence += "Writable By    :`n"
            foreach ($wp in $writablePrincipals) {
                $evidence += "  $wp`n"
            }
            $evidence += "`n--- Full icacls output ---`n$icaclsOutput"

            $findings += New-Finding `
                -CheckId    "autoruns" `
                -FindingId  "writable_autorun" `
                -Severity   "medium" `
                -Title      "Writable Startup Folder: $folder" `
                -Description "The startup folder '$folder' has write permissions for unprivileged principals. An attacker can place a malicious executable or shortcut (.lnk) in this folder to achieve persistent code execution at the next user logon, potentially with elevated privileges if the affected user has administrative rights." `
                -Evidence   $evidence `
                -Remediation "Restrict write permissions on the startup folder to Administrators only. Run: icacls `"$folder`" /inheritance:d /grant Administrators:(F) /remove Users /remove Everyone. Audit existing startup items for malicious entries." `
                -Tags       @("autoruns", "startup-folder", "persistence", "writable") `
                -ToolHint   @()
        }
    }

    # -----------------------------------------------------------------------
    # 4. Always: raw context finding
    # -----------------------------------------------------------------------
    $rawEvidence  = "Registry autorun keys checked: $($registryKeys.Count)`n"
    $rawEvidence += "Startup folders checked       : $($startupFolders.Count)`n"
    $rawEvidence += "Writable startup folders      : $($writableFindings.Count)`n`n"
    $rawEvidence += "--- Detail ---`n" + ($rawLines -join "`n")

    $findings += New-Finding `
        -CheckId    "autoruns" `
        -FindingId  "autoruns_raw" `
        -Severity   "info" `
        -Title      "Autorun Locations Enumeration (Raw)" `
        -Description "Raw enumeration of all registry autorun keys (HKLM/HKCU Run and RunOnce) and startup folder contents with icacls permission output. Review for unexpected or suspicious entries." `
        -Evidence   $rawEvidence `
        -Remediation "" `
        -Tags       @("raw", "autoruns", "persistence", "registry")

    return $findings
}
