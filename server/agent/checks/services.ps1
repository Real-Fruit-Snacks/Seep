# check_id: services
# check_name: Services
# category: services
# description: Enumerates services, detects unquoted paths and non-standard services
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 3

function Invoke-CheckServices {
    [CmdletBinding()]
    param([hashtable]$Config)

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    $allServices       = @()
    $nonStandard       = @()
    $unquotedPaths     = @()
    $rawLines          = [System.Collections.Generic.List[string]]::new()

    # Retrieve all services via WMI
    try {
        $allServices = Get-WmiObject win32_service -ErrorAction Stop |
            Select-Object Name, DisplayName, PathName, StartName, State, StartMode
    } catch {
        $rawLines.Add("[ERROR] Get-WmiObject win32_service failed: $($_.Exception.Message)")
        try {
            $allServices = Get-CimInstance Win32_Service -ErrorAction Stop |
                Select-Object Name, DisplayName, PathName, StartName, State, StartMode
        } catch {
            $rawLines.Add("[ERROR] Get-CimInstance Win32_Service also failed: $($_.Exception.Message)")
        }
    }

    $rawLines.Add("Total services retrieved: $($allServices.Count)")

    foreach ($svc in $allServices) {
        $path = if ($svc.PathName) { $svc.PathName.Trim() } else { "" }

        # Build a raw summary line
        $rawLines.Add("[$($svc.State)][$($svc.StartMode)] $($svc.Name) | $($svc.StartName) | $path")

        # --- Non-standard detection ---
        # Standard services live under System32, SysWOW64, or the Windows directory
        if ($path -ne "") {
            $isStandard = ($path -imatch '\\Windows\\System32\\') -or
                          ($path -imatch '\\Windows\\SysWOW64\\') -or
                          ($path -imatch '^"?C:\\Windows\\')

            if (-not $isStandard) {
                $nonStandard += $svc
            }

            # --- Unquoted path detection ---
            # Criteria:
            #   1. Path does NOT start with a quote character
            #   2. Path contains at least one space
            #   3. Path is not purely under C:\Windows\*
            $startsWithQuote = $path.StartsWith('"') -or $path.StartsWith("'")
            $hasSpace        = $path -match ' '
            $inWindowsDir    = $path -imatch '^C:\\Windows\\'

            if (-not $startsWithQuote -and $hasSpace -and -not $inWindowsDir) {
                $unquotedPaths += $svc

                # Derive the exploitable insertion point (first space-containing directory segment)
                # e.g. C:\Program Files\My App\svc.exe -> C:\Program.exe would be checked
                $evidence = "Service Name : $($svc.Name)`n"
                $evidence += "Display Name : $($svc.DisplayName)`n"
                $evidence += "Path         : $path`n"
                $evidence += "Run As       : $($svc.StartName)`n"
                $evidence += "State        : $($svc.State)`n"
                $evidence += "Start Mode   : $($svc.StartMode)`n"

                # Show exploitable insertion points
                $segments = $path -split '\\'
                $rebuiltPath = ""
                $insertionPoints = @()
                foreach ($seg in $segments) {
                    if ($rebuiltPath -eq "") {
                        $rebuiltPath = $seg
                    } else {
                        $rebuiltPath += "\$seg"
                    }
                    # If the segment (before any space/arg) contains a space, flag insertion point
                    $segBase = ($seg -split ' ')[0]
                    if ($seg -match ' ' -and (-not $seg.EndsWith('.exe'))) {
                        $insertionPoints += "$rebuiltPath.exe (place malicious binary here)"
                    }
                }
                if ($insertionPoints.Count -gt 0) {
                    $evidence += "`nExploitable insertion points:`n" + ($insertionPoints -join "`n")
                }

                $findings += New-Finding `
                    -CheckId    "services" `
                    -FindingId  "unquoted_service_path" `
                    -Severity   "critical" `
                    -Title      "Unquoted Service Path: $($svc.Name)" `
                    -Description "The service binary path contains spaces and is not enclosed in quotes. Windows will attempt to execute each space-delimited path prefix, allowing a low-privileged user to place a malicious executable at an earlier path segment to achieve code execution as the service account ($($svc.StartName))." `
                    -Evidence   $evidence `
                    -Remediation "Wrap the service ImagePath value in double quotes: sc config `"$($svc.Name)`" binpath= `"`"$path`"`". Verify write permissions on parent directories are restricted to administrators only." `
                    -Tags       @("services", "unquoted-path", "privilege-escalation") `
                    -ToolHint   @("accesschk.exe")
            }
        }
    }

    # --- Non-standard services raw finding ---
    $nsRaw = "Non-standard services ($($nonStandard.Count)):`n"
    foreach ($svc in $nonStandard) {
        $nsRaw += "  [$($svc.State)][$($svc.StartMode)] $($svc.Name) ($($svc.DisplayName))`n"
        $nsRaw += "    Path   : $($svc.PathName)`n"
        $nsRaw += "    RunAs  : $($svc.StartName)`n"
    }

    $findings += New-Finding `
        -CheckId    "services" `
        -FindingId  "non_standard_services_raw" `
        -Severity   "info" `
        -Title      "Non-Standard Services (Raw)" `
        -Description "Services whose binary paths are not located under System32, SysWOW64, or the Windows directory. These are third-party or custom services that warrant manual review for weak permissions, writable binaries, and DLL hijacking opportunities." `
        -Evidence   $nsRaw `
        -Remediation "" `
        -Tags       @("raw", "services", "non-standard")

    # --- All services raw finding ---
    $allRaw = "All services ($($allServices.Count)):`n" + ($rawLines -join "`n")

    $findings += New-Finding `
        -CheckId    "services" `
        -FindingId  "services_raw" `
        -Severity   "info" `
        -Title      "All Services Enumeration (Raw)" `
        -Description "Complete raw enumeration of all Windows services including state, start mode, run-as account, and binary path." `
        -Evidence   $allRaw `
        -Remediation "" `
        -Tags       @("raw", "services")

    return $findings
}
