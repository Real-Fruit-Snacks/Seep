# check_id: processes
# check_name: Running Processes
# category: software
# description: Enumerates running processes with paths
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 2

function Invoke-CheckProcesses {
    [CmdletBinding()]
    param(
        [hashtable]$Config = @{}
    )

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    # Get-Process output - works on all PS versions
    $psProcs = try {
        Get-Process -ErrorAction Stop |
            Select-Object Id, ProcessName, Path |
            Sort-Object ProcessName |
            Format-Table -AutoSize |
            Out-String
    } catch {
        "Get-Process failed: $_"
    }

    # WMI/CIM - richer data, includes owner info where accessible
    $wmiProcs = try {
        $items = Get-CimInstance Win32_Process -ErrorAction Stop |
            Select-Object ProcessId, Name, ExecutablePath |
            Sort-Object Name
        $items | Format-Table -AutoSize | Out-String
    } catch {
        try {
            $items = Get-WmiObject Win32_Process -ErrorAction Stop |
                Select-Object ProcessId, Name, ExecutablePath |
                Sort-Object Name
            $items | Format-Table -AutoSize | Out-String
        } catch {
            "WMI/CIM process query failed: $_"
        }
    }

    $evidence = @"
=== RUNNING PROCESSES (Get-Process) ===
$psProcs

=== RUNNING PROCESSES (Win32_Process via CIM/WMI) ===
$wmiProcs
"@

    $findings += New-Finding `
        -CheckId    "processes" `
        -FindingId  "processes_raw" `
        -Severity   "info" `
        -Title      "Running Processes" `
        -Description "Enumeration of running processes via Get-Process and Win32_Process (CIM/WMI fallback). Executable paths help identify non-standard or user-writable process locations." `
        -Evidence   $evidence `
        -Tags       @("processes", "software", "raw")

    return $findings
}
