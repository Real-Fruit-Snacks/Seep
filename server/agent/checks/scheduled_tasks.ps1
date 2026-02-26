# check_id: scheduled_tasks
# check_name: Scheduled Tasks
# category: persistence
# description: Enumerates scheduled tasks, highlights privileged tasks
# requires_admin: false
# opsec_impact: low
# estimated_time_seconds: 5

function Invoke-CheckScheduledTasks {
    [CmdletBinding()]
    param([hashtable]$Config)

    $findings = @()
    $ErrorActionPreference = "SilentlyContinue"

    $rawOutput = ""
    $parsedTasks = @()

    # Run schtasks and capture raw output
    try {
        $rawOutput = & schtasks /query /fo CSV /v 2>&1 | Out-String
    } catch {
        $rawOutput = "[ERROR] schtasks execution failed: $($_.Exception.Message)"
    }

    # Parse CSV output
    if ($rawOutput -match '"TaskName"') {
        try {
            # ConvertFrom-Csv handles the header row automatically
            $csvLines = $rawOutput -split "`r?`n" | Where-Object { $_ -match '^\s*"' }
            $csvContent = $csvLines -join "`n"
            $parsedTasks = $csvContent | ConvertFrom-Csv -ErrorAction Stop
        } catch {
            # Fallback: try splitting on newlines and manual parse
            $parsedTasks = @()
        }
    }

    # Patterns that indicate a privileged run-as context
    $privilegedPatterns = @(
        'SYSTEM',
        'NT AUTHORITY\SYSTEM',
        'LOCAL SERVICE',
        'NETWORK SERVICE',
        'Administrator',
        'Administrators',
        'BUILTIN\Administrators'
    )

    $privilegedTasks = [System.Collections.Generic.List[object]]::new()

    foreach ($task in $parsedTasks) {
        # schtasks CSV column names vary by OS locale/version; try common variants
        $taskName  = if ($task.PSObject.Properties['TaskName'])       { $task.TaskName }
                     elseif ($task.PSObject.Properties['Task Name'])  { $task.'Task Name' }
                     else { "" }

        $runAs     = if ($task.PSObject.Properties['Run As User'])    { $task.'Run As User' }
                     elseif ($task.PSObject.Properties['RunAs'])      { $task.RunAs }
                     else { "" }

        $taskToRun = if ($task.PSObject.Properties['Task To Run'])    { $task.'Task To Run' }
                     elseif ($task.PSObject.Properties['TaskToRun'])  { $task.TaskToRun }
                     else { "" }

        $status    = if ($task.PSObject.Properties['Status'])         { $task.Status }
                     elseif ($task.PSObject.Properties['Scheduled Task State']) { $task.'Scheduled Task State' }
                     else { "" }

        $nextRun   = if ($task.PSObject.Properties['Next Run Time'])  { $task.'Next Run Time' }
                     else { "" }

        $lastRun   = if ($task.PSObject.Properties['Last Run Time'])  { $task.'Last Run Time' }
                     else { "" }

        # Skip empty/header artifacts
        if (-not $taskName -or $taskName -eq "TaskName" -or $taskName -eq "INFO: There are no scheduled tasks presently available") {
            continue
        }

        # Check if run-as matches a privileged pattern
        $isPrivileged = $false
        foreach ($pattern in $privilegedPatterns) {
            if ($runAs -imatch [regex]::Escape($pattern)) {
                $isPrivileged = $true
                break
            }
        }

        if ($isPrivileged) {
            $privilegedTasks.Add($task)

            $evidence  = "Task Name   : $taskName`n"
            $evidence += "Run As User : $runAs`n"
            $evidence += "Task To Run : $taskToRun`n"
            $evidence += "Status      : $status`n"
            $evidence += "Next Run    : $nextRun`n"
            $evidence += "Last Run    : $lastRun`n"

            # Flag if the task action path is writable or non-standard
            $actionPath = ($taskToRun -split ' ')[0].Trim('"')
            if ($actionPath -and -not ($actionPath -imatch '^C:\\Windows\\')) {
                $evidence += "`nNote: Task action binary is outside Windows directory - check for writable path: $actionPath"
            }

            $findings += New-Finding `
                -CheckId    "scheduled_tasks" `
                -FindingId  "privileged_scheduled_task" `
                -Severity   "medium" `
                -Title      "Privileged Scheduled Task: $taskName" `
                -Description "A scheduled task runs under a privileged account ($($runAs)). If the task's executable or its parent directory is writable by the current user, replacing or hijacking the binary could yield privilege escalation. Also review DLL search order for the task binary." `
                -Evidence   $evidence `
                -Remediation "Verify that the binary executed by this task and its parent directories are not writable by unprivileged users. Use accesschk.exe to audit permissions. Remove unnecessary privileged scheduled tasks." `
                -Tags       @("scheduled-tasks", "privilege-escalation", "persistence") `
                -ToolHint   @("accesschk.exe")
        }
    }

    # Always: raw schtasks output
    $rawEvidence  = "Total parsed tasks  : $($parsedTasks.Count)`n"
    $rawEvidence += "Privileged tasks    : $($privilegedTasks.Count)`n`n"
    $rawEvidence += "--- Raw schtasks output ---`n$rawOutput"

    $findings += New-Finding `
        -CheckId    "scheduled_tasks" `
        -FindingId  "scheduled_tasks_raw" `
        -Severity   "info" `
        -Title      "Scheduled Tasks Enumeration (Raw)" `
        -Description "Full raw output from 'schtasks /query /fo CSV /v'. Review all tasks for writable action binaries, DLL hijacking opportunities, and tasks running as high-privileged accounts." `
        -Evidence   $rawEvidence `
        -Remediation "" `
        -Tags       @("raw", "scheduled-tasks", "persistence")

    return $findings
}
